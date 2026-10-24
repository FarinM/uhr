use uhr_core::filter::Filter;
use uhr_core::functions;
use uhr_core::query::{Error, GroupBy, Query, QueryResult, Row, run};
use uhr_core::recording::*;
use uhr_core::symbols::{FrameName, InlineFrame, Source, SourceStatus, Symbols};

fn frame(address: u64, mapping: Option<u32>) -> Frame {
    Frame {
        origin: if mapping.is_some() {
            Origin::Binary
        } else {
            Origin::Kernel
        },
        address,
        mapping,
        file_offset: mapping.map(|_| address),
        return_address: false,
    }
}

fn sample(stack: u32, cpu_ns: u64) -> Sample {
    Sample {
        time_ns: 1,
        pid: 1,
        tid: 1,
        cpu: None,
        mode: Mode::User,
        stack,
        cpu_ns,
    }
}

/// Frames: 0 = leaf, 1 = recurse, 2 = recurse (another address), 3 = main,
/// 4 = a placeholder in the binary, 5 = kernel.
fn recording() -> Recording {
    Recording {
        manifest: Manifest {
            format_version: FORMAT_VERSION,
            target: Target {
                command: vec!["app".into()],
                launched: true,
                exit: None,
            },
            clock: Clock::Monotonic,
            start_ns: None,
            end_ns: None,
            streams: Vec::new(),
        },
        threads: Vec::new(),
        thread_names: Vec::new(),
        mappings: vec![Mapping {
            pid: Some(1),
            start: 0,
            end: 0x1000,
            file_offset: 0,
            path: "/bin/app".into(),
            build_id: None,
            time_ns: None,
        }],
        frames: vec![
            frame(0x10, Some(0)),
            frame(0x20, Some(0)),
            frame(0x24, Some(0)),
            frame(0x30, Some(0)),
            frame(0x40, Some(0)),
            frame(0xffff_0000, None),
        ],
        stacks: vec![vec![0, 1, 2, 3], vec![4, 3], vec![5, 3]],
        samples: vec![sample(0, 6), sample(0, 2), sample(1, 1), sample(2, 1)],
    }
}

fn symbols() -> Symbols {
    let name = |n: &str| Some(FrameName::Symbol(n.to_owned()));
    Symbols {
        function_addresses: vec![
            Some(0x10),
            Some(0x20),
            Some(0x20),
            Some(0x30),
            Some(0x40),
            None,
        ],
        names: vec![
            name("leaf"),
            name("recurse"),
            name("recurse"),
            name("main"),
            Some(FrameName::Placeholder("fun_40".into())),
            None,
        ],
        inline: vec![Vec::new(); 6],
        sources: vec![Source {
            path: "[kernel]".into(),
            build_id: None,
            status: SourceStatus::Unsupported,
            detail: None,
        }],
    }
}

fn query(top: usize) -> Query {
    Query {
        group_by: GroupBy::Function,
        top,
        filter: Filter::default(),
    }
}

#[test]
fn shares_self_and_total_time() {
    let result = run(&recording(), Some(&symbols()), &query(10)).unwrap();
    assert_eq!(result.cpu_ns, 10);
    let row = |name: Option<&str>, origin: Origin| {
        result
            .rows
            .iter()
            .find(|r| r.function.name.as_deref() == name && r.function.origin == origin)
            .unwrap()
    };

    let leaf = row(Some("leaf"), Origin::Binary);
    assert_eq!(leaf.function.id.as_deref(), Some("/bin/app+0x10"));
    assert_eq!((leaf.self_cpu_ns, leaf.total_cpu_ns), (8, 8));
    assert_eq!(leaf.self_share, 0.8);

    let recurse = row(Some("recurse"), Origin::Binary);
    assert_eq!(
        (recurse.self_cpu_ns, recurse.total_cpu_ns),
        (0, 8),
        "recursion counts once"
    );

    let main = row(Some("main"), Origin::Binary);
    assert_eq!((main.self_cpu_ns, main.total_cpu_ns), (0, 10));

    let placeholder = row(None, Origin::Binary);
    assert_eq!(placeholder.function.placeholder.as_deref(), Some("fun_40"));
    assert_eq!(placeholder.function.module.as_deref(), Some("/bin/app"));
    assert_eq!(placeholder.self_cpu_ns, 1);

    assert_eq!(result.rows[0].function.name.as_deref(), Some("leaf"));

    let kernel = row(None, Origin::Kernel);
    assert_eq!(
        kernel.function.id, None,
        "no function address to name it by"
    );
}

#[test]
fn reports_named_share_and_symbol_problems() {
    let result = run(&recording(), Some(&symbols()), &query(10)).unwrap();
    let coverage = &result.coverage;
    assert_eq!(coverage.named_share, Some(0.8));
    assert_eq!(coverage.unnamed_by_origin[&Origin::Binary], 0.1);
    assert_eq!(coverage.unnamed_by_origin[&Origin::Kernel], 0.1);
    assert!(coverage.symbols.symbolized);
    assert_eq!(coverage.symbols.symbol_problems.len(), 1);
}

#[test]
fn reports_cut_rows() {
    let result = run(&recording(), Some(&symbols()), &query(2)).unwrap();
    assert_eq!(result.rows.len(), 2);
    assert_eq!(result.rows_omitted, 3);
}

#[test]
fn works_without_symbols() {
    let result = run(&recording(), None, &query(10)).unwrap();
    assert!(!result.coverage.symbols.symbolized);
    assert_eq!(result.coverage.named_share, Some(0.0));
    assert!(result.rows.iter().all(|r| r.function.name.is_none()));
    assert!(result.rows.iter().all(|r| r.function.id.is_none()));
}

#[test]
fn has_no_named_share_without_samples() {
    let mut recording = recording();
    recording.samples.clear();
    let result = run(&recording, Some(&symbols()), &query(10)).unwrap();
    assert!(result.rows.is_empty());
    assert_eq!(result.coverage.named_share, None);
}

fn perf_stream() -> Stream {
    Stream {
        id: "perf".into(),
        collector: Collector::Perf {
            version: "6.8".into(),
            event: "cpu-clock".into(),
            frequency_hz: 999,
            requested_frequency_hz: 999,
            unwinding: Unwinding::FramePointers,
        },
        signals: vec![Signal::UserCPUSamples],
        missing_signals: Vec::new(),
        coverage: StreamCoverage {
            samples: 4,
            lost_events: 0,
            throttle_events: 3,
            max_stack_depth: 127,
            samples_at_stack_limit: 0,
            overhead_ns: None,
            known_biases: Vec::new(),
        },
    }
}

#[test]
fn reports_throttling() {
    let mut recording = recording();
    recording.manifest.streams.push(perf_stream());
    let result = run(&recording, Some(&symbols()), &query(10)).unwrap();
    assert_eq!(result.coverage.recording.throttle_events, 3);
}

#[test]
fn says_kernel_time_is_left_out_when_it_was_not_sampled() {
    let mut recording = recording();
    let mut stream = perf_stream();
    stream.missing_signals.push(MissingSignal {
        signal: Signal::KernelCPUSamples,
        reason: "excluded".into(),
    });
    recording.manifest.streams.push(stream);
    let result = run(&recording, Some(&symbols()), &query(10)).unwrap();
    assert!(
        result
            .coverage
            .recording
            .unknown
            .iter()
            .any(|u| u.starts_with("CPU time in the kernel")),
        "{:?}",
        result.coverage.recording.unknown
    );

    recording.manifest.streams = vec![perf_stream()];
    let result = run(&recording, Some(&symbols()), &query(10)).unwrap();
    assert!(
        !result
            .coverage
            .recording
            .unknown
            .iter()
            .any(|u| u.starts_with("CPU time in the kernel"))
    );
}

#[test]
fn separates_distinct_functions_with_the_same_name() {
    let mut recording = recording();
    recording.frames = vec![frame(0x10, Some(0)), frame(0x20, Some(0))];
    recording.stacks = vec![vec![0, 1], vec![1]];
    recording.samples = vec![sample(0, 6), sample(1, 4)];
    let symbols = Symbols {
        names: vec![Some(FrameName::Symbol("worker".into())); 2],
        function_addresses: vec![Some(0x10), Some(0x20)],
        inline: vec![Vec::new(); 2],
        sources: Vec::new(),
    };

    let result = run(&recording, Some(&symbols), &query(10)).unwrap();
    assert_eq!(result.rows.len(), 2);
    assert_eq!(result.rows[0].function.name.as_deref(), Some("worker"));
    assert_eq!(result.rows[1].function.name.as_deref(), Some("worker"));
    assert_eq!(result.rows[0].function.function_address, Some(0x10));
    assert_eq!(result.rows[1].function.function_address, Some(0x20));
    assert_eq!(
        (result.rows[0].self_cpu_ns, result.rows[0].total_cpu_ns),
        (6, 6)
    );
    assert_eq!(
        (result.rows[1].self_cpu_ns, result.rows[1].total_cpu_ns),
        (4, 10)
    );
}

#[test]
fn merges_the_same_function_across_mappings_and_counts_recursion_once() {
    let mut recording = recording();
    recording.mappings[0].build_id = Some("abcd".into());
    let mut remapped = recording.mappings[0].clone();
    remapped.start = 0x2000;
    remapped.end = 0x3000;
    recording.mappings.push(remapped);
    recording.frames = vec![frame(0x10, Some(0)), frame(0x2010, Some(1))];
    recording.stacks = vec![vec![0, 1], vec![1]];
    recording.samples = vec![sample(0, 4), sample(1, 6)];
    let symbols = Symbols {
        names: vec![
            Some(FrameName::Symbol("worker".into())),
            Some(FrameName::Symbol("worker_alias".into())),
        ],
        function_addresses: vec![Some(0x10); 2],
        inline: vec![Vec::new(); 2],
        sources: Vec::new(),
    };

    let result = run(&recording, Some(&symbols), &query(10)).unwrap();
    assert_eq!(result.rows.len(), 1);
    let row = &result.rows[0];
    assert_eq!((row.self_cpu_ns, row.total_cpu_ns), (10, 10));
    assert_eq!(row.function.function_address, Some(0x10));
    assert_eq!(row.function.build_id.as_deref(), Some("abcd"));
    assert_eq!(row.function.id.as_deref(), Some("abcd+0x10"));
    assert_eq!(result.coverage.named_share, Some(1.0));
}

#[test]
fn separates_builds_at_the_same_path_and_function_address() {
    let mut recording = recording();
    recording.mappings[0].build_id = Some("abcd".into());
    let mut rebuilt = recording.mappings[0].clone();
    rebuilt.build_id = Some("ef01".into());
    recording.mappings.push(rebuilt);
    recording.frames = vec![frame(0x10, Some(0)), frame(0x10, Some(1))];
    recording.stacks = vec![vec![0], vec![1]];
    recording.samples = vec![sample(0, 6), sample(1, 4)];
    let symbols = Symbols {
        names: vec![Some(FrameName::Placeholder("fun_10".into())); 2],
        function_addresses: vec![Some(0x10); 2],
        inline: vec![Vec::new(); 2],
        sources: Vec::new(),
    };

    let result = run(&recording, Some(&symbols), &query(10)).unwrap();
    assert_eq!(result.rows.len(), 2);
    assert_eq!(result.rows[0].function.build_id.as_deref(), Some("abcd"));
    assert_eq!(result.rows[1].function.build_id.as_deref(), Some("ef01"));
    assert_eq!(result.rows[0].self_cpu_ns, 6);
    assert_eq!(result.rows[1].self_cpu_ns, 4);
    assert!(
        result
            .rows
            .iter()
            .all(|row| row.function.function_address == Some(0x10))
    );
    assert_eq!(result.coverage.named_share, Some(0.0));
}

#[test]
fn combines_copies_of_one_binary_at_different_paths() {
    let mut recording = recording();
    recording.mappings[0].build_id = Some("abcd".into());
    let mut copy = recording.mappings[0].clone();
    copy.path = "/opt/app".into();
    copy.start = 0x2000;
    copy.end = 0x3000;
    recording.mappings.push(copy);
    recording.frames = vec![frame(0x10, Some(0)), frame(0x2010, Some(1))];
    recording.stacks = vec![vec![0], vec![1]];
    recording.samples = vec![sample(0, 4), sample(1, 6)];
    let symbols = Symbols {
        names: vec![Some(FrameName::Symbol("worker".into())); 2],
        function_addresses: vec![Some(0x10); 2],
        inline: vec![Vec::new(); 2],
        sources: Vec::new(),
    };

    let result = run(&recording, Some(&symbols), &query(10)).unwrap();
    assert_eq!(result.rows.len(), 1, "one function, one id");
    let row = &result.rows[0];
    assert_eq!(row.function.id.as_deref(), Some("abcd+0x10"));
    assert_eq!(row.function.module.as_deref(), Some("/bin/app"));
    assert_eq!(row.self_cpu_ns, 10);
}

#[test]
fn the_entry_point_range_of_a_stripped_binary_has_no_id() {
    let mut recording = recording();
    recording.frames = vec![frame(0x10, Some(0)), frame(0x40, Some(0))];
    recording.stacks = vec![vec![0], vec![1]];
    recording.samples = vec![sample(0, 4), sample(1, 6)];
    let symbols = Symbols {
        names: vec![
            Some(FrameName::Placeholder("EntryPoint".into())),
            Some(FrameName::Placeholder("fun_40".into())),
        ],
        function_addresses: vec![Some(0x10), Some(0x40)],
        inline: vec![Vec::new(); 2],
        sources: Vec::new(),
    };

    let result = run(&recording, Some(&symbols), &query(10)).unwrap();
    let id = |placeholder: &str| {
        let row = result
            .rows
            .iter()
            .find(|r| r.function.placeholder.as_deref() == Some(placeholder))
            .unwrap();
        row.function.id.clone()
    };
    assert_eq!(id("EntryPoint"), None, "the range is not one function");
    assert_eq!(id("fun_40").as_deref(), Some("/bin/app+0x40"));
}

fn under(functions: &[&str]) -> Query {
    let mut query = query(10);
    query.filter.under = functions.iter().map(|f| f.to_string()).collect();
    query
}

#[test]
fn keeps_only_samples_under_a_function() {
    let cpu_ns = |functions: &[&str]| {
        run(&recording(), Some(&symbols()), &under(functions))
            .unwrap()
            .cpu_ns
    };
    assert_eq!(cpu_ns(&["main"]), 10);
    assert_eq!(cpu_ns(&["recurse"]), 8);
    // The placeholder has no name to pick it by, only its id.
    assert_eq!(cpu_ns(&["leaf", "/bin/app+0x40"]), 9);

    let result = run(&recording(), Some(&symbols()), &under(&["recurse"])).unwrap();
    assert_eq!(result.rows[0].function.name.as_deref(), Some("leaf"));
    assert_eq!(result.rows[0].self_share, 1.0);
}

#[test]
fn a_function_that_is_not_there_is_an_error() {
    let missing = run(&recording(), Some(&symbols()), &under(&["missing"]));
    assert!(matches!(
        missing,
        Err(Error::Function(functions::Error::NotFound(_)))
    ));
    let unsymbolized = run(&recording(), None, &under(&["leaf"]));
    assert!(matches!(
        unsymbolized,
        Err(Error::Function(functions::Error::NotSymbolized))
    ));
}

/// Running `function` at `file:line`, declared at the start of `file`.
fn call(function: &str, file: &str, line: u32) -> InlineFrame {
    InlineFrame {
        function: Some(function.into()),
        file: Some(file.into()),
        line: Some(line),
        decl_file: Some(file.into()),
        decl_line: Some(1),
    }
}

/// The leaf frame runs `helper`, inlined into `leaf` from `/src/app.c`.
fn symbols_with_inlining() -> Symbols {
    let mut symbols = symbols();
    symbols.inline[0] = vec![
        call("helper", "/src/app.c", 5),
        call("leaf", "/src/app.c", 20),
    ];
    symbols.inline[1] = vec![call("recurse", "/src/app.c", 30)];
    symbols
}

fn row<'a>(result: &'a QueryResult, name: &str) -> &'a Row {
    result
        .rows
        .iter()
        .find(|r| r.function.name.as_deref() == Some(name))
        .unwrap_or_else(|| panic!("no row for {name}"))
}

#[test]
fn credits_inlined_code_to_the_inlined_function() {
    let result = run(&recording(), Some(&symbols_with_inlining()), &query(10)).unwrap();
    let helper = row(&result, "helper");
    assert!(helper.function.inlined);
    assert_eq!(helper.function.function_address, None);
    assert_eq!(helper.function.file.as_deref(), Some("/src/app.c"));
    assert!(
        helper
            .function
            .id
            .as_deref()
            .unwrap()
            .starts_with("/bin/app+inline:")
    );
    assert_eq!((helper.self_cpu_ns, helper.total_cpu_ns), (8, 8));

    let leaf = row(&result, "leaf");
    assert!(!leaf.function.inlined);
    assert_eq!((leaf.self_cpu_ns, leaf.total_cpu_ns), (0, 8));
    assert_eq!(leaf.function.file.as_deref(), Some("/src/app.c"));
    assert_eq!(result.coverage.named_share, Some(0.8));
    assert!(result.coverage.symbols.without_debug_info.is_empty());
}

#[test]
fn an_inlined_function_is_one_function_per_declaration() {
    let mut symbols = symbols_with_inlining();
    // Inlined into the placeholder function too, running code a #line
    // directive puts in another file.
    symbols.inline[4] = vec![
        InlineFrame {
            file: Some("/src/generated.inc".into()),
            ..call("helper", "/src/app.c", 6)
        },
        call("fun_40", "/src/app.c", 40),
    ];
    let result = run(&recording(), Some(&symbols), &query(10)).unwrap();
    let helpers: Vec<_> = result
        .rows
        .iter()
        .filter(|r| r.function.name.as_deref() == Some("helper"))
        .collect();
    assert_eq!(helpers.len(), 1);
    assert_eq!(helpers[0].self_cpu_ns, 9);

    // A function of the same name declared elsewhere is another function,
    // as is one whose name differs only by a leading underscore.
    symbols.inline[4][0].decl_file = Some("/src/other.c".into());
    let result = run(&recording(), Some(&symbols), &query(10)).unwrap();
    let ids: Vec<_> = result
        .rows
        .iter()
        .filter(|r| r.function.name.as_deref() == Some("helper"))
        .map(|r| r.function.id.clone().unwrap())
        .collect();
    assert_eq!(ids.len(), 2);
    assert_ne!(ids[0], ids[1]);

    symbols.inline[4][0] = call("_helper", "/src/app.c", 6);
    let result = run(&recording(), Some(&symbols), &query(10)).unwrap();
    assert!(
        result
            .rows
            .iter()
            .any(|r| r.function.name.as_deref() == Some("_helper"))
    );
    assert!(
        result
            .rows
            .iter()
            .any(|r| r.function.name.as_deref() == Some("helper"))
    );
}

#[test]
fn filters_by_an_inlined_function_on_the_stack() {
    let mut query = under(&["helper"]);
    query.top = 10;
    let result = run(&recording(), Some(&symbols_with_inlining()), &query).unwrap();
    assert_eq!(result.cpu_ns, 8);
}

#[test]
fn lists_files_without_debug_info() {
    let result = run(&recording(), Some(&symbols()), &query(10)).unwrap();
    assert_eq!(result.coverage.symbols.without_debug_info, ["/bin/app"]);
}
