use uhr_core::filter::{self, Filter};
use uhr_core::functions;
use uhr_core::metric::{self, Metric};
use uhr_core::query::{
    Error, FunctionRow, GroupBy, ModuleRow, Query, QueryResult, Rows, SyscallRow, run,
};
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
                runtime_support: Some(Vec::new()),
                exit: None,
            },
            clock: Clock::Monotonic,
            start_ns: None,
            end_ns: None,
            streams: Vec::new(),
            kernel_symbols: KernelSymbols::Saved,
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
        off_cpu: Vec::new(),
        kernel_symbols: Vec::new(),
        jit_symbols: Vec::new(),
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

fn function_rows(result: &QueryResult) -> &[FunctionRow] {
    let Rows::Functions(rows) = &result.rows else {
        panic!("rows of another grouping: {:?}", result.rows)
    };
    rows
}

fn query(top: usize) -> Query {
    Query {
        group_by: GroupBy::Function,
        top,
        metric: Metric::OnCPU,
        filter: Filter::default(),
    }
}

#[test]
fn shares_self_and_total_time() {
    let result = run(&recording(), Some(&symbols()), &query(10)).unwrap();
    assert_eq!(result.time_ns, 10);
    let row = |name: Option<&str>, origin: Origin| {
        function_rows(&result)
            .iter()
            .find(|r| r.function.name.as_deref() == name && r.function.origin == origin)
            .unwrap()
    };

    let leaf = row(Some("leaf"), Origin::Binary);
    assert_eq!(leaf.function.id.as_deref(), Some("/bin/app+0x10"));
    assert_eq!((leaf.self_ns, leaf.total_ns), (8, 8));
    assert_eq!(leaf.self_share, 0.8);

    let recurse = row(Some("recurse"), Origin::Binary);
    assert_eq!(
        (recurse.self_ns, recurse.total_ns),
        (0, 8),
        "recursion counts once"
    );

    let main = row(Some("main"), Origin::Binary);
    assert_eq!((main.self_ns, main.total_ns), (0, 10));

    let placeholder = row(None, Origin::Binary);
    assert_eq!(placeholder.function.placeholder.as_deref(), Some("fun_40"));
    assert_eq!(placeholder.function.module.as_deref(), Some("/bin/app"));
    assert_eq!(placeholder.self_ns, 1);

    assert_eq!(
        function_rows(&result)[0].function.name.as_deref(),
        Some("leaf")
    );

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
    assert_eq!(function_rows(&result).len(), 2);
    assert_eq!(result.rows_omitted, 3);
}

#[test]
fn works_without_symbols() {
    let result = run(&recording(), None, &query(10)).unwrap();
    assert!(!result.coverage.symbols.symbolized);
    assert_eq!(result.coverage.named_share, Some(0.0));
    assert!(
        function_rows(&result)
            .iter()
            .all(|r| r.function.name.is_none())
    );
    assert!(
        function_rows(&result)
            .iter()
            .all(|r| r.function.id.is_none())
    );
}

#[test]
fn has_no_named_share_without_samples() {
    let mut recording = recording();
    recording.samples.clear();
    let result = run(&recording, Some(&symbols()), &query(10)).unwrap();
    assert!(function_rows(&result).is_empty());
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
            stack_copy_bytes: None,
            context_switches: false,
        },
        signals: vec![Signal::UserCPUSamples],
        missing_signals: Vec::new(),
        coverage: StreamCoverage {
            samples: 4,
            off_cpu_intervals: None,
            lost_events: 0,
            throttle_events: 3,
            max_stack_depth: 127,
            stacks_at_stack_limit: 0,
            stacks_cut_at_stack_copy: None,
            stacks_not_unwound: None,
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
    assert_eq!(function_rows(&result).len(), 2);
    assert_eq!(
        function_rows(&result)[0].function.name.as_deref(),
        Some("worker")
    );
    assert_eq!(
        function_rows(&result)[1].function.name.as_deref(),
        Some("worker")
    );
    assert_eq!(
        function_rows(&result)[0].function.function_address,
        Some(0x10)
    );
    assert_eq!(
        function_rows(&result)[1].function.function_address,
        Some(0x20)
    );
    assert_eq!(
        (
            function_rows(&result)[0].self_ns,
            function_rows(&result)[0].total_ns
        ),
        (6, 6)
    );
    assert_eq!(
        (
            function_rows(&result)[1].self_ns,
            function_rows(&result)[1].total_ns
        ),
        (4, 10)
    );
}

#[test]
fn keeps_kernel_code_outside_mappings_apart() {
    const EGRESS: &str = "bpf_prog_6deef7357e7b4530_sd_fw_egress";
    const INGRESS: &str = "bpf_prog_ee0e253c78993a24_sd_fw_ingress";
    const TRAMPOLINE: &str = "bpf_trampoline_6442";
    let mut recording = recording();
    // The egress program twice, as when it is loaded again.
    let addresses = [0xc0009010, 0xc000b010, 0xc000a010, 0xc000c010, 0xc0020000];
    recording.frames = addresses.map(|a| frame(a, None)).to_vec();
    recording.stacks = (0..5).map(|frame| vec![frame]).collect();
    recording.samples = [1, 8, 2, 16, 4]
        .into_iter()
        .enumerate()
        .map(|(stack, cpu_ns)| sample(stack as u32, cpu_ns))
        .collect();
    let symbol = |start, name: &str| KernelSymbol {
        start,
        end: start + 0x800,
        name: name.into(),
        module: Some("bpf".into()),
    };
    recording.kernel_symbols = vec![
        symbol(0xc0009000, EGRESS),
        symbol(0xc000a000, INGRESS),
        symbol(0xc000b000, EGRESS),
        symbol(0xc000c000, TRAMPOLINE),
    ];
    let name = |n: &str| Some(FrameName::Symbol(n.into()));
    let symbols = Symbols {
        names: vec![
            name(EGRESS),
            name(EGRESS),
            name(INGRESS),
            name(TRAMPOLINE),
            None,
        ],
        function_addresses: vec![None; 5],
        inline: vec![Vec::new(); 5],
        sources: Vec::new(),
    };

    let result = run(&recording, Some(&symbols), &query(10)).unwrap();
    let rows: Vec<_> = function_rows(&result)
        .iter()
        .map(|r| {
            let f = &r.function;
            (
                f.name.as_deref(),
                f.id.as_deref(),
                f.module.as_deref(),
                r.self_ns,
            )
        })
        .collect();
    assert_eq!(
        rows,
        [
            (Some(TRAMPOLINE), None, Some("[bpf]"), 16),
            (
                Some(EGRESS),
                Some("bpf+6deef7357e7b4530_sd_fw_egress"),
                Some("[bpf]"),
                9
            ),
            (None, None, None, 4),
            (
                Some(INGRESS),
                Some("bpf+ee0e253c78993a24_sd_fw_ingress"),
                Some("[bpf]"),
                2
            ),
        ]
    );
    assert_eq!(result.coverage.named_share, Some(27.0 / 31.0));
    for wanted in [INGRESS, "bpf+ee0e253c78993a24_sd_fw_ingress"] {
        let under = run(&recording, Some(&symbols), &under(&[wanted])).unwrap();
        assert_eq!(under.time_ns, 2, "{wanted}");
    }
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
    assert_eq!(function_rows(&result).len(), 1);
    let row = &function_rows(&result)[0];
    assert_eq!((row.self_ns, row.total_ns), (10, 10));
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
    assert_eq!(function_rows(&result).len(), 2);
    assert_eq!(
        function_rows(&result)[0].function.build_id.as_deref(),
        Some("abcd")
    );
    assert_eq!(
        function_rows(&result)[1].function.build_id.as_deref(),
        Some("ef01")
    );
    assert_eq!(function_rows(&result)[0].self_ns, 6);
    assert_eq!(function_rows(&result)[1].self_ns, 4);
    assert!(
        function_rows(&result)
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
    assert_eq!(function_rows(&result).len(), 1, "one function, one id");
    let row = &function_rows(&result)[0];
    assert_eq!(row.function.id.as_deref(), Some("abcd+0x10"));
    assert_eq!(row.function.module.as_deref(), Some("/bin/app"));
    assert_eq!(row.self_ns, 10);
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
        let row = function_rows(&result)
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
            .time_ns
    };
    assert_eq!(cpu_ns(&["main"]), 10);
    assert_eq!(cpu_ns(&["recurse"]), 8);
    // The placeholder has no name to pick it by, only its id.
    assert_eq!(cpu_ns(&["leaf", "/bin/app+0x40"]), 9);

    let result = run(&recording(), Some(&symbols()), &under(&["recurse"])).unwrap();
    assert_eq!(
        function_rows(&result)[0].function.name.as_deref(),
        Some("leaf")
    );
    assert_eq!(function_rows(&result)[0].self_share, 1.0);
}

#[test]
fn a_function_that_is_not_there_is_an_error() {
    let missing = run(&recording(), Some(&symbols()), &under(&["missing"]));
    assert!(matches!(
        missing,
        Err(Error::Filter(filter::Error::Function(
            functions::Error::NotFound(_)
        )))
    ));
    let unsymbolized = run(&recording(), None, &under(&["leaf"]));
    assert!(matches!(
        unsymbolized,
        Err(Error::Filter(filter::Error::Function(
            functions::Error::NotSymbolized
        )))
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

fn row<'a>(result: &'a QueryResult, name: &str) -> &'a FunctionRow {
    function_rows(result)
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
    assert_eq!((helper.self_ns, helper.total_ns), (8, 8));

    let leaf = row(&result, "leaf");
    assert!(!leaf.function.inlined);
    assert_eq!((leaf.self_ns, leaf.total_ns), (0, 8));
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
    let helpers: Vec<_> = function_rows(&result)
        .iter()
        .filter(|r| r.function.name.as_deref() == Some("helper"))
        .collect();
    assert_eq!(helpers.len(), 1);
    assert_eq!(helpers[0].self_ns, 9);

    // A function of the same name declared elsewhere is another function,
    // as is one whose name differs only by a leading underscore.
    symbols.inline[4][0].decl_file = Some("/src/other.c".into());
    let result = run(&recording(), Some(&symbols), &query(10)).unwrap();
    let ids: Vec<_> = function_rows(&result)
        .iter()
        .filter(|r| r.function.name.as_deref() == Some("helper"))
        .map(|r| r.function.id.clone().unwrap())
        .collect();
    assert_eq!(ids.len(), 2);
    assert_ne!(ids[0], ids[1]);

    symbols.inline[4][0] = call("_helper", "/src/app.c", 6);
    let result = run(&recording(), Some(&symbols), &query(10)).unwrap();
    assert!(
        function_rows(&result)
            .iter()
            .any(|r| r.function.name.as_deref() == Some("_helper"))
    );
    assert!(
        function_rows(&result)
            .iter()
            .any(|r| r.function.name.as_deref() == Some("helper"))
    );
}

#[test]
fn filters_by_an_inlined_function_on_the_stack() {
    let mut query = under(&["helper"]);
    query.top = 10;
    let result = run(&recording(), Some(&symbols_with_inlining()), &query).unwrap();
    assert_eq!(result.time_ns, 8);
}

#[test]
fn lists_files_without_debug_info() {
    let result = run(&recording(), Some(&symbols()), &query(10)).unwrap();
    assert_eq!(result.coverage.symbols.without_debug_info, ["/bin/app"]);
}

#[test]
fn groups_by_source_line() {
    let mut query = query(20);
    query.group_by = GroupBy::Line;
    let result = run(&recording(), Some(&symbols_with_inlining()), &query).unwrap();
    assert_eq!(result.group_by, GroupBy::Line);
    let at = |function: &str, line: Option<u32>| {
        function_rows(&result)
            .iter()
            .find(|r| {
                r.function.name.as_deref() == Some(function)
                    && r.line.as_ref().map(|l| l.line) == line
            })
            .unwrap_or_else(|| panic!("no row for {function} at {line:?}"))
    };
    let helper = at("helper", Some(5));
    assert_eq!(helper.line.as_ref().unwrap().file, "/src/app.c");
    assert_eq!((helper.self_ns, helper.total_ns), (8, 8));
    // The leaf frame's caller is at the line of the call.
    assert_eq!(at("leaf", Some(20)).total_ns, 8);
    assert_eq!(at("recurse", Some(30)).total_ns, 8);
    // Code without line info keeps its time in a row with no line.
    assert_eq!(at("main", None).total_ns, 10);
    let rows: u64 = function_rows(&result).iter().map(|r| r.self_ns).sum();
    assert_eq!(rows, result.time_ns);

    let by_function = run(
        &recording(),
        Some(&symbols_with_inlining()),
        &self::query(10),
    )
    .unwrap();
    assert!(function_rows(&by_function).iter().all(|r| r.line.is_none()));
}

/// Context switches: blocked for 20 under leaf, preempted for 5 under the
/// placeholder, and blocked for 15 without a stack.
fn with_off_cpu(mut recording: Recording) -> Recording {
    let mut stream = perf_stream();
    stream
        .signals
        .extend([Signal::OffCPUTime, Signal::OffCPUStacks]);
    recording.manifest.streams.push(stream);
    let interval = |start_ns, end_ns, state, stack| OffCPUInterval {
        start_ns,
        end_ns,
        pid: 1,
        tid: 1,
        state,
        stack,
    };
    recording.off_cpu = vec![
        interval(10, 30, ThreadState::Blocked, Some(0)),
        interval(40, 45, ThreadState::Runnable, Some(1)),
        interval(50, 65, ThreadState::Blocked, None),
    ];
    recording
}

fn by(metric: Metric) -> Query {
    Query {
        metric,
        ..query(10)
    }
}

fn times(result: &QueryResult, name: &str) -> (u64, u64) {
    let row = function_rows(result)
        .iter()
        .find(|r| r.function.name.as_deref() == Some(name))
        .unwrap_or_else(|| panic!("no row {name}"));
    (row.self_ns, row.total_ns)
}

#[test]
fn weighs_stacks_by_the_metric() {
    let recording = with_off_cpu(recording());
    let run = |metric| run(&recording, Some(&symbols()), &by(metric)).unwrap();

    let cpu = run(Metric::OnCPU);
    assert_eq!(
        (cpu.samples, cpu.off_cpu_intervals, cpu.time_ns),
        (4, 0, 10)
    );
    assert_eq!(times(&cpu, "leaf"), (8, 8));
    assert_eq!(cpu.coverage.no_stack_share, 0.0);

    let off = run(Metric::OffCPU);
    assert_eq!(
        (off.samples, off.off_cpu_intervals, off.time_ns),
        (0, 3, 40)
    );
    assert_eq!(times(&off, "leaf"), (20, 20));
    assert_eq!(times(&off, "main"), (0, 25));
    assert_eq!(off.coverage.named_share, Some(0.5));
    assert_eq!(off.coverage.unnamed_by_origin[&Origin::Binary], 0.125);
    assert_eq!(off.coverage.no_stack_share, 0.375);

    let wall = run(Metric::Wall);
    assert_eq!(
        (wall.samples, wall.off_cpu_intervals, wall.time_ns),
        (4, 3, 50)
    );
    assert_eq!(times(&wall, "leaf"), (28, 28));
    assert_eq!(times(&wall, "main"), (0, 35));
}

#[test]
fn off_cpu_time_without_a_stack_is_under_no_function() {
    let query = Query {
        filter: Filter {
            under: vec!["main".into()],
            ..Filter::default()
        },
        ..by(Metric::OffCPU)
    };
    let result = run(&with_off_cpu(recording()), Some(&symbols()), &query).unwrap();
    assert_eq!(result.time_ns, 25);
    assert_eq!(result.coverage.no_stack_share, 0.0);
}

#[test]
fn needs_context_switches_for_off_cpu_time() {
    for metric in [Metric::OffCPU, Metric::Wall] {
        assert!(matches!(
            run(&recording(), Some(&symbols()), &by(metric)),
            Err(Error::Metric(metric::Error::NoContextSwitches))
        ));
    }
}

fn module_rows(result: &QueryResult) -> &[ModuleRow] {
    let Rows::Modules(rows) = &result.rows else {
        panic!("rows of another grouping: {:?}", result.rows)
    };
    rows
}

#[test]
fn groups_by_module() {
    let mut recording = recording();
    // One libc, mapped from two paths.
    let libc = |start, path: &str| Mapping {
        pid: Some(1),
        start,
        end: start + 0x1000,
        file_offset: 0,
        path: path.into(),
        build_id: Some("abcd".into()),
        time_ns: None,
    };
    recording.mappings.push(libc(0x1000, "/lib/libc.so.6"));
    recording.mappings.push(libc(0x2000, "/other/libc.so.6"));
    recording.frames.push(frame(0x1010, Some(1)));
    recording.frames.push(frame(0x2010, Some(2)));
    recording.stacks.push(vec![6, 7, 3]);
    recording.samples.push(sample(3, 4));
    let query = Query {
        group_by: GroupBy::Module,
        ..query(10)
    };
    let result = run(&recording, None, &query).unwrap();
    let rows: Vec<_> = module_rows(&result)
        .iter()
        .map(|r| (r.module.as_deref(), r.origin, r.self_ns, r.total_ns))
        .collect();
    assert_eq!(
        rows,
        [
            (Some("/bin/app"), Origin::Binary, 9, 14),
            (Some("/lib/libc.so.6"), Origin::Binary, 4, 4),
            (None, Origin::Kernel, 1, 1),
        ]
    );
    assert_eq!(module_rows(&result)[1].build_id.as_deref(), Some("abcd"));
    assert_eq!(module_rows(&result)[1].self_share, 4.0 / 14.0);
}

/// Adds a sample on kernel functions of these names, leaf first, called
/// from main.
fn kernel_sample(
    recording: &mut Recording,
    symbols: &mut Symbols,
    names: &[Option<&str>],
    cpu_ns: u64,
) {
    let kernel = match recording.mappings.iter().position(|m| m.path == KERNEL) {
        Some(id) => id as u32,
        None => {
            recording.mappings.push(Mapping {
                pid: None,
                start: 0xffff_0000_0000,
                end: 0xffff_1000_0000,
                file_offset: 0,
                path: KERNEL.into(),
                build_id: None,
                time_ns: None,
            });
            recording.mappings.len() as u32 - 1
        }
    };
    let mut stack = Vec::new();
    for name in names {
        let address = 0xffff_0000_0000 + 0x100 * recording.frames.len() as u64;
        stack.push(recording.frames.len() as u32);
        recording.frames.push(Frame {
            origin: Origin::Kernel,
            address,
            mapping: Some(kernel),
            file_offset: None,
            return_address: false,
        });
        symbols
            .function_addresses
            .push(name.map(|_| (address - 0xffff_0000_0000) as u32));
        symbols
            .names
            .push(name.map(|n| FrameName::Symbol(n.to_owned())));
        symbols.inline.push(Vec::new());
    }
    stack.push(3);
    recording.stacks.push(stack);
    recording.samples.push(Sample {
        mode: Mode::Kernel,
        ..sample(recording.stacks.len() as u32 - 1, cpu_ns)
    });
}

fn syscall_rows(result: &QueryResult) -> Vec<(Option<bool>, Option<&str>, u64)> {
    let Rows::Syscalls(rows) = &result.rows else {
        panic!("rows of another grouping: {:?}", result.rows)
    };
    rows.iter()
        .map(|r: &SyscallRow| (r.in_syscall, r.syscall.as_deref(), r.time_ns))
        .collect()
}

/// User code for 9 and an unnamed kernel function for 1, then 20 in read,
/// 5 on the way out of a syscall, 4 in futex under an unnamed kernel
/// function, 2 in a page fault, 2 in a stack cut short before the kernel
/// entry, and 3 in a page fault at the depth limit of 4. Last, an
/// unresolved frame: 7 in neither user nor kernel mode, as guest code runs,
/// and 1 in user mode.
fn with_syscalls() -> (Recording, Symbols) {
    let (mut recording, mut symbols) = (recording(), symbols());
    let mut stream = perf_stream();
    stream.coverage.max_stack_depth = 4;
    recording.manifest.streams.push(stream);
    let entry = [
        Some("do_syscall_64"),
        Some("entry_SYSCALL_64_after_hwframe"),
    ];
    let mut kernel =
        |names: &[Option<&str>], cpu_ns| kernel_sample(&mut recording, &mut symbols, names, cpu_ns);
    kernel(
        &[&[Some("vfs_read"), Some("__x64_sys_read")][..], &entry].concat(),
        20,
    );
    kernel(
        &[
            &[Some("schedule"), Some("syscall_exit_to_user_mode")][..],
            &entry,
        ]
        .concat(),
        5,
    );
    kernel(
        &[
            &[None, Some("futex_wait"), Some("__x64_sys_futex")][..],
            &entry,
        ]
        .concat(),
        4,
    );
    kernel(&[Some("handle_mm_fault"), Some("asm_exc_page_fault")], 2);
    kernel(&[Some("vfs_read")], 2);
    kernel(
        &[
            Some("filemap_fault"),
            Some("handle_mm_fault"),
            Some("asm_exc_page_fault"),
        ],
        3,
    );

    recording.frames.push(Frame {
        origin: Origin::Unresolved,
        address: 0x5000,
        mapping: None,
        file_offset: None,
        return_address: false,
    });
    symbols.function_addresses.push(None);
    symbols.names.push(None);
    symbols.inline.push(Vec::new());
    recording
        .stacks
        .push(vec![recording.frames.len() as u32 - 1]);
    let stack = recording.stacks.len() as u32 - 1;
    recording.samples.push(Sample {
        mode: Mode::Unknown,
        ..sample(stack, 7)
    });
    recording.samples.push(sample(stack, 1));
    (recording, symbols)
}

#[test]
fn groups_by_the_syscall_on_the_stack() {
    let (recording, symbols) = with_syscalls();
    let query = Query {
        group_by: GroupBy::Syscall,
        ..query(10)
    };
    let result = run(&recording, Some(&symbols), &query).unwrap();
    assert_eq!(
        syscall_rows(&result),
        [
            (Some(true), Some("read"), 20),
            (None, None, 13),
            (Some(false), None, 12),
            (Some(true), None, 5),
            (Some(true), Some("futex"), 4),
        ]
    );

    // Without names, any kernel function could be a syscall's.
    let result = run(&recording, None, &query).unwrap();
    assert_eq!(
        syscall_rows(&result),
        [(None, None, 44), (Some(false), None, 10)]
    );
}

/// Threads go off CPU in the kernel, so a stack without kernel functions
/// lacks them.
#[test]
fn off_cpu_time_without_kernel_functions_is_in_an_unknown_syscall() {
    let query = Query {
        group_by: GroupBy::Syscall,
        ..by(Metric::OffCPU)
    };
    let result = run(&with_off_cpu(recording()), Some(&symbols()), &query).unwrap();
    assert_eq!(syscall_rows(&result), [(None, None, 40)]);
}

fn in_syscalls(syscalls: &[&str], under: &[&str]) -> Query {
    Query {
        filter: Filter {
            syscalls: syscalls.iter().map(|&s| s.to_owned()).collect(),
            under: under.iter().map(|&f| f.to_owned()).collect(),
            ..Filter::default()
        },
        ..query(10)
    }
}

#[test]
fn filters_by_the_syscall_on_the_stack() {
    let (recording, symbols) = with_syscalls();
    let time_ns = |syscalls: &[&str], under: &[&str]| {
        run(&recording, Some(&symbols), &in_syscalls(syscalls, under))
            .unwrap()
            .time_ns
    };
    assert_eq!(time_ns(&["read"], &[]), 20);
    assert_eq!(time_ns(&["read", "futex"], &[]), 24);
    assert_eq!(time_ns(&["futex"], &["futex_wait"]), 4);
    assert_eq!(time_ns(&["read"], &["futex_wait"]), 0);

    match run(&recording, Some(&symbols), &in_syscalls(&["futx"], &[])) {
        Err(Error::Filter(filter::Error::NoSuchSyscall { name, known })) => {
            assert_eq!(name, "futx");
            assert_eq!(known, ["futex", "read"]);
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        run(&recording, None, &in_syscalls(&["read"], &[])),
        Err(Error::Filter(filter::Error::Function(
            functions::Error::NotSymbolized
        )))
    ));
    let mut unnamed = recording.clone();
    unnamed.manifest.kernel_symbols = KernelSymbols::Unavailable {
        reason: "kptr_restrict".into(),
    };
    assert!(matches!(
        run(&unnamed, Some(&symbols), &in_syscalls(&["read"], &[])),
        Err(Error::Filter(filter::Error::NoKernelNames(_)))
    ));
}

#[test]
fn off_cpu_time_without_a_stack_is_in_no_syscall() {
    let (mut recording, symbols) = with_syscalls();
    recording = with_off_cpu(recording);
    recording.off_cpu[1].stack = Some(3);
    let query = Query {
        metric: Metric::OffCPU,
        ..in_syscalls(&["read"], &[])
    };
    let result = run(&recording, Some(&symbols), &query).unwrap();
    assert_eq!((result.off_cpu_intervals, result.time_ns), (1, 5));
}

/// Code runtimes compiled in two processes: `inner` in each, then one of
/// V8's builtins, and code no runtime uhr reads the names of. Each is
/// sampled for 1, called from main.
fn with_jit() -> (Recording, Symbols) {
    let (mut recording, mut symbols) = (recording(), symbols());
    let names = [
        (1, "py::inner:/app/spin.py"),
        (2, "py::inner:/app/spin.py"),
        (2, "Builtin:ArrayPrototypePush"),
        (2, "[OptimizedTier1] Program::Main()"),
    ];
    for (i, (pid, name)) in names.into_iter().enumerate() {
        let start = 0x7f00_0000_0000 + 0x1000 * i as u64;
        recording.mappings.push(Mapping {
            pid: Some(pid),
            start,
            end: start + 0x1000,
            file_offset: 0,
            path: "//anon".into(),
            build_id: None,
            time_ns: None,
        });
        recording.frames.push(Frame {
            origin: Origin::Jit,
            address: start + 0x10,
            mapping: Some(recording.mappings.len() as u32 - 1),
            file_offset: None,
            return_address: false,
        });
        recording.jit_symbols.push(JitSymbol {
            pid,
            start,
            end: start + 0x20,
            name: name.into(),
        });
        symbols.function_addresses.push(None);
        symbols.names.push(Some(FrameName::Symbol(name.into())));
        symbols.inline.push(Vec::new());
        recording
            .stacks
            .push(vec![recording.frames.len() as u32 - 1, 3]);
        recording
            .samples
            .push(sample(recording.stacks.len() as u32 - 1, 1));
    }
    recording.jit_symbols.sort_by_key(|s| (s.pid, s.start));
    (recording, symbols)
}

#[test]
fn groups_code_runtimes_compiled_by_their_names() {
    let (recording, symbols) = with_jit();
    let result = run(&recording, Some(&symbols), &query(20)).unwrap();
    let jit: Vec<_> = function_rows(&result)
        .iter()
        .filter(|r| r.function.origin == Origin::Jit)
        .map(|r| {
            (
                r.function.name.as_deref().unwrap(),
                r.function.id.as_deref().unwrap(),
                r.function.module.as_deref(),
                r.function.file.as_deref(),
                r.self_ns,
            )
        })
        .collect();
    assert_eq!(
        jit,
        [
            (
                "inner",
                "jit+python:inner:/app/spin.py",
                Some("[python]"),
                Some("/app/spin.py"),
                2
            ),
            (
                "Builtin:ArrayPrototypePush",
                "jit+node+Builtin:ArrayPrototypePush",
                Some("[node]"),
                None,
                1
            ),
            (
                "[OptimizedTier1] Program::Main()",
                "jit:[OptimizedTier1] Program::Main()",
                None,
                None,
                1
            ),
        ]
    );
}
