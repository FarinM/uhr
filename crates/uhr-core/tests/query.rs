use uhr_core::query::{GroupBy, Query, run};
use uhr_core::recording::*;
use uhr_core::symbols::{FrameName, Source, SourceStatus, Symbols};

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
    }
}

#[test]
fn shares_self_and_total_time() {
    let result = run(&recording(), Some(&symbols()), &query(10));
    assert_eq!(result.cpu_ns, 10);
    let row = |name: Option<&str>, origin: Origin| {
        result
            .rows
            .iter()
            .find(|r| r.function.as_deref() == name && r.origin == origin)
            .unwrap()
    };

    let leaf = row(Some("leaf"), Origin::Binary);
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
    assert_eq!(placeholder.placeholder.as_deref(), Some("fun_40"));
    assert_eq!(placeholder.module.as_deref(), Some("/bin/app"));
    assert_eq!(placeholder.self_cpu_ns, 1);

    assert_eq!(result.rows[0].function.as_deref(), Some("leaf"));
}

#[test]
fn reports_named_share_and_symbol_problems() {
    let result = run(&recording(), Some(&symbols()), &query(10));
    let coverage = &result.coverage;
    assert_eq!(coverage.named_share, Some(0.8));
    assert_eq!(coverage.unnamed_by_origin[&Origin::Binary], 0.1);
    assert_eq!(coverage.unnamed_by_origin[&Origin::Kernel], 0.1);
    assert!(coverage.symbolized);
    assert_eq!(coverage.symbol_problems.len(), 1);
}

#[test]
fn reports_cut_rows() {
    let result = run(&recording(), Some(&symbols()), &query(2));
    assert_eq!(result.rows.len(), 2);
    assert_eq!(result.rows_omitted, 3);
}

#[test]
fn works_without_symbols() {
    let result = run(&recording(), None, &query(10));
    assert!(!result.coverage.symbolized);
    assert_eq!(result.coverage.named_share, Some(0.0));
    assert!(result.rows.iter().all(|r| r.function.is_none()));
}

#[test]
fn has_no_named_share_without_samples() {
    let mut recording = recording();
    recording.samples.clear();
    let result = run(&recording, Some(&symbols()), &query(10));
    assert!(result.rows.is_empty());
    assert_eq!(result.coverage.named_share, None);
}

#[test]
fn reports_throttling() {
    let mut recording = recording();
    recording.manifest.streams.push(Stream {
        id: "perf".into(),
        collector: Collector::Perf {
            version: "6.8".into(),
            event: "cpu-clock".into(),
            frequency_hz: 999,
            requested_frequency_hz: 999,
            unwinding: Unwinding::FramePointers,
        },
        signals: vec![Signal::CPUSamples],
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
    });
    let result = run(&recording, Some(&symbols()), &query(10));
    assert_eq!(result.coverage.recording.throttle_events, 3);
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
        sources: Vec::new(),
    };

    let result = run(&recording, Some(&symbols), &query(10));
    assert_eq!(result.rows.len(), 2);
    assert_eq!(result.rows[0].function.as_deref(), Some("worker"));
    assert_eq!(result.rows[1].function.as_deref(), Some("worker"));
    assert_eq!(result.rows[0].function_address, Some(0x10));
    assert_eq!(result.rows[1].function_address, Some(0x20));
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
        sources: Vec::new(),
    };

    let result = run(&recording, Some(&symbols), &query(10));
    assert_eq!(result.rows.len(), 1);
    let row = &result.rows[0];
    assert_eq!((row.self_cpu_ns, row.total_cpu_ns), (10, 10));
    assert_eq!(row.function_address, Some(0x10));
    assert_eq!(row.build_id.as_deref(), Some("abcd"));
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
        sources: Vec::new(),
    };

    let result = run(&recording, Some(&symbols), &query(10));
    assert_eq!(result.rows.len(), 2);
    assert_eq!(result.rows[0].build_id.as_deref(), Some("abcd"));
    assert_eq!(result.rows[1].build_id.as_deref(), Some("ef01"));
    assert_eq!(result.rows[0].self_cpu_ns, 6);
    assert_eq!(result.rows[1].self_cpu_ns, 4);
    assert!(
        result
            .rows
            .iter()
            .all(|row| row.function_address == Some(0x10))
    );
    assert_eq!(result.coverage.named_share, Some(0.0));
}
