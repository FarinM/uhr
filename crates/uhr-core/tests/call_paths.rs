use uhr_core::call_paths::{CallPaths, Error, Node, Omitted, Query, run};
use uhr_core::filter::Filter;
use uhr_core::functions;
use uhr_core::metric::Metric;
use uhr_core::recording::*;
use uhr_core::symbols::{FrameName, InlineFrame, Symbols};

/// The binary's functions by frame id, then a kernel frame.
const FUNCTIONS: [(&str, u32); 8] = [
    ("main", 0x10),
    ("a", 0x20),
    ("b", 0x30),
    ("spin", 0x40),
    ("keep", 0x50),
    ("rec", 0x60),
    ("dup", 0x70),
    ("dup", 0x80),
];
const KERNEL: u32 = 8;

/// Each stack, leaf first, with its CPU time:
///   spin a main          6
///   spin b main          2
///   keep spin a main     1
///   main                 1
///   spin rec spin a main 1   spin recurses through rec
///   spin                 1   nothing called spin
///   dup main             1   two functions named dup
///   dup main             1
///   kernel spin a main   1   in kernel mode
fn recording() -> Recording {
    let mut frames: Vec<Frame> = FUNCTIONS
        .iter()
        .map(|&(_, address)| Frame {
            origin: Origin::Binary,
            address: address as u64,
            mapping: Some(0),
            file_offset: Some(address as u64),
            return_address: false,
        })
        .collect();
    frames.push(Frame {
        origin: Origin::Kernel,
        address: 0xffff_0000,
        mapping: None,
        file_offset: None,
        return_address: false,
    });
    let stacks: Vec<(Vec<u32>, u64)> = vec![
        (vec![3, 1, 0], 6),
        (vec![3, 2, 0], 2),
        (vec![4, 3, 1, 0], 1),
        (vec![0], 1),
        (vec![3, 5, 3, 1, 0], 1),
        (vec![3], 1),
        (vec![6, 0], 1),
        (vec![7, 0], 1),
        (vec![KERNEL, 3, 1, 0], 1),
    ];
    let samples = stacks
        .iter()
        .enumerate()
        .map(|(id, &(ref stack, cpu_ns))| Sample {
            time_ns: 1,
            pid: 1,
            tid: 1,
            cpu: None,
            mode: if stack[0] == KERNEL {
                Mode::Kernel
            } else {
                Mode::User
            },
            stack: id as u32,
            cpu_ns,
        })
        .collect();
    Recording {
        manifest: Manifest {
            format_version: FORMAT_VERSION,
            platform: Platform {
                os: "linux".into(),
                arch: "x86_64".into(),
            },
            target: Target {
                command: vec!["app".into()],
                launched: true,
                runtime_support: Some(Vec::new()),
                exit: None,
            },
            clock: Clock::Monotonic,
            start_ns: Some(0),
            end_ns: Some(10),
            streams: Vec::new(),
            missing_signals: Vec::new(),
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
        frames,
        stacks: stacks.into_iter().map(|(stack, _)| stack).collect(),
        samples,
        off_cpu: Vec::new(),
        kernel_symbols: Vec::new(),
        jit_symbols: Vec::new(),
        syscall_calls: Vec::new(),
    }
}

fn symbols() -> Symbols {
    let mut names: Vec<_> = FUNCTIONS
        .iter()
        .map(|&(name, _)| Some(FrameName::Symbol(name.into())))
        .collect();
    let mut function_addresses: Vec<_> = FUNCTIONS.iter().map(|&(_, a)| Some(a)).collect();
    names.push(None);
    function_addresses.push(None);
    Symbols {
        names,
        function_addresses,
        inline: vec![Vec::new(); FUNCTIONS.len() + 1],
        sources: Vec::new(),
    }
}

fn query(function: &str, depth: usize, top: usize) -> Query {
    Query {
        function: function.into(),
        depth,
        top,
        metric: Metric::OnCPU,
        filter: Filter::default(),
    }
}

fn paths(query: &Query) -> CallPaths {
    run(&recording(), Some(&symbols()), query).unwrap()
}

/// Each node as its name and CPU time, indented by level.
fn tree(nodes: &[Node]) -> Vec<String> {
    fn walk(nodes: &[Node], level: usize, out: &mut Vec<String>) {
        for node in nodes {
            let name = node.function.name.as_deref().unwrap_or("<unnamed>");
            out.push(format!("{}{name} {}", "  ".repeat(level), node.time_ns));
            walk(&node.children, level + 1, out);
        }
    }
    let mut out = Vec::new();
    walk(nodes, 0, &mut out);
    out
}

#[test]
fn follows_the_paths_through_a_function() {
    let result = paths(&query("spin", 3, 5));
    assert_eq!(result.function.name.as_deref(), Some("spin"));
    assert_eq!(result.function.id.as_deref(), Some("/bin/app+0x40"));
    assert_eq!(result.time_ns, 15);
    assert_eq!((result.total_ns, result.self_ns), (12, 10));
    assert_eq!(result.total_share, 0.8);
    assert_eq!(result.no_caller_ns, 1);

    assert_eq!(
        tree(&result.callers),
        ["a 9", "  main 9", "b 2", "  main 2"]
    );
    assert!(result.callers.iter().all(|n| n.self_ns.is_none()));
    assert_eq!(
        result.callers_omitted,
        Omitted {
            nodes: 0,
            time_ns: 0
        }
    );
}

#[test]
fn counts_a_recursive_call_from_its_outermost_call() {
    let result = paths(&query("spin", 3, 5));
    assert!(
        tree(&result.callers)
            .iter()
            .all(|line| !line.trim_start().starts_with("spin ")),
        "spin is never its own caller"
    );
    let rec = result
        .callees
        .iter()
        .find(|n| n.function.name.as_deref() == Some("rec"))
        .unwrap();
    assert_eq!((rec.time_ns, rec.self_ns), (1, Some(0)));
    let inner = &rec.children[0];
    assert_eq!(inner.function.name.as_deref(), Some("spin"));
    assert_eq!(inner.self_ns, Some(1));
}

#[test]
fn lists_callees_with_their_leaf_time() {
    let result = paths(&query("spin", 3, 5));
    let callee = |name: Option<&str>| {
        result
            .callees
            .iter()
            .find(|n| n.function.name.as_deref() == name)
            .unwrap()
    };
    assert_eq!(callee(Some("keep")).self_ns, Some(1));
    let kernel = callee(None);
    assert_eq!(kernel.function.origin, Origin::Kernel);
    assert_eq!((kernel.time_ns, kernel.self_ns), (1, Some(1)));
    assert_eq!(result.callees.len(), 3);
}

#[test]
fn reports_what_the_depth_limit_cuts() {
    let result = paths(&query("spin", 1, 5));
    let a = &result.callers[0];
    assert!(a.children.is_empty());
    assert_eq!(
        a.omitted,
        Omitted {
            nodes: 1,
            time_ns: 9
        }
    );
    let rec = result
        .callees
        .iter()
        .find(|n| n.function.name.as_deref() == Some("rec"))
        .unwrap();
    assert_eq!(
        rec.omitted,
        Omitted {
            nodes: 1,
            time_ns: 1
        }
    );
    assert_eq!(rec.self_ns, Some(0), "the leaf is below the limit");
}

#[test]
fn sums_the_children_cut_by_top() {
    let result = paths(&query("spin", 3, 1));
    assert_eq!(tree(&result.callers), ["a 9", "  main 9"]);
    assert_eq!(
        result.callers_omitted,
        Omitted {
            nodes: 1,
            time_ns: 2
        }
    );
    assert_eq!(result.callees.len(), 1);
    assert_eq!(
        result.callees_omitted,
        Omitted {
            nodes: 2,
            time_ns: 2
        }
    );
}

#[test]
fn selects_by_id_or_unique_name() {
    let by_id = paths(&query("/bin/app+0x40", 3, 5));
    assert_eq!(by_id.function.name.as_deref(), Some("spin"));
    assert_eq!(by_id.total_ns, 12);

    let recording = recording();
    let error = |name: &str| run(&recording, Some(&symbols()), &query(name, 3, 5)).unwrap_err();
    match error("dup") {
        Error::Function(functions::Error::Ambiguous { name, ids }) => {
            assert_eq!(name, "dup");
            assert_eq!(ids, ["/bin/app+0x70", "/bin/app+0x80"]);
        }
        other => panic!("{other}"),
    }
    assert!(matches!(
        error("missing"),
        Error::Function(functions::Error::NotFound(_))
    ));
    assert!(matches!(
        run(&recording, None, &query("spin", 3, 5)),
        Err(Error::Function(functions::Error::NotSymbolized))
    ));

    let dup = paths(&query("/bin/app+0x80", 3, 5));
    assert_eq!(dup.total_ns, 1);
}

#[test]
fn follows_only_the_samples_that_pass_the_filter() {
    let mut query = query("spin", 3, 5);
    query.filter.modes = vec![Mode::Kernel];
    let result = paths(&query);
    assert_eq!((result.time_ns, result.total_ns, result.self_ns), (1, 1, 0));
    assert_eq!(tree(&result.callers), ["a 1", "  main 1"]);
    assert_eq!(result.total_share, 1.0);
}

#[test]
fn reports_how_much_of_the_trees_is_named() {
    let result = paths(&query("spin", 3, 5));
    let coverage = &result.coverage;
    assert_eq!(coverage.named_share, Some(11.0 / 12.0));
    assert_eq!(coverage.unnamed_by_origin[&Origin::Kernel], 1.0 / 12.0);
    assert!(coverage.symbols.symbolized);

    let none = paths(&Query {
        filter: Filter {
            tids: vec![99],
            ..Filter::default()
        },
        ..query("spin", 3, 5)
    });
    assert_eq!(none.coverage.named_share, None);
}

#[test]
fn the_largest_depth_keeps_every_path() {
    let unlimited = paths(&query("spin", usize::MAX, 5));
    let deep = paths(&query("spin", 10, 5));
    assert_eq!(tree(&unlimited.callers), tree(&deep.callers));
    assert_eq!(tree(&unlimited.callees), tree(&deep.callees));
    assert!(!unlimited.callers.is_empty());
}

#[test]
fn a_binary_that_ran_from_two_paths_is_one_function() {
    let mut recording = recording();
    recording.mappings[0].build_id = Some("abcd".into());
    let mut copy = recording.mappings[0].clone();
    copy.path = "/opt/app".into();
    copy.start = 0x2000;
    copy.end = 0x3000;
    recording.mappings.push(copy);
    // spin in the copy, called from main in the copy.
    let in_copy = |frame: &Frame| Frame {
        address: frame.address + 0x2000,
        mapping: Some(1),
        ..frame.clone()
    };
    let (spin, main) = (in_copy(&recording.frames[3]), in_copy(&recording.frames[0]));
    recording.frames.extend([spin, main]);
    let mut symbols = symbols();
    symbols.names.extend([
        Some(FrameName::Symbol("spin".into())),
        Some(FrameName::Symbol("main".into())),
    ]);
    symbols.function_addresses.extend([Some(0x40), Some(0x10)]);
    symbols.inline.extend([Vec::new(), Vec::new()]);
    recording.stacks.push(vec![9, 10]);
    recording.samples.push(Sample {
        stack: recording.stacks.len() as u32 - 1,
        cpu_ns: 5,
        ..recording.samples[0].clone()
    });

    for function in ["abcd+0x40", "spin"] {
        let result = run(&recording, Some(&symbols), &query(function, 3, 5)).unwrap();
        assert_eq!(result.total_ns, 17, "{function}: both copies count");
        assert_eq!(tree(&result.callers)[..2], ["a 9", "  main 9"]);
        assert!(tree(&result.callers).contains(&"main 5".to_owned()));
    }
}

#[test]
fn goes_through_inlined_calls() {
    let mut symbols = symbols();
    let call = |function: &str| InlineFrame {
        function: Some(function.into()),
        file: Some("/src/app.c".into()),
        line: Some(1),
        decl_file: Some("/src/app.c".into()),
        decl_line: Some(1),
    };
    symbols.inline[3] = vec![call("mixin"), call("spin")];
    let mixin = run(&recording(), Some(&symbols), &query("mixin", 3, 5)).unwrap();
    assert!(mixin.function.inlined);
    assert_eq!((mixin.total_ns, mixin.self_ns), (12, 10));
    assert_eq!(
        tree(&mixin.callers),
        ["spin 12", "  a 9", "    main 9", "  b 2", "    main 2"]
    );

    let spin = run(&recording(), Some(&symbols), &query("spin", 3, 5)).unwrap();
    assert_eq!(spin.self_ns, 0, "the time is in the inlined code");
    let callee = spin
        .callees
        .iter()
        .find(|n| n.function.name.as_deref() == Some("mixin"))
        .unwrap();
    // The tenth is the recursive call, below the depth limit.
    assert_eq!(callee.self_ns, Some(9));
}

#[test]
fn follows_off_cpu_time_through_the_paths() {
    let mut recording = recording();
    recording.manifest.streams.push(Stream {
        id: "perf".into(),
        collector: Collector::Perf {
            version: "6.8".into(),
            sampling: Some(Sampling {
                event: "cpu-clock".into(),
                frequency_hz: 999,
                requested_frequency_hz: 999,
            }),
            context_switches: true,
        },
        signals: vec![Signal::OffCPUTime, Signal::OffCPUStacks],
        missing_signals: Vec::new(),
        coverage: StreamCoverage {
            lost_events: 0,
            stacks: Some(StackCoverage {
                unwinding: Unwinding::FramePointers,
                stack_copy_bytes: None,
                samples: 15,
                off_cpu_intervals: Some(3),
                throttle_events: 0,
                max_stack_depth: 127,
                stacks_at_stack_limit: 0,
                stacks_cut_at_stack_copy: None,
                stacks_not_unwound: None,
            }),
            overhead_ns: None,
            known_biases: Vec::new(),
        },
    });
    let interval = |stack, end_ns| OffCPUInterval {
        start_ns: 0,
        end_ns,
        pid: 1,
        tid: 1,
        state: ThreadState::Blocked,
        stack,
    };
    // Under spin b main, under main alone, and without a stack.
    recording.off_cpu = vec![
        interval(Some(1), 30),
        interval(Some(3), 10),
        interval(None, 10),
    ];
    let by = |metric| {
        let query = Query {
            metric,
            ..query("spin", 3, 5)
        };
        run(&recording, Some(&symbols()), &query).unwrap()
    };

    let off = by(Metric::OffCPU);
    assert_eq!((off.time_ns, off.total_ns, off.self_ns), (50, 30, 30));
    assert_eq!(off.off_cpu_intervals, 3);
    assert_eq!(tree(&off.callers), ["b 30", "  main 30"]);
    assert_eq!(off.coverage.no_stack_share, 0.2);

    let wall = by(Metric::Wall);
    assert_eq!((wall.time_ns, wall.total_ns), (65, 42));
    assert_eq!(
        tree(&wall.callers),
        ["b 32", "  main 32", "a 9", "  main 9"]
    );
}
