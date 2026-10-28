use uhr_core::filter::Filter;
use uhr_core::flamegraph::{FlameGraph, Query, run};
use uhr_core::metric::Metric;
use uhr_core::recording::*;
use uhr_core::symbols::{FrameName, Symbols};

/// The binary's functions by frame id, then a kernel frame without a name,
/// then two Ruby functions named `work`, from lines 2 and 7 of one file.
const FUNCTIONS: [(&str, u32); 6] = [
    ("main", 0x10),
    ("a", 0x20),
    ("spin", 0x40),
    ("rec", 0x60),
    ("dup", 0x70),
    ("dup", 0x80),
];
const KERNEL: u32 = 6;
const WORK: [u32; 2] = [7, 8];

/// Each stack, leaf first, with its CPU time:
///   spin a main          6
///   kernel spin a main   1
///   spin rec spin a main 1   spin recurses through rec
///   dup main             1   two functions named dup
///   dup main             2
///   work main            3   two Ruby functions named work
///   work main            1
fn recording() -> (Recording, Symbols) {
    let binary = |address: u32| Frame {
        origin: Origin::Binary,
        address: address as u64,
        mapping: Some(0),
        file_offset: Some(address as u64),
        return_address: false,
        interpreted: None,
    };
    let mut frames: Vec<Frame> = FUNCTIONS.iter().map(|&(_, a)| binary(a)).collect();
    frames.push(Frame {
        origin: Origin::Kernel,
        address: 0xffff_0000,
        mapping: None,
        file_offset: None,
        return_address: false,
        interpreted: None,
    });
    let mut interpreted_code = Vec::new();
    for (code, first_line) in [2, 7].into_iter().enumerate() {
        frames.push(Frame {
            origin: Origin::Interpreted,
            address: 0x5000 + 0x1000 * code as u64,
            mapping: None,
            file_offset: None,
            return_address: false,
            interpreted: Some(Interpreted {
                code: code as u32,
                line: Some(first_line + 1),
            }),
        });
        interpreted_code.push(InterpretedCode {
            pid: 1,
            runtime: "ruby".into(),
            address: 0x5000 + 0x1000 * code as u64,
            name: Some("work".into()),
            file: Some("/app/work.rb".into()),
            first_line: Some(first_line),
            first_column: Some(1),
        });
    }
    let stacks: Vec<(Vec<u32>, u64)> = vec![
        (vec![2, 1, 0], 6),
        (vec![KERNEL, 2, 1, 0], 1),
        (vec![2, 3, 2, 1, 0], 1),
        (vec![4, 0], 1),
        (vec![5, 0], 2),
        (vec![WORK[0], 0], 3),
        (vec![WORK[1], 0], 1),
    ];
    let samples = stacks
        .iter()
        .enumerate()
        .map(|(id, (_, cpu_ns))| Sample {
            time_ns: 1,
            pid: 1,
            tid: 1,
            cpu: None,
            mode: Mode::User,
            stack: id as u32,
            cpu_ns: *cpu_ns,
        })
        .collect();
    let recording = Recording {
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
        page_faults: Vec::new(),
        off_cpu: Vec::new(),
        kernel_symbols: Vec::new(),
        jit_symbols: Vec::new(),
        interpreted_code,
        syscall_calls: Vec::new(),
        memory: Vec::new(),
    };
    let mut names: Vec<_> = FUNCTIONS
        .iter()
        .map(|&(name, _)| Some(FrameName::Symbol(name.into())))
        .collect();
    let mut function_addresses: Vec<_> = FUNCTIONS.iter().map(|&(_, a)| Some(a)).collect();
    names.extend([None, Some(FrameName::Symbol("work".into()))]);
    names.push(Some(FrameName::Symbol("work".into())));
    function_addresses.extend([None, None, None]);
    let symbols = Symbols {
        names,
        function_addresses,
        inline: vec![Vec::new(); FUNCTIONS.len() + 3],
        sources: Vec::new(),
    };
    (recording, symbols)
}

fn graph(root: Option<&str>) -> FlameGraph {
    let (recording, symbols) = recording();
    graph_of(&recording, &symbols, root)
}

fn graph_of(recording: &Recording, symbols: &Symbols, root: Option<&str>) -> FlameGraph {
    let query = Query {
        metric: Metric::OnCPU,
        filter: Filter::default(),
        root: root.map(str::to_owned),
    };
    run(recording, Some(symbols), &query).unwrap()
}

fn folded(graph: &FlameGraph) -> Vec<String> {
    let mut out = Vec::new();
    graph.write_folded(&mut out).unwrap();
    String::from_utf8(out)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn folds_each_stack_from_where_its_thread_started() {
    let graph = graph(None);
    assert_eq!((graph.value, graph.graphed, graph.stacks), (15, 15, 7));
    assert_eq!(
        folded(&graph),
        [
            "main;a;spin 6",
            "main;a;spin;[kernel] 1",
            "main;a;spin;rec;spin 1",
            "main;dup (/bin/app+0x70) 1",
            "main;dup (/bin/app+0x80) 2",
            "main;work (work.rb:2:1) 3",
            "main;work (work.rb:7:1) 1",
        ]
    );
    assert_eq!(graph.coverage.named_share, Some(14.0 / 15.0));
}

#[test]
fn starts_at_the_outermost_call_of_a_function() {
    let graph = graph(Some("spin"));
    let root = graph.root.as_ref().unwrap();
    assert_eq!(root.name.as_deref(), Some("spin"));
    assert_eq!((graph.graphed, graph.graphed_share), (8, 8.0 / 15.0));
    assert_eq!(
        folded(&graph),
        ["spin 6", "spin;[kernel] 1", "spin;rec;spin 1"]
    );
}

#[test]
fn draws_an_svg_of_the_stacks() {
    let mut svg = Vec::new();
    graph(None)
        .write_svg("CPU time", Some("app"), &mut svg)
        .unwrap();
    let svg = String::from_utf8(svg).unwrap();
    assert!(svg.starts_with("<?xml"), "{}", &svg[..100]);
    for text in ["CPU time", "spin: 8 ns, 53.33%", "work (work.rb:2:1)"] {
        assert!(svg.contains(text), "{text}");
    }
}

#[test]
fn keeps_each_frame_one_frame_whatever_its_file_is_called() {
    let (mut recording, symbols) = recording();
    for code in &mut recording.interpreted_code {
        code.file = Some("/app/a;b\nc.rb".into());
    }
    let lines = folded(&graph_of(&recording, &symbols, None));
    assert_eq!(lines.len(), 7, "{lines:?}");
    assert!(lines.contains(&"main;work (a\\u003bb\\u000ac.rb:2:1) 3".to_owned()));
    assert!(lines.contains(&"main;work (a\\u003bb\\u000ac.rb:7:1) 1".to_owned()));
}

#[test]
fn labels_every_function_apart_from_every_other() {
    let (recording, mut symbols) = recording();
    // rec's own name is the label a Ruby work gets.
    symbols.names[3] = Some(FrameName::Symbol("work (work.rb:2:1)".into()));
    let lines = folded(&graph_of(&recording, &symbols, None));
    assert!(
        lines.contains(&"main;a;spin;work (work.rb:2:1) [/bin/app+0x60];spin 1".to_owned()),
        "{lines:?}"
    );
    assert!(
        lines.contains(&"main;work (work.rb:2:1) [jit+ruby:work@2%3A1:/app/work.rb] 3".to_owned()),
        "{lines:?}"
    );
}

#[test]
fn draws_what_xml_cannot_hold_as_escapes() {
    let (mut recording, symbols) = recording();
    // As PHP names an anonymous class.
    recording.interpreted_code[0].name = Some("class@anonymous\0/app/x.php:3$0".into());
    let mut svg = Vec::new();
    graph_of(&recording, &symbols, None)
        .write_svg("CPU time: \u{1b}[31mapp", None, &mut svg)
        .unwrap();
    let svg = String::from_utf8(svg).unwrap();
    assert!(svg.chars().all(|c| c == '\n' || !c.is_control()));
    assert!(svg.contains("class@anonymous\\u0000/app/x.php:3$0"));
    assert!(svg.contains("CPU time: \\u001b[31mapp"));
    // Every block but the one under all others says the block it is on.
    let blocks = svg.matches("<g data-x=").count();
    assert_eq!(svg.matches(" data-p=").count(), blocks - 1);
}
