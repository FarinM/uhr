use serde_json::Value;
use uhr_core::export::{self, Error};
use uhr_core::filter::Filter;
use uhr_core::recording::*;
use uhr_core::symbols::{FrameName, InlineFrame, Symbols};

const START: u64 = 9_000_000_000_000_000_000;

fn recording() -> (Recording, Symbols) {
    let frames = (0..3)
        .map(|i| Frame {
            origin: Origin::Binary,
            address: 0x1000 + i * 0x100,
            mapping: Some(0),
            file_offset: Some(i * 0x100),
            return_address: false,
            interpreted: None,
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
                runtime_support: None,
                exit: None,
            },
            clock: Clock::Monotonic,
            start_ns: Some(START),
            end_ns: Some(START + 20_000_000),
            wall_clock: None,
            streams: Vec::new(),
            missing_signals: Vec::new(),
            kernel_symbols: KernelSymbols::Saved,
        },
        threads: vec![
            thread(1, None, None),
            thread(2, None, Some(START + 5_000_000)),
            thread(2, Some(START + 6_000_000), None),
        ],
        thread_names: vec![
            ThreadName {
                pid: 1,
                tid: 1,
                time_ns: None,
                name: "main".into(),
            },
            ThreadName {
                pid: 1,
                tid: 2,
                time_ns: None,
                name: "old-worker".into(),
            },
            ThreadName {
                pid: 1,
                tid: 2,
                time_ns: Some(START + 6_000_000),
                name: "new-worker".into(),
            },
        ],
        mappings: vec![Mapping {
            pid: Some(1),
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            path: "/bin/app".into(),
            build_id: Some("abcd".into()),
            time_ns: None,
        }],
        frames,
        stacks: vec![vec![1, 0], vec![2, 0]],
        samples: vec![
            sample(1, 9_000_000, 0, 1_234_567),
            sample(2, 1_000_000, 1, 500_001),
            sample(1, 1_000_001, 1, 123),
            sample(2, 7_000_000, 0, 800_000),
        ],
        page_faults: Vec::new(),
        off_cpu: Vec::new(),
        kernel_symbols: Vec::new(),
        jit_symbols: Vec::new(),
        interpreted_code: Vec::new(),
        syscall_calls: Vec::new(),
        memory: Vec::new(),
        regions: Vec::new(),
        region_memory: Vec::new(),
    };
    let symbols = Symbols {
        names: vec![
            Some(FrameName::Symbol("main".into())),
            Some(FrameName::Symbol("work".into())),
            Some(FrameName::Symbol("work".into())),
        ],
        function_addresses: vec![Some(0), Some(0x100), Some(0x200)],
        inline: vec![Vec::new(); 3],
        sources: Vec::new(),
    };
    (recording, symbols)
}

fn thread(tid: u32, start_ns: Option<u64>, end_ns: Option<u64>) -> Thread {
    Thread {
        pid: 1,
        tid,
        parent_pid: None,
        parent_tid: None,
        start_ns,
        end_ns,
    }
}

fn sample(tid: u32, time: u64, stack: u32, cpu_ns: u64) -> Sample {
    Sample {
        pid: 1,
        tid,
        time_ns: START + time,
        cpu: Some(0),
        mode: Mode::User,
        stack,
        cpu_ns,
    }
}

fn json(recording: &Recording, symbols: Option<&Symbols>, filter: &Filter) -> Value {
    let profile = export::run(recording, symbols, filter).unwrap();
    let mut bytes = Vec::new();
    profile.write(&mut bytes).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn chain(thread: &Value, mut stack: usize) -> Vec<String> {
    let mut result = Vec::new();
    loop {
        let frame = thread["stackTable"]["frame"][stack].as_u64().unwrap() as usize;
        let function = thread["frameTable"]["func"][frame].as_u64().unwrap() as usize;
        let name = thread["funcTable"]["name"][function].as_u64().unwrap() as usize;
        result.push(thread["stringArray"][name].as_str().unwrap().into());
        match thread["stackTable"]["prefix"][stack].as_u64() {
            Some(parent) => {
                assert!(parent < stack as u64);
                stack = parent as usize;
            }
            None => break,
        }
    }
    result.reverse();
    result
}

#[test]
fn preserves_cpu_weights_timestamps_and_thread_lifetimes() {
    let (recording, symbols) = recording();
    let profile = json(&recording, Some(&symbols), &Filter::default());
    let threads = profile["threads"].as_array().unwrap();
    assert_eq!(threads.len(), 3);
    let names: Vec<_> = threads
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"old-worker"));
    assert!(names.contains(&"new-worker"));
    assert_ne!(threads[0]["tid"], threads[2]["tid"]);
    let mut cpu_ms = 0.0;
    for thread in threads {
        assert_eq!(thread["samples"]["weightType"], "tracing-ms");
        assert!(thread["samples"].get("threadCPUDelta").is_none());
        let times: Vec<_> = thread["samples"]["time"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_f64().unwrap())
            .collect();
        assert!(times.windows(2).all(|p| p[0] <= p[1]));
        cpu_ms += thread["samples"]["weight"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_f64().unwrap())
            .sum::<f64>();
        for stack in thread["samples"]["stack"].as_array().unwrap() {
            let names = chain(thread, stack.as_u64().unwrap() as usize);
            assert_eq!(names[0], "main");
            assert!(names[1].starts_with("work [abcd+0x"), "{names:?}");
        }
    }
    assert!((cpu_ms - 2.534691).abs() < 1e-12);
    let main = threads.iter().find(|t| t["name"] == "main").unwrap();
    assert_eq!(main["samples"]["time"][0], 1.000001);
    assert_eq!(main["samples"]["weight"][0], 0.000123);
    let a = chain(main, main["samples"]["stack"][0].as_u64().unwrap() as usize);
    let b = chain(main, main["samples"]["stack"][1].as_u64().unwrap() as usize);
    assert_ne!(a[1], b[1]);
}

#[test]
fn expands_inline_and_mixed_stacks_with_source_lines() {
    let (mut recording, mut symbols) = recording();
    symbols.inline[1] = vec![
        InlineFrame {
            function: Some("inline".into()),
            file: Some("/src/app.rs".into()),
            line: Some(42),
            decl_file: Some("/src/app.rs".into()),
            decl_line: Some(40),
        },
        InlineFrame {
            function: Some("work".into()),
            file: Some("/src/app.rs".into()),
            line: Some(17),
            decl_file: Some("/src/app.rs".into()),
            decl_line: Some(10),
        },
    ];
    recording.frames.push(Frame {
        origin: Origin::Kernel,
        address: 0xffff0000,
        mapping: None,
        file_offset: None,
        return_address: false,
        interpreted: None,
    });
    recording.frames.push(Frame {
        origin: Origin::Interpreted,
        address: 11,
        mapping: None,
        file_offset: None,
        return_address: false,
        interpreted: Some(Interpreted {
            code: 0,
            line: Some(8),
        }),
    });
    recording.interpreted_code.push(InterpretedCode {
        pid: 1,
        runtime: "python".into(),
        address: 11,
        name: Some("parse".into()),
        file: Some("/src/app.py".into()),
        first_line: Some(5),
        first_column: None,
    });
    symbols
        .names
        .extend([None, Some(FrameName::Symbol("parse".into()))]);
    symbols.function_addresses.extend([None, None]);
    symbols.inline.extend([Vec::new(), Vec::new()]);
    recording.stacks[0] = vec![3, 1, 4, 0];
    recording.samples.truncate(1);
    let profile = json(&recording, Some(&symbols), &Filter::default());
    let t = &profile["threads"][0];
    let names = chain(t, t["samples"]["stack"][0].as_u64().unwrap() as usize);
    assert_eq!(&names[..2], ["main", "parse"]);
    assert_eq!(names[3], "inline");
    assert!(names[4].starts_with("[unknown kernel"));
    assert!(
        t["frameTable"]["line"]
            .as_array()
            .unwrap()
            .contains(&Value::from(42))
    );
    assert!(
        t["frameTable"]["line"]
            .as_array()
            .unwrap()
            .contains(&Value::from(8))
    );
    assert!(
        t["frameTable"]["inlineDepth"]
            .as_array()
            .unwrap()
            .contains(&Value::from(1))
    );
    assert!(
        t["stringArray"]
            .as_array()
            .unwrap()
            .contains(&Value::from("/src/app.py"))
    );
}

#[test]
fn filters_samples_without_moving_the_recording_clock() {
    let (recording, symbols) = recording();
    let filter = Filter {
        thread_names: vec!["new-*".into()],
        from_ns: Some(6_000_000),
        to_ns: Some(8_000_000),
        ..Default::default()
    };
    let profile = json(&recording, Some(&symbols), &filter);
    assert_eq!(profile["threads"].as_array().unwrap().len(), 1);
    assert_eq!(
        profile["threads"][0]["samples"]["time"],
        serde_json::json!([7.0])
    );
    assert_eq!(
        profile["threads"][0]["samples"]["weight"],
        serde_json::json!([0.8])
    );
    let filter = Filter {
        pids: vec![999],
        ..Default::default()
    };
    assert!(matches!(
        export::run(&recording, Some(&symbols), &filter),
        Err(Error::Empty)
    ));
}

#[test]
fn exports_unsymbolized_recordings_and_coverage() {
    let (recording, _) = recording();
    let profile = json(&recording, None, &Filter::default());
    assert!(
        profile["threads"][0]["stringArray"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.as_str().unwrap().contains("[unknown binary"))
    );
    let report: Value = serde_json::from_str(
        profile["meta"]["extra"][0]["entries"][0]["value"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(report["symbols"]["symbolized"], false);
    assert!(
        report["limitations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.as_str().unwrap().contains("Absolute time is unknown"))
    );
}

#[test]
fn reads_an_existing_recording_without_modifying_it() {
    let (mut recording, _) = recording();
    let dir = tempfile::tempdir().unwrap();
    recording.manifest.start_ns = Some(START);
    recording.write(dir.path()).unwrap();
    let manifest = std::fs::read(dir.path().join("manifest.json")).unwrap();
    let exported = export::firefox(dir.path(), &Filter::default()).unwrap();
    assert_eq!(exported.report.samples, 4);
    assert_eq!(
        std::fs::read(dir.path().join("manifest.json")).unwrap(),
        manifest
    );
}
