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

fn with_observations() -> (Recording, Symbols) {
    let (mut recording, symbols) = recording();
    recording.off_cpu = vec![OffCPUInterval {
        pid: 1,
        tid: 1,
        start_ns: START + 2_000_000,
        end_ns: START + 6_000_000,
        state: ThreadState::Blocked,
        stack: Some(0),
        wakeup: Some(Wakeup {
            time_ns: START + 4_000_000,
            waker: Waker::Thread {
                pid: 8,
                tid: 9,
                name: "waker".into(),
            },
            stack: Some(1),
        }),
    }];
    recording.page_faults = vec![FaultSample {
        time_ns: START + 3_000_000,
        pid: 1,
        tid: 1,
        cpu: Some(2),
        mode: Mode::User,
        stack: 1,
        faults: 100,
        address: u64::MAX - 1,
    }];
    recording.memory = [1_000_000, 100, 200]
        .into_iter()
        .enumerate()
        .map(|(i, bytes)| MemoryReading {
            time_ns: START + (i as u64 + 1) * 1_000_000,
            pid: 1,
            rss_anon_bytes: bytes,
            rss_file_bytes: 50,
            rss_shmem_bytes: 5,
            swap_bytes: 2,
            peak_rss_bytes: 1_000_055,
        })
        .collect();
    (recording, symbols)
}

#[test]
fn shows_waits_and_faults_without_adding_them_to_cpu_time() {
    let (recording, symbols) = with_observations();
    let exported = export::run(&recording, Some(&symbols), &Filter::default()).unwrap();
    assert_eq!(exported.report.cpu_ns, 2_534_691);
    assert_eq!(exported.report.observations.off_cpu_ns, 4_000_000);
    let profile = json(&recording, Some(&symbols), &Filter::default());
    let main = profile["threads"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["tid"] == "1")
        .unwrap();
    let markers = &main["markers"];
    let data = markers["data"].as_array().unwrap();
    let blocked = data.iter().position(|m| m["state"] == "blocked").unwrap();
    let runnable = data.iter().position(|m| m["state"] == "runnable").unwrap();
    assert_eq!(markers["startTime"][blocked], 2.0);
    assert_eq!(markers["endTime"][blocked], 4.0);
    assert_eq!(markers["startTime"][runnable], 4.0);
    assert_eq!(markers["endTime"][runnable], 6.0);
    let wakeup = data.iter().find(|m| m["type"] == "UhrWakeup").unwrap();
    assert_eq!(wakeup["waker"], "waker (pid 8, tid 9)");
    let sleeping = chain(
        main,
        data[blocked]["cause"]["stack"].as_u64().unwrap() as usize,
    );
    let waking = chain(main, wakeup["cause"]["stack"].as_u64().unwrap() as usize);
    assert_ne!(sleeping, waking, "the wakeup carries the waker's stack");
    let fault = data.iter().find(|m| m["type"] == "UhrPageFault").unwrap();
    assert_eq!(fault["faults"], 100);
    assert_eq!(fault["address"], "0xfffffffffffffffe");
    let times: Vec<_> = markers["startTime"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_f64().unwrap())
        .collect();
    assert!(times.windows(2).all(|w| w[0] <= w[1]));
}

#[test]
fn clips_waits_and_retains_unknown_stacks() {
    let (mut recording, symbols) = with_observations();
    recording.samples.clear();
    recording.off_cpu[0].stack = None;
    let filter = Filter {
        from_ns: Some(5_000_000),
        to_ns: Some(5_500_000),
        ..Default::default()
    };
    let profile = json(&recording, Some(&symbols), &filter);
    let markers = &profile["threads"][0]["markers"];
    assert_eq!(markers["length"], 1);
    assert_eq!(markers["startTime"][0], 5.0);
    assert_eq!(markers["endTime"][0], 5.5);
    assert_eq!(markers["data"][0]["state"], "runnable");
    assert_eq!(markers["data"][0]["stackStatus"], "not recorded");
    assert!(markers["data"][0].get("cause").is_none());
    assert_eq!(profile["threads"][0]["samples"]["length"], 0);
}

#[test]
fn exports_memory_only_with_deltas_and_absolute_readings() {
    let (mut recording, symbols) = with_observations();
    recording.samples.clear();
    recording.off_cpu.clear();
    recording.page_faults.clear();
    let profile = json(&recording, Some(&symbols), &Filter::default());
    let counter = &profile["counters"][0];
    assert_eq!(
        counter["samples"]["count"],
        serde_json::json!([0.0, -999900.0, 100.0])
    );
    let thread = &profile["threads"][counter["mainThreadIndex"].as_u64().unwrap() as usize];
    assert_eq!(thread["pid"], counter["pid"]);
    assert_eq!(thread["markers"]["data"][0]["rss"], 1_000_055);
    assert_eq!(thread["markers"]["data"][1]["rss"], 155);
    let filter = Filter {
        tids: vec![1],
        ..Default::default()
    };
    assert!(matches!(
        export::run(&recording, Some(&symbols), &filter),
        Err(Error::Empty)
    ));
    let filter = Filter {
        from_ns: Some(2_000_000),
        ..Default::default()
    };
    let profile = json(&recording, Some(&symbols), &filter);
    assert_eq!(
        profile["counters"][0]["samples"]["count"],
        serde_json::json!([0.0, 100.0])
    );
}

#[test]
fn keeps_reused_process_ids_separate() {
    let (mut recording, symbols) = with_observations();
    recording.threads[0].end_ns = Some(START + 5_000_000);
    recording
        .threads
        .push(thread(1, Some(START + 6_000_000), None));
    recording.memory.push(MemoryReading {
        time_ns: START + 7_000_000,
        ..recording.memory[2].clone()
    });
    let profile = json(&recording, Some(&symbols), &Filter::default());
    let counters = profile["counters"].as_array().unwrap();
    assert_eq!(counters.len(), 2);
    assert_ne!(counters[0]["pid"], counters[1]["pid"]);
    for counter in counters {
        let t = &profile["threads"][counter["mainThreadIndex"].as_u64().unwrap() as usize];
        assert_eq!(t["pid"], counter["pid"]);
    }
}
