use uhr_core::filter::Filter;
use uhr_core::overview::{OffCPUTime, Overview, ThreadRow, Window, run};
use uhr_core::recording::*;

fn thread(tid: u32, start_ns: Option<u64>, end_ns: Option<u64>) -> Thread {
    Thread {
        pid: 1,
        tid,
        parent_pid: start_ns.map(|_| 1),
        parent_tid: start_ns.map(|_| 1),
        start_ns,
        end_ns,
    }
}

fn name(tid: u32, time_ns: Option<u64>, name: &str) -> ThreadName {
    ThreadName {
        pid: 1,
        tid,
        time_ns,
        name: name.into(),
    }
}

fn sample(pid: u32, tid: u32, time_ns: u64, mode: Mode, cpu_ns: u64) -> Sample {
    Sample {
        time_ns,
        pid,
        tid,
        cpu: None,
        mode,
        stack: 0,
        cpu_ns,
    }
}

fn stream(kernel: bool) -> Stream {
    let kernel_signals = [Signal::KernelCPUSamples, Signal::KernelStacks];
    let mut signals = vec![Signal::UserCPUSamples, Signal::UserStacks];
    let mut missing_signals = Vec::new();
    if kernel {
        signals.extend(kernel_signals);
    } else {
        missing_signals.extend(kernel_signals.map(|signal| MissingSignal {
            signal,
            reason: "excluded".into(),
        }));
    }
    Stream {
        id: "perf".into(),
        collector: Collector::Perf {
            version: "6.8".into(),
            event: "cpu-clock".into(),
            frequency_hz: 1000,
            requested_frequency_hz: 1000,
            unwinding: Unwinding::FramePointers,
            stack_copy_bytes: None,
            context_switches: false,
        },
        signals,
        missing_signals,
        coverage: StreamCoverage {
            samples: 7,
            off_cpu_intervals: None,
            lost_events: 0,
            throttle_events: 0,
            max_stack_depth: 127,
            stacks_at_stack_limit: 0,
            stacks_cut_at_stack_copy: None,
            stacks_not_unwound: None,
            overhead_ns: None,
            known_biases: Vec::new(),
        },
    }
}

/// From 1000 to 11000: main thread 1, worker 2 renamed from "app" right
/// after it started, thread id 3 used twice, and thread 7 of process 7 that
/// only appears in a sample.
fn recording() -> Recording {
    Recording {
        manifest: Manifest {
            format_version: FORMAT_VERSION,
            platform: Platform {
                os: "linux".into(),
                arch: "x86_64".into(),
            },
            target: Target {
                command: vec!["app".into(), "--fast".into()],
                launched: true,
                runtime_support: Some(Vec::new()),
                exit: Some(Exit::Code(0)),
            },
            clock: Clock::Monotonic,
            start_ns: Some(1_000),
            end_ns: Some(11_000),
            streams: vec![stream(true)],
            kernel_symbols: KernelSymbols::Saved,
        },
        threads: vec![
            thread(1, None, Some(11_000)),
            thread(2, Some(2_000), Some(6_000)),
            thread(3, Some(3_000), Some(4_000)),
            thread(3, Some(8_000), None),
        ],
        thread_names: vec![
            name(1, None, "app"),
            name(2, Some(2_000), "app"),
            name(2, Some(2_100), "worker"),
            name(3, Some(3_000), "app"),
            name(3, Some(8_000), "app"),
        ],
        mappings: Vec::new(),
        frames: vec![Frame {
            origin: Origin::Unresolved,
            address: 0x10,
            mapping: None,
            file_offset: None,
            return_address: false,
        }],
        stacks: vec![vec![0]],
        samples: vec![
            sample(1, 1, 1_500, Mode::User, 100),
            sample(1, 2, 3_000, Mode::User, 1_000),
            sample(1, 2, 4_000, Mode::Kernel, 1_000),
            sample(1, 2, 5_000, Mode::User, 1_000),
            sample(1, 3, 3_500, Mode::User, 500),
            sample(1, 3, 9_000, Mode::User, 2_000),
            sample(7, 7, 10_000, Mode::Unknown, 100),
        ],
        off_cpu: Vec::new(),
        kernel_symbols: Vec::new(),
        jit_symbols: Vec::new(),
    }
}

/// Adds context switches: main thread 1 blocked from 2000 to 10000, worker
/// 2 preempted from 3500 to 3900 and blocked from 4200 to 4800, and the
/// second thread 3 blocked from 8500 to 8800.
fn with_off_cpu(mut recording: Recording) -> Recording {
    let stream = &mut recording.manifest.streams[0];
    stream
        .signals
        .extend([Signal::OffCPUTime, Signal::OffCPUStacks]);
    let interval = |tid, start_ns, end_ns, state, stack| OffCPUInterval {
        start_ns,
        end_ns,
        pid: 1,
        tid,
        state,
        stack,
    };
    recording.off_cpu = vec![
        interval(1, 2_000, 10_000, ThreadState::Blocked, Some(0)),
        interval(2, 3_500, 3_900, ThreadState::Runnable, None),
        interval(2, 4_200, 4_800, ThreadState::Blocked, Some(0)),
        interval(3, 8_500, 8_800, ThreadState::Blocked, Some(0)),
    ];
    recording
}

fn off_cpu(intervals: u64, runnable_ns: u64, blocked_ns: u64) -> Option<OffCPUTime> {
    Some(OffCPUTime {
        intervals,
        runnable_ns,
        blocked_ns,
        unknown_state_ns: 0,
    })
}

fn overview(recording: &Recording, filter: Filter) -> Overview {
    run(recording, None, &filter, 10).unwrap()
}

fn find(overview: &Overview, tid: u32, start_ns: Option<u64>) -> &ThreadRow {
    overview
        .threads
        .iter()
        .find(|t| t.tid == tid && t.start_ns == start_ns)
        .unwrap_or_else(|| panic!("no thread {tid} started at {start_ns:?}"))
}

#[test]
fn breaks_cpu_time_down_by_mode() {
    let result = overview(&recording(), Filter::default());
    assert_eq!(result.command, ["app", "--fast"]);
    assert_eq!(result.exit, Some(Exit::Code(0)));
    assert_eq!(result.recording_start_ns, Some(1_000));
    assert_eq!(result.recording_duration_ns, 10_000);
    assert_eq!(
        result.window,
        Window {
            start_ns: 0,
            end_ns: 10_000
        }
    );
    let cpu = &result.cpu;
    assert_eq!(cpu.samples, 7);
    assert_eq!(cpu.cpu_ns, 5_700);
    assert_eq!(cpu.user_cpu_ns, 4_600);
    assert_eq!(cpu.kernel_cpu_ns, Some(1_000));
    assert_eq!(cpu.unknown_mode_cpu_ns, 100);
    assert_eq!(result.cpu_utilization, Some(0.57));
}

#[test]
fn compares_each_thread_lifetime_with_its_cpu_time() {
    let result = overview(&recording(), Filter::default());
    let order: Vec<_> = result.threads.iter().map(|t| (t.pid, t.tid)).collect();
    assert_eq!(order, [(1, 2), (1, 3), (1, 3), (1, 1), (7, 7)]);
    let rows: u64 = result.threads.iter().map(|t| t.cpu.cpu_ns).sum();
    assert_eq!(rows, result.cpu.cpu_ns);

    let worker = find(&result, 2, Some(1_000));
    assert_eq!(worker.names, ["app", "worker"]);
    assert_eq!(worker.end_ns, Some(5_000));
    assert_eq!(worker.alive_ns, 4_000);
    assert_eq!(
        (worker.cpu.user_cpu_ns, worker.cpu.kernel_cpu_ns),
        (2_000, Some(1_000))
    );
    assert_eq!(worker.on_cpu_share, Some(0.75));

    let main = find(&result, 1, None);
    assert_eq!(main.alive_ns, 10_000);
    assert_eq!(main.on_cpu_share, Some(0.01));
}

#[test]
fn gives_each_lifetime_of_a_reused_thread_id_its_own_samples() {
    let result = overview(&recording(), Filter::default());
    let first = find(&result, 3, Some(2_000));
    assert_eq!((first.cpu.cpu_ns, first.alive_ns), (500, 1_000));
    let second = find(&result, 3, Some(7_000));
    assert_eq!(second.end_ns, None);
    assert_eq!((second.cpu.cpu_ns, second.alive_ns), (2_000, 3_000));
}

#[test]
fn keeps_samples_of_threads_missing_from_the_thread_table() {
    let result = overview(&recording(), Filter::default());
    let unknown = find(&result, 7, None);
    assert!(unknown.names.is_empty());
    assert_eq!(unknown.cpu.unknown_mode_cpu_ns, 100);
    assert_eq!(unknown.alive_ns, 10_000);
}

#[test]
fn rolls_threads_up_into_processes() {
    let result = overview(&recording(), Filter::default());
    let pids: Vec<_> = result.processes.iter().map(|p| p.pid).collect();
    assert_eq!(pids, [1, 7]);
    let app = &result.processes[0];
    assert_eq!(app.name.as_deref(), Some("app"));
    assert_eq!(app.threads, 4);
    assert_eq!(app.cpu.cpu_ns, 5_600);
    assert_eq!(app.alive_ns, 10_000);
    assert_eq!(app.cpu_utilization, Some(0.56));
    assert_eq!(result.processes[1].name, None);
}

#[test]
fn a_time_range_narrows_the_window_and_lifetimes() {
    let filter = Filter {
        from_ns: Some(4_500),
        to_ns: Some(9_500),
        ..Filter::default()
    };
    let result = overview(&recording(), filter);
    assert_eq!(
        result.window,
        Window {
            start_ns: 4_500,
            end_ns: 9_500
        }
    );
    assert_eq!(result.cpu.cpu_ns, 2_100);
    assert_eq!(result.cpu_utilization, Some(0.42));
    assert_eq!(result.threads.len(), 4, "the first thread 3 ended before");
    assert_eq!(find(&result, 2, Some(1_000)).alive_ns, 500);
    assert_eq!(find(&result, 3, Some(7_000)).alive_ns, 2_500);
    assert_eq!(find(&result, 1, None).alive_ns, 5_000);
}

#[test]
fn a_time_range_past_the_end_leaves_an_empty_window() {
    let filter = Filter {
        from_ns: Some(20_000),
        ..Filter::default()
    };
    let result = overview(&recording(), filter);
    assert_eq!(
        result.window,
        Window {
            start_ns: 10_000,
            end_ns: 10_000
        }
    );
    assert_eq!(result.cpu.cpu_ns, 0);
    assert_eq!(result.cpu_utilization, None);
    assert!(result.threads.is_empty());
    assert!(result.processes.is_empty());
}

#[test]
fn a_thread_filter_keeps_the_process_name() {
    let filter = Filter {
        thread_names: vec!["worker".into()],
        ..Filter::default()
    };
    let result = overview(&recording(), filter);
    assert_eq!(result.threads.len(), 1);
    assert_eq!(result.threads[0].tid, 2);
    assert_eq!(result.cpu.cpu_ns, 3_000);
    assert_eq!(result.processes.len(), 1);
    let process = &result.processes[0];
    assert_eq!(process.name.as_deref(), Some("app"));
    assert_eq!(process.threads, 4, "the process, not the filtered rows");
    assert_eq!(process.alive_ns, 10_000);
    assert_eq!(process.cpu.cpu_ns, 3_000);
}

#[test]
fn a_reused_pid_is_two_processes() {
    let mut recording = recording();
    let thread = |tid, start_ns, end_ns| Thread {
        pid: 9,
        tid,
        parent_pid: Some(1),
        parent_tid: Some(1),
        start_ns: Some(start_ns),
        end_ns: Some(end_ns),
    };
    recording.threads.extend([
        thread(9, 2_000, 4_000),
        thread(10, 2_500, 3_500),
        thread(9, 8_000, 10_000),
    ]);
    recording.thread_names.extend([
        ThreadName {
            pid: 9,
            tid: 9,
            time_ns: Some(2_000),
            name: "first".into(),
        },
        ThreadName {
            pid: 9,
            tid: 10,
            time_ns: Some(2_500),
            name: "first".into(),
        },
        ThreadName {
            pid: 9,
            tid: 9,
            time_ns: Some(8_000),
            name: "second".into(),
        },
    ]);
    recording.samples.extend([
        sample(9, 9, 3_000, Mode::User, 100),
        sample(9, 10, 3_000, Mode::User, 100),
        sample(9, 9, 9_000, Mode::User, 300),
    ]);

    let result = overview(&recording, Filter::default());
    let mut nines: Vec<_> = result.processes.iter().filter(|p| p.pid == 9).collect();
    nines.sort_by_key(|p| p.start_ns);
    let summary: Vec<_> = nines
        .iter()
        .map(|p| {
            (
                p.name.as_deref(),
                p.start_ns,
                p.end_ns,
                p.threads,
                p.alive_ns,
                p.cpu.cpu_ns,
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            (Some("first"), Some(1_000), Some(3_000), 2, 2_000, 200),
            (Some("second"), Some(7_000), Some(9_000), 1, 2_000, 300),
        ]
    );
}

fn listed(result: &Overview) -> Vec<(u32, Option<u64>)> {
    let mut threads: Vec<_> = result.threads.iter().map(|t| (t.tid, t.start_ns)).collect();
    threads.sort();
    threads
}

#[test]
fn the_end_of_a_time_range_is_exclusive() {
    let recording = recording();
    let until = |to_ns| {
        let filter = Filter {
            to_ns: Some(to_ns),
            ..Filter::default()
        };
        listed(&overview(&recording, filter))
    };
    // Worker 2 starts at offset 1000.
    assert!(!until(1_000).contains(&(2, Some(1_000))));
    assert!(until(1_001).contains(&(2, Some(1_000))));

    // It is renamed to worker at offset 1100.
    let worker_until = |to_ns| {
        let filter = Filter {
            to_ns: Some(to_ns),
            thread_names: vec!["worker".into()],
            ..Filter::default()
        };
        overview(&recording, filter)
    };
    assert!(worker_until(1_100).threads.is_empty());
    assert_eq!(worker_until(1_101).threads.len(), 1);
}

#[test]
fn a_thread_counts_at_the_moment_it_exits() {
    let recording = recording();
    let from = |from_ns| {
        let filter = Filter {
            from_ns: Some(from_ns),
            ..Filter::default()
        };
        overview(&recording, filter)
    };
    // Worker 2 exits at offset 5000.
    let at_exit = from(5_000);
    let worker = find(&at_exit, 2, Some(1_000));
    assert_eq!(worker.alive_ns, 0);
    assert!(!listed(&from(5_001)).contains(&(2, Some(1_000))));
}

#[test]
fn without_a_time_range_the_window_keeps_the_end_of_the_capture() {
    let mut recording = recording();
    recording.threads.push(thread(4, Some(11_000), None));
    let all = overview(&recording, Filter::default());
    assert_eq!(find(&all, 4, Some(10_000)).alive_ns, 0);
    let filter = Filter {
        to_ns: Some(10_000),
        ..Filter::default()
    };
    assert!(!listed(&overview(&recording, filter)).contains(&(4, Some(10_000))));
}

#[test]
fn an_empty_window_lists_no_threads() {
    let empty = Filter {
        from_ns: Some(3_000),
        to_ns: Some(3_000),
        ..Filter::default()
    };
    let result = overview(&recording(), empty);
    assert!(result.threads.is_empty());
    assert!(result.processes.is_empty());
}

#[test]
fn a_thread_without_samples_is_still_listed() {
    let filter = Filter {
        tids: vec![1],
        modes: vec![Mode::Kernel],
        ..Filter::default()
    };
    let result = overview(&recording(), filter);
    assert_eq!(result.threads.len(), 1);
    assert_eq!(result.threads[0].cpu.cpu_ns, 0);
    assert_eq!(result.threads[0].on_cpu_share, Some(0.0));
}

#[test]
fn kernel_time_is_unknown_when_the_kernel_was_not_sampled() {
    let mut recording = recording();
    recording.manifest.streams = vec![stream(false)];
    recording.samples.retain(|s| s.mode != Mode::Kernel);
    let result = overview(&recording, Filter::default());
    assert_eq!(result.cpu.kernel_cpu_ns, None);
    assert!(result.threads.iter().all(|t| t.cpu.kernel_cpu_ns.is_none()));
    assert!(
        result
            .coverage
            .unknown
            .iter()
            .any(|u| u.starts_with("CPU time in the kernel")),
        "{:?}",
        result.coverage.unknown
    );
}

#[test]
fn splits_off_cpu_time_into_runnable_and_blocked() {
    let result = overview(&with_off_cpu(recording()), Filter::default());
    assert_eq!(result.off_cpu, off_cpu(4, 400, 8_900));
    let worker = find(&result, 2, Some(1_000));
    assert_eq!(worker.off_cpu, off_cpu(2, 400, 600));
    assert_eq!(
        (worker.runnable_share, worker.blocked_share),
        (Some(0.1), Some(0.15))
    );
    assert_eq!(find(&result, 1, None).blocked_share, Some(0.8));
    assert_eq!(find(&result, 3, Some(2_000)).off_cpu, off_cpu(0, 0, 0));
    assert_eq!(find(&result, 3, Some(7_000)).off_cpu, off_cpu(1, 0, 300));
    assert_eq!(result.processes[0].off_cpu, off_cpu(4, 400, 8_900));
    assert_eq!(result.processes[1].off_cpu, off_cpu(0, 0, 0));
    assert!(
        !result
            .coverage
            .unknown
            .iter()
            .any(|u| u.starts_with("why threads were off CPU")),
        "{:?}",
        result.coverage.unknown
    );
}

#[test]
fn cuts_off_cpu_time_to_the_time_range() {
    let filter = Filter {
        from_ns: Some(4_500),
        to_ns: Some(9_500),
        ..Filter::default()
    };
    let result = overview(&with_off_cpu(recording()), filter);
    assert_eq!(result.off_cpu, off_cpu(2, 0, 4_800));
    assert_eq!(find(&result, 1, None).blocked_share, Some(0.9));
}

#[test]
fn matches_off_cpu_time_by_thread() {
    let recording = with_off_cpu(recording());
    let worker = Filter {
        thread_names: vec!["worker".into()],
        ..Filter::default()
    };
    assert_eq!(overview(&recording, worker).off_cpu, off_cpu(2, 400, 600));
    let main = Filter {
        tids: vec![1],
        ..Filter::default()
    };
    assert_eq!(overview(&recording, main).off_cpu, off_cpu(1, 0, 8_000));
}

#[test]
fn off_cpu_time_takes_the_name_its_thread_went_off_cpu_with() {
    let mut recording = with_off_cpu(recording());
    recording.thread_names.push(name(1, Some(5_000), "renamed"));
    let renamed = Filter {
        thread_names: vec!["renamed".into()],
        ..Filter::default()
    };
    assert_eq!(
        overview(&recording, renamed.clone()).off_cpu,
        off_cpu(0, 0, 0)
    );
    let later = Filter {
        from_ns: Some(5_000),
        ..renamed
    };
    assert_eq!(overview(&recording, later).off_cpu, off_cpu(0, 0, 0));
}

#[test]
fn off_cpu_time_has_no_mode() {
    let filter = Filter {
        modes: vec![Mode::Kernel],
        ..Filter::default()
    };
    let result = overview(&with_off_cpu(recording()), filter);
    assert_eq!(result.off_cpu, off_cpu(0, 0, 0));
}

#[test]
fn off_cpu_time_is_unknown_without_context_switches() {
    let result = overview(&recording(), Filter::default());
    assert_eq!(result.off_cpu, None);
    assert!(
        result
            .threads
            .iter()
            .all(|t| t.off_cpu.is_none() && t.blocked_share.is_none())
    );
    assert!(
        result
            .coverage
            .unknown
            .iter()
            .any(|u| u.starts_with("why threads were off CPU")),
        "{:?}",
        result.coverage.unknown
    );
}

#[test]
fn reports_cut_rows() {
    let result = run(&recording(), None, &Filter::default(), 2).unwrap();
    assert_eq!(result.threads.len(), 2);
    assert_eq!(result.threads_omitted, 3);
    assert_eq!(result.processes.len(), 2);
    assert_eq!(result.processes_omitted, 0);
}
