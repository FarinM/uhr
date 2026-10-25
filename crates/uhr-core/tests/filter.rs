use uhr_core::filter::Filter;
use uhr_core::query::{GroupBy, Query, run};
use uhr_core::recording::*;

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

fn name(tid: u32, time_ns: Option<u64>, name: &str) -> ThreadName {
    ThreadName {
        pid: 1,
        tid,
        time_ns,
        name: name.into(),
    }
}

/// Each sample has a distinct power of two as its CPU time, so the total
/// says which samples passed.
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
            start_ns: Some(1_000),
            end_ns: Some(3_000),
            streams: Vec::new(),
            kernel_symbols: KernelSymbols::Saved,
        },
        threads: Vec::new(),
        thread_names: vec![
            name(1, None, "app"),
            name(2, Some(1_050), "app"),
            name(2, Some(1_200), "worker-1"),
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
            sample(1, 1, 1_000, Mode::User, 1),
            sample(1, 2, 1_500, Mode::User, 2),
            sample(1, 2, 1_100, Mode::Kernel, 4),
            sample(2, 3, 3_000, Mode::Kernel, 8),
            sample(1, 2, 2_000, Mode::User, 16),
        ],
        off_cpu: Vec::new(),
        kernel_symbols: Vec::new(),
    }
}

fn cpu_ns(recording: &Recording, filter: Filter) -> u64 {
    let query = Query {
        group_by: GroupBy::Function,
        top: 10,
        filter,
    };
    let result = run(recording, None, &query).unwrap();
    let rows: u64 = result.rows.iter().map(|r| r.self_cpu_ns).sum();
    assert_eq!(rows, result.cpu_ns);
    result.cpu_ns
}

#[test]
fn an_empty_filter_keeps_everything() {
    assert!(Filter::default().is_empty());
    assert_eq!(cpu_ns(&recording(), Filter::default()), 31);
}

#[test]
fn filters_by_process_thread_and_mode() {
    let recording = recording();
    let pids = Filter {
        pids: vec![1],
        ..Filter::default()
    };
    assert_eq!(cpu_ns(&recording, pids), 23);
    let tids = Filter {
        tids: vec![1, 3],
        ..Filter::default()
    };
    assert_eq!(cpu_ns(&recording, tids), 9);
    let kernel = Filter {
        modes: vec![Mode::Kernel],
        ..Filter::default()
    };
    assert_eq!(cpu_ns(&recording, kernel), 12);
}

#[test]
fn every_list_has_to_match() {
    let filter = Filter {
        pids: vec![1],
        modes: vec![Mode::User],
        ..Filter::default()
    };
    assert_eq!(cpu_ns(&recording(), filter), 19);
}

#[test]
fn matches_the_thread_name_at_sample_time() {
    let recording = recording();
    let workers = Filter {
        thread_names: vec!["worker-*".into()],
        ..Filter::default()
    };
    assert_eq!(
        cpu_ns(&recording, workers),
        18,
        "not the sample from before the rename"
    );
    let app = Filter {
        thread_names: vec!["app".into()],
        ..Filter::default()
    };
    assert_eq!(cpu_ns(&recording, app), 5);
    let either = Filter {
        thread_names: vec!["app".into(), "w*".into()],
        ..Filter::default()
    };
    assert_eq!(cpu_ns(&recording, either), 23, "pid 2 has no known name");
}

#[test]
fn time_ranges_are_offsets_from_the_start_and_end_exclusive() {
    let recording = recording();
    let range = Filter {
        from_ns: Some(500),
        to_ns: Some(1_000),
        ..Filter::default()
    };
    assert_eq!(cpu_ns(&recording, range), 2);
    let from = Filter {
        from_ns: Some(1_000),
        ..Filter::default()
    };
    assert_eq!(cpu_ns(&recording, from), 24);
    let to = Filter {
        to_ns: Some(100),
        ..Filter::default()
    };
    assert_eq!(cpu_ns(&recording, to), 1);
}

#[test]
fn time_ranges_match_nothing_without_a_start() {
    let mut recording = recording();
    recording.manifest.start_ns = None;
    let from = Filter {
        from_ns: Some(0),
        ..Filter::default()
    };
    assert_eq!(cpu_ns(&recording, from), 0);
}
