use std::fs;
use std::path::PathBuf;

use uhr_core::recording::*;

fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&dir);
    dir
}

fn example() -> Recording {
    Recording {
        manifest: Manifest {
            format_version: FORMAT_VERSION,
            target: Target {
                command: vec!["./app".into(), "--fast".into()],
                launched: true,
                exit: Some(Exit::Unknown("perf was interrupted".into())),
            },
            clock: Clock::Monotonic,
            start_ns: Some(1_000),
            end_ns: Some(9_000),
            streams: vec![Stream {
                id: "perf".into(),
                collector: Collector::Perf {
                    version: "6.8.12".into(),
                    event: "cpu-clock".into(),
                    frequency_hz: 999,
                    requested_frequency_hz: 999,
                    unwinding: Unwinding::FramePointers,
                },
                signals: vec![Signal::CPUSamples, Signal::UserStacks],
                missing_signals: vec![MissingSignal {
                    signal: Signal::KernelStacks,
                    reason: "perf_event_paranoid is 2".into(),
                }],
                coverage: StreamCoverage {
                    samples: 2,
                    lost_events: 0,
                    throttle_events: 0,
                    max_stack_depth: 127,
                    samples_at_stack_limit: 0,
                    overhead_ns: None,
                    known_biases: vec!["example bias".into()],
                },
            }],
        },
        threads: vec![
            Thread {
                pid: 7,
                tid: 7,
                parent_pid: None,
                parent_tid: None,
                start_ns: None,
                end_ns: Some(9_000),
            },
            Thread {
                pid: 7,
                tid: 8,
                parent_pid: Some(7),
                parent_tid: Some(7),
                start_ns: Some(1_500),
                end_ns: None,
            },
        ],
        thread_names: vec![ThreadName {
            pid: 7,
            tid: 7,
            time_ns: Some(1_000),
            name: "app".into(),
        }],
        mappings: vec![Mapping {
            pid: Some(7),
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            path: "/bin/app".into(),
            build_id: Some("abcd".into()),
            time_ns: None,
        }],
        frames: vec![
            Frame {
                origin: Origin::Binary,
                address: 0x1010,
                mapping: Some(0),
                file_offset: Some(0x10),
                return_address: false,
            },
            Frame {
                origin: Origin::Unresolved,
                address: 0x9999,
                mapping: None,
                file_offset: None,
                return_address: true,
            },
        ],
        stacks: vec![vec![0, 1], vec![1]],
        samples: vec![
            Sample {
                time_ns: 2_000,
                pid: 7,
                tid: 7,
                cpu: Some(3),
                mode: Mode::User,
                stack: 0,
                cpu_ns: 1_001_001,
            },
            Sample {
                time_ns: 3_000,
                pid: 7,
                tid: 7,
                cpu: None,
                mode: Mode::Kernel,
                stack: 1,
                cpu_ns: 1_001_001,
            },
        ],
    }
}

#[test]
fn round_trips() {
    let dir = scratch("round_trips");
    let recording = example();
    recording.write(&dir).unwrap();
    assert_eq!(Recording::read(&dir).unwrap(), recording);
}

#[test]
fn rejects_dangling_references() {
    let dir = scratch("dangling");
    let mut recording = example();
    recording.stacks[1] = vec![5];
    recording.write(&dir).unwrap();
    match Recording::read(&dir).unwrap_err() {
        Error::Invalid { path, reason } => {
            assert_eq!(path, dir);
            assert!(reason.contains("stack 1 refers to frame 5"), "{reason}");
        }
        error => panic!("{error}"),
    }
}

#[test]
fn rejects_unfinished_recordings() {
    let dir = scratch("unfinished");
    example().write(&dir).unwrap();
    fs::remove_file(dir.join("manifest.json")).unwrap();
    let error = Recording::read(&dir).unwrap_err();
    assert!(matches!(error, Error::NotARecording(_)), "{error}");
}

#[test]
fn rejects_other_format_versions() {
    let dir = scratch("version");
    let mut recording = example();
    recording.manifest.format_version = FORMAT_VERSION + 1;
    recording.write(&dir).unwrap();
    let error = Recording::read(&dir).unwrap_err();
    assert!(
        matches!(error, Error::FormatVersion { found, .. } if found == FORMAT_VERSION + 1),
        "{error}"
    );
}
