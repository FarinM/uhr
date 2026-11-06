use std::fs::{self, File};
use std::path::{Path, PathBuf};

use arrow_array::RecordBatch;
use parquet::arrow::ArrowWriter;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
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
            platform: Platform {
                os: "linux".into(),
                arch: "x86_64".into(),
            },
            target: Target {
                command: vec!["./app".into(), "--fast".into()],
                launched: true,
                runtime_support: Some(Vec::new()),
                exit: Some(Exit::Unknown("perf was interrupted".into())),
            },
            clock: Clock::Monotonic,
            start_ns: Some(1_000),
            end_ns: Some(9_000),
            wall_clock: Some(WallClock {
                start: ClockReading {
                    time_ns: 900,
                    realtime_ns: 1_793_997_015_000_000_000,
                },
                end: ClockReading {
                    time_ns: 9_100,
                    realtime_ns: 1_793_997_015_000_008_200,
                },
            }),
            streams: vec![
                Stream {
                    id: "perf".into(),
                    collector: Collector::Perf {
                        version: "6.8.12".into(),
                        sampling: Some(Sampling {
                            event: "cpu-clock".into(),
                            frequency_hz: 999,
                            requested_frequency_hz: 999,
                        }),
                        page_faults: Some(FaultSampling {
                            event: "page-faults".into(),
                            period: 64,
                        }),
                        context_switches: true,
                    },
                    signals: vec![
                        Signal::UserCPUSamples,
                        Signal::UserStacks,
                        Signal::PageFaults,
                        Signal::OffCPUTime,
                        Signal::OffCPUStacks,
                    ],
                    missing_signals: [Signal::KernelCPUSamples, Signal::KernelStacks]
                        .map(|signal| MissingSignal {
                            signal,
                            reason: "perf_event_paranoid is 2".into(),
                        })
                        .to_vec(),
                    coverage: StreamCoverage {
                        lost_events: 0,
                        stacks: Some(StackCoverage {
                            unwinding: Unwinding::FramePointers,
                            stack_copy_bytes: None,
                            samples: 2,
                            page_fault_samples: Some(1),
                            off_cpu_intervals: Some(2),
                            throttle_events: Some(0),
                            max_stack_depth: 127,
                            stacks_at_stack_limit: 0,
                            stacks_cut_at_stack_copy: None,
                            stacks_not_unwound: None,
                            interpreters: Vec::new(),
                        }),
                        overhead_ns: None,
                        known_biases: vec!["example bias".into()],
                    },
                },
                Stream {
                    id: "procfs".into(),
                    collector: Collector::Procfs {
                        interval_ns: 100_000_000,
                    },
                    signals: vec![Signal::ResidentMemory],
                    missing_signals: Vec::new(),
                    coverage: StreamCoverage {
                        lost_events: 0,
                        stacks: None,
                        overhead_ns: Some(250_000),
                        known_biases: Vec::new(),
                    },
                },
            ],
            missing_signals: vec![MissingSignal {
                signal: Signal::SyscallCalls,
                reason: "loading eBPF needs root".into(),
            }],
            kernel_symbols: KernelSymbols::Saved,
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
                interpreted: None,
            },
            Frame {
                origin: Origin::Unresolved,
                address: 0x9999,
                mapping: None,
                file_offset: None,
                return_address: true,
                interpreted: None,
            },
            Frame {
                origin: Origin::Interpreted,
                address: 0x7f00_0000_2042,
                mapping: None,
                file_offset: None,
                return_address: false,
                interpreted: Some(Interpreted {
                    code: 0,
                    line: Some(12),
                }),
            },
        ],
        stacks: vec![vec![0, 1], vec![1], vec![2, 0]],
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
        page_faults: vec![FaultSample {
            time_ns: 1_500,
            pid: 7,
            tid: 8,
            cpu: Some(3),
            mode: Mode::Kernel,
            stack: 0,
            faults: 64,
            address: 0x7f00_0000_8000,
        }],
        off_cpu: vec![
            OffCPUInterval {
                start_ns: 2_500,
                end_ns: 2_900,
                pid: 7,
                tid: 7,
                state: ThreadState::Blocked,
                stack: Some(1),
                wakeup: Some(Wakeup {
                    time_ns: 2_800,
                    waker: Waker::Thread {
                        pid: 7,
                        tid: 8,
                        name: "worker".into(),
                    },
                    stack: Some(0),
                }),
            },
            OffCPUInterval {
                start_ns: 4_000,
                end_ns: 4_100,
                pid: 7,
                tid: 8,
                state: ThreadState::Runnable,
                stack: None,
                wakeup: None,
            },
            OffCPUInterval {
                start_ns: 4_200,
                end_ns: 4_600,
                pid: 7,
                tid: 8,
                state: ThreadState::Blocked,
                stack: None,
                wakeup: Some(Wakeup {
                    time_ns: 4_500,
                    waker: Waker::Interrupt,
                    stack: None,
                }),
            },
        ],
        kernel_symbols: vec![
            KernelSymbol {
                start: 0xffffffff81001010,
                end: 0xffffffff81001400,
                name: "vfs_read".into(),
                module: None,
            },
            KernelSymbol {
                start: 0xffffffffc0001100,
                end: 0xffffffffc0001180,
                name: "ext4_write".into(),
                module: Some("ext4".into()),
            },
        ],
        jit_symbols: vec![
            JitSymbol {
                pid: 7,
                start: 0x7f00_0000_1000,
                end: 0x7f00_0000_1080,
                name: "py::inner:/app/spin.py".into(),
            },
            JitSymbol {
                pid: 7,
                start: 0x7f00_0000_1080,
                end: 0x7f00_0000_10c0,
                name: "py::outer:/app/spin.py".into(),
            },
        ],
        interpreted_code: vec![
            InterpretedCode {
                pid: 7,
                runtime: "python".into(),
                address: 0x7f00_0000_2000,
                name: Some("Pool.acquire".into()),
                file: Some("/app/pool.py".into()),
                first_line: Some(10),
                first_column: Some(5),
            },
            InterpretedCode {
                pid: 7,
                runtime: "python".into(),
                address: 0x7f00_0000_3000,
                name: None,
                file: None,
                first_line: None,
                first_column: None,
            },
        ],
        syscall_calls: vec![
            SyscallCalls {
                pid: 7,
                tid: 8,
                thread_name: Some("app".into()),
                number: 0,
                name: Some("read".into()),
                interval_start_ns: Some(0),
                calls: 3,
                time_ns: 4_500,
                latency: vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1],
                unfinished_ns: None,
            },
            SyscallCalls {
                pid: 7,
                tid: 8,
                thread_name: Some("worker".into()),
                number: 4_000,
                name: None,
                interval_start_ns: Some(1 << 30),
                calls: 0,
                time_ns: 0,
                latency: vec![0; 12],
                unfinished_ns: Some(7_000),
            },
        ],
        memory: vec![
            MemoryReading {
                time_ns: 1_000,
                pid: 7,
                rss_anon_bytes: 4_096,
                rss_file_bytes: 8_192,
                rss_shmem_bytes: 0,
                swap_bytes: 0,
                peak_rss_bytes: 12_288,
            },
            MemoryReading {
                time_ns: 2_000,
                pid: 7,
                rss_anon_bytes: 1 << 30,
                rss_file_bytes: 8_192,
                rss_shmem_bytes: 4_096,
                swap_bytes: 1 << 20,
                peak_rss_bytes: (1 << 30) + 12_288,
            },
        ],
        regions: vec![
            MemoryRegion {
                pid: 7,
                start: 0x5555_0000_0000,
                end: 0x5555_0002_1000,
                permissions: "rw-p".into(),
                file_offset: 0,
                path: Some("[heap]".into()),
                kind: RegionKind::Heap,
                time_ns: None,
                unmapped_ns: None,
            },
            MemoryRegion {
                pid: 7,
                start: 0x7f00_0000_0000,
                end: 0x7f00_0010_0000,
                permissions: "rw-p".into(),
                file_offset: 0,
                path: None,
                kind: RegionKind::Anonymous,
                time_ns: Some(2_000),
                unmapped_ns: Some(3_000),
            },
        ],
        region_memory: vec![
            RegionMemory {
                time_ns: 1_000,
                pid: 7,
                kind: RegionKind::Heap,
                name: None,
                rss_bytes: 1 << 20,
                swap_bytes: 0,
            },
            RegionMemory {
                time_ns: 2_000,
                pid: 7,
                kind: RegionKind::Anonymous,
                name: Some("[anon: glibc: malloc]".into()),
                rss_bytes: 1 << 30,
                swap_bytes: 4_096,
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
fn reads_a_recording_from_before_syscalls_could_be_skipped() {
    let dir = scratch("before_skipped_syscalls");
    let mut recording = example();
    recording.manifest.streams.push(Stream {
        id: "ebpf".into(),
        collector: Collector::Ebpf {
            programs: Vec::new(),
            sampling: None,
            page_faults: None,
            call_interval_ns: None,
            skipped_syscalls: Vec::new(),
        },
        signals: vec![Signal::SyscallCalls],
        missing_signals: Vec::new(),
        coverage: StreamCoverage {
            lost_events: 0,
            stacks: None,
            overhead_ns: None,
            known_biases: Vec::new(),
        },
    });
    recording.write(&dir).unwrap();
    let path = dir.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let collector = &mut manifest["streams"][2]["collector"];
    assert!(
        collector
            .as_object_mut()
            .unwrap()
            .remove("skipped_syscalls")
            .is_some()
    );
    fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    assert_eq!(Recording::read(&dir).unwrap(), recording);
}

#[test]
fn reads_a_recording_from_before_its_wall_clock() {
    let dir = scratch("before_wall_clock");
    let mut recording = example();
    recording.write(&dir).unwrap();
    let path = dir.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let removed = manifest.as_object_mut().unwrap().remove("wall_clock");
    assert!(removed.is_some());
    fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    recording.manifest.wall_clock = None;
    assert_eq!(Recording::read(&dir).unwrap(), recording);
}

/// Writes the table at `path` again without the column `name`, as a
/// recording from before it was added has it.
fn drop_column(path: &Path, name: &str) {
    let file = File::open(path).unwrap();
    let batches: Vec<RecordBatch> = ParquetRecordBatchReaderBuilder::try_new(file)
        .unwrap()
        .build()
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let schema = batches[0].schema();
    let kept: Vec<usize> = (0..schema.fields().len())
        .filter(|&i| schema.field(i).name() != name)
        .collect();
    let batch = batches[0].project(&kept).unwrap();
    let file = File::create(path).unwrap();
    let mut writer = ArrowWriter::try_new(file, batch.schema(), None).unwrap();
    writer.write(&batch).unwrap();
    writer.close().unwrap();
}

#[test]
fn reads_a_recording_from_before_the_names_of_counted_threads() {
    let dir = scratch("before_counted_thread_names");
    let mut recording = example();
    recording.write(&dir).unwrap();
    drop_column(&dir.join("syscall_calls.parquet"), "thread_name");
    for calls in &mut recording.syscall_calls {
        calls.thread_name = None;
    }
    assert_eq!(Recording::read(&dir).unwrap(), recording);
}

#[test]
fn reads_a_recording_from_before_calls_were_counted_by_interval() {
    let dir = scratch("before_call_intervals");
    let mut recording = example();
    recording.write(&dir).unwrap();
    drop_column(&dir.join("syscall_calls.parquet"), "interval_start_ns");
    for calls in &mut recording.syscall_calls {
        calls.interval_start_ns = None;
    }
    assert_eq!(Recording::read(&dir).unwrap(), recording);
}

#[test]
fn reads_a_recording_from_before_wakeups() {
    let dir = scratch("before_wakeups");
    let mut recording = example();
    recording.write(&dir).unwrap();
    let path = dir.join("off_cpu.parquet");
    let file = File::open(&path).unwrap();
    let batches: Vec<RecordBatch> = ParquetRecordBatchReaderBuilder::try_new(file)
        .unwrap()
        .build()
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    // Its columns then: times, ids, state and stack.
    let batch = batches[0].project(&[0, 1, 2, 3, 4, 5]).unwrap();
    let file = File::create(&path).unwrap();
    let mut writer = ArrowWriter::try_new(file, batch.schema(), None).unwrap();
    writer.write(&batch).unwrap();
    writer.close().unwrap();
    for interval in &mut recording.off_cpu {
        interval.wakeup = None;
    }
    assert_eq!(Recording::read(&dir).unwrap(), recording);
}

#[test]
fn will_not_write_calls_its_latency_does_not_count() {
    let dir = scratch("uncounted_calls");
    let mut recording = example();
    recording.syscall_calls[0].calls = 4;
    let error = recording.write(&dir).unwrap_err();
    assert!(error.to_string().contains("syscall calls 0"), "{error}");
}

#[test]
fn will_not_write_what_it_could_not_read() {
    let dir = scratch("unreadable");
    let mut recording = example();
    recording.stacks[1] = vec![5];
    match recording.write(&dir).unwrap_err() {
        Error::Invalid { path, reason } => {
            assert_eq!(path, dir);
            assert!(reason.contains("stack 1 refers to frame 5"), "{reason}");
        }
        error => panic!("{error}"),
    }
    assert!(!dir.exists());
}

#[test]
fn rejects_dangling_references() {
    let dir = scratch("dangling");
    example().write(&dir).unwrap();
    let other = scratch("dangling_other");
    let mut fewer_frames = example();
    fewer_frames.frames.truncate(1);
    fewer_frames.stacks = vec![vec![0]];
    fewer_frames.samples.truncate(1);
    fewer_frames.off_cpu.clear();
    fewer_frames.write(&other).unwrap();
    fs::copy(other.join("frames.parquet"), dir.join("frames.parquet")).unwrap();
    match Recording::read(&dir).unwrap_err() {
        Error::Invalid { path, reason } => {
            assert_eq!(path, dir);
            assert!(reason.contains("stack 0 refers to frame 1"), "{reason}");
        }
        error => panic!("{error}"),
    }
}

#[test]
fn rejects_interpreted_frames_without_their_code() {
    let dir = scratch("interpreted_dangling");
    example().write(&dir).unwrap();
    let other = scratch("interpreted_dangling_other");
    let mut no_code = example();
    no_code.frames.truncate(2);
    no_code.stacks.truncate(2);
    no_code.interpreted_code.clear();
    no_code.write(&other).unwrap();
    fs::copy(
        other.join("interpreted_code.parquet"),
        dir.join("interpreted_code.parquet"),
    )
    .unwrap();
    match Recording::read(&dir).unwrap_err() {
        Error::Invalid { reason, .. } => {
            assert!(
                reason.contains("frame 2 refers to interpreted code 0"),
                "{reason}"
            );
        }
        error => panic!("{error}"),
    }
}

#[test]
fn rejects_off_cpu_intervals_that_end_before_they_start() {
    let dir = scratch("backwards_off_cpu");
    let mut recording = example();
    recording.off_cpu[1].end_ns = 3_999;
    match recording.write(&dir).unwrap_err() {
        Error::Invalid { reason, .. } => {
            assert!(
                reason.contains("off-CPU interval 1 ends before it starts"),
                "{reason}"
            );
        }
        error => panic!("{error}"),
    }
}

#[test]
fn rejects_wakeups_outside_the_time_off_cpu_they_end() {
    let mut recording = example();
    recording.off_cpu[0].wakeup.as_mut().unwrap().time_ns = 2_901;
    let error = recording.write(&scratch("late_wakeup")).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("off-CPU interval 0 was woken outside its time off CPU"),
        "{error}"
    );
    let mut recording = example();
    recording.off_cpu[0].state = ThreadState::Runnable;
    let error = recording.write(&scratch("woken_runnable")).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("off-CPU interval 0 was woken, but did not block"),
        "{error}"
    );
}

#[test]
fn rejects_overlapping_kernel_symbols() {
    let dir = scratch("overlapping_kernel_symbols");
    let mut recording = example();
    recording.kernel_symbols[0].end = 0xffffffffc0001101;
    match recording.write(&dir).unwrap_err() {
        Error::Invalid { reason, .. } => {
            assert!(reason.contains("kernel symbol 1 starts before"), "{reason}");
        }
        error => panic!("{error}"),
    }
}

#[test]
fn rejects_overlapping_jit_symbols() {
    let dir = scratch("overlapping_jit_symbols");
    let mut recording = example();
    recording.jit_symbols[0].end = 0x7f00_0000_1081;
    match recording.write(&dir).unwrap_err() {
        Error::Invalid { reason, .. } => {
            assert!(reason.contains("JIT symbol 1 is not after"), "{reason}");
        }
        error => panic!("{error}"),
    }
}

#[test]
fn will_not_write_memory_readings_out_of_order() {
    let dir = scratch("memory_out_of_order");
    let mut recording = example();
    recording.memory.swap(0, 1);
    let error = recording.write(&dir).unwrap_err();
    assert!(error.to_string().contains("memory reading 1"), "{error}");
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
