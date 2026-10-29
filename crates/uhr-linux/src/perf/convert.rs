use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::env;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::mem::size_of;
use std::os::unix::fs::FileExt;
use std::path::Path;

use linux_perf_data::linux_perf_event_reader::constants::{
    PERF_CONTEXT_KERNEL, PERF_CONTEXT_MAX, PERF_CONTEXT_USER, PERF_REG_X86_BP, PERF_REG_X86_IP,
    PERF_REG_X86_SP, PERF_SAMPLE_REGS_ABI_32, PERF_SAMPLE_REGS_ABI_64,
};
use linux_perf_data::linux_perf_event_reader::{
    AttrFlags, ClockId, ContextSwitchRecord, CpuMode, Endianness, EventRecord, Mmap2FileId,
    PerfClock, PerfEventAttr, PerfEventType, RawEventRecord, SampleFormat, SampleRecord,
    SamplingPolicy, SoftwareCounterType, TaskWasPreempted,
};
use linux_perf_data::{PerfFileReader, PerfFileRecord};
use tracing::warn;

use super::unwind::{Unwinding as UserUnwinding, UserCopy};
use super::{Error, Result, io_error};
use crate::interpreters::{Interpreters, Program};
use crate::kallsyms::{self, Kallsyms};
use crate::memory::Naming;
use crate::procfs;
use uhr_core::recording::{
    Clock, Collector, Exit, FORMAT_VERSION, FaultSample, FaultSampling, Frame, Interpreted,
    InterpretedCode, InterpreterCoverage, KERNEL, KernelSymbols, Manifest, Mapping, MemoryRegion,
    MissingSignal, Mode, OffCPUInterval, Origin, Platform, Recording, RegionKind, Sample, Sampling,
    Signal, StackCoverage, Stream, StreamCoverage, Target, Thread, ThreadName, ThreadState,
    Unwinding,
};
use uhr_core::runtimes::{Frames, Interpreter, WalkedFrame};
use uhr_ebpf::{MAX_FRAMES, SampleHeader, UserRegisters, event, mode, walk};

pub(super) struct Input<'a> {
    pub perf_data: &'a Path,
    pub command: &'a [String],
    /// The process uhr started and held until perf sampled it. Until its
    /// first exec it still runs uhr's code, so that is left out.
    pub launched_pid: Option<u32>,
    pub runtime_support: Option<Vec<String>>,
    pub exit: Option<Exit>,
    /// When uhr stopped the capture before the target exited, at an
    /// interrupt or the end of a duration, on CLOCK_MONOTONIC.
    pub stopped_ns: Option<u64>,
    /// When perf started sampling a process uhr attached to, on
    /// CLOCK_MONOTONIC.
    pub attached_ns: Option<u64>,
    /// When the first and last memory readings were taken, on
    /// CLOCK_MONOTONIC.
    pub memory_span: Option<(u64, u64)>,
    /// What the processes named of their memory, by reading, sorted by time.
    pub naming: &'a [Naming],
    pub perf_version: String,
    pub requested_frequency_hz: u64,
    pub max_stack_depth: u32,
    pub kallsyms: Result<&'a Kallsyms, &'a kallsyms::Error>,
    /// The samples of uhr's eBPF programs, if they sampled instead of perf.
    pub ebpf_samples: Option<EbpfSamples<'a>>,
}

#[derive(Clone, Copy)]
pub(super) struct EbpfSamples<'a> {
    pub path: &'a Path,
    pub period_ns: u64,
    /// The bytes of user stack copied with each sample, `None` where they
    /// walked user stacks with frame pointers.
    pub stack_bytes: Option<u32>,
    /// The interpreters whose frames they walked.
    pub interpreters: &'a Interpreters,
    /// Whether they sampled page faults too.
    pub page_faults: bool,
}

pub(super) const TIMER_BIAS: &str = "cpu-clock samples come from a timer interrupt, so code \
     that runs with interrupts disabled is under-sampled and samples can land a few instructions \
     late.";
pub(super) const FAULTS_BIAS: &str = "Page faults show where threads first touched memory, \
     not how much they use: one fault can map many pages, as a huge page or the pages of a file \
     around the one touched, memory touched before the capture faults no more, and freeing it is \
     not seen. One fault in every period is sampled, and stands for the period's faults, so code \
     that faults fewer times than that shows only by chance.";
pub(super) const FRAME_POINTER_BIAS: &str = "Frame-pointer unwinding cuts stacks short in code \
     built without frame pointers, and misses the caller of a leaf function that has no frame \
     setup.";
pub(super) const DWARF_BIAS: &str = "DWARF unwinding falls back to frame pointers in code without unwind \
     tables, such as JIT code, and stops at the end of each sample's stack copy.";
const OFF_CPU_BIAS: &str = "Off-CPU time comes from context switches, without wakeups, so the \
     time a woken thread waits for a CPU counts as blocked rather than runnable.";

/// What became of the samples of uhr's eBPF programs.
pub(super) struct EbpfStacks {
    pub coverage: StackCoverage,
    /// Samples of processes perf has no record of, which are left out.
    pub untracked: u64,
}

/// The recording, and what became of the samples of uhr's eBPF programs if
/// they sampled.
pub(super) fn convert(input: Input) -> Result<(Recording, Option<EbpfStacks>)> {
    let file = File::open(input.perf_data).map_err(io_error("opening", input.perf_data))?;
    let PerfFileReader {
        mut perf_file,
        mut record_iter,
    } = PerfFileReader::parse_file(BufReader::new(file)).map_err(Error::PerfData)?;

    // Started with sampling off, perf adds a dummy event that tracks the
    // target meanwhile. It samples nothing.
    let attributes: Vec<_> = perf_file
        .event_attributes()
        .iter()
        .enumerate()
        .filter(|(_, a)| !is_dummy(a.attributes()))
        .collect();
    let index = |wanted: fn(&PerfEventType) -> bool| {
        attributes
            .iter()
            .find_map(|&(index, a)| wanted(&a.attributes().type_).then_some(index))
    };
    let cpu_clock = index(|t| matches!(t, PerfEventType::Software(SoftwareCounterType::CpuClock)));
    let switches = index(|t| {
        matches!(
            t,
            PerfEventType::Software(SoftwareCounterType::ContextSwitches)
        )
    });
    let faults = index(|t| matches!(t, PerfEventType::Software(SoftwareCounterType::PageFaults)));
    // With uhr's eBPF programs sampling, perf only tracks the processes.
    let sampled = input.ebpf_samples.is_none();
    let expected =
        usize::from(sampled) + usize::from(switches.is_some()) + usize::from(faults.is_some());
    if cpu_clock.is_some() != sampled
        || (faults.is_some() && !sampled)
        || attributes.len() != expected
    {
        let types: Vec<_> = attributes
            .iter()
            .map(|(_, a)| a.attributes().type_)
            .collect();
        let wanted = if sampled {
            "a cpu-clock event, and maybe a context-switches and a page-faults event"
        } else {
            "at most a context-switches event"
        };
        return Err(unexpected(format!("expected {wanted}, found {types:?}")));
    }
    let all = perf_file.event_attributes();
    let mut frequency_hz = None;
    let mut kernel_excluded = false;
    if let Some(cpu_clock) = cpu_clock {
        let attr = all[cpu_clock].attributes();
        check_clock(attr)?;
        let SamplingPolicy::Frequency(frequency) = attr.sampling_policy else {
            return Err(unexpected(format!(
                "expected sampling by frequency, found {:?}",
                attr.sampling_policy
            )));
        };
        frequency_hz = Some(frequency);
        kernel_excluded = attr.flags.contains(AttrFlags::EXCLUDE_KERNEL);
    }
    let mut fault_period = None;
    if let Some(faults) = faults {
        let attr = all[faults].attributes();
        check_clock(attr)?;
        let SamplingPolicy::Period(period) = attr.sampling_policy else {
            return Err(unexpected(format!(
                "expected page faults sampled by period, found {:?}",
                attr.sampling_policy
            )));
        };
        fault_period = Some(period.get());
    }
    // perf takes every stack the same way.
    let stack_copy_bytes = cpu_clock.or(switches).and_then(|index| {
        let attr = all[index].attributes();
        let copied = SampleFormat::REGS_USER | SampleFormat::STACK_USER;
        attr.sample_format
            .contains(copied)
            .then_some(attr.sample_stack_user)
    });
    // Threads go off CPU in the kernel, so without it there are no stacks.
    let mut switch_stacks_excluded = false;
    if let Some(index) = switches {
        let attr = all[index].attributes();
        check_clock(attr)?;
        if !matches!(attr.sampling_policy, SamplingPolicy::Period(period) if period.get() == 1) {
            return Err(unexpected(format!(
                "expected a sample at every context switch, found {:?}",
                attr.sampling_policy
            )));
        }
        if !all
            .iter()
            .any(|a| a.attributes().flags.contains(AttrFlags::CONTEXT_SWITCH))
        {
            return Err(unexpected(
                "context-switches samples without switch records".into(),
            ));
        }
        switch_stacks_excluded = attr.flags.contains(AttrFlags::EXCLUDE_KERNEL);
    }

    // perf records the regions of memory that map no code too.
    let regions_recorded = all
        .iter()
        .any(|a| a.attributes().flags.contains(AttrFlags::MMAP_DATA));

    let ours: HashSet<u64> = all
        .iter()
        .flat_map(|a| a.event_ids.iter().copied())
        .collect();

    let mut state = State::new(input.max_stack_depth);
    let ebpf_copies = input.ebpf_samples.and_then(|s| s.stack_bytes);
    if stack_copy_bytes.is_some() || ebpf_copies.is_some() {
        state.unwinding = Some(UserUnwinding::new());
    }
    let mut ebpf = input.ebpf_samples.map(EbpfReader::open).transpose()?;
    let mut held = input.launched_pid;
    let mut foreign = 0;
    let mut naming = input.naming.iter().peekable();
    while let Some(record) = record_iter
        .next_record(&mut perf_file)
        .map_err(Error::PerfData)?
    {
        let PerfFileRecord::EventRecord { attr_index, record } = record else {
            continue;
        };
        // Another perf that watches the same processes, as a uhr that uhr
        // records runs, can have its records land here, and the reader would
        // take them for the first event's. perf gives the records it
        // synthesizes the id 0, which the kernel gives no event.
        if record.id().is_some_and(|id| id != 0 && !ours.contains(&id)) {
            foreign += 1;
            continue;
        }
        let parsed = record
            .parse()
            .map_err(io_error("parsing a record in", input.perf_data))?;
        if let Some(pid) = held {
            match &parsed {
                EventRecord::Comm(c) if c.is_execve && id(c.pid)? == pid => held = None,
                _ if record_pid(&record, &parsed) == Some(pid) => continue,
                _ => {}
            }
        }
        // perf stamps the records it synthesizes at startup with 0.
        let time = record.timestamp().filter(|&t| t != 0);
        if let Some(time) = time {
            // So a sample sees the mappings and threads of its time.
            if let Some(ebpf) = ebpf.as_mut() {
                ebpf.add(&mut state, Some(time))?;
            }
            // So a region mapped later is not named from a reading before.
            while let Some(reading) = naming.next_if(|n| n.time_ns <= time) {
                state.name(reading);
            }
            state.seen_at(time);
        }
        match parsed {
            EventRecord::Sample(sample) if Some(attr_index) == cpu_clock => {
                state.sample(&record, &sample)?
            }
            EventRecord::Sample(sample) if Some(attr_index) == switches => {
                state.switch_sample(&record, &sample)?
            }
            EventRecord::Sample(sample) if Some(attr_index) == faults => {
                state.fault_sample(&record, &sample, fault_period)?
            }
            EventRecord::Sample(_) => {
                return Err(unexpected(
                    "a sample of an event uhr did not ask for".into(),
                ));
            }
            EventRecord::ContextSwitch(switch) if switches.is_some() => {
                let common = record
                    .common_data()
                    .map_err(io_error("parsing a record in", input.perf_data))?;
                let (Some(pid), Some(tid), Some(time)) = (common.pid, common.tid, common.timestamp)
                else {
                    return Err(unexpected("context switch without pid, tid or time".into()));
                };
                let (pid, tid) = (id(pid)?, id(tid)?);
                match switch {
                    ContextSwitchRecord::Out { preempted, .. } => {
                        state.switch_out(pid, tid, time, preempted)
                    }
                    ContextSwitchRecord::In { .. } => state.switch_in(pid, tid, time),
                }
            }
            EventRecord::Mmap(m) => state.mmap(Mmap {
                pid: m.pid,
                start: m.address,
                len: m.length,
                file_offset: m.page_offset,
                kernel: is_kernel(m.pid, m.cpu_mode),
                executable: m.is_executable,
                path: lossy(&m.path.as_slice()),
                build_id: None,
                permissions: None,
                time,
            })?,
            EventRecord::Mmap2(m) => state.mmap(Mmap {
                pid: m.pid,
                start: m.address,
                len: m.length,
                file_offset: m.page_offset,
                kernel: is_kernel(m.pid, m.cpu_mode),
                executable: m.protection & PROT_EXEC != 0,
                path: lossy(&m.path.as_slice()),
                build_id: match m.file_id {
                    Mmap2FileId::BuildId(id) => Some(hex(&id)),
                    Mmap2FileId::InodeAndVersion(_) => None,
                },
                permissions: Some(permissions(m.protection, m.flags)),
                time,
            })?,
            EventRecord::Comm(c) => state.comm(
                id(c.pid)?,
                id(c.tid)?,
                lossy(&c.name.as_slice()),
                c.is_execve,
                time,
            ),
            EventRecord::Fork(f) => {
                let parent = u32::try_from(f.ppid).ok().zip(u32::try_from(f.ptid).ok());
                state.fork(id(f.pid)?, id(f.tid)?, parent, time);
            }
            EventRecord::Exit(e) => state.exit(id(e.pid)?, id(e.tid)?, time),
            EventRecord::Lost(l) => state.lost_events += l.count,
            EventRecord::Throttle(_) => state.throttle_events += 1,
            _ => {}
        }
    }
    if let Some(ebpf) = ebpf.as_mut() {
        ebpf.add(&mut state, None)?;
    }
    naming.for_each(|reading| state.name(reading));
    if foreign > 0 {
        warn!(
            records = foreign,
            "left out records of events perf did not open for this recording, which another perf that watches the same processes wrote"
        );
    }

    // Stopping perf ends the capture, which can be long after the last
    // event, and before the target's exit. Attached, it starts when perf
    // samples, which can be long before the first event.
    if let Some(stopped) = input.stopped_ns {
        state.end_ns = Some(state.end_ns.map_or(stopped, |end| end.max(stopped)));
    }
    if let Some(attached) = input.attached_ns {
        state.start_ns = Some(state.start_ns.map_or(attached, |start| start.min(attached)));
    }
    // Before the threads' times off CPU are closed at the end, so they
    // still add up to the threads' lives.
    if let Some((first, last)) = input.memory_span {
        state.start_ns = Some(state.start_ns.map_or(first, |start| start.min(first)));
        state.end_ns = Some(state.end_ns.map_or(last, |end| end.max(last)));
    }
    state.attached_ns = input.attached_ns;
    state.finish_off_cpu();

    let mut signals = Vec::new();
    let mut missing_signals = Vec::new();
    if sampled {
        signals.extend([Signal::UserCPUSamples, Signal::UserStacks]);
        let kernel_signals = [Signal::KernelCPUSamples, Signal::KernelStacks];
        if kernel_excluded {
            missing_signals.extend(kernel_signals.map(|signal| {
                MissingSignal {
                    signal,
                    reason: "perf excluded the kernel, usually because perf_event_paranoid is 2 \
                         or higher. Run `uhr doctor`."
                        .into(),
                }
            }));
        } else {
            signals.extend(kernel_signals);
        }
    }
    if faults.is_some() {
        signals.push(Signal::PageFaults);
    }
    if regions_recorded {
        signals.push(Signal::MemoryRegions);
    }
    if switches.is_some() {
        signals.push(Signal::OffCPUTime);
        if switch_stacks_excluded {
            missing_signals.push(MissingSignal {
                signal: Signal::OffCPUStacks,
                reason: "perf excluded the kernel, where threads go off CPU, usually because \
                     perf_event_paranoid is 2 or higher. Run `uhr doctor`."
                    .into(),
            });
        } else {
            signals.push(Signal::OffCPUStacks);
        }
    }

    // perf takes no stacks when it only tracks the processes.
    let stacks_taken = sampled || switches.is_some();
    let mut known_biases = Vec::new();
    if sampled {
        known_biases.push(TIMER_BIAS);
    }
    if regions_recorded {
        known_biases.push(
            "The regions of memory come from the kernel's reports of mapping it, which leave out \
             a region moved or grown with mremap, as realloc does with large blocks, so a page \
             fault there is in no region.",
        );
        if input.memory_span.is_some() {
            known_biases.push(
                "A region has the name its process gave it from the next reading of the \
                 process's smaps, so one gone by then, as when the process ended first, has \
                 none.",
            );
        }
    }
    if faults.is_some() {
        known_biases.push(FAULTS_BIAS);
        if kernel_excluded {
            known_biases.push(
                "Page faults taken in the kernel, as when a syscall copies to or from the \
                 process's memory, are not sampled: perf excluded the kernel.",
            );
        }
    }
    if stacks_taken {
        known_biases.push(match stack_copy_bytes {
            Some(_) => DWARF_BIAS,
            None => FRAME_POINTER_BIAS,
        });
    }
    if switches.is_some() {
        known_biases.push(OFF_CPU_BIAS);
    }
    let stream = Stream {
        id: "perf".into(),
        collector: Collector::Perf {
            version: input.perf_version,
            sampling: frequency_hz.map(|frequency_hz| Sampling {
                event: "cpu-clock".into(),
                frequency_hz,
                requested_frequency_hz: input.requested_frequency_hz,
            }),
            page_faults: fault_period.map(|period| FaultSampling {
                event: "page-faults".into(),
                period,
            }),
            context_switches: switches.is_some(),
        },
        signals,
        missing_signals,
        coverage: StreamCoverage {
            lost_events: state.lost_events,
            stacks: stacks_taken.then(|| StackCoverage {
                unwinding: match stack_copy_bytes {
                    Some(_) => Unwinding::Dwarf,
                    None => Unwinding::FramePointers,
                },
                stack_copy_bytes,
                samples: state.samples.len() as u64 - state.ebpf_samples,
                page_fault_samples: faults.map(|_| state.page_faults.len() as u64),
                off_cpu_intervals: switches.map(|_| state.off_cpu.len() as u64),
                throttle_events: Some(state.throttle_events),
                max_stack_depth: input.max_stack_depth,
                stacks_at_stack_limit: state.stacks_at_stack_limit,
                stacks_cut_at_stack_copy: stack_copy_bytes.map(|_| state.stacks_cut_at_stack_copy),
                stacks_not_unwound: stack_copy_bytes.map(|_| state.stacks_not_unwound),
                interpreters: Vec::new(),
            }),
            overhead_ns: None,
            known_biases: known_biases.iter().map(|b| b.to_string()).collect(),
        },
    };
    let ebpf_stacks = input.ebpf_samples.map(|samples| EbpfStacks {
        coverage: ebpf_coverage(&state, input.max_stack_depth, samples),
        untracked: state.ebpf_untracked,
    });

    let (kernel_symbols, saved) = match input.kallsyms {
        Ok(kallsyms) => (
            kallsyms.covering(&state.frames, &state.mappings),
            KernelSymbols::Saved,
        ),
        Err(error) => (
            Vec::new(),
            KernelSymbols::Unavailable {
                reason: error.to_string(),
            },
        ),
    };
    let recording = Recording {
        manifest: Manifest {
            format_version: FORMAT_VERSION,
            platform: Platform {
                os: env::consts::OS.into(),
                arch: env::consts::ARCH.into(),
            },
            target: Target {
                command: input.command.to_vec(),
                launched: input.launched_pid.is_some(),
                runtime_support: input.runtime_support,
                exit: input.exit,
            },
            clock: Clock::Monotonic,
            start_ns: state.start_ns,
            end_ns: state.end_ns,
            streams: vec![stream],
            missing_signals: Vec::new(),
            kernel_symbols: saved,
        },
        threads: state.take_threads(),
        thread_names: state.thread_names,
        mappings: state.mappings,
        frames: state.frames,
        stacks: state.stacks,
        samples: state.samples,
        page_faults: state.page_faults,
        off_cpu: state.off_cpu,
        kernel_symbols,
        jit_symbols: Vec::new(),
        interpreted_code: state.interpreted_code,
        syscall_calls: Vec::new(),
        memory: Vec::new(),
        regions: state.regions,
        region_memory: Vec::new(),
    };
    Ok((recording, ebpf_stacks))
}

fn ebpf_coverage(state: &State, max_stack_depth: u32, samples: EbpfSamples) -> StackCoverage {
    let stack_bytes = samples.stack_bytes;
    StackCoverage {
        unwinding: match stack_bytes {
            Some(_) => Unwinding::Dwarf,
            None => Unwinding::FramePointers,
        },
        stack_copy_bytes: stack_bytes,
        samples: state.ebpf_samples,
        page_fault_samples: samples
            .page_faults
            .then_some(state.page_faults.len() as u64),
        off_cpu_intervals: None,
        // The kernel reports throttling in an event's buffer, and the
        // events the programs sample at have none.
        throttle_events: None,
        max_stack_depth: ebpf_depth(max_stack_depth),
        stacks_at_stack_limit: state.ebpf_at_limit,
        stacks_cut_at_stack_copy: stack_bytes.map(|_| state.ebpf_cut_at_copy),
        stacks_not_unwound: stack_bytes.map(|_| state.ebpf_not_unwound),
        interpreters: state
            .interpreters
            .iter()
            .map(|((runtime, version), walks)| InterpreterCoverage {
                runtime: (*runtime).to_owned(),
                version: version.clone(),
                processes: walks.processes.len() as u64,
                samples: walks.samples,
                before_found: walks.before_found,
                no_thread: walks.no_thread,
                unsearched: walks.unsearched,
                failed: walks.failed,
                cut: walks.cut,
                frames: walks.frames,
                unread_frames: walks.unread_frames,
                unmatched: walks.unmatched,
            })
            .collect(),
    }
}

/// A native frame of a sample, as `place` and `place_native` see it.
struct Native {
    id: u32,
    /// Whether it runs the program's frames: the interpreter's eval loop,
    /// or for frames on the native stack, code the runtime compiled too.
    eval: bool,
    /// Where it ends on the stack, if known.
    end: Option<u64>,
}

/// The interpreter frames that one call native code made into the
/// interpreter ran, leaf first, and where the frame is that started the
/// call, if the interpreter keeps it in the call's native frame.
#[derive(Debug, Default)]
struct Group {
    frames: Vec<u32>,
    entry: Option<u64>,
}

/// Puts groups of interpreter frames into a native stack, both leaf first,
/// each just above its call's eval-loop frame, as the code that ran there.
///
/// Where groups say where they started, each goes just above the native
/// frame that holds where, whose function ran the call, the eval loop or
/// one it was inlined into. Where the stack's ends come from walking
/// `frame_pointers`, a user leaf outside the eval loop that holds it set up
/// no frame, so that the walk lost its caller, the eval loop, and the group
/// goes just above the leaf. One that started past the native stack's end
/// goes at its outer end, and one whose start the walk did not reach goes
/// above the next run of eval-loop frames outward of the group before it.
///
/// Otherwise groups are matched to the runs of eval-loop frames from the
/// outer end, which a whole frame-pointer stack keeps: the ones without a
/// run go just above the user leaf, at `user`. A stack or walk that lost
/// its outer end is matched `from_inner` instead. Also says whether a group
/// had no run, so that where it went is a guess.
fn place(
    native: &[Native],
    user: usize,
    mut groups: Vec<Group>,
    from_inner: bool,
    frame_pointers: bool,
) -> (Vec<u32>, bool) {
    // What follows the outermost call's start is no call.
    while groups.last().is_some_and(|group| group.frames.is_empty()) {
        groups.pop();
    }
    let mut unmatched = false;
    let mut at: Vec<(usize, Vec<u32>)> = Vec::with_capacity(groups.len());
    let mut runs = Vec::new();
    for (i, frame) in native.iter().enumerate() {
        if frame.eval && !(i > 0 && native[i - 1].eval) {
            runs.push(i);
        }
    }
    let by_entries = groups.iter().any(|group| group.entry.is_some())
        && native.iter().skip(user).any(|frame| frame.end.is_some());
    if by_entries {
        // Where the group before went, which the next is outward of.
        let mut outward = user;
        for group in groups {
            let holds = |entry: u64| {
                native
                    .iter()
                    .enumerate()
                    .skip(user)
                    .find(|(_, frame)| frame.end.is_some_and(|end| end > entry))
            };
            let position = match group.entry {
                Some(entry) => match holds(entry) {
                    Some((i, frame)) if i == user && !frame.eval && frame_pointers => i + 1,
                    Some((i, _)) => i,
                    None => native.len(),
                },
                None => match runs.iter().find(|&&run| run >= outward) {
                    Some(&run) => run,
                    None => {
                        unmatched |= !group.frames.is_empty();
                        native.len()
                    }
                },
            };
            outward = outward.max(position + 1);
            at.push((position, group.frames));
        }
    } else {
        let shift = if from_inner {
            0
        } else {
            runs.len() as isize - groups.len() as isize
        };
        let lost = (user + 1).min(runs.first().copied().unwrap_or(native.len()));
        for (k, group) in groups.into_iter().enumerate() {
            let run = usize::try_from(k as isize + shift)
                .ok()
                .and_then(|run| runs.get(run));
            let position = match run {
                Some(&position) => position,
                None => {
                    unmatched |= !group.frames.is_empty();
                    if from_inner { native.len() } else { lost }
                }
            };
            at.push((position.min(native.len()), group.frames));
        }
    }
    at.sort_by_key(|(position, _)| *position);
    let frames: usize = at.iter().map(|(_, frames)| frames.len()).sum();
    let mut merged = Vec::with_capacity(native.len() + frames);
    let mut at = at.into_iter().peekable();
    for (i, frame) in native.iter().enumerate() {
        while let Some((_, frames)) = at.next_if(|(position, _)| *position == i) {
            merged.extend(frames);
        }
        merged.push(frame.id);
    }
    merged.extend(at.flat_map(|(_, frames)| frames));
    (merged, unmatched)
}

/// Puts the frames of a runtime that keeps them on the native stack into
/// it, leaf first. `walked` has them by their frame pointer, which is
/// where the native frame that ran each ends, less 16. Each takes the
/// place of that native frame where it runs the program's frames, and
/// else goes just above it: a function that sets up no frame keeps its
/// caller's frame pointer, so that the walk of frame pointers lost the
/// caller, whose frame this is.
fn place_native(native: &[Native], walked: &HashMap<u64, u32>) -> Vec<u32> {
    let mut merged = Vec::with_capacity(native.len() + 1);
    for frame in native {
        let found = frame.end.and_then(|end| walked.get(&end.wrapping_sub(16)));
        match found {
            Some(&walked) if frame.eval => merged.push(walked),
            Some(&walked) => merged.extend([frame.id, walked]),
            None => merged.push(frame.id),
        }
    }
    merged
}

/// The deepest stack uhr's eBPF programs take, kernel and user frames
/// together: the kernel's limit, or their room for frames if lower.
fn ebpf_depth(max_stack_depth: u32) -> u32 {
    max_stack_depth.min(MAX_FRAMES as u32)
}

/// The samples of uhr's eBPF programs, in the order they were taken. The
/// ring buffer they come through has them in the order the CPUs wrote
/// them, which is not quite that.
struct EbpfReader<'a> {
    path: &'a Path,
    file: File,
    /// The time, place in the file and length of each sample, by time.
    index: Vec<(u64, u64, u32)>,
    next: usize,
    period_ns: u64,
    /// The bytes of user stack each copy was asked for.
    stack_bytes: Option<u32>,
    interpreters: &'a Interpreters,
    buffer: Vec<u8>,
}

impl<'a> EbpfReader<'a> {
    fn open(samples: EbpfSamples<'a>) -> Result<Self> {
        let path = samples.path;
        let file = File::open(path).map_err(io_error("opening", path))?;
        let mut reader = BufReader::new(&file);
        let mut index = Vec::new();
        let mut at = 0;
        loop {
            let mut len = [0; 4];
            match reader.read_exact(&mut len) {
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                result => result.map_err(io_error("reading", path))?,
            }
            let len = u32::from_le_bytes(len);
            if (len as usize) < size_of::<SampleHeader>() {
                return Err(unexpected(format!("an eBPF sample of {len} bytes")));
            }
            // The time comes first.
            let mut time = [0; 8];
            reader
                .read_exact(&mut time)
                .map_err(io_error("reading", path))?;
            reader
                .seek_relative(i64::from(len) - 8)
                .map_err(io_error("reading", path))?;
            index.push((u64::from_ne_bytes(time), at + 4, len));
            at += 4 + u64::from(len);
        }
        index.sort_unstable();
        Ok(Self {
            path,
            file,
            index,
            next: 0,
            period_ns: samples.period_ns,
            stack_bytes: samples.stack_bytes,
            interpreters: samples.interpreters,
            buffer: Vec::new(),
        })
    }

    /// Adds the samples taken before `until` to `state`, or all that are
    /// left.
    fn add(&mut self, state: &mut State, until: Option<u64>) -> Result<()> {
        while let Some(&(time, at, len)) = self.index.get(self.next) {
            if until.is_some_and(|until| time >= until) {
                break;
            }
            self.buffer.resize(len as usize, 0);
            self.file
                .read_exact_at(&mut self.buffer, at)
                .map_err(io_error("reading", self.path))?;
            // SAFETY: the sample is longer than the header, which is plain
            // numbers, any bits of which are valid.
            let header: SampleHeader =
                unsafe { std::ptr::read_unaligned(self.buffer.as_ptr().cast()) };
            let rest = &self.buffer[size_of::<SampleHeader>()..];
            let (kernel, user) = (header.kernel_frames as usize, header.user_frames as usize);
            let ends = header.frame_ends != 0;
            let count = kernel + user * (1 + usize::from(ends));
            let copied = match header.copy {
                0 => 0,
                _ => size_of::<UserRegisters>() + header.stack_bytes as usize,
            };
            let walked = header.walked_frames as usize * header.walked_bytes as usize;
            if rest.len() != count * 8 + copied + walked {
                return Err(unexpected(format!(
                    "an eBPF sample of {len} bytes with {count} frames, a {copied}-byte copy \
                     and {walked} bytes of interpreter frames"
                )));
            }
            let (frames, rest) = rest.split_at(count * 8);
            let (rest, walked) = rest.split_at(copied);
            let word =
                |at: usize| u64::from_ne_bytes(frames[at * 8..at * 8 + 8].try_into().unwrap());
            let frames: Vec<(u64, Option<u64>)> = (0..kernel)
                .map(|i| (word(i), None))
                .chain((0..user).map(|i| match ends {
                    // 0 for the outermost.
                    true => (
                        word(kernel + 2 * i),
                        Some(word(kernel + 2 * i + 1)).filter(|&e| e != 0),
                    ),
                    false => (word(kernel + i), None),
                }))
                .collect();
            let copy = (header.copy != 0).then(|| {
                let (registers, stack) = rest.split_at(size_of::<UserRegisters>());
                // SAFETY: as for the header, plain numbers, as many bytes.
                let registers: UserRegisters =
                    unsafe { std::ptr::read_unaligned(registers.as_ptr().cast()) };
                UserCopy {
                    ip: registers.ip,
                    sp: registers.sp,
                    bp: registers.bp,
                    compat: registers.compat != 0,
                    stack,
                    full: Some(header.stack_bytes) == self.stack_bytes,
                }
            });
            let walked = (self.interpreters, walked);
            state.ebpf_sample(
                &header,
                frames.into_iter(),
                copy,
                Some(walked),
                self.period_ns,
            );
            self.next += 1;
        }
        Ok(())
    }
}

pub(crate) fn is_dummy(attr: &PerfEventAttr) -> bool {
    matches!(
        attr.type_,
        PerfEventType::Software(SoftwareCounterType::Dummy)
    )
}

fn first(times: &mut HashMap<(u32, u32), u64>, thread: (u32, u32), time_ns: u64) {
    let earliest = times.entry(thread).or_insert(time_ns);
    *earliest = (*earliest).min(time_ns);
}

/// The process a record is about, if it names one.
fn record_pid(record: &RawEventRecord, parsed: &EventRecord) -> Option<u32> {
    let pid = match parsed {
        EventRecord::Comm(c) => c.pid,
        EventRecord::Mmap(m) => m.pid,
        EventRecord::Mmap2(m) => m.pid,
        EventRecord::Fork(f) => f.pid,
        EventRecord::Exit(e) => e.pid,
        _ => record.common_data().ok()?.pid?,
    };
    u32::try_from(pid).ok()
}

fn check_clock(attr: &PerfEventAttr) -> Result<()> {
    if !matches!(attr.clock, PerfClock::ClockId(ClockId::Monotonic)) {
        return Err(unexpected(format!(
            "expected CLOCK_MONOTONIC timestamps, found {:?}",
            attr.clock
        )));
    }
    Ok(())
}

const PROT_EXEC: u32 = 0x4;

struct Mmap {
    pid: i32,
    start: u64,
    len: u64,
    file_offset: u64,
    kernel: bool,
    executable: bool,
    path: String,
    build_id: Option<String>,
    /// As `maps` lists them, as in `r-xp`, from an MMAP2 record.
    permissions: Option<String>,
    time: Option<u64>,
}

const PROT_READ: u32 = 0x1;
const PROT_WRITE: u32 = 0x2;
const MAP_SHARED: u32 = 0x1;

/// Permissions as `maps` lists them, as in `r-xp`.
fn permissions(protection: u32, flags: u32) -> String {
    let bit = |set: bool, c| if set { c } else { '-' };
    [
        bit(protection & PROT_READ != 0, 'r'),
        bit(protection & PROT_WRITE != 0, 'w'),
        bit(protection & PROT_EXEC != 0, 'x'),
        if flags & MAP_SHARED != 0 { 's' } else { 'p' },
    ]
    .into_iter()
    .collect()
}

/// The rows of the regions in a process's `space` that hold any of
/// `start..end`.
fn overlapping(
    space: &BTreeMap<u64, usize>,
    regions: &[MemoryRegion],
    start: u64,
    end: u64,
) -> Vec<usize> {
    let before = space
        .range(..start)
        .next_back()
        .map(|(_, &row)| row)
        .filter(|&row| regions[row].end > start);
    before
        .into_iter()
        .chain(space.range(start..end).map(|(_, &row)| row))
        .collect()
}

#[derive(Clone, Copy)]
enum ChainContext {
    Kernel,
    User,
    /// Hypervisor and guest frames, which this collector does not resolve.
    Other,
}

struct State {
    max_stack_depth: u32,
    start_ns: Option<u64>,
    end_ns: Option<u64>,
    /// The current lifetime of each thread id. Earlier lifetimes of reused
    /// ids move to `ended`.
    threads: HashMap<(u32, u32), Thread>,
    ended: Vec<Thread>,
    names: HashMap<(u32, u32), String>,
    thread_names: Vec<ThreadName>,
    mappings: Vec<Mapping>,
    /// Mapping ids live in each process, oldest first. A later mapping
    /// shadows an earlier one at the same address.
    processes: HashMap<u32, Vec<u32>>,
    /// A process's own copy of a mapping it inherited, by the mapping and
    /// the process.
    own_mappings: HashMap<(u32, u32), u32>,
    kernel_mappings: Vec<u32>,
    frames: Vec<Frame>,
    frame_ids: HashMap<Frame, u32>,
    stacks: Vec<Vec<u32>>,
    stack_ids: HashMap<Vec<u32>, u32>,
    samples: Vec<Sample>,
    page_faults: Vec<FaultSample>,
    regions: Vec<MemoryRegion>,
    /// Each process's regions as mapped now, which don't overlap, by start.
    spaces: HashMap<u32, BTreeMap<u64, usize>>,
    /// The end and name of each region each process had named at the last
    /// reading of its `smaps`, by start.
    named: HashMap<u32, BTreeMap<u64, (u64, String)>>,
    /// The stack perf took of a thread about to go off CPU, until its
    /// switch record comes.
    switch_stacks: HashMap<(u32, u32), u32>,
    /// Threads off CPU, until their switch back in.
    switched_out: HashMap<(u32, u32), SwitchedOut>,
    off_cpu: Vec<OffCPUInterval>,
    /// When perf started sampling a process uhr attached to.
    attached_ns: Option<u64>,
    /// When each thread was first seen on CPU, and first switched in.
    first_on_cpu: HashMap<(u32, u32), u64>,
    first_in: HashMap<(u32, u32), u64>,
    lost_events: u64,
    throttle_events: u64,
    stacks_at_stack_limit: u64,
    ebpf_samples: u64,
    ebpf_at_limit: u64,
    ebpf_untracked: u64,
    ebpf_cut_at_copy: u64,
    ebpf_not_unwound: u64,
    /// Only for recordings with a stack copy in each sample.
    unwinding: Option<UserUnwinding>,
    stacks_cut_at_stack_copy: u64,
    stacks_not_unwound: u64,
    interpreted_code: Vec<InterpretedCode>,
    /// Rows of `interpreted_code`, by pid and address.
    code_rows: HashMap<(Program, u64), u32>,
    /// By runtime and version.
    interpreters: BTreeMap<(&'static str, String), Walks>,
}

/// How the frames of one runtime and version were read.
#[derive(Default)]
struct Walks {
    processes: BTreeSet<u32>,
    samples: u64,
    before_found: u64,
    no_thread: u64,
    unsearched: u64,
    failed: u64,
    cut: u64,
    frames: u64,
    unread_frames: u64,
    unmatched: u64,
}

struct Taken {
    time_ns: u64,
    pid: u32,
    tid: u32,
    mode: Mode,
    stack: u32,
    /// The time or the faults the sample stands for.
    period: u64,
}

struct SwitchedOut {
    time_ns: u64,
    state: ThreadState,
    stack: Option<u32>,
}

impl State {
    fn new(max_stack_depth: u32) -> Self {
        Self {
            max_stack_depth,
            start_ns: None,
            end_ns: None,
            threads: HashMap::new(),
            ended: Vec::new(),
            names: HashMap::new(),
            thread_names: Vec::new(),
            mappings: Vec::new(),
            processes: HashMap::new(),
            own_mappings: HashMap::new(),
            kernel_mappings: Vec::new(),
            frames: Vec::new(),
            frame_ids: HashMap::new(),
            stacks: Vec::new(),
            stack_ids: HashMap::new(),
            samples: Vec::new(),
            switch_stacks: HashMap::new(),
            switched_out: HashMap::new(),
            page_faults: Vec::new(),
            regions: Vec::new(),
            spaces: HashMap::new(),
            named: HashMap::new(),
            off_cpu: Vec::new(),
            attached_ns: None,
            first_on_cpu: HashMap::new(),
            first_in: HashMap::new(),
            lost_events: 0,
            throttle_events: 0,
            stacks_at_stack_limit: 0,
            ebpf_samples: 0,
            ebpf_at_limit: 0,
            ebpf_untracked: 0,
            ebpf_cut_at_copy: 0,
            ebpf_not_unwound: 0,
            unwinding: None,
            stacks_cut_at_stack_copy: 0,
            stacks_not_unwound: 0,
            interpreted_code: Vec::new(),
            code_rows: HashMap::new(),
            interpreters: BTreeMap::new(),
        }
    }

    /// The capture runs from its first event to its last.
    fn seen_at(&mut self, time: u64) {
        self.start_ns = Some(self.start_ns.map_or(time, |t| t.min(time)));
        self.end_ns = Some(self.end_ns.map_or(time, |t| t.max(time)));
    }

    fn thread(&mut self, pid: u32, tid: u32) -> &mut Thread {
        self.threads.entry((pid, tid)).or_insert(Thread {
            pid,
            tid,
            parent_pid: None,
            parent_tid: None,
            start_ns: None,
            end_ns: None,
        })
    }

    fn comm(&mut self, pid: u32, tid: u32, name: String, exec: bool, time: Option<u64>) {
        if exec {
            self.processes.insert(pid, Vec::new());
            self.exec_regions(pid, time);
            // Another thread's exec takes the ids of the main thread, whose
            // exit came first, and goes on as a new one.
            let ended = self
                .threads
                .get(&(pid, tid))
                .is_some_and(|t| t.end_ns.is_some());
            if ended && let Some(earlier) = self.threads.remove(&(pid, tid)) {
                self.ended.push(earlier);
                self.thread(pid, tid).start_ns = time;
            }
        }
        self.thread(pid, tid);
        self.names.insert((pid, tid), name.clone());
        self.thread_names.push(ThreadName {
            pid,
            tid,
            time_ns: time,
            name,
        });
    }

    fn fork(&mut self, pid: u32, tid: u32, parent: Option<(u32, u32)>, time: Option<u64>) {
        if let Some((ppid, _)) = parent.filter(|&(ppid, _)| ppid != pid) {
            let inherited = self.processes.get(&ppid).cloned();
            self.processes.insert(pid, inherited.unwrap_or_default());
            self.fork_regions(pid, ppid, time);
        }
        // A thread id seen before means the kernel reused it.
        if let Some(earlier) = self.threads.remove(&(pid, tid)) {
            self.ended.push(earlier);
        }
        // Left from an earlier thread with this id, whose exit was lost.
        self.switched_out.remove(&(pid, tid));
        self.switch_stacks.remove(&(pid, tid));
        self.threads.insert(
            (pid, tid),
            Thread {
                pid,
                tid,
                parent_pid: parent.map(|(ppid, _)| ppid),
                parent_tid: parent.map(|(_, ptid)| ptid),
                start_ns: time,
                end_ns: None,
            },
        );
        // The kernel sends no COMM event for the name a child inherits.
        self.names.remove(&(pid, tid));
        if let Some(name) = parent.and_then(|p| self.names.get(&p)).cloned() {
            self.comm(pid, tid, name, false, time);
        }
    }

    fn take_threads(&mut self) -> Vec<Thread> {
        let mut threads = std::mem::take(&mut self.ended);
        threads.extend(self.threads.drain().map(|(_, thread)| thread));
        threads.sort_by_key(|t| (t.pid, t.tid, t.start_ns));
        threads
    }

    fn mmap(&mut self, m: Mmap) -> Result<()> {
        if m.len == 0 {
            return Ok(());
        }
        if !m.kernel
            && let Some(permissions) = &m.permissions
        {
            self.region(id(m.pid)?, &m, permissions);
        }
        // perf's own records for the kernel and its modules carry no
        // protection bits.
        if !(m.kernel || m.executable) {
            return Ok(());
        }
        let pid = if m.kernel { None } else { Some(id(m.pid)?) };
        let path = if m.kernel {
            kernel_mapping_path(m.path)
        } else {
            m.path
        };
        let start = m.start;
        let mut end = m.start.saturating_add(m.len);
        if m.kernel {
            // perf gives a module the start of its code and its total size,
            // but its data can lie elsewhere, so ranges overlap. A module's
            // code ends before the next one's starts.
            for &id in &self.kernel_mappings {
                let other = &mut self.mappings[id as usize];
                if other.start < start && start < other.end {
                    other.end = start;
                }
                if start < other.start && other.start < end {
                    end = other.start;
                }
            }
        }
        let mapping_id = self.mappings.len() as u32;
        self.mappings.push(Mapping {
            pid,
            start,
            end,
            file_offset: m.file_offset,
            path,
            build_id: m.build_id,
            time_ns: m.time,
        });
        match pid {
            None => self.kernel_mappings.push(mapping_id),
            Some(pid) => self.processes.entry(pid).or_default().push(mapping_id),
        }
        Ok(())
    }

    /// A region a process mapped. Each process's regions are kept as the
    /// kernel reports them: one that grows in place is reported again, and
    /// stays one, and what a region maps over was unmapped by then, so the
    /// regions there end.
    fn region(&mut self, pid: u32, m: &Mmap, permissions: &str) {
        let (start, end) = (m.start, m.start.saturating_add(m.len));
        // The kernel names memory that maps no file `//anon` here. perf
        // lists what was mapped before it started as `maps` does, with the
        // names processes gave their memory.
        let path = match m.path.as_str() {
            "//anon" => None,
            path => Some(procfs::memory_name(Some(path)).unwrap_or_else(|| path.to_owned())),
        };
        if self.grow(pid, m, permissions, path.as_deref()) {
            return;
        }
        self.unmap(pid, start, end, m.time, None);
        let row = self.regions.len();
        self.regions.push(MemoryRegion {
            pid,
            start,
            end,
            permissions: permissions.to_owned(),
            file_offset: m.file_offset,
            kind: procfs::region_kind(permissions, path.as_deref()),
            path,
            time_ns: m.time,
            unmapped_ns: None,
        });
        self.spaces.entry(pid).or_default().insert(start, row);
    }

    /// Grows the region of `pid` that the mapping `m` extends: up, as a
    /// heap or an arena grows, or down, as a stack does. Returns whether one
    /// grew. The kernel reports a heap's first `brk` unnamed, as it names
    /// the heap only once it has grown, so a heap that grows from there
    /// names it. It reports none of the names processes give their memory,
    /// so a region keeps its name as it grows while the last reading of its
    /// process's `smaps` had it.
    fn grow(&mut self, pid: u32, m: &Mmap, permissions: &str, path: Option<&str>) -> bool {
        let (start, end, file_offset) = (m.start, m.start.saturating_add(m.len), m.file_offset);
        let Some(space) = self.spaces.get(&pid) else {
            return false;
        };
        let up = space.get(&start).copied();
        let down = space
            .range(..end)
            .next_back()
            .map(|(_, &row)| row)
            .filter(|&row| self.regions[row].end == end && start < self.regions[row].start);
        // A file's region grows only up, from where in the file it starts.
        let anonymous = path.is_none_or(|path| path.starts_with('['));
        let grows = |row: usize, up: bool| {
            let region = &self.regions[row];
            let named = region.path.as_deref() == path
                || up && region.path.is_none() && path == Some("[heap]")
                || path.is_none()
                    && region.path.as_deref().is_some_and(|name| {
                        self.named_at_last_reading(pid, region.start, region.end, name)
                    });
            region.permissions == permissions
                && named
                && (anonymous || up && region.file_offset == file_offset)
        };
        let (row, extension) = match (up, down) {
            (Some(row), _) if grows(row, true) && self.regions[row].end <= end => {
                (row, self.regions[row].end..end)
            }
            (_, Some(row)) if grows(row, false) => (row, start..self.regions[row].start),
            _ => return false,
        };
        // It keeps when it was mapped, so it grows only where nothing was
        // mapped since: every address mapped is in a region until another
        // maps over it, so where none is, none was. Or over memory that
        // could not be touched, which a thread's arena grows over as it
        // makes its reserved memory usable.
        let over = overlapping(space, &self.regions, extension.start, extension.end);
        if over
            .into_iter()
            .any(|row| !self.regions[row].permissions.starts_with("---"))
        {
            return false;
        }
        if !extension.is_empty() {
            self.unmap(pid, extension.start, extension.end, m.time, Some(row));
        }
        let region = &mut self.regions[row];
        if path == Some("[heap]") && region.path.is_none() {
            region.path = Some("[heap]".into());
            region.kind = RegionKind::Heap;
        }
        if start < region.start {
            let space = self.spaces.entry(pid).or_default();
            space.remove(&region.start);
            space.insert(start, row);
            region.file_offset = file_offset;
            region.start = start;
        }
        region.end = region.end.max(end);
        true
    }

    /// Ends the regions of `pid` in `start..end` at `time`, but `except`,
    /// as a region mapped there took their place. The parts of them outside
    /// it are still mapped, and become regions of their own.
    fn unmap(&mut self, pid: u32, start: u64, end: u64, time: Option<u64>, except: Option<usize>) {
        let Some(space) = self.spaces.get(&pid) else {
            return;
        };
        let over = overlapping(space, &self.regions, start, end);
        for row in over.into_iter().filter(|&row| Some(row) != except) {
            self.cut(pid, row, start, end);
            let region = &mut self.regions[row];
            region.unmapped_ns = Some(time.unwrap_or(0));
            if let Some(space) = self.spaces.get_mut(&pid) {
                space.remove(&region.start);
            }
        }
    }

    /// Cuts the region of `pid` at `row` down to its part in `start..end`.
    /// Its parts outside become regions of their own, mapped as it was.
    fn cut(&mut self, pid: u32, row: usize, start: u64, end: u64) {
        let region = self.regions[row].clone();
        let space = self.spaces.entry(pid).or_default();
        space.remove(&region.start);
        let piece = |from: u64, to: u64| MemoryRegion {
            start: from,
            end: to,
            file_offset: region.file_offset + (from - region.start),
            ..region.clone()
        };
        for (from, to) in [(region.start, start), (end, region.end)] {
            if from < to {
                space.insert(from, self.regions.len());
                self.regions.push(piece(from, to));
            }
        }
        let (from, to) = (region.start.max(start), region.end.min(end));
        space.insert(from, row);
        self.regions[row] = piece(from, to);
    }

    /// What a process had named of its memory at a reading of its `smaps`,
    /// which the kernel's reports of mapping it don't say: its regions there
    /// take the names. A process names memory right after mapping it, so a
    /// region has its name from when it was mapped, but one whose name it
    /// changed or took away is a new region from the reading.
    fn name(&mut self, reading: &Naming) {
        let pid = reading.pid;
        let mut named = self.named.remove(&pid).unwrap_or_default();
        for start in &reading.gone {
            named.remove(start);
        }
        for (start, end, name) in &reading.named {
            named.insert(*start, (*end, name.clone()));
        }
        // All of them, as a region mapped where one named alike was before
        // reads the same in `smaps`.
        for (&start, (end, name)) in &named {
            let Some(space) = self.spaces.get(&pid) else {
                break;
            };
            for row in overlapping(space, &self.regions, start, *end) {
                match self.regions[row].path.as_deref() {
                    None => {
                        self.cut(pid, row, start, *end);
                        self.regions[row].path = Some(name.clone());
                    }
                    Some(path) if path != name && procfs::memory_name(Some(path)).is_some() => {
                        self.rename(pid, row, start, *end, reading.time_ns, Some(name.clone()));
                    }
                    // A file, the heap or a stack, which the reports said
                    // was mapped there, or memory named so already.
                    _ => {}
                }
            }
        }
        for &(start, end) in &reading.unnamed {
            let Some(space) = self.spaces.get(&pid) else {
                break;
            };
            for row in overlapping(space, &self.regions, start, end) {
                let path = self.regions[row].path.as_deref();
                if procfs::memory_name(path).is_some() {
                    self.rename(pid, row, start, end, reading.time_ns, None);
                }
            }
        }
        self.named.insert(pid, named);
    }

    /// Ends the part in `start..end` of the region of `pid` at `row` at
    /// `time`, and maps it again from then with the name `path`.
    fn rename(
        &mut self,
        pid: u32,
        row: usize,
        start: u64,
        end: u64,
        time: u64,
        path: Option<String>,
    ) {
        self.cut(pid, row, start, end);
        let region = &mut self.regions[row];
        region.unmapped_ns = Some(time);
        let renamed = MemoryRegion {
            path,
            time_ns: Some(time),
            unmapped_ns: None,
            ..region.clone()
        };
        let space = self.spaces.entry(pid).or_default();
        space.insert(renamed.start, self.regions.len());
        self.regions.push(renamed);
    }

    /// Whether the last reading of the `smaps` of `pid` had memory in
    /// `start..end` named `name`.
    fn named_at_last_reading(&self, pid: u32, start: u64, end: u64, name: &str) -> bool {
        let Some(named) = self.named.get(&pid) else {
            return false;
        };
        named
            .range(..end)
            .rev()
            .take_while(|(_, (to, _))| *to > start)
            .any(|(_, (_, is))| is == name)
    }

    /// A process's exec gave it new memory, so its regions end.
    fn exec_regions(&mut self, pid: u32, time: Option<u64>) {
        for (_, row) in self.spaces.remove(&pid).unwrap_or_default() {
            self.regions[row].unmapped_ns = Some(time.unwrap_or(0));
        }
    }

    /// A forked process starts with its parent's memory, so with copies of
    /// its regions.
    fn fork_regions(&mut self, pid: u32, parent: u32, time: Option<u64>) {
        // Of an earlier process with its pid: the readings of this one say
        // all it names.
        self.named.remove(&pid);
        let Some(regions) = self.spaces.get(&parent).cloned() else {
            return;
        };
        let space = self.spaces.entry(pid).or_default();
        for (start, row) in regions {
            space.insert(start, self.regions.len());
            self.regions.push(MemoryRegion {
                pid,
                time_ns: time,
                ..self.regions[row].clone()
            });
        }
    }

    fn sample(&mut self, record: &RawEventRecord, sample: &SampleRecord) -> Result<()> {
        let taken = self.taken(record, sample, None)?;
        self.samples.push(Sample {
            time_ns: taken.time_ns,
            pid: taken.pid,
            tid: taken.tid,
            cpu: sample.cpu,
            mode: taken.mode,
            stack: taken.stack,
            cpu_ns: taken.period,
        });
        Ok(())
    }

    /// A sample of page faults, one in every `period`, which perf then
    /// leaves out of each.
    fn fault_sample(
        &mut self,
        record: &RawEventRecord,
        sample: &SampleRecord,
        period: Option<u64>,
    ) -> Result<()> {
        let Some(address) = sample.addr else {
            return Err(unexpected("page-fault sample without its address".into()));
        };
        let taken = self.taken(record, sample, period)?;
        self.page_faults.push(FaultSample {
            time_ns: taken.time_ns,
            pid: taken.pid,
            tid: taken.tid,
            cpu: sample.cpu,
            mode: taken.mode,
            stack: taken.stack,
            faults: taken.period,
            address,
        });
        Ok(())
    }

    /// What perf took of a thread on CPU, at a timer's tick or a fault,
    /// with the event's period where the sample has none.
    fn taken(
        &mut self,
        record: &RawEventRecord,
        sample: &SampleRecord,
        period: Option<u64>,
    ) -> Result<Taken> {
        let (Some(pid), Some(tid), Some(time_ns), Some(period)) = (
            sample.pid,
            sample.tid,
            sample.timestamp,
            sample.period.or(period),
        ) else {
            return Err(unexpected("sample without pid, tid, time or period".into()));
        };
        let (pid, tid) = (id(pid)?, id(tid)?);
        self.thread(pid, tid);
        self.seen_on_cpu(pid, tid, time_ns);
        Ok(Taken {
            time_ns,
            pid,
            tid,
            mode: match sample.cpu_mode {
                CpuMode::User => Mode::User,
                CpuMode::Kernel => Mode::Kernel,
                _ => Mode::Unknown,
            },
            stack: self.stack(pid, time_ns, record, sample)?,
            period,
        })
    }

    /// A sample of uhr's eBPF programs, with its kernel frames and then its
    /// user frames, each leaf first, or with the user registers and stack
    /// to unwind instead of the user frames.
    fn ebpf_sample(
        &mut self,
        header: &SampleHeader,
        frames: impl Iterator<Item = (u64, Option<u64>)>,
        copy: Option<UserCopy>,
        walked: Option<(&Interpreters, &[u8])>,
        period_ns: u64,
    ) {
        let (pid, tid, time_ns) = (header.tgid, header.tid, header.time_ns);
        // perf follows a thread from its start, or from when it attached,
        // until it exits. One the target started while perf attached has no
        // record, nor do its mappings, and a later thread with the ids of one
        // that exited is another.
        let alive = self
            .threads
            .get(&(pid, tid))
            .is_some_and(|thread| thread.end_ns.is_none_or(|end| time_ns <= end));
        if !alive {
            self.ebpf_untracked += 1;
            return;
        }
        self.seen_at(time_ns);
        self.thread(pid, tid);
        self.seen_on_cpu(pid, tid, time_ns);
        let kernel = header.kernel_frames as usize;
        let mut stack = Vec::new();
        // Where each frame of `stack` ends on the stack, where known.
        let mut ends = Vec::new();
        for (i, (address, end)) in frames.enumerate() {
            let context = if i < kernel {
                ChainContext::Kernel
            } else {
                ChainContext::User
            };
            let first = i == 0 || i == kernel;
            stack.push(self.frame(pid, context, address, !first));
            ends.push(end);
        }
        let limit = ebpf_depth(self.max_stack_depth) as usize;
        // Whether the native stack lost its outer end.
        let mut cut_short = false;
        if let (Some(copy), Some(unwinding)) = (copy, self.unwinding.as_mut()) {
            let ids = self.processes.get(&pid).map_or(&[][..], Vec::as_slice);
            let room = limit.saturating_sub(stack.len());
            let user = unwinding.unwind(&copy, pid, ids, &self.mappings, room);
            cut_short |= user.cut;
            self.ebpf_cut_at_copy += u64::from(user.cut);
            self.ebpf_not_unwound += u64::from(user.not_unwound);
            for (address, return_address, end) in user.frames {
                stack.push(self.frame(pid, ChainContext::User, address, return_address));
                ends.push(end);
            }
        }
        let (mode, context) = match header.mode {
            mode::KERNEL => (Mode::Kernel, ChainContext::Kernel),
            mode::USER => (Mode::User, ChainContext::User),
            _ => (Mode::Unknown, ChainContext::Other),
        };
        // In a guest, or both walks failed.
        if stack.is_empty() {
            stack.push(self.frame(pid, context, header.ip, false));
            ends.push(None);
        }
        if stack.len() >= limit {
            self.ebpf_at_limit += 1;
            cut_short = true;
        }
        if let Some((interpreters, walked)) = walked {
            self.add_walked(header, &mut stack, &ends, interpreters, walked, cut_short);
        }
        let stack = intern(&mut self.stacks, &mut self.stack_ids, stack);
        if header.event == event::PAGE_FAULT {
            self.page_faults.push(FaultSample {
                time_ns,
                pid,
                tid,
                cpu: Some(header.cpu),
                mode,
                stack,
                faults: header.period,
                address: header.address,
            });
            return;
        }
        self.ebpf_samples += 1;
        self.samples.push(Sample {
            time_ns,
            pid,
            tid,
            cpu: Some(header.cpu),
            mode,
            stack,
            cpu_ns: period_ns,
        });
    }

    /// Puts the interpreter frames a sample walked into its native stack,
    /// leaf first, as `place` says. `cut_short` if the native stack lost its
    /// outer end.
    fn add_walked(
        &mut self,
        header: &SampleHeader,
        stack: &mut Vec<u32>,
        ends: &[Option<u64>],
        interpreters: &Interpreters,
        walked: &[u8],
        cut_short: bool,
    ) {
        let (pid, time_ns) = (header.tgid, header.time_ns);
        let program = (pid, header.exec);
        let (at, first) = interpreters.of(program, time_ns);
        let Some(found) = at.or(first) else {
            return;
        };
        let mut counts = Walks {
            samples: 1,
            ..Walks::default()
        };
        match header.walk {
            walk::NONE => counts.before_found = 1,
            walk::NO_THREAD => counts.no_thread = 1,
            walk::UNSEARCHED => counts.unsearched = 1,
            walk::FAILED => counts.failed = 1,
            walk::CUT => counts.cut = 1,
            _ => {}
        }
        if let (Some(interpreter), true) = (at, header.walked_frames > 0) {
            // Each frame after its address.
            let bytes = header.walked_bytes.max(9) as usize;
            let records = walked.chunks_exact(bytes).map(|record| {
                let (address, frame) = record.split_at(8);
                let address = u64::from_ne_bytes(address.try_into().unwrap());
                (address, interpreter.frame(frame))
            });
            let runs = |frame: &Frame| {
                let address = frame
                    .address
                    .saturating_sub(u64::from(frame.return_address));
                let ranges = interpreter.eval_loop();
                let after = ranges.partition_point(|range| range.start <= address);
                frame.origin == Origin::Binary
                    && after
                        .checked_sub(1)
                        .is_some_and(|i| ranges[i].contains(&address))
            };
            // Where the innermost frame of the program holds only where it
            // last called, its instruction is not known. On the native
            // stack, other code above it may have been called without it
            // saving where it is.
            let mut innermost = interpreter.saves_instruction_on_calls();
            if interpreter.walk().frames == Frames::Native {
                let mut placed = HashMap::new();
                for (address, frame) in records {
                    let WalkedFrame::Code {
                        code, instruction, ..
                    } = frame
                    else {
                        continue;
                    };
                    let instruction = if innermost { 0 } else { instruction };
                    innermost = false;
                    let (id, read) = self.interpreted_frame(
                        program,
                        interpreter,
                        interpreters,
                        code,
                        instruction,
                    );
                    counts.frames += 1;
                    counts.unread_frames += u64::from(!read);
                    // A frame whose code can't be read may be no frame of
                    // the runtime's at all.
                    if read {
                        placed.insert(address, id);
                    }
                }
                // Code the runtime compiled is in no file.
                let native: Vec<Native> = stack
                    .iter()
                    .zip(ends)
                    .map(|(id, end)| {
                        let frame = &self.frames[*id as usize];
                        Native {
                            id: *id,
                            eval: frame.origin == Origin::Unresolved || runs(frame),
                            end: *end,
                        }
                    })
                    .collect();
                *stack = place_native(&native, &placed);
            } else {
                let mut groups = vec![Group::default()];
                for (address, frame) in records {
                    // A call the runtime made from a frame saved where it
                    // was.
                    let saved = !std::mem::take(&mut innermost);
                    let entry = match frame {
                        WalkedFrame::Code {
                            code,
                            instruction,
                            entered,
                        } => {
                            let instruction = if saved { instruction } else { 0 };
                            let (id, read) = self.interpreted_frame(
                                program,
                                interpreter,
                                interpreters,
                                code,
                                instruction,
                            );
                            groups.last_mut().expect("never empty").frames.push(id);
                            counts.frames += 1;
                            counts.unread_frames += u64::from(!read);
                            entered.then_some(None)
                        }
                        WalkedFrame::Entry { native } => Some(native.then_some(address)),
                        WalkedFrame::Native => None,
                    };
                    if let Some(entry) = entry {
                        groups.last_mut().expect("never empty").entry = entry;
                        groups.push(Group::default());
                    }
                }
                let native: Vec<Native> = stack
                    .iter()
                    .zip(ends)
                    .map(|(id, end)| Native {
                        id: *id,
                        eval: runs(&self.frames[*id as usize]),
                        end: *end,
                    })
                    .collect();
                let user = stack
                    .iter()
                    .position(|id| self.frames[*id as usize].origin != Origin::Kernel)
                    .unwrap_or(stack.len());
                // A frame-pointer walk that runs into code without frames ends
                // at an address in no mapping.
                let lost_outer = cut_short
                    || stack.last().is_some_and(|id| {
                        let frame = &self.frames[*id as usize];
                        frame.origin == Origin::Unresolved && frame.mapping.is_none()
                    });
                let from_inner = lost_outer || header.walk == walk::CUT;
                let frame_pointers = header.frame_ends != 0;
                let (merged, unmatched) = place(&native, user, groups, from_inner, frame_pointers);
                counts.unmatched = u64::from(unmatched);
                *stack = merged;
            }
        }
        let walks = self
            .interpreters
            .entry((found.runtime(), found.version().to_owned()))
            .or_default();
        walks.processes.insert(pid);
        walks.samples += counts.samples;
        walks.before_found += counts.before_found;
        walks.no_thread += counts.no_thread;
        walks.unsearched += counts.unsearched;
        walks.failed += counts.failed;
        walks.cut += counts.cut;
        walks.frames += counts.frames;
        walks.unread_frames += counts.unread_frames;
        walks.unmatched += counts.unmatched;
    }

    /// The frame of the interpreted code at `code` in `program`, at
    /// `instruction`, and whether the code was read.
    fn interpreted_frame(
        &mut self,
        program: Program,
        interpreter: &dyn Interpreter,
        interpreters: &Interpreters,
        code: u64,
        instruction: u64,
    ) -> (u32, bool) {
        let read = interpreters
            .code
            .get(&(program, code))
            .and_then(Option::as_ref);
        let line = read.and_then(|code| code.line(instruction));
        let row = self.code_row(program, interpreter, code, read);
        let frame = Frame {
            origin: Origin::Interpreted,
            address: instruction,
            mapping: None,
            file_offset: None,
            return_address: false,
            interpreted: Some(Interpreted { code: row, line }),
        };
        (
            intern(&mut self.frames, &mut self.frame_ids, frame),
            read.is_some(),
        )
    }

    /// The row of `interpreted_code` for the code at `address` in
    /// `program`, named if it was read.
    fn code_row(
        &mut self,
        program: Program,
        interpreter: &dyn Interpreter,
        address: u64,
        read: Option<&uhr_core::runtimes::Code>,
    ) -> u32 {
        let table = &mut self.interpreted_code;
        *self.code_rows.entry((program, address)).or_insert_with(|| {
            table.push(InterpretedCode {
                pid: program.0,
                runtime: interpreter.runtime().to_owned(),
                address,
                name: read.map(|code| code.name.clone()),
                file: read.map(|code| code.file.clone()),
                first_line: read.map(|code| code.first_line),
                first_column: read.and_then(|code| code.first_column),
            });
            table.len() as u32 - 1
        })
    }

    /// perf samples a thread right before it goes off CPU, and the switch
    /// record follows.
    fn switch_sample(&mut self, record: &RawEventRecord, sample: &SampleRecord) -> Result<()> {
        let (Some(pid), Some(tid), Some(time_ns)) = (sample.pid, sample.tid, sample.timestamp)
        else {
            return Err(unexpected(
                "context-switches sample without pid, tid or time".into(),
            ));
        };
        let (pid, tid) = (id(pid)?, id(tid)?);
        let stack = self.stack(pid, time_ns, record, sample)?;
        self.switch_stack(pid, tid, time_ns, stack);
        Ok(())
    }

    fn switch_stack(&mut self, pid: u32, tid: u32, time_ns: u64, stack: u32) {
        self.seen_on_cpu(pid, tid, time_ns);
        // Records with the same time can come in either order.
        match self.switched_out.get_mut(&(pid, tid)) {
            Some(out) if out.stack.is_none() && out.time_ns == time_ns => out.stack = Some(stack),
            _ => {
                self.switch_stacks.insert((pid, tid), stack);
            }
        }
    }

    fn switch_out(&mut self, pid: u32, tid: u32, time_ns: u64, preempted: TaskWasPreempted) {
        self.thread(pid, tid);
        first(&mut self.first_on_cpu, (pid, tid), time_ns);
        let state = match preempted {
            TaskWasPreempted::Yes => ThreadState::Runnable,
            TaskWasPreempted::No => ThreadState::Blocked,
        };
        let stack = self.switch_stacks.remove(&(pid, tid));
        // This drops one still off CPU: its switch back in was lost, so when
        // it ended is unknown.
        self.switched_out.insert(
            (pid, tid),
            SwitchedOut {
                time_ns,
                state,
                stack,
            },
        );
    }

    fn switch_in(&mut self, pid: u32, tid: u32, time_ns: u64) {
        first(&mut self.first_in, (pid, tid), time_ns);
        // A stack left from before belongs to a switch out that was lost.
        self.switch_stacks.remove(&(pid, tid));
        if let Some(out) = self.switched_out.remove(&(pid, tid)) {
            self.off_cpu.push(OffCPUInterval {
                start_ns: out.time_ns,
                end_ns: time_ns,
                pid,
                tid,
                state: out.state,
                stack: out.stack,
            });
        }
    }

    /// A thread seen on CPU after it went off lost its switch back in, so
    /// when it came back is unknown.
    fn seen_on_cpu(&mut self, pid: u32, tid: u32, time_ns: u64) {
        first(&mut self.first_on_cpu, (pid, tid), time_ns);
        if self
            .switched_out
            .get(&(pid, tid))
            .is_some_and(|out| out.time_ns < time_ns)
        {
            self.switched_out.remove(&(pid, tid));
        }
    }

    fn exit(&mut self, pid: u32, tid: u32, time: Option<u64>) {
        self.thread(pid, tid).end_ns = time;
        // A thread runs to exit, so these lost their switch back in.
        self.switched_out.remove(&(pid, tid));
        self.switch_stacks.remove(&(pid, tid));
    }

    /// Threads still off CPU stay off until the capture ends. Attached,
    /// a thread that ran before the capture and first switched in was off
    /// CPU from its start until then, and one never seen all along, for
    /// reasons unknown.
    fn finish_off_cpu(&mut self) {
        if let (Some(_), Some(start_ns), Some(end_ns)) =
            (self.attached_ns, self.start_ns, self.end_ns)
        {
            for thread in self.threads.values().chain(&self.ended) {
                if thread.start_ns.is_some() {
                    continue;
                }
                let key = (thread.pid, thread.tid);
                let (back, on) = (self.first_in.get(&key), self.first_on_cpu.get(&key));
                let until = match (back, on) {
                    (Some(&back), None) => back,
                    (Some(&back), Some(&on)) if back <= on => back,
                    (None, None) => end_ns,
                    _ => continue,
                };
                let until = until.min(thread.end_ns.unwrap_or(end_ns));
                if start_ns < until {
                    self.off_cpu.push(OffCPUInterval {
                        start_ns,
                        end_ns: until,
                        pid: thread.pid,
                        tid: thread.tid,
                        state: ThreadState::Unknown,
                        stack: None,
                    });
                }
            }
        }
        if let Some(end_ns) = self.end_ns {
            for ((pid, tid), out) in self.switched_out.drain() {
                self.off_cpu.push(OffCPUInterval {
                    start_ns: out.time_ns,
                    end_ns,
                    pid,
                    tid,
                    state: out.state,
                    stack: out.stack,
                });
            }
        }
        self.off_cpu
            .sort_by_key(|i| (i.start_ns, i.pid, i.tid, i.end_ns));
    }

    fn stack(
        &mut self,
        pid: u32,
        time_ns: u64,
        record: &RawEventRecord,
        sample: &SampleRecord,
    ) -> Result<u32> {
        let mut stack = Vec::new();
        if let Some(callchain) = &sample.callchain {
            let mut context = ChainContext::Other;
            let mut first_in_context = true;
            for address in (0..callchain.len()).filter_map(|i| callchain.get(i)) {
                if address >= PERF_CONTEXT_MAX {
                    context = match address {
                        PERF_CONTEXT_KERNEL => ChainContext::Kernel,
                        PERF_CONTEXT_USER => ChainContext::User,
                        _ => ChainContext::Other,
                    };
                    first_in_context = true;
                    continue;
                }
                stack.push(self.frame(pid, context, address, !first_in_context));
                first_in_context = false;
            }
        }
        // With a stack copy, perf leaves user frames out of the chain.
        let user = match self.unwinding.as_mut() {
            Some(unwinding) => {
                let abi = user_regs_abi(record, sample)?;
                let bytes = sample.user_stack.as_ref().map(|(bytes, valid)| {
                    let bytes = bytes.as_slice();
                    let valid = (*valid as usize).min(bytes.len());
                    (bytes, valid)
                });
                let copy = bytes.as_ref().and_then(|(bytes, valid)| {
                    user_copy(sample, abi, &bytes[..*valid], *valid == bytes.len())
                });
                copy.map(|copy| {
                    let ids = self.processes.get(&pid).map_or(&[][..], Vec::as_slice);
                    let room = (self.max_stack_depth as usize).saturating_sub(stack.len());
                    unwinding.unwind(&copy, pid, ids, &self.mappings, room)
                })
            }
            None => None,
        };
        if let Some(user) = user {
            self.stacks_cut_at_stack_copy += u64::from(user.cut);
            self.stacks_not_unwound += u64::from(user.not_unwound);
            for (address, return_address, _) in user.frames {
                stack.push(self.frame(pid, ChainContext::User, address, return_address));
            }
        }
        if stack.is_empty()
            && let Some(ip) = sample.ip
        {
            let context = match sample.cpu_mode {
                CpuMode::Kernel => ChainContext::Kernel,
                CpuMode::User => ChainContext::User,
                _ => ChainContext::Other,
            };
            stack.push(self.frame(pid, context, ip, false));
        }
        if stack.is_empty() {
            return Err(unexpected(format!("sample at {time_ns} has no address")));
        }
        if stack.len() >= self.max_stack_depth as usize {
            self.stacks_at_stack_limit += 1;
        }
        Ok(intern(&mut self.stacks, &mut self.stack_ids, stack))
    }

    fn frame(
        &mut self,
        pid: u32,
        context: ChainContext,
        address: u64,
        return_address: bool,
    ) -> u32 {
        // A return address can be one past the end of the mapping that holds
        // the call, so find the mapping from the call instead.
        let lookup = address.saturating_sub(u64::from(return_address));
        let frame = match context {
            ChainContext::Kernel => Frame {
                origin: Origin::Kernel,
                address,
                mapping: self.find_mapping(&self.kernel_mappings, lookup),
                file_offset: None,
                return_address,
                interpreted: None,
            },
            ChainContext::User => {
                let mapping = self
                    .processes
                    .get(&pid)
                    .and_then(|ids| self.find_mapping(ids, lookup));
                match mapping.map(|id| &self.mappings[id as usize]) {
                    Some(m) if is_code_file(&m.path) => Frame {
                        origin: Origin::Binary,
                        address,
                        mapping,
                        file_offset: Some(address - m.start + m.file_offset),
                        return_address,
                        interpreted: None,
                    },
                    _ => Frame {
                        origin: Origin::Unresolved,
                        address,
                        mapping: mapping.map(|id| self.own_mapping(id, pid)),
                        file_offset: None,
                        return_address,
                        interpreted: None,
                    },
                }
            }
            ChainContext::Other => Frame {
                origin: Origin::Unresolved,
                address,
                mapping: None,
                file_offset: None,
                return_address,
                interpreted: None,
            },
        };
        intern(&mut self.frames, &mut self.frame_ids, frame)
    }

    /// The mapping `id` as the process `pid`'s own. A child shares the files
    /// it inherited, but fills memory that is not a file, such as a JIT's,
    /// in its own way, so its frames there are its own.
    fn own_mapping(&mut self, id: u32, pid: u32) -> u32 {
        let mapping = &self.mappings[id as usize];
        if mapping.pid == Some(pid) {
            return id;
        }
        if let Some(&copy) = self.own_mappings.get(&(id, pid)) {
            return copy;
        }
        let copy = Mapping {
            pid: Some(pid),
            ..mapping.clone()
        };
        self.mappings.push(copy);
        let copy = self.mappings.len() as u32 - 1;
        self.own_mappings.insert((id, pid), copy);
        copy
    }

    fn find_mapping(&self, ids: &[u32], address: u64) -> Option<u32> {
        ids.iter().rev().copied().find(|&id| {
            let m = &self.mappings[id as usize];
            m.start <= address && address < m.end
        })
    }
}

/// The user registers and stack copy perf took with a sample, in `abi`.
/// `None` without them, as for a kernel thread.
fn user_copy<'a>(
    sample: &SampleRecord,
    abi: u64,
    stack: &'a [u8],
    full: bool,
) -> Option<UserCopy<'a>> {
    let regs = sample.user_regs.as_ref()?;
    Some(UserCopy {
        ip: regs.get(PERF_REG_X86_IP)?,
        sp: regs.get(PERF_REG_X86_SP)?,
        bp: regs.get(PERF_REG_X86_BP)?,
        compat: abi == PERF_SAMPLE_REGS_ABI_32,
        stack,
        full,
    })
}

/// The ABI perf recorded the sample's user registers in, which tells 32-bit
/// code apart. linux-perf-event-reader reads it but does not keep it, so this
/// finds it in the record and checks the registers after it against the
/// parsed ones.
fn user_regs_abi(record: &RawEventRecord, sample: &SampleRecord) -> Result<u64> {
    let info = &record.parse_info;
    let format = info.sample_format;
    // They come before the registers and vary in size, and recordings uhr
    // makes have none of them.
    let unsupported = SampleFormat::READ | SampleFormat::RAW | SampleFormat::BRANCH_STACK;
    if format.intersects(unsupported) {
        return Err(unexpected(format!(
            "unexpected sample fields {:?} with a stack copy",
            format & unsupported
        )));
    }
    let data = record.data.as_slice();
    let word = |index: usize| {
        let bytes = data.get(index * 8..index * 8 + 8)?.try_into().ok()?;
        Some(match info.endian {
            Endianness::LittleEndian => u64::from_le_bytes(bytes),
            Endianness::BigEndian => u64::from_be_bytes(bytes),
        })
    };
    let one_word = [
        SampleFormat::IDENTIFIER,
        SampleFormat::IP,
        SampleFormat::TID,
        SampleFormat::TIME,
        SampleFormat::ADDR,
        SampleFormat::ID,
        SampleFormat::STREAM_ID,
        SampleFormat::CPU,
        SampleFormat::PERIOD,
    ];
    let at = one_word.iter().filter(|&&f| format.contains(f)).count()
        + sample.callchain.as_ref().map_or(0, |chain| 1 + chain.len());
    let abi = word(at);
    let found = match (abi, &sample.user_regs) {
        (Some(0), None) => true,
        (Some(PERF_SAMPLE_REGS_ABI_32 | PERF_SAMPLE_REGS_ABI_64), Some(regs)) => (0..64)
            .filter(|bit| info.sample_regs_user >> bit & 1 == 1)
            .enumerate()
            .all(|(i, register)| word(at + 1 + i) == regs.get(register)),
        _ => false,
    };
    match abi {
        Some(abi) if found => Ok(abi),
        _ => Err(unexpected(
            "the user registers of a sample are not where expected".into(),
        )),
    }
}

/// `[kernel]` for the kernel, and the module's name in brackets for a
/// module. perf names the kernel after the file it reads its symbols from,
/// and a module `[name]` or, when it finds one, after the module's file,
/// whose name the kernel turns into the module's by changing `-` to `_`.
fn kernel_mapping_path(path: String) -> String {
    if path.starts_with("[kernel.kallsyms]") {
        return KERNEL.to_owned();
    }
    let file = path.rsplit('/').next().unwrap_or_default();
    let module = [".ko", ".ko.gz", ".ko.xz", ".ko.zst"]
        .iter()
        .find_map(|suffix| file.strip_suffix(suffix))
        .filter(|_| path.starts_with('/'));
    match module {
        Some(name) => format!("[{}]", name.replace('-', "_")),
        None => path,
    }
}

/// Anonymous executable memory is usually JIT code and has no file to read
/// symbols from. Some of its names look like absolute paths. `[vdso]` is an
/// ELF image the kernel maps into every process.
fn is_code_file(path: &str) -> bool {
    const NOT_FILES: [&str; 5] = ["//anon", "/memfd:", "/dev/zero", "/SYSV", "/anon_hugepage"];
    if NOT_FILES.iter().any(|prefix| path.starts_with(prefix)) {
        return false;
    }
    path.starts_with('/') || path == "[vdso]"
}

fn is_kernel(pid: i32, mode: CpuMode) -> bool {
    pid == -1 || matches!(mode, CpuMode::Kernel)
}

fn intern<T: Clone + Eq + std::hash::Hash>(
    values: &mut Vec<T>,
    ids: &mut HashMap<T, u32>,
    value: T,
) -> u32 {
    *ids.entry(value).or_insert_with_key(|value| {
        values.push(value.clone());
        values.len() as u32 - 1
    })
}

fn unexpected(what: String) -> Error {
    Error::UnexpectedData(what)
}

fn id(value: i32) -> Result<u32> {
    u32::try_from(value).map_err(|_| unexpected(format!("unexpected negative pid or tid {value}")))
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use linux_perf_data::linux_perf_event_reader::constants::PERF_RECORD_MISC_USER;
    use linux_perf_data::linux_perf_event_reader::{
        BranchSampleFormat, RawData, ReadFormat, RecordIdParseInfo, RecordParseInfo, RecordType,
    };

    use super::*;

    fn mmap(pid: i32, start: u64, path: &str, kernel: bool, executable: bool) -> Mmap {
        Mmap {
            pid,
            start,
            len: 0x1000,
            file_offset: 0x100,
            kernel,
            executable,
            path: path.into(),
            build_id: None,
            permissions: None,
            time: None,
        }
    }

    #[test]
    fn writes_permissions_as_maps_lists_them() {
        assert_eq!(permissions(PROT_READ | PROT_EXEC, 0x2), "r-xp");
        assert_eq!(permissions(PROT_READ | PROT_WRITE, MAP_SHARED), "rw-s");
    }

    /// A mapping by process `pid` of `start..end`, with these permissions,
    /// at `time`.
    fn mapped(
        pid: i32,
        (start, end): (u64, u64),
        path: &str,
        permissions: &str,
        time: u64,
    ) -> Mmap {
        Mmap {
            len: end - start,
            file_offset: start,
            permissions: Some(permissions.into()),
            time: Some(time),
            ..mmap(pid, start, path, false, permissions.contains('x'))
        }
    }

    /// A region's pid, start, end and kind, and when it was mapped and
    /// unmapped.
    type Region = (u32, u64, u64, RegionKind, Option<u64>, Option<u64>);

    fn regions(state: &State) -> Vec<Region> {
        state
            .regions
            .iter()
            .map(|r| (r.pid, r.start, r.end, r.kind, r.time_ns, r.unmapped_ns))
            .collect()
    }

    #[test]
    fn keeps_a_region_that_grows_in_place_as_one() {
        let mut state = State::new(127);
        // The kernel reports a heap's first brk unnamed.
        for (end, path, time) in [(0x6000, "//anon", 10), (0x8000, "[heap]", 20)] {
            state
                .mmap(mapped(1, (0x5000, end), path, "rw-p", time))
                .unwrap();
        }
        // A stack grows down.
        for (start, time) in [(0xf000, 30), (0xd000, 40)] {
            state
                .mmap(mapped(1, (start, 0x10000), "[stack]", "rw-p", time))
                .unwrap();
        }
        assert_eq!(
            regions(&state),
            [
                (1, 0x5000, 0x8000, RegionKind::Heap, Some(10), None),
                (1, 0xd000, 0x10000, RegionKind::Stack, Some(30), None),
            ]
        );
        // Neither maps code.
        assert!(state.mappings.is_empty());
    }

    #[test]
    fn grows_no_region_over_one_below_it() {
        let mut state = State::new(127);
        state
            .mmap(mapped(1, (0x1000, 0x3000), "//anon", "rw-p", 10))
            .unwrap();
        state
            .mmap(mapped(1, (0x4000, 0x5000), "[stack]", "rw-p", 20))
            .unwrap();
        state
            .mmap(mapped(1, (0x2000, 0x5000), "[stack]", "rw-p", 30))
            .unwrap();
        let mut current: Vec<_> = regions(&state)
            .into_iter()
            .filter(|&(_, _, _, _, _, unmapped)| unmapped.is_none())
            .collect();
        current.sort();
        assert_eq!(
            current,
            [
                (1, 0x1000, 0x2000, RegionKind::Anonymous, Some(10), None),
                (1, 0x2000, 0x5000, RegionKind::Stack, Some(30), None),
            ]
        );
    }

    #[test]
    fn grows_a_threads_arena_over_the_memory_it_reserved() {
        let mut state = State::new(127);
        state
            .mmap(mapped(1, (0x100000, 0x500000), "//anon", "---p", 10))
            .unwrap();
        for (end, time) in [(0x101000, 20), (0x102000, 30), (0x103000, 40)] {
            state
                .mmap(mapped(1, (0x100000, end), "//anon", "rw-p", time))
                .unwrap();
        }
        let mut usable: Vec<_> = regions(&state)
            .into_iter()
            .filter(|&(_, _, _, _, _, unmapped)| unmapped.is_none())
            .collect();
        usable.sort();
        assert_eq!(
            usable,
            [
                (1, 0x100000, 0x103000, RegionKind::Anonymous, Some(20), None),
                (1, 0x103000, 0x500000, RegionKind::Anonymous, Some(10), None),
            ]
        );
    }

    #[test]
    fn names_the_regions_where_a_process_named_its_memory() {
        let mut state = State::new(127);
        let reading = |time_ns, named: &[(u64, u64, &str)], gone: &[u64]| Naming {
            time_ns,
            pid: 1,
            named: named
                .iter()
                .map(|&(start, end, name)| (start, end, name.to_owned()))
                .collect(),
            gone: gone.to_vec(),
            unnamed: Vec::new(),
        };
        state
            .mmap(mapped(1, (0x10000, 0x50000), "//anon", "rw-p", 10))
            .unwrap();
        state
            .mmap(mapped(1, (0x60000, 0x70000), "/data/table", "r--p", 10))
            .unwrap();
        state.name(&reading(
            20,
            &[
                (0x20000, 0x30000, "[anon:a]"),
                (0x60000, 0x70000, "[anon:a]"),
            ],
            &[],
        ));
        // Made read-only where it was named, which reads no differently.
        state
            .mmap(mapped(1, (0x20000, 0x30000), "//anon", "r--p", 30))
            .unwrap();
        state.name(&reading(40, &[], &[]));
        state.name(&reading(50, &[(0x20000, 0x30000, "[anon:b]")], &[0x20000]));
        let mut named: Vec<_> = state
            .regions
            .iter()
            .map(|r| (r.start, r.end, r.path.as_deref(), r.time_ns, r.unmapped_ns))
            .collect();
        named.sort();
        assert_eq!(
            named,
            [
                (0x10000, 0x20000, None, Some(10), None),
                (0x20000, 0x30000, Some("[anon:a]"), Some(10), Some(30)),
                (0x20000, 0x30000, Some("[anon:a]"), Some(30), Some(50)),
                (0x20000, 0x30000, Some("[anon:b]"), Some(50), None),
                (0x30000, 0x50000, None, Some(10), None),
                (0x60000, 0x70000, Some("/data/table"), Some(10), None),
            ]
        );
    }

    #[test]
    fn names_no_region_as_an_earlier_process_with_its_pid_named_it() {
        let mut state = State::new(127);
        let reading = |time_ns, start, name: &str| Naming {
            time_ns,
            pid: 1,
            named: vec![(start, start + 0x10000, name.to_owned())],
            gone: Vec::new(),
            unnamed: Vec::new(),
        };
        let anonymous = |time| mapped(1, (0x10000, 0x20000), "//anon", "rw-p", time);
        state.mmap(anonymous(10)).unwrap();
        state.name(&reading(20, 0x10000, "[anon:a]"));
        state.fork(1, 1, Some((2, 2)), Some(30));
        state.mmap(anonymous(40)).unwrap();
        state.name(&reading(50, 0x30000, "[anon:b]"));
        let current: Vec<_> = state
            .regions
            .iter()
            .filter(|r| r.unmapped_ns.is_none())
            .map(|r| (r.start, r.path.as_deref(), r.time_ns))
            .collect();
        assert_eq!(current, [(0x10000, None, Some(40))]);
    }

    #[test]
    fn takes_the_name_of_a_region_away_as_its_process_did() {
        let mut state = State::new(127);
        let reading =
            |time_ns, pid, named: &[(u64, u64, &str)], gone: &[u64], unnamed: &[(u64, u64)]| {
                Naming {
                    time_ns,
                    pid,
                    named: named
                        .iter()
                        .map(|&(start, end, name)| (start, end, name.to_owned()))
                        .collect(),
                    gone: gone.to_vec(),
                    unnamed: unnamed.to_vec(),
                }
            };
        state
            .mmap(mapped(1, (0x10000, 0x30000), "//anon", "rw-p", 10))
            .unwrap();
        state.name(&reading(20, 1, &[(0x10000, 0x30000, "[anon:a]")], &[], &[]));
        // With its parent's names, which it took away before it was read.
        state.fork(2, 2, Some((1, 1)), Some(30));
        state.name(&reading(40, 2, &[], &[], &[(0x10000, 0x30000)]));
        state.name(&reading(
            50,
            1,
            &[(0x10000, 0x20000, "[anon:a]")],
            &[0x10000],
            &[(0x20000, 0x30000)],
        ));
        let mut named: Vec<_> = state
            .regions
            .iter()
            .map(|r| {
                (
                    r.pid,
                    r.start,
                    r.end,
                    r.path.as_deref(),
                    r.time_ns,
                    r.unmapped_ns,
                )
            })
            .collect();
        named.sort();
        assert_eq!(
            named,
            [
                (1, 0x10000, 0x20000, Some("[anon:a]"), Some(10), None),
                (1, 0x20000, 0x30000, None, Some(50), None),
                (1, 0x20000, 0x30000, Some("[anon:a]"), Some(10), Some(50)),
                (2, 0x10000, 0x30000, None, Some(40), None),
                (2, 0x10000, 0x30000, Some("[anon:a]"), Some(30), Some(40)),
            ]
        );
    }

    #[test]
    fn keeps_the_name_of_a_region_as_it_grows_while_the_last_reading_had_it() {
        let mut state = State::new(127);
        let reading = |time_ns, named: &[(u64, u64, &str)], gone: &[u64]| Naming {
            time_ns,
            pid: 1,
            named: named
                .iter()
                .map(|&(start, end, name)| (start, end, name.to_owned()))
                .collect(),
            gone: gone.to_vec(),
            unnamed: Vec::new(),
        };
        let anonymous = |range, permissions, time| mapped(1, range, "//anon", permissions, time);
        // Reserved, and made usable in part, as a thread's malloc arena is.
        state
            .mmap(anonymous((0x100000, 0x500000), "---p", 10))
            .unwrap();
        state
            .mmap(anonymous((0x100000, 0x200000), "rw-p", 20))
            .unwrap();
        state
            .mmap(anonymous((0x600000, 0x700000), "rw-p", 10))
            .unwrap();
        state.name(&reading(
            30,
            &[
                (0x100000, 0x200000, "[anon:arena]"),
                (0x200000, 0x500000, "[anon:arena]"),
                (0x600000, 0x700000, "[anon:b]"),
            ],
            &[],
        ));
        state
            .mmap(anonymous((0x100000, 0x300000), "rw-p", 40))
            .unwrap();
        // The other unmapped, and what is mapped where it was then reported
        // as if it grew.
        state.name(&reading(
            50,
            &[
                (0x100000, 0x300000, "[anon:arena]"),
                (0x300000, 0x500000, "[anon:arena]"),
            ],
            &[0x100000, 0x200000, 0x600000],
        ));
        state
            .mmap(anonymous((0x600000, 0x800000), "rw-p", 60))
            .unwrap();
        let mut named: Vec<_> = state
            .regions
            .iter()
            .map(|r| (r.start, r.end, r.path.as_deref(), r.time_ns, r.unmapped_ns))
            .collect();
        named.sort();
        assert_eq!(
            named,
            [
                (0x100000, 0x200000, None, Some(10), Some(20)),
                (0x100000, 0x300000, Some("[anon:arena]"), Some(20), None),
                (0x200000, 0x300000, Some("[anon:arena]"), Some(10), Some(40)),
                (0x300000, 0x500000, Some("[anon:arena]"), Some(10), None),
                (0x600000, 0x700000, Some("[anon:b]"), Some(10), Some(60)),
                (0x600000, 0x800000, None, Some(60), None),
            ]
        );
    }

    #[test]
    fn ends_the_regions_that_a_later_one_maps_over() {
        let mut state = State::new(127);
        let anonymous = |time| mapped(1, (0x10000, 0x50000), "//anon", "rw-p", time);
        state.mmap(anonymous(10)).unwrap();
        // Over the upper half, after the first was unmapped.
        let file = Mmap {
            file_offset: 0,
            ..mapped(1, (0x30000, 0x50000), "/data.bin", "r--p", 20)
        };
        state.mmap(file).unwrap();
        state.mmap(anonymous(30)).unwrap();
        assert_eq!(
            regions(&state),
            [
                (
                    1,
                    0x30000,
                    0x50000,
                    RegionKind::Anonymous,
                    Some(10),
                    Some(20)
                ),
                (
                    1,
                    0x10000,
                    0x30000,
                    RegionKind::Anonymous,
                    Some(10),
                    Some(30)
                ),
                (1, 0x30000, 0x50000, RegionKind::File, Some(20), Some(30)),
                (1, 0x10000, 0x50000, RegionKind::Anonymous, Some(30), None),
            ]
        );
    }

    #[test]
    fn gives_a_forked_process_its_parents_regions_until_it_execs() {
        let mut state = State::new(127);
        state
            .mmap(mapped(1, (0x5000, 0x6000), "[heap]", "rw-p", 10))
            .unwrap();
        state.fork(2, 2, Some((1, 1)), Some(20));
        state.comm(2, 2, "child".into(), true, Some(30));
        assert_eq!(
            regions(&state),
            [
                (1, 0x5000, 0x6000, RegionKind::Heap, Some(10), None),
                (2, 0x5000, 0x6000, RegionKind::Heap, Some(20), Some(30)),
            ]
        );
    }

    #[test]
    fn puts_interpreter_frames_above_the_calls_into_the_interpreter() {
        // Native frames 0..10, interpreter frames 100 and up.
        let (leaf, c1, c2, eval0, c3, eval1, main) = (0, 1, 2, 3, 4, 5, 6);
        let frames = |ids: &[(u32, bool)]| -> Vec<Native> {
            let native = |&(id, eval): &(u32, bool)| Native {
                id,
                eval,
                end: None,
            };
            ids.iter().map(native).collect()
        };
        let groups = || {
            vec![
                Group {
                    frames: vec![100],
                    entry: None,
                },
                Group {
                    frames: vec![101, 102],
                    entry: None,
                },
                Group::default(),
            ]
        };
        // Every call shows, the leaf in the eval loop.
        let whole = frames(&[(eval0, true), (c3, false), (eval1, true), (main, false)]);
        assert_eq!(
            place(&whole, 0, groups(), false, false),
            (vec![100, eval0, c3, 101, 102, eval1, main], false)
        );
        // The leaf set up no frame, so its caller, the inner eval loop,
        // does not show.
        let lost = frames(&[
            (leaf, false),
            (c1, false),
            (c2, false),
            (eval1, true),
            (main, false),
        ]);
        assert_eq!(
            place(&lost, 0, groups(), false, false),
            (vec![leaf, 100, c1, c2, 101, 102, eval1, main], true)
        );
        // Under kernel frames.
        let kernel = frames(&[
            (7, false),
            (8, false),
            (leaf, false),
            (c1, false),
            (eval1, true),
            (main, false),
        ]);
        assert_eq!(
            place(&kernel, 2, groups(), false, false).0,
            [7, 8, leaf, 100, c1, 101, 102, eval1, main]
        );
        // A walk cut short, or a native stack that lost its outer end.
        let cut = vec![
            Group {
                frames: vec![100],
                entry: None,
            },
            Group {
                frames: vec![101],
                entry: None,
            },
            Group {
                frames: vec![102],
                entry: None,
            },
        ];
        assert_eq!(
            place(&whole, 0, cut, true, false),
            (vec![100, eval0, c3, 101, eval1, main, 102], true)
        );
        let truncated = frames(&[(eval0, true), (c1, false), (c2, false)]);
        assert_eq!(
            place(&truncated, 0, groups(), true, false),
            (vec![100, eval0, c1, c2, 101, 102], true)
        );
        // An inner call that has run none of its frames yet.
        let empty = vec![
            Group::default(),
            Group {
                frames: vec![101],
                entry: None,
            },
            Group::default(),
        ];
        assert_eq!(
            place(&whole, 0, empty, false, false),
            (vec![eval0, c3, 101, eval1, main], false)
        );
    }

    #[test]
    fn puts_frames_on_the_native_stack_in_place_of_the_code_that_ran_them() {
        // Native frames 0..10, each ending 0x100 apart, the runtime's
        // frames 100 and up.
        let frame = |id: u32, eval: bool| Native {
            id,
            eval,
            end: Some(0x1000 + 0x100 * u64::from(id)),
        };
        let at = |id: u32| 0x1000 + 0x100 * u64::from(id) - 16;
        let (jit, builtin, native, outer_jit, main) = (0, 1, 2, 3, 4);
        let stack = [
            frame(jit, true),
            frame(builtin, false),
            frame(native, false),
            frame(outer_jit, true),
            Native {
                id: main,
                eval: false,
                end: None,
            },
        ];
        // The builtin set up no frame, so the frame at its frame pointer is
        // its caller's, which the walk lost.
        let walked = HashMap::from([(at(jit), 100), (at(builtin), 101), (at(outer_jit), 102)]);
        assert_eq!(
            place_native(&stack, &walked),
            vec![100, builtin, 101, native, 102, main]
        );
        assert_eq!(
            place_native(&stack, &HashMap::new()),
            vec![jit, builtin, native, outer_jit, main]
        );
    }

    #[test]
    fn puts_interpreter_frames_where_their_calls_started() {
        let native = |id, eval, end| Native { id, eval, end };
        let group = |frames: &[u32], entry| Group {
            frames: frames.to_vec(),
            entry: Some(entry),
        };
        // Each call started in its eval loop's frame.
        let whole = [
            native(0, false, Some(0x1000)),
            native(1, true, Some(0x1100)),
            native(2, false, Some(0x1200)),
            native(3, true, Some(0x1300)),
            native(4, false, None),
        ];
        let groups = vec![
            group(&[100], 0x10f0),
            group(&[101, 102], 0x12f0),
            Group::default(),
        ];
        assert_eq!(
            place(&whole, 0, groups, false, true),
            (vec![0, 100, 1, 2, 101, 102, 3, 4], false)
        );
        // The eval loop inlined into the function that called it, as 3.14
        // has it in gen_iternext: the call started in that one's frame.
        let (op, gen_iternext, sum, call, main) = (0, 1, 2, 3, 4);
        let inlined = [
            native(op, true, Some(0x1000)),
            native(gen_iternext, false, Some(0x1100)),
            native(sum, false, Some(0x1200)),
            native(call, true, Some(0x1300)),
            native(main, false, None),
        ];
        let groups = vec![
            group(&[100, 101], 0x10f0),
            group(&[102], 0x12f0),
            Group::default(),
        ];
        assert_eq!(
            place(&inlined, 0, groups, false, false),
            (
                vec![op, 100, 101, gen_iternext, sum, 102, call, main],
                false
            )
        );
        // Python called qsort, which called Python. The leaf set up no
        // frame, so the inner eval loop's frame is lost, and code without
        // frame pointers ended the walk before the outer one.
        let (leaf, msort, qsort, ffi) = (0, 1, 2, 3);
        let lost = [
            native(leaf, false, Some(0x1000)),
            native(msort, false, Some(0x1080)),
            native(qsort, false, Some(0x1100)),
            native(ffi, false, None),
        ];
        let groups = vec![
            group(&[100], 0x0ff0),
            group(&[101, 102], 0x2000),
            Group::default(),
        ];
        assert_eq!(
            place(&lost, 0, groups, false, true),
            (vec![leaf, 100, msort, qsort, ffi, 101, 102], false)
        );
        // The walk stopped before the outer call's start: it goes above the
        // next eval loop's frames out, not past the stack's end.
        let (eval0, qsort, eval1, start) = (0, 1, 2, 3);
        let cut = [
            native(eval0, true, Some(0x1000)),
            native(qsort, false, Some(0x1100)),
            native(eval1, true, Some(0x1200)),
            native(start, false, None),
        ];
        let groups = vec![
            group(&[100], 0x0ff0),
            Group {
                frames: vec![101, 102],
                entry: None,
            },
        ];
        assert_eq!(
            place(&cut, 0, groups, true, true),
            (vec![100, eval0, qsort, 101, 102, eval1, start], false)
        );
    }

    #[test]
    fn leaves_out_ebpf_samples_of_threads_perf_has_no_record_of_then() {
        let mut state = State::new(127);
        // A kernel thread, which has no mappings, and a thread that exits.
        state.comm(1, 1, "rcu_preempt".into(), false, None);
        state.comm(3, 3, "short".into(), false, None);
        state.exit(3, 3, Some(4));
        let header = |tgid| SampleHeader {
            time_ns: 5,
            ip: 0xffff_0000_1000,
            period: 1000,
            address: 0,
            event: event::CPU_CLOCK,
            tgid,
            tid: tgid,
            cpu: 0,
            mode: mode::KERNEL,
            kernel_frames: 1,
            user_frames: 0,
            stack_bytes: 0,
            copy: 0,
            walk: 0,
            walked_frames: 0,
            walked_bytes: 0,
            frame_ends: 0,
            exec: 0,
            mapped: 0,
        };
        for pid in [1, 2, 3] {
            state.ebpf_sample(
                &header(pid),
                [(0xffff_0000_1000, None)].into_iter(),
                None,
                None,
                1000,
            );
        }
        assert_eq!((state.samples.len(), state.ebpf_untracked), (1, 2));
        assert_eq!(state.samples[0].pid, 1);
        assert!(!state.threads.contains_key(&(2, 2)));
    }

    #[test]
    fn takes_an_exec_by_another_thread_for_a_new_main_thread() {
        let mut state = State::new(127);
        state.comm(1, 1, "app".into(), false, None);
        state.fork(1, 2, Some((1, 1)), Some(1));
        state.exit(1, 1, Some(5));
        state.comm(1, 1, "worker".into(), true, Some(6));
        let header = SampleHeader {
            time_ns: 7,
            ip: 0x1010,
            period: 1000,
            address: 0,
            event: event::CPU_CLOCK,
            tgid: 1,
            tid: 1,
            cpu: 0,
            mode: mode::USER,
            kernel_frames: 0,
            user_frames: 1,
            stack_bytes: 0,
            copy: 0,
            walk: 0,
            walked_frames: 0,
            walked_bytes: 0,
            frame_ends: 0,
            exec: 0,
            mapped: 0,
        };
        state.ebpf_sample(&header, [(0x1010, None)].into_iter(), None, None, 1000);
        assert_eq!((state.samples.len(), state.ebpf_untracked), (1, 0));
        let threads = state.take_threads();
        let main: Vec<_> = threads
            .iter()
            .filter(|t| t.tid == 1)
            .map(|t| (t.start_ns, t.end_ns))
            .collect();
        assert_eq!(main, [(None, Some(5)), (Some(6), None)]);
    }

    #[test]
    fn puts_ebpf_samples_of_page_faults_apart_with_their_period() {
        let mut state = State::new(127);
        state.comm(1, 1, "app".into(), false, None);
        let header = |event, period, address| SampleHeader {
            time_ns: 7,
            ip: 0x1010,
            period,
            address,
            event,
            tgid: 1,
            tid: 1,
            cpu: 0,
            mode: mode::USER,
            kernel_frames: 0,
            user_frames: 1,
            stack_bytes: 0,
            copy: 0,
            walk: 0,
            walked_frames: 0,
            walked_bytes: 0,
            frame_ends: 0,
            exec: 0,
            mapped: 0,
        };
        for header in [
            header(event::CPU_CLOCK, 1000, 0),
            header(event::PAGE_FAULT, 167, 0x7f00_0000),
        ] {
            state.ebpf_sample(&header, [(0x1010, None)].into_iter(), None, None, 1000);
        }
        assert_eq!((state.samples.len(), state.ebpf_samples), (1, 1));
        let faults: Vec<_> = state
            .page_faults
            .iter()
            .map(|f| (f.pid, f.faults, f.address))
            .collect();
        assert_eq!(faults, [(1, 167, 0x7f00_0000)]);
        assert_eq!(state.page_faults[0].stack, state.samples[0].stack);
    }

    #[test]
    fn gives_a_child_its_own_copy_of_memory_that_is_not_a_file() {
        let mut state = State::new(127);
        state.mmap(mmap(1, 0x1000, "/app", false, true)).unwrap();
        state.mmap(mmap(1, 0x8000, "//anon", false, true)).unwrap();
        state.fork(2, 2, Some((1, 1)), Some(10));
        let frames = |state: &mut State, pid| {
            [0x1010, 0x8010].map(|address| state.frame(pid, ChainContext::User, address, false))
        };
        let parent = frames(&mut state, 1);
        let child = frames(&mut state, 2);
        assert_eq!(parent[0], child[0]);
        assert_ne!(parent[1], child[1]);
        let pid = |frame: u32| {
            let mapping = state.frames[frame as usize].mapping.unwrap();
            state.mappings[mapping as usize].pid
        };
        assert_eq!(pid(child[0]), Some(1));
        assert_eq!(pid(child[1]), Some(2));
        assert_eq!(frames(&mut state, 2), child);
        assert_eq!(state.mappings.len(), 3);
    }

    #[test]
    fn keeps_kernel_mappings_without_protection_bits() {
        let mut state = State::new(127);
        state
            .mmap(mmap(-1, 0xffff_0000, "[kernel.kallsyms]_text", true, false))
            .unwrap();
        state.mmap(mmap(7, 0x1000, "/data", false, false)).unwrap();
        assert_eq!(state.mappings.len(), 1);
        assert_eq!(state.mappings[0].path, KERNEL);
        let frame = state.frame(7, ChainContext::Kernel, 0xffff_0010, false);
        assert_eq!(state.frames[frame as usize].mapping, Some(0));
    }

    #[test]
    fn ends_kernel_modules_where_the_next_one_starts() {
        let module = |start, len, path: &str| Mmap {
            pid: -1,
            start,
            len,
            file_offset: 0,
            kernel: true,
            executable: false,
            path: path.into(),
            build_id: None,
            permissions: None,
            time: None,
        };
        let mut state = State::new(127);
        // As this host's /proc/modules gives them, and in either order.
        for m in [
            module(0xffffffffc051c000, 0x57000, "[aesni_intel]"),
            module(0xffffffffc0572000, 0x5000, "[xhci_pci_renesas]"),
            module(0xffffffffc05a0000, 0x2000, "[libahci]"),
            module(0xffffffffc059e000, 0x5000, "[raid0]"),
        ] {
            state.mmap(m).unwrap();
        }
        let ranges: Vec<_> = state
            .mappings
            .iter()
            .map(|m| (m.path.as_str(), m.start, m.end))
            .collect();
        assert_eq!(
            ranges,
            [
                ("[aesni_intel]", 0xffffffffc051c000, 0xffffffffc0572000),
                ("[xhci_pci_renesas]", 0xffffffffc0572000, 0xffffffffc0577000),
                ("[libahci]", 0xffffffffc05a0000, 0xffffffffc05a2000),
                ("[raid0]", 0xffffffffc059e000, 0xffffffffc05a0000),
            ]
        );
        let frame = state.frame(7, ChainContext::Kernel, 0xffffffffc0572010, false);
        assert_eq!(state.frames[frame as usize].mapping, Some(1));
    }

    #[test]
    fn names_kernel_modules_as_the_kernel_does() {
        let crypto = "/lib/modules/6.8.0-139-generic/kernel/arch/x86/crypto";
        for (path, name) in [
            ("[kernel.kallsyms]_text", "[kernel]"),
            ("[ghash_clmulni_intel]", "[ghash_clmulni_intel]"),
            (
                &format!("{crypto}/ghash-clmulni-intel.ko.zst"),
                "[ghash_clmulni_intel]",
            ),
            ("/lib/modules/6.8.0/kernel/fs/ext4/ext4.ko", "[ext4]"),
            ("/lib/modules/6.8.0/kernel/fs/xfs/xfs.ko.xz", "[xfs]"),
        ] {
            assert_eq!(kernel_mapping_path(path.into()), name, "{path}");
        }
    }

    #[test]
    fn anonymous_code_is_unresolved() {
        for path in ["//anon", "/memfd:jit (deleted)", "/dev/zero (deleted)"] {
            assert!(!is_code_file(path), "{path}");
        }
        for path in ["/usr/lib/libc.so.6", "/tmp/app (deleted)", "[vdso]"] {
            assert!(is_code_file(path), "{path}");
        }
        let mut state = State::new(127);
        state.mmap(mmap(7, 0x1000, "//anon", false, true)).unwrap();
        let frame = state.frame(7, ChainContext::User, 0x1010, false);
        let frame = &state.frames[frame as usize];
        assert_eq!(frame.origin, Origin::Unresolved);
        assert_eq!((frame.mapping, frame.file_offset), (Some(0), None));
    }

    #[test]
    fn finds_the_mapping_of_a_return_address_at_its_end() {
        let mut state = State::new(127);
        state
            .mmap(mmap(7, 0x1000, "/bin/app", false, true))
            .unwrap();
        let ret = state.frame(7, ChainContext::User, 0x2000, true);
        let ret = &state.frames[ret as usize];
        assert_eq!(ret.origin, Origin::Binary);
        assert_eq!((ret.mapping, ret.file_offset), (Some(0), Some(0x1100)));

        let leaf = state.frame(7, ChainContext::User, 0x2000, false);
        assert_eq!(state.frames[leaf as usize].mapping, None);
    }

    #[test]
    fn attached_threads_were_off_cpu_until_first_seen() {
        let attached = || {
            let mut state = State::new(127);
            (state.start_ns, state.end_ns) = (Some(100), Some(1_000));
            // Running before the capture: 1 first switches in, 2 is seen on
            // CPU first, and 3 is never seen.
            for tid in [1, 2, 3] {
                state.comm(7, tid, "t".into(), false, None);
            }
            state.fork(7, 4, Some((7, 1)), Some(150));
            state.switch_in(7, 1, 300);
            state.seen_on_cpu(7, 2, 200);
            state.switch_in(7, 2, 400);
            state.switch_in(7, 4, 500);
            state
        };
        let unknown = |state: State| -> Vec<_> {
            state
                .off_cpu
                .iter()
                .filter(|i| i.state == ThreadState::Unknown)
                .map(|i| (i.tid, i.start_ns, i.end_ns, i.stack))
                .collect()
        };

        let mut state = attached();
        state.attached_ns = Some(100);
        state.finish_off_cpu();
        assert_eq!(unknown(state), [(1, 100, 300, None), (3, 100, 1_000, None)]);

        // Launched, every thread ran in the capture.
        let mut state = attached();
        state.finish_off_cpu();
        assert!(unknown(state).is_empty());
    }

    #[test]
    fn pairs_each_switch_out_with_the_next_switch_in() {
        let mut state = State::new(127);
        state.switch_in(1, 2, 5);
        state.switch_stack(1, 2, 10, 0);
        state.switch_out(1, 2, 11, TaskWasPreempted::No);
        state.switch_in(1, 2, 20);
        state.switch_out(1, 2, 25, TaskWasPreempted::Yes);
        state.switch_out(1, 2, 26, TaskWasPreempted::No);
        // The same time as its switch out, but after it.
        state.switch_stack(1, 2, 26, 1);
        state.switch_in(1, 2, 30);
        // Its switch out was lost.
        state.switch_stack(1, 2, 35, 2);
        state.switch_in(1, 2, 40);
        state.switch_out(1, 2, 45, TaskWasPreempted::No);
        state.switch_out(1, 3, 50, TaskWasPreempted::No);
        state.exit(1, 3, Some(55));
        state.end_ns = Some(60);
        state.finish_off_cpu();

        let intervals: Vec<_> = state
            .off_cpu
            .iter()
            .map(|i| (i.tid, i.start_ns, i.end_ns, i.state, i.stack))
            .collect();
        assert_eq!(
            intervals,
            [
                (2, 11, 20, ThreadState::Blocked, Some(0)),
                (2, 26, 30, ThreadState::Blocked, Some(1)),
                (2, 45, 60, ThreadState::Blocked, None),
            ]
        );
    }

    #[test]
    fn drops_waits_a_thread_was_seen_on_cpu_during() {
        let mut state = State::new(127);
        state.switch_out(1, 2, 10, TaskWasPreempted::No);
        // Sampled right as it went off CPU.
        state.seen_on_cpu(1, 2, 10);
        state.switch_in(1, 2, 20);
        // Its switch back in was lost.
        state.switch_out(1, 2, 30, TaskWasPreempted::No);
        state.seen_on_cpu(1, 2, 35);
        state.switch_in(1, 2, 40);
        // Its switch back in was lost, and so was its next switch out.
        state.switch_out(1, 2, 45, TaskWasPreempted::No);
        state.switch_stack(1, 2, 50, 0);
        state.switch_in(1, 2, 55);
        state.switch_out(1, 2, 60, TaskWasPreempted::Yes);
        state.seen_on_cpu(1, 2, 65);
        state.end_ns = Some(70);
        state.finish_off_cpu();

        let intervals: Vec<_> = state
            .off_cpu
            .iter()
            .map(|i| (i.start_ns, i.end_ns))
            .collect();
        assert_eq!(intervals, [(10, 20)]);
    }

    #[test]
    fn drops_waits_of_an_earlier_thread_with_the_same_id() {
        let mut state = State::new(127);
        // Thread 5 lost its switch back in and its exit.
        state.fork(5, 5, Some((1, 1)), Some(10));
        state.switch_out(5, 5, 20, TaskWasPreempted::No);
        // Thread 6 lost its switch out and its exit.
        state.fork(5, 6, Some((1, 1)), Some(10));
        state.switch_stack(5, 6, 30, 0);
        state.fork(5, 5, Some((1, 1)), Some(1_000));
        state.switch_in(5, 5, 1_001);
        // Its first switch in and the stack of its switch out were lost.
        state.fork(5, 6, Some((1, 1)), Some(1_000));
        state.switch_out(5, 6, 1_010, TaskWasPreempted::Yes);
        state.switch_in(5, 6, 1_020);
        state.finish_off_cpu();

        let intervals: Vec<_> = state
            .off_cpu
            .iter()
            .map(|i| (i.tid, i.start_ns, i.end_ns, i.stack))
            .collect();
        assert_eq!(intervals, [(6, 1_010, 1_020, None)]);
    }

    #[test]
    fn keeps_every_lifetime_of_a_reused_thread_id() {
        let mut state = State::new(127);
        state.fork(5, 5, Some((1, 1)), Some(10));
        state.thread(5, 5).end_ns = Some(20);
        state.fork(5, 5, Some((1, 1)), Some(30));
        let threads = state.take_threads();
        let lifetimes: Vec<_> = threads.iter().map(|t| (t.start_ns, t.end_ns)).collect();
        assert_eq!(lifetimes, [(Some(10), Some(20)), (Some(30), None)]);
    }

    #[test]
    fn forked_children_inherit_the_parent_name() {
        let mut state = State::new(127);
        state.comm(1, 1, "server".into(), true, Some(5));
        state.fork(2, 2, Some((1, 1)), Some(10));
        state.fork(2, 3, Some((2, 2)), Some(11));
        state.comm(2, 3, "worker".into(), false, Some(12));

        let names: Vec<_> = state
            .thread_names
            .iter()
            .map(|n| (n.tid, n.time_ns, n.name.as_str()))
            .collect();
        assert_eq!(
            names,
            [
                (1, Some(5), "server"),
                (2, Some(10), "server"),
                (3, Some(11), "server"),
                (3, Some(12), "worker"),
            ]
        );
        let child = &state.threads[&(2, 3)];
        assert_eq!((child.parent_pid, child.parent_tid), (Some(2), Some(2)));
    }

    /// The ABI perf records for a sample of a recording with a stack copy,
    /// and the registers BP, SP and IP after it unless the ABI is none.
    fn user_regs_abi_of(abi: u64) -> Result<u64> {
        let pid_and_tid = 7 << 32 | 7;
        let mut words = vec![0x1010, pid_and_tid, 100, 0, 1_000_000];
        words.extend([2, PERF_CONTEXT_USER, 0x1010]);
        words.push(abi);
        if abi != 0 {
            words.extend([0x7ff0, 0x7fe0, 0x1010]);
        }
        words.push(0);
        let data: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let info = RecordParseInfo {
            endian: Endianness::LittleEndian,
            sample_format: SampleFormat::IP
                | SampleFormat::TID
                | SampleFormat::TIME
                | SampleFormat::CPU
                | SampleFormat::PERIOD
                | SampleFormat::CALLCHAIN
                | SampleFormat::REGS_USER
                | SampleFormat::STACK_USER,
            branch_sample_format: BranchSampleFormat::empty(),
            read_format: ReadFormat::empty(),
            common_data_offset_from_end: None,
            sample_regs_user: 1 << PERF_REG_X86_BP | 1 << PERF_REG_X86_SP | 1 << PERF_REG_X86_IP,
            user_regs_count: 3,
            sample_regs_intr: 0,
            intr_regs_count: 0,
            id_parse_info: RecordIdParseInfo {
                nonsample_record_id_offset_from_end: None,
                sample_record_id_offset_from_start: None,
            },
            nonsample_record_time_offset_from_end: None,
            sample_record_time_offset_from_start: Some(16),
        };
        let record = RawEventRecord::new(
            RecordType::SAMPLE,
            PERF_RECORD_MISC_USER,
            RawData::Single(&data),
            info,
        );
        let EventRecord::Sample(sample) = record.parse().unwrap() else {
            panic!("not a sample");
        };
        user_regs_abi(&record, &sample)
    }

    #[test]
    fn reads_the_abi_of_user_registers() {
        for abi in [0, PERF_SAMPLE_REGS_ABI_32, PERF_SAMPLE_REGS_ABI_64] {
            assert_eq!(user_regs_abi_of(abi).unwrap(), abi);
        }
        assert!(user_regs_abi_of(3).is_err());
    }
}
