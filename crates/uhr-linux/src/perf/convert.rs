use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use linux_perf_data::linux_perf_event_reader::constants::{
    PERF_CONTEXT_KERNEL, PERF_CONTEXT_MAX, PERF_CONTEXT_USER, PERF_SAMPLE_REGS_ABI_32,
    PERF_SAMPLE_REGS_ABI_64,
};
use linux_perf_data::linux_perf_event_reader::{
    AttrFlags, ClockId, ContextSwitchRecord, CpuMode, Endianness, EventRecord, Mmap2FileId,
    PerfClock, PerfEventAttr, PerfEventType, RawEventRecord, SampleFormat, SampleRecord,
    SamplingPolicy, SoftwareCounterType, TaskWasPreempted,
};
use linux_perf_data::{PerfFileReader, PerfFileRecord};

use super::unwind::Unwinding as UserUnwinding;
use super::{Error, Result, io_error};
use crate::kallsyms::{self, Kallsyms};
use uhr_core::recording::{
    Clock, Collector, Exit, FORMAT_VERSION, Frame, KERNEL, KernelSymbols, Manifest, Mapping,
    MissingSignal, Mode, OffCPUInterval, Origin, Recording, Sample, Signal, Stream, StreamCoverage,
    Target, Thread, ThreadName, ThreadState, Unwinding,
};

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
    pub perf_version: String,
    pub requested_frequency_hz: u64,
    pub max_stack_depth: u32,
    pub kallsyms: Result<&'a Kallsyms, &'a kallsyms::Error>,
}

const TIMER_BIAS: &str = "cpu-clock samples come from a timer interrupt, so code that runs \
     with interrupts disabled is under-sampled and samples can land a few instructions late.";
const FRAME_POINTER_BIAS: &str = "Frame-pointer unwinding cuts stacks short in code built \
     without frame pointers, and misses the caller of a leaf function that has no frame setup.";
const DWARF_BIAS: &str = "DWARF unwinding falls back to frame pointers in code without unwind \
     tables, such as JIT code, and stops at the end of each sample's stack copy.";
const OFF_CPU_BIAS: &str = "Off-CPU time comes from context switches, without wakeups, so the \
     time a woken thread waits for a CPU counts as blocked rather than runnable.";

pub(super) fn convert(input: Input) -> Result<Recording> {
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
    let expected = if switches.is_some() { 2 } else { 1 };
    let Some(cpu_clock) = cpu_clock.filter(|_| attributes.len() == expected) else {
        let types: Vec<_> = attributes
            .iter()
            .map(|(_, a)| a.attributes().type_)
            .collect();
        return Err(unexpected(format!(
            "expected a cpu-clock event and maybe a context-switches event, found {types:?}"
        )));
    };
    let all = perf_file.event_attributes();
    let attr = all[cpu_clock].attributes();
    check_clock(attr)?;
    let SamplingPolicy::Frequency(frequency_hz) = attr.sampling_policy else {
        return Err(unexpected(format!(
            "expected sampling by frequency, found {:?}",
            attr.sampling_policy
        )));
    };
    let kernel_excluded = attr.flags.contains(AttrFlags::EXCLUDE_KERNEL);
    let stack_copy_bytes = attr
        .sample_format
        .contains(SampleFormat::REGS_USER | SampleFormat::STACK_USER)
        .then_some(attr.sample_stack_user);
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

    let mut state = State::new(input.max_stack_depth);
    if stack_copy_bytes.is_some() {
        state.unwinding = Some(UserUnwinding::new());
    }
    let mut held = input.launched_pid;
    while let Some(record) = record_iter
        .next_record(&mut perf_file)
        .map_err(Error::PerfData)?
    {
        let PerfFileRecord::EventRecord { attr_index, record } = record else {
            continue;
        };
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
            state.start_ns = Some(state.start_ns.map_or(time, |t| t.min(time)));
            state.end_ns = Some(state.end_ns.map_or(time, |t| t.max(time)));
        }
        match parsed {
            EventRecord::Sample(sample) if attr_index == cpu_clock => {
                state.sample(&record, &sample)?
            }
            EventRecord::Sample(sample) if Some(attr_index) == switches => {
                state.switch_sample(&record, &sample)?
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

    // Stopping perf ends the capture, which can be long after the last
    // event, and before the target's exit. Attached, it starts when perf
    // samples, which can be long before the first event.
    if let Some(stopped) = input.stopped_ns {
        state.end_ns = Some(state.end_ns.map_or(stopped, |end| end.max(stopped)));
    }
    if let Some(attached) = input.attached_ns {
        state.start_ns = Some(state.start_ns.map_or(attached, |start| start.min(attached)));
    }
    state.attached_ns = input.attached_ns;
    state.finish_off_cpu();

    let mut signals = vec![Signal::UserCPUSamples, Signal::UserStacks];
    let mut missing_signals = Vec::new();
    let kernel_signals = [Signal::KernelCPUSamples, Signal::KernelStacks];
    if kernel_excluded {
        missing_signals.extend(kernel_signals.map(|signal| {
            MissingSignal {
                signal,
                reason: "perf excluded the kernel, usually because perf_event_paranoid is 2 or \
                     higher. Run `uhr doctor`."
                    .into(),
            }
        }));
    } else {
        signals.extend(kernel_signals);
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

    let mut known_biases = vec![
        TIMER_BIAS,
        match stack_copy_bytes {
            Some(_) => DWARF_BIAS,
            None => FRAME_POINTER_BIAS,
        },
    ];
    if switches.is_some() {
        known_biases.push(OFF_CPU_BIAS);
    }
    let stream = Stream {
        id: "perf".into(),
        collector: Collector::Perf {
            version: input.perf_version,
            event: "cpu-clock".into(),
            frequency_hz,
            requested_frequency_hz: input.requested_frequency_hz,
            unwinding: match stack_copy_bytes {
                Some(_) => Unwinding::Dwarf,
                None => Unwinding::FramePointers,
            },
            stack_copy_bytes,
            context_switches: switches.is_some(),
        },
        signals,
        missing_signals,
        coverage: StreamCoverage {
            samples: state.samples.len() as u64,
            off_cpu_intervals: switches.map(|_| state.off_cpu.len() as u64),
            lost_events: state.lost_events,
            throttle_events: state.throttle_events,
            max_stack_depth: input.max_stack_depth,
            stacks_at_stack_limit: state.stacks_at_stack_limit,
            stacks_cut_at_stack_copy: stack_copy_bytes.map(|_| state.stacks_cut_at_stack_copy),
            stacks_not_unwound: stack_copy_bytes.map(|_| state.stacks_not_unwound),
            overhead_ns: None,
            known_biases: known_biases.iter().map(|b| b.to_string()).collect(),
        },
    };

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
    Ok(Recording {
        manifest: Manifest {
            format_version: FORMAT_VERSION,
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
            kernel_symbols: saved,
        },
        threads: state.take_threads(),
        thread_names: state.thread_names,
        mappings: state.mappings,
        frames: state.frames,
        stacks: state.stacks,
        samples: state.samples,
        off_cpu: state.off_cpu,
        kernel_symbols,
        jit_symbols: Vec::new(),
    })
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
    time: Option<u64>,
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
    /// Only for recordings with a stack copy in each sample.
    unwinding: Option<UserUnwinding>,
    stacks_cut_at_stack_copy: u64,
    stacks_not_unwound: u64,
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
            off_cpu: Vec::new(),
            attached_ns: None,
            first_on_cpu: HashMap::new(),
            first_in: HashMap::new(),
            lost_events: 0,
            throttle_events: 0,
            stacks_at_stack_limit: 0,
            unwinding: None,
            stacks_cut_at_stack_copy: 0,
            stacks_not_unwound: 0,
        }
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
        // perf's own records for the kernel and its modules carry no
        // protection bits.
        if m.len == 0 || !(m.kernel || m.executable) {
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

    fn sample(&mut self, record: &RawEventRecord, sample: &SampleRecord) -> Result<()> {
        let (Some(pid), Some(tid), Some(time_ns), Some(period)) =
            (sample.pid, sample.tid, sample.timestamp, sample.period)
        else {
            return Err(unexpected("sample without pid, tid, time or period".into()));
        };
        let (pid, tid) = (id(pid)?, id(tid)?);
        self.thread(pid, tid);
        self.seen_on_cpu(pid, tid, time_ns);
        let stack = self.stack(pid, time_ns, record, sample)?;
        self.samples.push(Sample {
            time_ns,
            pid,
            tid,
            cpu: sample.cpu,
            mode: match sample.cpu_mode {
                CpuMode::User => Mode::User,
                CpuMode::Kernel => Mode::Kernel,
                _ => Mode::Unknown,
            },
            stack,
            cpu_ns: period,
        });
        Ok(())
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
                let ids = self.processes.get(&pid).map_or(&[][..], Vec::as_slice);
                let room = (self.max_stack_depth as usize).saturating_sub(stack.len());
                unwinding.unwind(sample, abi, pid, ids, &self.mappings, room)
            }
            None => None,
        };
        if let Some(user) = user {
            self.stacks_cut_at_stack_copy += u64::from(user.cut);
            self.stacks_not_unwound += u64::from(user.not_unwound);
            for (address, return_address) in user.frames {
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
                    },
                    _ => Frame {
                        origin: Origin::Unresolved,
                        address,
                        mapping: mapping.map(|id| self.own_mapping(id, pid)),
                        file_offset: None,
                        return_address,
                    },
                }
            }
            ChainContext::Other => Frame {
                origin: Origin::Unresolved,
                address,
                mapping: None,
                file_offset: None,
                return_address,
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
            time: None,
        }
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
        use ThreadState::*;
        assert_eq!(
            intervals,
            [
                (2, 11, 20, Blocked, Some(0)),
                (2, 26, 30, Blocked, Some(1)),
                (2, 45, 60, Blocked, None),
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
        use linux_perf_data::linux_perf_event_reader::constants::{
            PERF_RECORD_MISC_USER, PERF_REG_X86_BP, PERF_REG_X86_IP, PERF_REG_X86_SP,
        };
        use linux_perf_data::linux_perf_event_reader::{
            BranchSampleFormat, RawData, ReadFormat, RecordIdParseInfo, RecordParseInfo, RecordType,
        };

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
