use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use linux_perf_data::linux_perf_event_reader::constants::{
    PERF_CONTEXT_KERNEL, PERF_CONTEXT_MAX, PERF_CONTEXT_USER,
};
use linux_perf_data::linux_perf_event_reader::{
    AttrFlags, ClockId, CpuMode, EventRecord, Mmap2FileId, PerfClock, PerfEventType, SampleRecord,
    SamplingPolicy, SoftwareCounterType,
};
use linux_perf_data::{PerfFileReader, PerfFileRecord};

use super::{Error, Result, io_error};
use crate::recording::{
    Clock, Collector, Exit, FORMAT_VERSION, Frame, Manifest, Mapping, MissingSignal, Mode, Origin,
    Recording, Sample, Signal, Stream, StreamCoverage, Target, Thread, ThreadName, Unwinding,
};

pub(super) struct Input<'a> {
    pub perf_data: &'a Path,
    pub command: &'a [String],
    pub exit: Option<Exit>,
    pub perf_version: String,
    pub requested_frequency_hz: u64,
    pub max_stack_depth: u32,
}

const KNOWN_BIASES: [&str; 2] = [
    "cpu-clock samples come from a timer interrupt, so code that runs with interrupts \
     disabled is under-sampled and samples can land a few instructions late.",
    "Frame-pointer unwinding cuts stacks short in code built without frame pointers, \
     and misses the caller of a leaf function that has no frame setup.",
];

pub(super) fn convert(input: Input) -> Result<Recording> {
    let file = File::open(input.perf_data).map_err(io_error("opening", input.perf_data))?;
    let PerfFileReader {
        mut perf_file,
        mut record_iter,
    } = PerfFileReader::parse_file(BufReader::new(file)).map_err(Error::PerfData)?;

    let [attributes] = perf_file.event_attributes() else {
        return Err(unexpected(format!(
            "expected one perf event, found {}",
            perf_file.event_attributes().len()
        )));
    };
    let attr = attributes.attributes();
    if !matches!(
        attr.type_,
        PerfEventType::Software(SoftwareCounterType::CpuClock)
    ) {
        return Err(unexpected(format!(
            "expected a cpu-clock event, found {:?}",
            attr.type_
        )));
    }
    if !matches!(attr.clock, PerfClock::ClockId(ClockId::Monotonic)) {
        return Err(unexpected(format!(
            "expected CLOCK_MONOTONIC timestamps, found {:?}",
            attr.clock
        )));
    }
    let SamplingPolicy::Frequency(frequency_hz) = attr.sampling_policy else {
        return Err(unexpected(format!(
            "expected sampling by frequency, found {:?}",
            attr.sampling_policy
        )));
    };
    let kernel_excluded = attr.flags.contains(AttrFlags::EXCLUDE_KERNEL);

    let mut state = State::new(input.max_stack_depth);
    while let Some(record) = record_iter
        .next_record(&mut perf_file)
        .map_err(Error::PerfData)?
    {
        let PerfFileRecord::EventRecord { record, .. } = record else {
            continue;
        };
        // perf stamps the records it synthesizes at startup with 0.
        let time = record.timestamp().filter(|&t| t != 0);
        if let Some(time) = time {
            state.start_ns = Some(state.start_ns.map_or(time, |t| t.min(time)));
            state.end_ns = Some(state.end_ns.map_or(time, |t| t.max(time)));
        }
        let parsed = record
            .parse()
            .map_err(io_error("parsing a record in", input.perf_data))?;
        match parsed {
            EventRecord::Sample(sample) => state.sample(&sample)?,
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
            EventRecord::Exit(e) => state.thread(id(e.pid)?, id(e.tid)?).end_ns = time,
            EventRecord::Lost(l) => state.lost_events += l.count,
            EventRecord::Throttle(_) => state.throttle_events += 1,
            _ => {}
        }
    }

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

    let stream = Stream {
        id: "perf".into(),
        collector: Collector::Perf {
            version: input.perf_version,
            event: "cpu-clock".into(),
            frequency_hz,
            requested_frequency_hz: input.requested_frequency_hz,
            unwinding: Unwinding::FramePointers,
        },
        signals,
        missing_signals,
        coverage: StreamCoverage {
            samples: state.samples.len() as u64,
            lost_events: state.lost_events,
            throttle_events: state.throttle_events,
            max_stack_depth: input.max_stack_depth,
            samples_at_stack_limit: state.samples_at_stack_limit,
            overhead_ns: None,
            known_biases: KNOWN_BIASES.iter().map(|b| b.to_string()).collect(),
        },
    };

    Ok(Recording {
        manifest: Manifest {
            format_version: FORMAT_VERSION,
            target: Target {
                command: input.command.to_vec(),
                launched: true,
                exit: input.exit,
            },
            clock: Clock::Monotonic,
            start_ns: state.start_ns,
            end_ns: state.end_ns,
            streams: vec![stream],
        },
        threads: state.take_threads(),
        thread_names: state.thread_names,
        mappings: state.mappings,
        frames: state.frames,
        stacks: state.stacks,
        samples: state.samples,
    })
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
    kernel_mappings: Vec<u32>,
    frames: Vec<Frame>,
    frame_ids: HashMap<Frame, u32>,
    stacks: Vec<Vec<u32>>,
    stack_ids: HashMap<Vec<u32>, u32>,
    samples: Vec<Sample>,
    lost_events: u64,
    throttle_events: u64,
    samples_at_stack_limit: u64,
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
            kernel_mappings: Vec::new(),
            frames: Vec::new(),
            frame_ids: HashMap::new(),
            stacks: Vec::new(),
            stack_ids: HashMap::new(),
            samples: Vec::new(),
            lost_events: 0,
            throttle_events: 0,
            samples_at_stack_limit: 0,
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
        let mapping_id = self.mappings.len() as u32;
        self.mappings.push(Mapping {
            pid,
            start: m.start,
            end: m.start.saturating_add(m.len),
            file_offset: m.file_offset,
            path: m.path,
            build_id: m.build_id,
            time_ns: m.time,
        });
        match pid {
            None => self.kernel_mappings.push(mapping_id),
            Some(pid) => self.processes.entry(pid).or_default().push(mapping_id),
        }
        Ok(())
    }

    fn sample(&mut self, sample: &SampleRecord) -> Result<()> {
        let (Some(pid), Some(tid), Some(time_ns), Some(period)) =
            (sample.pid, sample.tid, sample.timestamp, sample.period)
        else {
            return Err(unexpected("sample without pid, tid, time or period".into()));
        };
        let (pid, tid) = (id(pid)?, id(tid)?);
        self.thread(pid, tid);

        let mut stack = Vec::new();
        match &sample.callchain {
            Some(callchain) if !callchain.is_empty() => {
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
            _ => {
                if let Some(ip) = sample.ip {
                    let context = match sample.cpu_mode {
                        CpuMode::Kernel => ChainContext::Kernel,
                        CpuMode::User => ChainContext::User,
                        _ => ChainContext::Other,
                    };
                    stack.push(self.frame(pid, context, ip, false));
                }
            }
        }
        if stack.is_empty() {
            return Err(unexpected(format!("sample at {time_ns} has no address")));
        }
        if stack.len() >= self.max_stack_depth as usize {
            self.samples_at_stack_limit += 1;
        }

        let stack = intern(&mut self.stacks, &mut self.stack_ids, stack);
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
                        mapping,
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

    fn find_mapping(&self, ids: &[u32], address: u64) -> Option<u32> {
        ids.iter().rev().copied().find(|&id| {
            let m = &self.mappings[id as usize];
            m.start <= address && address < m.end
        })
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
    fn keeps_kernel_mappings_without_protection_bits() {
        let mut state = State::new(127);
        state
            .mmap(mmap(-1, 0xffff_0000, "[kernel.kallsyms]_text", true, false))
            .unwrap();
        state.mmap(mmap(7, 0x1000, "/data", false, false)).unwrap();
        assert_eq!(state.mappings.len(), 1);
        let frame = state.frame(7, ChainContext::Kernel, 0xffff_0010, false);
        assert_eq!(state.frames[frame as usize].mapping, Some(0));
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
}
