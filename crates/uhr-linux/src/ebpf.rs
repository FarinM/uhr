//! uhr's own eBPF programs, which sample the target's stacks and count and
//! time its syscalls.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as _;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use aya::maps::{Array, HashMap, MapData, PerCpuArray, ProgramArray, RingBuf};
use aya::programs::perf_event::{
    PerfEventConfig, PerfEventLinkId, PerfEventScope, SamplePolicy, SoftwareEvent,
};
use aya::programs::raw_trace_point::RawTracePointLinkId;
use aya::programs::trace_point::TracePointLinkId;
use aya::programs::{PerfEvent, RawTracePoint, TracePoint};
use aya::util::{nr_cpus, online_cpus};
use aya::{Ebpf, EbpfLoader};
use syscalls::Sysno;
use tracing::warn;
use uhr_core::recording::SyscallCalls;
use uhr_ebpf::{ACTIVE, CallKey, Calls, HELD, SampleHeader, Start, UserRegisters};

use crate::btf;
use crate::interpreters::{Finder, Interpreters, Maps, Walked};
use crate::launch::monotonic_ns;

/// Why the eBPF collector could not run.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "this uhr was built without its eBPF programs, which need nightly Rust with rust-src \
         and bpf-linker to build"
    )]
    NotBuilt,
    #[error("loading eBPF needs root, or CAP_BPF and CAP_PERFMON")]
    NotPermitted,
    #[error("loading uhr's eBPF programs")]
    Load(#[source] aya::EbpfError),
    #[error("the eBPF program {0}")]
    Program(&'static str, #[source] aya::programs::ProgramError),
    #[error("the eBPF map {0}")]
    Map(&'static str, #[source] aya::maps::MapError),
    #[error("uhr's eBPF programs have no {0}")]
    Missing(&'static str),
    #[error(
        "uhr runs in a PID namespace of its own, as in a container, and its eBPF programs know \
         processes by their ids outside it"
    )]
    PidNamespace,
    #[error("reading uhr's PID namespace")]
    Namespace(#[source] io::Error),
    #[error("listing the online CPUs: {0}")]
    Cpus(#[source] io::Error),
    #[error("writing the samples to {}", .path.display())]
    Samples {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

impl Error {
    /// The error and what caused it, in one line.
    pub fn reason(&self) -> String {
        let mut reason = self.to_string();
        let mut source = self.source();
        while let Some(error) = source {
            reason.push_str(": ");
            reason.push_str(&error.to_string());
            source = error.source();
        }
        reason
    }

    /// The kernel refuses with EPERM wherever it is first asked, which is
    /// deep in aya's errors.
    fn or_not_permitted(self) -> Self {
        let mut source = self.source();
        while let Some(error) = source {
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|e| e.raw_os_error() == Some(rustix::io::Errno::PERM.raw_os_error()))
            {
                return Error::NotPermitted;
            }
            source = error.source();
        }
        self
    }
}

#[cfg(uhr_ebpf)]
static PROGRAMS: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/uhr-ebpf"));

/// The programs that follow the processes the target starts, and the
/// tracepoints they run at.
const FOLLOWERS: [(&str, &str, &str); 2] = [
    ("task_newtask", "task", "task_newtask"),
    ("sched_process_exec", "sched", "sched_process_exec"),
];

/// The programs that let go of a process: when its last thread exits, or,
/// where the kernel's BTF does not say how to see that, once it is freed,
/// by when a new process can have taken its id.
const LET_GO: (&str, &str, &str) = ("sched_process_exit", "sched", "sched_process_exit");
const LET_GO_LATE: (&str, &str, &str) = ("sched_process_free", "sched", "sched_process_free");

/// The programs that count syscalls, at the raw tracepoints of their names.
const SYSCALLS: [&str; 2] = ["sys_enter", "sys_exit"];

const SAMPLER: &str = "sample";

/// The programs the sampler goes on in to walk interpreter frames, by
/// their place in `PROGRAMS`: to find a thread's state in the runtime, to
/// walk frames on the native stack, and to walk them in the runtime's
/// memory from the state.
const WALKERS: [&str; 3] = ["walk_frames", "walk_native", "walk_memory"];

/// The program that sees CPUs go offline and online, and the tracepoint it
/// runs at.
const HOTPLUG: (&str, &str, &str) = ("cpuhp_enter", "cpuhp", "cpuhp_enter");

/// The programs that count the times each process maps a file's code, and
/// the tracepoints they run at.
const MAPPINGS: [(&str, &str, &str); 2] = [
    ("sys_enter_mmap", "syscalls", "sys_enter_mmap"),
    ("sys_exit_mmap", "syscalls", "sys_exit_mmap"),
];

/// Whether the programs can sample here: the sampler reads the registers
/// of these architectures only.
pub(crate) const CAN_SAMPLE: bool = cfg!(any(target_arch = "x86_64", target_arch = "aarch64"));

/// Room for samples while uhr is between reads, a few milliseconds apart.
const SAMPLE_BUFFER: u32 = 16 << 20;

/// Room for each CPU's samples with stack copies, for a few times as long.
const COPY_BUFFER_PER_CPU: u32 = 2 << 20;

/// The most kernel memory, which it can't swap out, that samples with
/// stack copies take.
const MAX_COPY_BUFFER: u32 = 1 << 30;

/// How often the samples are copied out of the ring buffer.
const READ_EVERY: Duration = Duration::from_millis(20);

pub(crate) struct Options {
    pub(crate) syscalls: bool,
    pub(crate) sampling: Option<Sampling>,
}

/// Sampling at every tick of each CPU's clock, `period_ns` apart, into
/// `path`, stacks of up to `max_stack` frames.
pub(crate) struct Sampling {
    pub(crate) period_ns: u64,
    pub(crate) path: PathBuf,
    pub(crate) max_stack: u32,
    /// The bytes of user stack to copy with each sample, for uhr to unwind.
    /// `None` to walk user stacks with frame pointers.
    pub(crate) stack_bytes: Option<u32>,
}

/// What the syscall programs counted.
pub(crate) struct Counted {
    pub(crate) calls: Vec<SyscallCalls>,
    /// Calls that found the programs' table of calls full.
    pub(crate) lost: u64,
}

pub(crate) struct Samples {
    /// Samples that found the ring buffer full.
    pub(crate) dropped: u64,
    pub(crate) interpreters: Interpreters,
}

/// What the programs found. Each part is `None` if it was not asked for.
pub(crate) struct Found {
    pub(crate) syscalls: Option<Counted>,
    pub(crate) samples: Option<Samples>,
    /// Processes the target started that found the programs' table of
    /// processes full, which they then did not follow.
    pub(crate) unfollowed: u64,
    /// Whether the programs let go of a process only once it was freed.
    pub(crate) let_go_late: bool,
    /// CPUs that came online during the capture, and those that could not
    /// be sampled by its end.
    pub(crate) late_cpus: u32,
    pub(crate) unsampled_cpus: u32,
    /// CPUs that went offline and back during the capture, as across a
    /// suspend, whose sampling uhr restarted, and at most how long they
    /// went unsampled until then, in all.
    pub(crate) restarted_cpus: u32,
    pub(crate) unsampled_ns: u64,
    /// Whether samples tell a thread running a virtual machine's guest
    /// apart.
    pub(crate) tells_guests: bool,
    /// The tags of the programs that ran, in hex.
    pub(crate) programs: Vec<String>,
}

/// The programs count and sample only between `begin` and `end`, so that
/// they can start before the capture and fail before it too.
pub(crate) struct Programs {
    ebpf: Ebpf,
    tracepoints: Vec<(&'static str, TracePointLinkId)>,
    syscalls: Option<Vec<(&'static str, RawTracePointLinkId)>>,
    /// By CPU, with when each was attached.
    sampler: BTreeMap<u32, (PerfEventLinkId, u64)>,
    period_ns: u64,
    late_cpus: u32,
    unsampled_cpus: BTreeSet<u32>,
    restarted_cpus: BTreeSet<u32>,
    unsampled_ns: u64,
    /// Every CPU sampled yet, and since when each that went offline since
    /// was not.
    sampled_cpus: BTreeSet<u32>,
    down_since: BTreeMap<u32, u64>,
    tells_guests: bool,
    let_go_late: bool,
    reader: Option<Reader>,
    finder: Option<Finder>,
    /// The kernel empties a program array once uhr no longer has it open.
    next: Option<ProgramArray<MapData>>,
    ended: Option<Result<u64, Error>>,
}

/// What the programs found, and the programs: detached, but loaded until
/// unloaded, so that the kernel's symbols still name them.
pub(crate) struct Stopped {
    found: Found,
    programs: Ebpf,
}

impl Stopped {
    pub(crate) fn unload(self) -> Found {
        drop(self.programs);
        self.found
    }
}

impl Programs {
    /// Loads the programs `options` asks for, for `pid` and the processes it
    /// starts, which they count and sample from `begin` on, or for a target
    /// `held` before its exec, from the exec.
    pub(crate) fn start(pid: u32, held: bool, options: &Options) -> Result<Self, Error> {
        let layout = Layout::read();
        let mut ebpf = load(options.sampling.as_ref(), layout)?;
        let targets = ebpf.map_mut("TARGETS").ok_or(Error::Missing("TARGETS"))?;
        let mut targets: HashMap<_, u32, u8> =
            HashMap::try_from(targets).map_err(|e| Error::Map("TARGETS", e))?;
        let state = if held { HELD } else { ACTIVE };
        targets
            .insert(pid, state, 0)
            .map_err(|e| Error::Map("TARGETS", e).or_not_permitted())?;
        let mut tracepoints = Vec::new();
        let let_go = if layout.exits.is_some() {
            LET_GO
        } else {
            LET_GO_LATE
        };
        for (program, category, name) in FOLLOWERS.into_iter().chain([let_go]) {
            let tracepoint = tracepoint(&mut ebpf, program)?;
            let link = tracepoint
                .load()
                .and_then(|()| tracepoint.attach(category, name))
                .map_err(|e| Error::Program(program, e).or_not_permitted())?;
            tracepoints.push((program, link));
        }
        let mut syscalls = None;
        if options.syscalls {
            let links = syscalls.insert(Vec::new());
            for program in SYSCALLS {
                let tracepoint = raw_tracepoint(&mut ebpf, program)?;
                let link = tracepoint
                    .load()
                    .and_then(|()| tracepoint.attach(program))
                    .map_err(|e| Error::Program(program, e).or_not_permitted())?;
                links.push((program, link));
            }
        }
        let mut programs = Self {
            ebpf,
            tracepoints,
            syscalls,
            sampler: BTreeMap::new(),
            period_ns: 0,
            late_cpus: 0,
            unsampled_cpus: BTreeSet::new(),
            restarted_cpus: BTreeSet::new(),
            unsampled_ns: 0,
            sampled_cpus: BTreeSet::new(),
            down_since: BTreeMap::new(),
            tells_guests: layout.task_flags.is_some(),
            let_go_late: layout.exits.is_none(),
            reader: None,
            finder: None,
            next: None,
            ended: None,
        };
        if let Some(sampling) = &options.sampling {
            programs.sample(sampling)?;
        }
        Ok(programs)
    }

    fn sample(&mut self, sampling: &Sampling) -> Result<(), Error> {
        let ring = self
            .ebpf
            .take_map("SAMPLES")
            .ok_or(Error::Missing("SAMPLES"))?;
        let ring = RingBuf::try_from(ring).map_err(|e| Error::Map("SAMPLES", e))?;
        sampler_program(&mut self.ebpf)?
            .load()
            .map_err(|e| Error::Program(SAMPLER, e).or_not_permitted())?;
        let next = self
            .ebpf
            .take_map("PROGRAMS")
            .ok_or(Error::Missing("PROGRAMS"))?;
        let mut next = ProgramArray::try_from(next).map_err(|e| Error::Map("PROGRAMS", e))?;
        for (index, name) in WALKERS.into_iter().enumerate() {
            let walker = perf_event(&mut self.ebpf, name)?;
            walker
                .load()
                .map_err(|e| Error::Program(name, e).or_not_permitted())?;
            let walker = walker.fd().map_err(|e| Error::Program(name, e))?;
            next.set(index as u32, walker, 0)
                .map_err(|e| Error::Map("PROGRAMS", e))?;
        }
        self.next = Some(next);
        self.period_ns = sampling.period_ns;
        // Before the CPUs' events, so no step of a CPU's goes unseen.
        let (program, category, name) = HOTPLUG;
        let hotplug = tracepoint(&mut self.ebpf, program)?;
        let link = hotplug
            .load()
            .and_then(|()| hotplug.attach(category, name))
            .map_err(|e| Error::Program(program, e).or_not_permitted())?;
        self.tracepoints.push((program, link));
        for (program, category, name) in MAPPINGS {
            let tracepoint = tracepoint(&mut self.ebpf, program)?;
            tracepoint
                .load()
                .map_err(|e| Error::Program(program, e).or_not_permitted())?;
            // A kernel can be built without the tracepoints of syscalls.
            match tracepoint.attach(category, name) {
                Ok(link) => self.tracepoints.push((program, link)),
                Err(error) => warn!(
                    program,
                    %error,
                    "a runtime loaded after the exec gets its frames read only a while later"
                ),
            }
        }
        for cpu in online_cpus().map_err(|(_, e)| Error::Cpus(e))? {
            // Before the event opens, so a CPU that goes offline and back in
            // between is seen to.
            let attached = monotonic_ns();
            let link = self.attach(cpu)?;
            self.sampler.insert(cpu, (link, attached));
            self.sampled_cpus.insert(cpu);
        }
        let walks = self.ebpf.take_map("WALKS").ok_or(Error::Missing("WALKS"))?;
        let threads = self
            .ebpf
            .take_map("THREADS")
            .ok_or(Error::Missing("THREADS"))?;
        let maps = Maps {
            walks: aya::maps::HashMap::try_from(walks).map_err(|e| Error::Map("WALKS", e))?,
            threads: aya::maps::HashMap::try_from(threads).map_err(|e| Error::Map("THREADS", e))?,
        };
        let finder = Finder::start(maps, sampling.stack_bytes.is_none());
        self.reader = Some(Reader::start(ring, &sampling.path, finder.sender())?);
        self.finder = Some(finder);
        Ok(())
    }

    fn attach(&mut self, cpu: u32) -> Result<PerfEventLinkId, Error> {
        sampler_program(&mut self.ebpf)?
            .attach(
                PerfEventConfig::Software(SoftwareEvent::CpuClock),
                PerfEventScope::AllProcessesOneCpu { cpu },
                SamplePolicy::Period(self.period_ns),
                false,
            )
            .map_err(|e| Error::Program(SAMPLER, e).or_not_permitted())
    }

    /// Keeps every online CPU sampled while the capture runs. The kernel
    /// samples none at an event opened while its CPU was offline, and drops
    /// that of a CPU going offline, which can go and come back between two
    /// of uhr's looks, as across a suspend.
    pub(crate) fn follow_cpus(&mut self) {
        if self.reader.is_none() || self.ended.is_some() {
            return;
        }
        let Ok(online) = online_cpus() else {
            return;
        };
        let (down, up) = (self.steps("WENT_DOWN"), self.steps("CAME_UP"));
        let now = monotonic_ns();
        let attached: Vec<(u32, u64)> = self
            .sampler
            .iter()
            .map(|(&cpu, &(_, attached))| (cpu, attached))
            .collect();
        for (cpu, attached) in attached {
            let went = down.get(&cpu).copied().filter(|&ns| ns > attached);
            if went.is_some() || !online.contains(&cpu) {
                self.detach(cpu);
                self.down_since.entry(cpu).or_insert(went.unwrap_or(now));
            }
        }
        for cpu in online {
            // Not before it is back up from its last step down.
            if self.sampler.contains_key(&cpu) || down.get(&cpu) > up.get(&cpu) {
                continue;
            }
            // A CPU can show online before perf can sample on it, so one
            // that fails is tried again.
            let Ok(link) = self.attach(cpu) else {
                self.unsampled_cpus.insert(cpu);
                continue;
            };
            self.sampler.insert(cpu, (link, now));
            self.unsampled_cpus.remove(&cpu);
            if let Some(went) = self.down_since.remove(&cpu) {
                self.restarted_cpus.insert(cpu);
                self.unsampled_ns += now.saturating_sub(went);
            } else if self.sampled_cpus.insert(cpu) {
                self.late_cpus += 1;
            }
        }
    }

    fn detach(&mut self, cpu: u32) {
        if let (Some((link, _)), Ok(sampler)) =
            (self.sampler.remove(&cpu), sampler_program(&mut self.ebpf))
        {
            let _ = sampler.detach(link);
        }
    }

    /// When each CPU last took a step one way, by `name`'s map.
    fn steps(&self, name: &str) -> BTreeMap<u32, u64> {
        let map = self.ebpf.map(name);
        let steps = map.and_then(|map| HashMap::<_, u32, u64>::try_from(map).ok());
        steps.map_or_else(BTreeMap::new, |steps| steps.iter().flatten().collect())
    }

    pub(crate) fn samples(&self) -> bool {
        self.reader.is_some()
    }

    /// Starts the capture.
    pub(crate) fn begin(&mut self) -> Result<(), Error> {
        self.run(1)
    }

    /// Ends the capture, at once.
    pub(crate) fn end(&mut self) {
        if self.ended.is_none() {
            let now = monotonic_ns();
            self.ended = Some(self.run(0).map(|()| now));
        }
    }

    fn run(&mut self, running: u32) -> Result<(), Error> {
        let map = self
            .ebpf
            .map_mut("RUNNING")
            .ok_or(Error::Missing("RUNNING"))?;
        let mut map: Array<_, u32> = Array::try_from(map).map_err(|e| Error::Map("RUNNING", e))?;
        map.set(0, running, 0).map_err(|e| Error::Map("RUNNING", e))
    }

    /// Stops the programs, and reads what they found.
    pub(crate) fn stop(mut self) -> Result<Stopped, Error> {
        let now = match self.ended.take() {
            Some(ended) => ended?,
            None => {
                let now = monotonic_ns();
                self.run(0)?;
                now
            }
        };
        let Self {
            mut ebpf,
            tracepoints,
            syscalls,
            sampler,
            late_cpus,
            unsampled_cpus,
            restarted_cpus,
            unsampled_ns,
            tells_guests,
            let_go_late,
            reader,
            finder,
            ..
        } = self;
        let mut programs = Vec::new();
        if reader.is_some() {
            let program = sampler_program(&mut ebpf)?;
            for (link, _) in sampler.into_values() {
                program
                    .detach(link)
                    .map_err(|e| Error::Program(SAMPLER, e))?;
            }
            let info = program.info().map_err(|e| Error::Program(SAMPLER, e))?;
            programs.push(format!("{:016x}", info.tag()));
            for name in WALKERS {
                let walker = perf_event(&mut ebpf, name)?;
                let info = walker.info().map_err(|e| Error::Program(name, e))?;
                programs.push(format!("{:016x}", info.tag()));
            }
        }
        for (program, link) in tracepoints {
            let tracepoint = tracepoint(&mut ebpf, program)?;
            tracepoint
                .detach(link)
                .map_err(|e| Error::Program(program, e))?;
            let info = tracepoint.info().map_err(|e| Error::Program(program, e))?;
            programs.push(format!("{:016x}", info.tag()));
        }
        let counting = syscalls.is_some();
        for (program, link) in syscalls.into_iter().flatten() {
            let tracepoint = raw_tracepoint(&mut ebpf, program)?;
            // So the maps stay as they are while read.
            tracepoint
                .detach(link)
                .map_err(|e| Error::Program(program, e))?;
            let info = tracepoint.info().map_err(|e| Error::Program(program, e))?;
            programs.push(format!("{:016x}", info.tag()));
        }
        let samples = match (reader, finder) {
            (Some(reader), Some(finder)) => {
                reader.finish()?;
                Some(Samples {
                    dropped: sum(&mut ebpf, "DROPPED")?,
                    interpreters: finder.finish(),
                })
            }
            _ => None,
        };
        let syscalls = if counting {
            Some(counted(&mut ebpf, now)?)
        } else {
            None
        };
        Ok(Stopped {
            found: Found {
                syscalls,
                samples,
                unfollowed: sum(&mut ebpf, "UNFOLLOWED")?,
                late_cpus,
                unsampled_cpus: unsampled_cpus.len() as u32,
                restarted_cpus: restarted_cpus.len() as u32,
                unsampled_ns,
                tells_guests,
                let_go_late,
                programs,
            },
            programs: ebpf,
        })
    }
}

fn counted(ebpf: &mut Ebpf, now: u64) -> Result<Counted, Error> {
    let mut take = |name| ebpf.take_map(name).ok_or(Error::Missing(name));
    let (calls, starts) = (take("CALLS")?, take("STARTS")?);
    let calls: HashMap<MapData, CallKey, Calls> =
        HashMap::try_from(calls).map_err(|e| Error::Map("CALLS", e))?;
    let mut rows = BTreeMap::new();
    for entry in calls.iter() {
        let (key, calls) = entry.map_err(|e| Error::Map("CALLS", e))?;
        rows.insert(
            (key.tgid, key.tid, key.nr),
            row(
                key.tgid,
                key.tid,
                key.nr,
                calls.calls,
                calls.ns,
                &calls.buckets,
            ),
        );
    }
    let starts: HashMap<MapData, u32, Start> =
        HashMap::try_from(starts).map_err(|e| Error::Map("STARTS", e))?;
    for entry in starts.iter() {
        let (tid, start) = entry.map_err(|e| Error::Map("STARTS", e))?;
        // A thread that exited in a syscall, or in exit, leaves it there.
        let ends = [Sysno::exit, Sysno::exit_group].map(|s| s as u32);
        let alive = Path::new(&format!("/proc/{}/task/{tid}", start.tgid)).exists();
        if !alive || ends.contains(&start.nr) {
            continue;
        }
        rows.entry((start.tgid, tid, start.nr))
            .or_insert_with(|| row(start.tgid, tid, start.nr, 0, 0, &[0; uhr_ebpf::BUCKETS]))
            .unfinished_ns = Some(now.saturating_sub(start.ns));
    }
    Ok(Counted {
        calls: rows.into_values().collect(),
        lost: sum(ebpf, "LOST")?,
    })
}

/// The total of a per-CPU counter.
fn sum(ebpf: &mut Ebpf, name: &'static str) -> Result<u64, Error> {
    let map = ebpf.take_map(name).ok_or(Error::Missing(name))?;
    let counter: PerCpuArray<MapData, u64> =
        PerCpuArray::try_from(map).map_err(|e| Error::Map(name, e))?;
    let values = counter.get(&0, 0).map_err(|e| Error::Map(name, e))?;
    Ok(values.iter().sum())
}

/// Copies samples from the ring buffer to a file while recording, each
/// after its length as a 32-bit number.
struct Reader {
    stop: Arc<AtomicBool>,
    /// `None` once joined.
    thread: Option<JoinHandle<io::Result<()>>>,
    path: PathBuf,
}

impl Reader {
    fn start(ring: RingBuf<MapData>, path: &Path, walked: Sender<Walked>) -> Result<Self, Error> {
        let error = |source| Error::Samples {
            path: path.to_owned(),
            source,
        };
        let file = create_private(path).map_err(error)?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let stop = stop.clone();
            thread::spawn(move || copy(ring, BufWriter::new(file), &stop, &walked))
        };
        Ok(Self {
            stop,
            thread: Some(thread),
            path: path.to_owned(),
        })
    }

    /// Copies what is left.
    fn finish(mut self) -> Result<(), Error> {
        self.stop.store(true, Ordering::Release);
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        let copied = thread
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        copied.map_err(|source| Error::Samples {
            path: self.path.clone(),
            source,
        })
    }
}

/// Left running, the thread would copy until uhr exits.
impl Drop for Reader {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

/// Only its owner may read it, as perf's data: samples give away where the
/// kernel and the target keep their code, and copies of the target's
/// stack.
fn create_private(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600).open(path)
}

fn copy(
    mut ring: RingBuf<MapData>,
    mut out: BufWriter<File>,
    stop: &AtomicBool,
    walked: &Sender<Walked>,
) -> io::Result<()> {
    loop {
        // Before the last read, so that it gets every sample from before.
        let stopping = stop.load(Ordering::Acquire);
        while let Some(sample) = ring.next() {
            out.write_all(&(sample.len() as u32).to_le_bytes())?;
            out.write_all(&sample)?;
            if let Some(found) = walked_frames(&sample) {
                // Gone only once uhr stops sampling.
                let _ = walked.send(found);
            }
        }
        if stopping {
            return out.flush();
        }
        thread::sleep(READ_EVERY);
    }
}

/// What a sample says of its interpreter frames, which follow all else.
fn walked_frames(sample: &[u8]) -> Option<Walked> {
    // SAFETY: plain numbers, any bits of which are valid.
    let header: SampleHeader = unsafe {
        std::ptr::read_unaligned(sample.get(..size_of::<SampleHeader>())?.as_ptr().cast())
    };
    let user_words = header.user_frames as usize * (1 + header.frame_ends as usize);
    let frames = (header.kernel_frames as usize + user_words) * 8;
    let copy = match header.copy {
        0 => 0,
        _ => size_of::<UserRegisters>() + header.stack_bytes as usize,
    };
    let start = size_of::<SampleHeader>() + frames + copy;
    let len = header.walked_frames as usize * header.walked_bytes as usize;
    Some(Walked {
        pid: header.tgid,
        exec: header.exec,
        mapped: header.mapped,
        time_ns: header.time_ns,
        status: header.walk,
        frame_bytes: header.walked_bytes,
        frames: sample.get(start..start + len)?.to_vec(),
    })
}

/// Loads every program without running them, as recording would.
pub fn check() -> Result<(), Error> {
    let mut ebpf = load(None, Layout::default())?;
    for (program, ..) in FOLLOWERS.into_iter().chain([LET_GO, LET_GO_LATE]) {
        tracepoint(&mut ebpf, program)?
            .load()
            .map_err(|e| Error::Program(program, e).or_not_permitted())?;
    }
    for program in SYSCALLS {
        raw_tracepoint(&mut ebpf, program)?
            .load()
            .map_err(|e| Error::Program(program, e).or_not_permitted())?;
    }
    if !CAN_SAMPLE {
        return Ok(());
    }
    for (program, ..) in [HOTPLUG].into_iter().chain(MAPPINGS) {
        tracepoint(&mut ebpf, program)?
            .load()
            .map_err(|e| Error::Program(program, e).or_not_permitted())?;
    }
    for program in [SAMPLER].into_iter().chain(WALKERS) {
        perf_event(&mut ebpf, program)?
            .load()
            .map_err(|e| Error::Program(program, e).or_not_permitted())?;
    }
    Ok(())
}

fn tracepoint<'a>(ebpf: &'a mut Ebpf, program: &'static str) -> Result<&'a mut TracePoint, Error> {
    ebpf.program_mut(program)
        .ok_or(Error::Missing(program))?
        .try_into()
        .map_err(|e| Error::Program(program, e))
}

fn raw_tracepoint<'a>(
    ebpf: &'a mut Ebpf,
    program: &'static str,
) -> Result<&'a mut RawTracePoint, Error> {
    ebpf.program_mut(program)
        .ok_or(Error::Missing(program))?
        .try_into()
        .map_err(|e| Error::Program(program, e))
}

fn sampler_program(ebpf: &mut Ebpf) -> Result<&mut PerfEvent, Error> {
    perf_event(ebpf, SAMPLER)
}

fn perf_event<'a>(ebpf: &'a mut Ebpf, program: &'static str) -> Result<&'a mut PerfEvent, Error> {
    ebpf.program_mut(program)
        .ok_or(Error::Missing(program))?
        .try_into()
        .map_err(|e| Error::Program(program, e))
}

/// Where the kernel keeps what the programs read of its tasks, from its BTF.
#[derive(Clone, Copy, Default)]
struct Layout {
    /// `task_struct.flags`, which say whether a thread runs a guest.
    task_flags: Option<u32>,
    /// `task_struct.signal`, and `signal_struct.live`, how many threads a
    /// process has live.
    exits: Option<(u32, u32)>,
    /// `task_struct.self_exec_id`, how many times the process exec'd.
    exec_id: Option<u32>,
    /// Where a `task_struct` keeps the user thread pointer, which
    /// thread-locals are found from.
    thread_pointer: Option<u32>,
}

impl Layout {
    fn read() -> Self {
        let [task_flags, signal, live, exec_id, thread_pointer] = btf::kernel_member_offsets([
            ("task_struct", "flags"),
            ("task_struct", "signal"),
            ("signal_struct", "live"),
            ("task_struct", "self_exec_id"),
            ("task_struct", btf::THREAD_POINTER),
        ]);
        Self {
            task_flags,
            exits: signal.zip(live),
            exec_id,
            thread_pointer,
        }
    }
}

/// The ring buffer's size for samples with stack copies from `cpus` CPUs,
/// a power of two as the kernel wants.
fn copy_buffer(cpus: usize) -> u32 {
    let size = (cpus as u64).saturating_mul(COPY_BUFFER_PER_CPU.into());
    let size = size.clamp(SAMPLE_BUFFER.into(), MAX_COPY_BUFFER.into());
    size.next_power_of_two() as u32
}

fn load(sampling: Option<&Sampling>, layout: Layout) -> Result<Ebpf, Error> {
    let stack_bytes = sampling.and_then(|s| s.stack_bytes);
    // A copy of the stack for each CPU, which the kernel wants room for in
    // every one it may bring online.
    let copies = match stack_bytes {
        Some(_) => nr_cpus().map_err(|(_, e)| Error::Cpus(e))? as u32,
        None => 1,
    };
    let size = match (sampling, stack_bytes) {
        // By the CPUs online: the kernel may say it could bring up many
        // more, and one it brings up later shares the room.
        (Some(_), Some(_)) => copy_buffer(online_cpus().map_err(|(_, e)| Error::Cpus(e))?.len()),
        (Some(_), None) => SAMPLE_BUFFER,
        // Without sampling, the smallest size the kernel allows, a page.
        (None, _) => rustix::param::page_size() as u32,
    };
    let max_stack = sampling.map_or(uhr_ebpf::MAX_FRAMES as u32, |s| s.max_stack);
    let stack_bytes = stack_bytes.unwrap_or(0);
    let task_flags = layout.task_flags.unwrap_or(u32::MAX);
    let exec_id = layout.exec_id.unwrap_or(u32::MAX);
    let thread_pointer = layout.thread_pointer.unwrap_or(u32::MAX);
    let (signal, live) = layout.exits.unwrap_or((u32::MAX, u32::MAX));
    #[cfg(uhr_ebpf)]
    {
        check_namespace()?;
        EbpfLoader::new()
            .map_max_entries("SAMPLES", size)
            .map_max_entries("COPIES", copies)
            .override_global("MAX_STACK", &max_stack, CAN_SAMPLE)
            .override_global("STACK_BYTES", &stack_bytes, CAN_SAMPLE)
            .override_global("TASK_FLAGS", &task_flags, CAN_SAMPLE)
            .override_global("TASK_EXEC_ID", &exec_id, CAN_SAMPLE)
            .override_global("TASK_THREAD_POINTER", &thread_pointer, CAN_SAMPLE)
            .override_global("TASK_SIGNAL", &signal, true)
            .override_global("SIGNAL_LIVE", &live, true)
            .load(PROGRAMS)
            .map_err(|e| Error::Load(e).or_not_permitted())
    }
    #[cfg(not(uhr_ebpf))]
    {
        let _ = (
            size,
            max_stack,
            stack_bytes,
            task_flags,
            signal,
            live,
            thread_pointer,
        );
        let _ = EbpfLoader::new;
        Err(Error::NotBuilt)
    }
}

/// The inode of the kernel's first PID namespace, which is fixed.
const FIRST_PID_NAMESPACE: u64 = 0xEFFF_FFFC;

/// The programs see processes by their ids in the kernel's first PID
/// namespace, and uhr knows them by their ids in its own.
#[cfg_attr(not(uhr_ebpf), allow(dead_code))]
fn check_namespace() -> Result<(), Error> {
    let namespace =
        rustix::fs::stat("/proc/self/ns/pid").map_err(|e| Error::Namespace(e.into()))?;
    if namespace.st_ino != FIRST_PID_NAMESPACE {
        return Err(Error::PidNamespace);
    }
    Ok(())
}

fn row(pid: u32, tid: u32, number: u32, calls: u64, ns: u64, buckets: &[u64]) -> SyscallCalls {
    SyscallCalls {
        pid,
        tid,
        number,
        name: Sysno::new(number as usize).map(|s| s.name().to_owned()),
        calls,
        time_ns: ns,
        latency: buckets.to_vec(),
        unfinished_ns: None,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn sizes_the_buffer_for_stack_copies_within_bounds() {
        assert_eq!(copy_buffer(1), SAMPLE_BUFFER);
        assert_eq!(copy_buffer(12), 32 << 20);
        for cpus in [1025, 1536, 2048, usize::MAX] {
            assert_eq!(copy_buffer(cpus), MAX_COPY_BUFFER);
        }
    }

    #[test]
    fn creates_the_samples_file_for_its_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("samples");
        create_private(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
