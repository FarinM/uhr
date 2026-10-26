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
use std::thread::{self, JoinHandle};
use std::time::Duration;

use aya::maps::{Array, HashMap, MapData, PerCpuArray, RingBuf};
use aya::programs::perf_event::{
    PerfEventConfig, PerfEventLinkId, PerfEventScope, SamplePolicy, SoftwareEvent,
};
use aya::programs::raw_trace_point::RawTracePointLinkId;
use aya::programs::trace_point::TracePointLinkId;
use aya::programs::{PerfEvent, RawTracePoint, TracePoint};
use aya::util::online_cpus;
use aya::{Ebpf, EbpfLoader};
use syscalls::Sysno;
use uhr_core::recording::SyscallCalls;
use uhr_ebpf::{ACTIVE, CallKey, Calls, HELD, Start};

use crate::btf;
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

/// The program that sees CPUs go offline and online, and the tracepoint it
/// runs at.
const HOTPLUG: (&str, &str, &str) = ("cpuhp_enter", "cpuhp", "cpuhp_enter");

/// Whether the programs can sample here: the sampler reads the registers
/// of these architectures only.
pub(crate) const CAN_SAMPLE: bool = cfg!(any(target_arch = "x86_64", target_arch = "aarch64"));

/// Room for samples while uhr is between reads, a few milliseconds apart.
const SAMPLE_BUFFER: u32 = 16 << 20;

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
        self.period_ns = sampling.period_ns;
        // Before the CPUs' events, so no step of a CPU's goes unseen.
        let (program, category, name) = HOTPLUG;
        let hotplug = tracepoint(&mut self.ebpf, program)?;
        let link = hotplug
            .load()
            .and_then(|()| hotplug.attach(category, name))
            .map_err(|e| Error::Program(program, e).or_not_permitted())?;
        self.tracepoints.push((program, link));
        for cpu in online_cpus().map_err(|(_, e)| Error::Cpus(e))? {
            // Before the event opens, so a CPU that goes offline and back in
            // between is seen to.
            let attached = monotonic_ns();
            let link = self.attach(cpu)?;
            self.sampler.insert(cpu, (link, attached));
            self.sampled_cpus.insert(cpu);
        }
        self.reader = Some(Reader::start(ring, &sampling.path)?);
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
        let samples = match reader {
            Some(reader) => {
                reader.finish()?;
                Some(Samples {
                    dropped: sum(&mut ebpf, "DROPPED")?,
                })
            }
            None => None,
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
    fn start(ring: RingBuf<MapData>, path: &Path) -> Result<Self, Error> {
        let error = |source| Error::Samples {
            path: path.to_owned(),
            source,
        };
        let file = create_private(path).map_err(error)?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let stop = stop.clone();
            thread::spawn(move || copy(ring, BufWriter::new(file), &stop))
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
/// kernel and the target keep their code.
fn create_private(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600).open(path)
}

fn copy(mut ring: RingBuf<MapData>, mut out: BufWriter<File>, stop: &AtomicBool) -> io::Result<()> {
    loop {
        // Before the last read, so that it gets every sample from before.
        let stopping = stop.load(Ordering::Acquire);
        while let Some(sample) = ring.next() {
            out.write_all(&(sample.len() as u32).to_le_bytes())?;
            out.write_all(&sample)?;
        }
        if stopping {
            return out.flush();
        }
        thread::sleep(READ_EVERY);
    }
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
    tracepoint(&mut ebpf, HOTPLUG.0)?
        .load()
        .map_err(|e| Error::Program(HOTPLUG.0, e).or_not_permitted())?;
    sampler_program(&mut ebpf)?
        .load()
        .map_err(|e| Error::Program(SAMPLER, e).or_not_permitted())
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
    ebpf.program_mut(SAMPLER)
        .ok_or(Error::Missing(SAMPLER))?
        .try_into()
        .map_err(|e| Error::Program(SAMPLER, e))
}

/// Without sampling, the ring buffer gets the smallest size the kernel
/// allows, a page.
/// Where the kernel keeps what the programs read of its tasks, from its BTF.
#[derive(Clone, Copy, Default)]
struct Layout {
    /// `task_struct.flags`, which say whether a thread runs a guest.
    task_flags: Option<u32>,
    /// `task_struct.signal`, and `signal_struct.live`, how many threads a
    /// process has live.
    exits: Option<(u32, u32)>,
}

impl Layout {
    fn read() -> Self {
        let [task_flags, signal, live] = btf::kernel_member_offsets([
            ("task_struct", "flags"),
            ("task_struct", "signal"),
            ("signal_struct", "live"),
        ]);
        Self {
            task_flags,
            exits: signal.zip(live),
        }
    }
}

fn load(sampling: Option<&Sampling>, layout: Layout) -> Result<Ebpf, Error> {
    let size = match sampling {
        Some(_) => SAMPLE_BUFFER,
        None => rustix::param::page_size() as u32,
    };
    let max_stack = sampling.map_or(uhr_ebpf::MAX_FRAMES as u32, |s| s.max_stack);
    let task_flags = layout.task_flags.unwrap_or(u32::MAX);
    let (signal, live) = layout.exits.unwrap_or((u32::MAX, u32::MAX));
    #[cfg(uhr_ebpf)]
    {
        check_namespace()?;
        EbpfLoader::new()
            .map_max_entries("SAMPLES", size)
            .override_global("MAX_STACK", &max_stack, CAN_SAMPLE)
            .override_global("TASK_FLAGS", &task_flags, CAN_SAMPLE)
            .override_global("TASK_SIGNAL", &signal, true)
            .override_global("SIGNAL_LIVE", &live, true)
            .load(PROGRAMS)
            .map_err(|e| Error::Load(e).or_not_permitted())
    }
    #[cfg(not(uhr_ebpf))]
    {
        let _ = (size, max_stack, task_flags, signal, live, EbpfLoader::new);
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
    fn creates_the_samples_file_for_its_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("samples");
        create_private(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
