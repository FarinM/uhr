//! uhr's own eBPF programs, which count and time the target's syscalls.

use std::collections::BTreeMap;
use std::error::Error as _;
use std::io;
use std::path::Path;

use aya::Ebpf;
use aya::maps::{HashMap, MapData, PerCpuArray};
use aya::programs::raw_trace_point::RawTracePointLinkId;
use aya::programs::trace_point::TracePointLinkId;
use aya::programs::{RawTracePoint, TracePoint};
use syscalls::Sysno;
use uhr_core::recording::SyscallCalls;
use uhr_ebpf::{ACTIVE, CallKey, Calls, HELD, Start};

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

/// The programs that count syscalls, at the raw tracepoints of their names.
const SYSCALLS: [&str; 2] = ["sys_enter", "sys_exit"];

/// What the programs counted.
pub(crate) struct Counted {
    pub(crate) calls: Vec<SyscallCalls>,
    /// Calls that found the programs' table of calls full.
    pub(crate) lost: u64,
    /// The programs' tags, in hex.
    pub(crate) programs: Vec<String>,
}

pub(crate) struct Syscalls {
    ebpf: Ebpf,
    tracepoints: Vec<(&'static str, TracePointLinkId)>,
    syscalls: Vec<(&'static str, RawTracePointLinkId)>,
}

/// The counts, and the programs: detached, but loaded until unloaded, so
/// that the kernel's symbols still name them.
pub(crate) struct Stopped {
    counted: Counted,
    programs: Ebpf,
}

impl Stopped {
    pub(crate) fn unload(self) -> Counted {
        drop(self.programs);
        self.counted
    }
}

impl Syscalls {
    /// Counts the syscalls of `pid` and of the processes it starts: at once,
    /// or for a target `held` before its exec, from the exec.
    pub(crate) fn start(pid: u32, held: bool) -> Result<Self, Error> {
        let mut ebpf = load()?;
        let targets = ebpf.map_mut("TARGETS").ok_or(Error::Missing("TARGETS"))?;
        let mut targets: HashMap<_, u32, u8> =
            HashMap::try_from(targets).map_err(|e| Error::Map("TARGETS", e))?;
        let state = if held { HELD } else { ACTIVE };
        targets
            .insert(pid, state, 0)
            .map_err(|e| Error::Map("TARGETS", e).or_not_permitted())?;
        let mut tracepoints = Vec::new();
        for (program, category, name) in FOLLOWERS {
            let tracepoint = tracepoint(&mut ebpf, program)?;
            let link = tracepoint
                .load()
                .and_then(|()| tracepoint.attach(category, name))
                .map_err(|e| Error::Program(program, e).or_not_permitted())?;
            tracepoints.push((program, link));
        }
        let mut syscalls = Vec::new();
        for program in SYSCALLS {
            let tracepoint = raw_tracepoint(&mut ebpf, program)?;
            let link = tracepoint
                .load()
                .and_then(|()| tracepoint.attach(program))
                .map_err(|e| Error::Program(program, e).or_not_permitted())?;
            syscalls.push((program, link));
        }
        Ok(Self {
            ebpf,
            tracepoints,
            syscalls,
        })
    }

    /// Stops counting, and reads what was counted.
    pub(crate) fn stop(self) -> Result<Stopped, Error> {
        let now = monotonic_ns();
        let Self {
            mut ebpf,
            tracepoints,
            syscalls,
        } = self;
        let mut programs = Vec::new();
        for (program, link) in tracepoints {
            let tracepoint = tracepoint(&mut ebpf, program)?;
            tracepoint
                .detach(link)
                .map_err(|e| Error::Program(program, e))?;
            let info = tracepoint.info().map_err(|e| Error::Program(program, e))?;
            programs.push(format!("{:016x}", info.tag()));
        }
        for (program, link) in syscalls {
            let tracepoint = raw_tracepoint(&mut ebpf, program)?;
            // So the maps stay as they are while read.
            tracepoint
                .detach(link)
                .map_err(|e| Error::Program(program, e))?;
            let info = tracepoint.info().map_err(|e| Error::Program(program, e))?;
            programs.push(format!("{:016x}", info.tag()));
        }
        let mut take = |name| ebpf.take_map(name).ok_or(Error::Missing(name));
        let (calls, starts, lost) = (take("CALLS")?, take("STARTS")?, take("LOST")?);

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
        let lost: PerCpuArray<MapData, u64> =
            PerCpuArray::try_from(lost).map_err(|e| Error::Map("LOST", e))?;
        let lost = lost
            .get(&0, 0)
            .map_err(|e| Error::Map("LOST", e))?
            .iter()
            .sum();
        Ok(Stopped {
            counted: Counted {
                calls: rows.into_values().collect(),
                lost,
                programs,
            },
            programs: ebpf,
        })
    }
}

/// Loads the programs without running them, as recording would.
pub fn check() -> Result<(), Error> {
    let mut ebpf = load()?;
    for (program, ..) in FOLLOWERS {
        tracepoint(&mut ebpf, program)?
            .load()
            .map_err(|e| Error::Program(program, e).or_not_permitted())?;
    }
    for program in SYSCALLS {
        raw_tracepoint(&mut ebpf, program)?
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

fn load() -> Result<Ebpf, Error> {
    #[cfg(uhr_ebpf)]
    {
        check_namespace()?;
        Ebpf::load(PROGRAMS).map_err(|e| Error::Load(e).or_not_permitted())
    }
    #[cfg(not(uhr_ebpf))]
    Err(Error::NotBuilt)
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
