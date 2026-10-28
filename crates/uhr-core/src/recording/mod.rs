mod manifest;
pub(crate) mod table;

use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};

use arrow_schema::ArrowError;
use parquet::errors::ParquetError;
use serde::{Deserialize, Serialize};

pub use manifest::*;
use table::{Column, Table};

const MANIFEST: &str = "manifest.json";
const THREADS: &str = "threads.parquet";
const THREAD_NAMES: &str = "thread_names.parquet";
const MAPPINGS: &str = "mappings.parquet";
const FRAMES: &str = "frames.parquet";
const STACKS: &str = "stacks.parquet";
const SAMPLES: &str = "samples.parquet";
const KERNEL_SYMBOLS: &str = "kernel_symbols.parquet";
const JIT_SYMBOLS: &str = "jit_symbols.parquet";
const INTERPRETED_CODE: &str = "interpreted_code.parquet";
const SYSCALL_CALLS: &str = "syscall_calls.parquet";
const OFF_CPU: &str = "off_cpu.parquet";
const MEMORY: &str = "memory.parquet";
const PAGE_FAULTS: &str = "page_faults.parquet";

type Result<T, E = Error> = std::result::Result<T, E>;

/// Why a recording could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "{} has no {MANIFEST}: it is not a recording, or the recording did not finish",
        .0.display()
    )]
    NotARecording(PathBuf),
    #[error(
        "{} has format version {found}, this build reads version {FORMAT_VERSION}",
        .path.display()
    )]
    FormatVersion { path: PathBuf, found: u32 },
    /// The files can be read, but break the format.
    #[error("invalid recording {}: {reason}", .path.display())]
    Invalid { path: PathBuf, reason: String },
    #[error("{action} {}", .path.display())]
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    #[error("{action} {}", .path.display())]
    Parquet {
        action: &'static str,
        path: PathBuf,
        source: ParquetError,
    },
    #[error("{action} {}", .path.display())]
    Arrow {
        action: &'static str,
        path: PathBuf,
        source: ArrowError,
    },
    #[error("{action} {}", .path.display())]
    Manifest {
        action: &'static str,
        path: PathBuf,
        source: serde_json::Error,
    },
}

/// Each returns a `map_err` argument that adds what was being done to which
/// file.
impl Error {
    pub(crate) fn io(action: &'static str, path: &Path) -> impl FnOnce(io::Error) -> Self {
        let path = path.to_owned();
        move |source| Self::Io {
            action,
            path,
            source,
        }
    }

    pub(crate) fn parquet(action: &'static str, path: &Path) -> impl FnOnce(ParquetError) -> Self {
        let path = path.to_owned();
        move |source| Self::Parquet {
            action,
            path,
            source,
        }
    }

    pub(crate) fn arrow(action: &'static str, path: &Path) -> impl FnOnce(ArrowError) -> Self {
        let path = path.to_owned();
        move |source| Self::Arrow {
            action,
            path,
            source,
        }
    }

    fn manifest(action: &'static str, path: &Path) -> impl FnOnce(serde_json::Error) -> Self {
        let path = path.to_owned();
        move |source| Self::Manifest {
            action,
            path,
            source,
        }
    }
}

/// One finished profiling session. Ids are positions in their tables, and
/// `read` checks every reference, so code holding a `Recording` can index
/// without checks.
#[derive(Debug, Clone, PartialEq)]
pub struct Recording {
    pub manifest: Manifest,
    pub threads: Vec<Thread>,
    pub thread_names: Vec<ThreadName>,
    pub mappings: Vec<Mapping>,
    pub frames: Vec<Frame>,
    /// Frame ids, leaf first.
    pub stacks: Vec<Vec<u32>>,
    pub samples: Vec<Sample>,
    pub page_faults: Vec<FaultSample>,
    pub off_cpu: Vec<OffCPUInterval>,
    /// Sorted by start, and not overlapping.
    pub kernel_symbols: Vec<KernelSymbol>,
    /// Sorted by pid and start, and not overlapping in a process.
    pub jit_symbols: Vec<JitSymbol>,
    pub interpreted_code: Vec<InterpretedCode>,
    pub syscall_calls: Vec<SyscallCalls>,
    /// Sorted by time.
    pub memory: Vec<MemoryReading>,
}

/// One lifetime of a thread. The kernel reuses ids, so `(pid, tid)` can
/// repeat; `start_ns` tells the lifetimes apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Thread {
    pub pid: u32,
    pub tid: u32,
    /// The thread that created this one. `None` if it started before the
    /// recording.
    pub parent_pid: Option<u32>,
    pub parent_tid: Option<u32>,
    /// `None` if the thread started before the recording.
    pub start_ns: Option<u64>,
    /// `None` if the thread outlived the recording, or its exit was not seen.
    pub end_ns: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadName {
    pub pid: u32,
    pub tid: u32,
    /// `None` if the name was set before the recording.
    pub time_ns: Option<u64>,
    pub name: String,
}

/// The path of the kernel's own mapping. A module's is its name in
/// brackets, as in `[ext4]`.
pub const KERNEL: &str = "[kernel]";

/// The source of the names of code runtimes compiled.
pub const JIT: &str = "[jit]";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    /// `None` for kernel mappings.
    pub pid: Option<u32>,
    pub start: u64,
    pub end: u64,
    pub file_offset: u64,
    pub path: String,
    pub build_id: Option<String>,
    pub time_ns: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Frame {
    pub origin: Origin,
    pub address: u64,
    pub mapping: Option<u32>,
    pub file_offset: Option<u64>,
    /// Return addresses point one instruction past the call, so symbol
    /// lookup must step back into the call.
    pub return_address: bool,
    /// For an interpreted frame, the code it ran and where in it.
    pub interpreted: Option<Interpreted>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Interpreted {
    /// Its row in `interpreted_code`.
    pub code: u32,
    /// The line it was at, when the runtime says.
    pub line: Option<u32>,
}

/// Where the code lives, decided from the mappings at record time. Whether
/// a frame got a name is a separate question, answered by symbolization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    Binary,
    Kernel,
    /// Code a runtime compiled as it ran, which the runtime named in its
    /// perf map.
    Jit,
    /// Code an interpreter ran, whose frames uhr read from its memory.
    Interpreted,
    /// No known code mapping contains the address.
    Unresolved,
}

impl Origin {
    pub fn as_str(self) -> &'static str {
        match self {
            Origin::Binary => "binary",
            Origin::Kernel => "kernel",
            Origin::Jit => "jit",
            Origin::Interpreted => "interpreted",
            Origin::Unresolved => "unresolved",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        Ok(match value {
            "binary" => Origin::Binary,
            "kernel" => Origin::Kernel,
            "jit" => Origin::Jit,
            "interpreted" => Origin::Interpreted,
            "unresolved" => Origin::Unresolved,
            _ => return Err(format!("unknown frame origin {value:?}")),
        })
    }
}

/// Code a runtime compiled, as its perf map named it while recording. Only
/// the code frames fall in is kept: the map can be gone later, or belong to
/// a later process with the same pid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JitSymbol {
    pub pid: u32,
    pub start: u64,
    /// Exclusive.
    pub end: u64,
    pub name: String,
}

/// Code an interpreter ran, as uhr read it from the process's memory while
/// recording, the only time it could.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterpretedCode {
    pub pid: u32,
    pub runtime: String,
    /// Where the runtime kept it.
    pub address: u64,
    /// `None` if it could not be read, as when the process freed it first.
    pub name: Option<String>,
    pub file: Option<String>,
    pub first_line: Option<u32>,
    pub first_column: Option<u32>,
}

/// The calls a thread made to one syscall during the capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallCalls {
    pub pid: u32,
    pub tid: u32,
    /// The syscall's number, in the table of the recording's architecture.
    pub number: u32,
    /// `None` for a number that table has no name for.
    pub name: Option<String>,
    /// Calls that returned during the capture.
    pub calls: u64,
    /// Their time from entry to exit, on CPU or not.
    pub time_ns: u64,
    /// The returned calls by time: bucket `i` counts those of at least
    /// `2^i` ns and less than `2^(i + 1)`, and the last one also every longer
    /// call.
    pub latency: Vec<u64>,
    /// The time so far of a call the thread was still in when the capture
    /// ended. `None` if it was in none.
    pub unfinished_ns: Option<u64>,
}

/// How much memory a process had when it was read, in the kernel's counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryReading {
    pub time_ns: u64,
    pub pid: u32,
    /// Resident in RAM: memory of the process's own, such as its heap and
    /// stacks, pages of files it mapped, and shared memory.
    pub rss_anon_bytes: u64,
    pub rss_file_bytes: u64,
    pub rss_shmem_bytes: u64,
    /// Its own memory the kernel moved out to swap.
    pub swap_bytes: u64,
    /// The most it had resident since it started, or last exec'd, as the
    /// kernel tracks it, between readings too.
    pub peak_rss_bytes: u64,
}

impl MemoryReading {
    pub fn rss_bytes(&self) -> u64 {
        self.rss_anon_bytes + self.rss_file_bytes + self.rss_shmem_bytes
    }
}

/// A kernel function or BPF program, as the kernel listed it while
/// recording. Only the ones kernel frames fall in are kept: the kernel
/// moves on every boot, so its symbols cannot be read again later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelSymbol {
    pub start: u64,
    /// Exclusive: where the next function starts, or the mapping ends.
    pub end: u64,
    pub name: String,
    /// `None` for the kernel itself, as in `ext4` for a module, or `bpf`.
    pub module: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sample {
    pub time_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub cpu: Option<u32>,
    pub mode: Mode,
    pub stack: u32,
    pub cpu_ns: u64,
}

/// A sample of the page faults a thread took: its stack at one, which
/// stands for `faults` of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultSample {
    pub time_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub cpu: Option<u32>,
    /// What the fault came from: user code, or the kernel, as when a
    /// syscall copied to or from the process's memory.
    pub mode: Mode,
    pub stack: u32,
    pub faults: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    User,
    Kernel,
    /// Hypervisor, guest or a CPU mode perf did not report.
    Unknown,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::User => "user",
            Mode::Kernel => "kernel",
            Mode::Unknown => "unknown",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        Ok(match value {
            "user" => Mode::User,
            "kernel" => Mode::Kernel,
            "unknown" => Mode::Unknown,
            _ => return Err(format!("unknown mode {value:?}")),
        })
    }
}

/// A time a thread spent off CPU, from the moment it was switched out to the
/// moment it was switched back in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OffCPUInterval {
    pub start_ns: u64,
    pub end_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub state: ThreadState,
    /// Where it was switched out. `None` if its stack was not recorded.
    pub stack: Option<u32>,
}

/// Why a thread was off CPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreadState {
    /// Preempted: it could have run, but had to wait for a CPU.
    Runnable,
    /// It gave up the CPU to wait: for a lock, I/O, a timer or another
    /// thread. Once woken, it can wait for a CPU too, and that time counts
    /// here as well.
    Blocked,
    /// It was off CPU already when an attached capture started, so whether
    /// it was preempted or blocked is not known.
    Unknown,
}

impl ThreadState {
    pub fn as_str(self) -> &'static str {
        match self {
            ThreadState::Runnable => "runnable",
            ThreadState::Blocked => "blocked",
            ThreadState::Unknown => "unknown",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        Ok(match value {
            "runnable" => ThreadState::Runnable,
            "blocked" => ThreadState::Blocked,
            "unknown" => ThreadState::Unknown,
            _ => return Err(format!("unknown thread state {value:?}")),
        })
    }
}

impl Recording {
    /// Writes the manifest last: a directory without one is a recording that
    /// did not finish. Checks first what `read` checks, so a recording that
    /// could not be read back is never written.
    pub fn write(&self, dir: &Path) -> Result<()> {
        self.check_references().map_err(|reason| Error::Invalid {
            path: dir.to_owned(),
            reason,
        })?;
        fs::create_dir_all(dir).map_err(Error::io("creating", dir))?;
        self.write_tables(dir)?;
        let path = dir.join(MANIFEST);
        let manifest = serde_json::to_vec_pretty(&self.manifest)
            .map_err(Error::manifest("serializing", &path))?;
        let partial = dir.join(format!("{MANIFEST}.partial"));
        fs::write(&partial, manifest).map_err(Error::io("writing", &partial))?;
        fs::rename(&partial, &path).map_err(Error::io("renaming into place", &path))?;
        Ok(())
    }

    pub fn read(dir: &Path) -> Result<Self> {
        let manifest = read_manifest(dir)?;
        let recording = Self {
            manifest,
            threads: read_threads(dir)?,
            thread_names: read_thread_names(dir)?,
            mappings: read_mappings(dir)?,
            frames: read_frames(dir)?,
            stacks: read_stacks(dir)?,
            samples: read_samples(dir)?,
            page_faults: read_page_faults(dir)?,
            off_cpu: read_off_cpu(dir)?,
            kernel_symbols: read_kernel_symbols(dir)?,
            jit_symbols: read_jit_symbols(dir)?,
            interpreted_code: read_interpreted_code(dir)?,
            syscall_calls: read_syscall_calls(dir)?,
            memory: read_memory(dir)?,
        };
        recording
            .check_references()
            .map_err(|reason| Error::Invalid {
                path: dir.to_owned(),
                reason,
            })?;
        Ok(recording)
    }

    /// The saved kernel function a kernel frame falls in.
    pub fn kernel_symbol(&self, frame: &Frame) -> Option<&KernelSymbol> {
        if frame.origin != Origin::Kernel {
            return None;
        }
        let address = frame
            .address
            .saturating_sub(u64::from(frame.return_address));
        let symbols = &self.kernel_symbols;
        let index = symbols
            .partition_point(|s| s.start <= address)
            .checked_sub(1)?;
        Some(&symbols[index]).filter(|s| address < s.end)
    }

    /// Which stacks run uhr's own eBPF programs. `None` without them, or
    /// without kernel stacks, or their names, to find them by.
    pub(crate) fn in_own_programs(&self) -> Option<Vec<bool>> {
        let streams = &self.manifest.streams;
        let tags = streams.iter().find_map(|s| match &s.collector {
            Collector::Ebpf { programs, .. } => Some(programs),
            Collector::Perf { .. } | Collector::Procfs { .. } => None,
        })?;
        let sampled = streams
            .iter()
            .any(|s| s.signals.contains(&Signal::KernelStacks));
        self.in_programs(tags).filter(|_| sampled)
    }

    /// Which stacks run one of the eBPF programs with these tags, if they
    /// are in the kernel stacks. `None` without the names of kernel frames
    /// to find them by.
    pub fn in_programs(&self, tags: &[String]) -> Option<Vec<bool>> {
        if self.manifest.kernel_symbols != KernelSymbols::Saved {
            return None;
        }
        let own: Vec<bool> = self
            .frames
            .iter()
            .map(|frame| {
                self.kernel_symbol(frame)
                    .and_then(|symbol| bpf_program(&symbol.name))
                    .is_some_and(|program| tags.iter().any(|tag| program.get(..16) == Some(tag)))
            })
            .collect();
        Some(
            self.stacks
                .iter()
                .map(|stack| stack.iter().any(|&frame| own[frame as usize]))
                .collect(),
        )
    }

    /// The saved runtime code a JIT frame falls in.
    pub fn jit_symbol(&self, frame: &Frame) -> Option<&JitSymbol> {
        if frame.origin != Origin::Jit {
            return None;
        }
        let pid = self.mappings[frame.mapping? as usize].pid?;
        let address = frame
            .address
            .saturating_sub(u64::from(frame.return_address));
        let symbols = &self.jit_symbols;
        let index = symbols
            .partition_point(|s| (s.pid, s.start) <= (pid, address))
            .checked_sub(1)?;
        Some(&symbols[index]).filter(|s| s.pid == pid && address < s.end)
    }

    fn write_tables(&self, dir: &Path) -> Result<()> {
        let threads = &self.threads;
        table::write(
            &dir.join(THREADS),
            vec![
                Column::u32("pid", threads.iter().map(|t| t.pid).collect()),
                Column::u32("tid", threads.iter().map(|t| t.tid).collect()),
                Column::optional_u32("parent_pid", threads.iter().map(|t| t.parent_pid).collect()),
                Column::optional_u32("parent_tid", threads.iter().map(|t| t.parent_tid).collect()),
                Column::optional_u64("start_ns", threads.iter().map(|t| t.start_ns).collect()),
                Column::optional_u64("end_ns", threads.iter().map(|t| t.end_ns).collect()),
            ],
        )?;

        let names = &self.thread_names;
        table::write(
            &dir.join(THREAD_NAMES),
            vec![
                Column::u32("pid", names.iter().map(|n| n.pid).collect()),
                Column::u32("tid", names.iter().map(|n| n.tid).collect()),
                Column::optional_u64("time_ns", names.iter().map(|n| n.time_ns).collect()),
                Column::string("name", names.iter().map(|n| n.name.as_str()).collect()),
            ],
        )?;

        let mappings = &self.mappings;
        table::write(
            &dir.join(MAPPINGS),
            vec![
                Column::u32("mapping_id", ids(mappings.len())),
                Column::optional_u32("pid", mappings.iter().map(|m| m.pid).collect()),
                Column::u64("start", mappings.iter().map(|m| m.start).collect()),
                Column::u64("end", mappings.iter().map(|m| m.end).collect()),
                Column::u64(
                    "file_offset",
                    mappings.iter().map(|m| m.file_offset).collect(),
                ),
                Column::string("path", mappings.iter().map(|m| m.path.as_str()).collect()),
                Column::optional_string(
                    "build_id",
                    mappings.iter().map(|m| m.build_id.as_deref()).collect(),
                ),
                Column::optional_u64("time_ns", mappings.iter().map(|m| m.time_ns).collect()),
            ],
        )?;

        let frames = &self.frames;
        table::write(
            &dir.join(FRAMES),
            vec![
                Column::u32("frame_id", ids(frames.len())),
                Column::string("origin", frames.iter().map(|f| f.origin.as_str()).collect()),
                Column::u64("address", frames.iter().map(|f| f.address).collect()),
                Column::optional_u32("mapping_id", frames.iter().map(|f| f.mapping).collect()),
                Column::optional_u64(
                    "file_offset",
                    frames.iter().map(|f| f.file_offset).collect(),
                ),
                Column::bool(
                    "return_address",
                    frames.iter().map(|f| f.return_address).collect(),
                ),
                Column::optional_u32(
                    "code_id",
                    frames
                        .iter()
                        .map(|f| f.interpreted.map(|i| i.code))
                        .collect(),
                ),
                Column::optional_u32(
                    "line",
                    frames
                        .iter()
                        .map(|f| f.interpreted.and_then(|i| i.line))
                        .collect(),
                ),
            ],
        )?;

        table::write(
            &dir.join(STACKS),
            vec![
                Column::u32("stack_id", ids(self.stacks.len())),
                Column::u32_lists("frame_ids", &self.stacks),
            ],
        )?;

        let samples = &self.samples;
        table::write(
            &dir.join(SAMPLES),
            vec![
                Column::u64("time_ns", samples.iter().map(|s| s.time_ns).collect()),
                Column::u32("pid", samples.iter().map(|s| s.pid).collect()),
                Column::u32("tid", samples.iter().map(|s| s.tid).collect()),
                Column::optional_u32("cpu", samples.iter().map(|s| s.cpu).collect()),
                Column::string("mode", samples.iter().map(|s| s.mode.as_str()).collect()),
                Column::u32("stack_id", samples.iter().map(|s| s.stack).collect()),
                Column::u64("cpu_ns", samples.iter().map(|s| s.cpu_ns).collect()),
            ],
        )?;

        let faults = &self.page_faults;
        table::write(
            &dir.join(PAGE_FAULTS),
            vec![
                Column::u64("time_ns", faults.iter().map(|f| f.time_ns).collect()),
                Column::u32("pid", faults.iter().map(|f| f.pid).collect()),
                Column::u32("tid", faults.iter().map(|f| f.tid).collect()),
                Column::optional_u32("cpu", faults.iter().map(|f| f.cpu).collect()),
                Column::string("mode", faults.iter().map(|f| f.mode.as_str()).collect()),
                Column::u32("stack_id", faults.iter().map(|f| f.stack).collect()),
                Column::u64("faults", faults.iter().map(|f| f.faults).collect()),
            ],
        )?;

        let off_cpu = &self.off_cpu;
        table::write(
            &dir.join(OFF_CPU),
            vec![
                Column::u64("start_ns", off_cpu.iter().map(|i| i.start_ns).collect()),
                Column::u64("end_ns", off_cpu.iter().map(|i| i.end_ns).collect()),
                Column::u32("pid", off_cpu.iter().map(|i| i.pid).collect()),
                Column::u32("tid", off_cpu.iter().map(|i| i.tid).collect()),
                Column::string("state", off_cpu.iter().map(|i| i.state.as_str()).collect()),
                Column::optional_u32("stack_id", off_cpu.iter().map(|i| i.stack).collect()),
            ],
        )?;

        let symbols = &self.kernel_symbols;
        table::write(
            &dir.join(KERNEL_SYMBOLS),
            vec![
                Column::u64("start", symbols.iter().map(|s| s.start).collect()),
                Column::u64("end", symbols.iter().map(|s| s.end).collect()),
                Column::string("name", symbols.iter().map(|s| s.name.as_str()).collect()),
                Column::optional_string(
                    "module",
                    symbols.iter().map(|s| s.module.as_deref()).collect(),
                ),
            ],
        )?;

        let symbols = &self.jit_symbols;
        table::write(
            &dir.join(JIT_SYMBOLS),
            vec![
                Column::u32("pid", symbols.iter().map(|s| s.pid).collect()),
                Column::u64("start", symbols.iter().map(|s| s.start).collect()),
                Column::u64("end", symbols.iter().map(|s| s.end).collect()),
                Column::string("name", symbols.iter().map(|s| s.name.as_str()).collect()),
            ],
        )?;

        let code = &self.interpreted_code;
        table::write(
            &dir.join(INTERPRETED_CODE),
            vec![
                Column::u32("code_id", ids(code.len())),
                Column::u32("pid", code.iter().map(|c| c.pid).collect()),
                Column::string("runtime", code.iter().map(|c| c.runtime.as_str()).collect()),
                Column::u64("address", code.iter().map(|c| c.address).collect()),
                Column::optional_string("name", code.iter().map(|c| c.name.as_deref()).collect()),
                Column::optional_string("file", code.iter().map(|c| c.file.as_deref()).collect()),
                Column::optional_u32("first_line", code.iter().map(|c| c.first_line).collect()),
                Column::optional_u32(
                    "first_column",
                    code.iter().map(|c| c.first_column).collect(),
                ),
            ],
        )?;

        let calls = &self.syscall_calls;
        let latency: Vec<Vec<u64>> = calls.iter().map(|c| c.latency.clone()).collect();
        table::write(
            &dir.join(SYSCALL_CALLS),
            vec![
                Column::u32("pid", calls.iter().map(|c| c.pid).collect()),
                Column::u32("tid", calls.iter().map(|c| c.tid).collect()),
                Column::u32("number", calls.iter().map(|c| c.number).collect()),
                Column::optional_string("name", calls.iter().map(|c| c.name.as_deref()).collect()),
                Column::u64("calls", calls.iter().map(|c| c.calls).collect()),
                Column::u64("time_ns", calls.iter().map(|c| c.time_ns).collect()),
                Column::u64_lists("latency", &latency),
                Column::optional_u64(
                    "unfinished_ns",
                    calls.iter().map(|c| c.unfinished_ns).collect(),
                ),
            ],
        )?;

        let memory = &self.memory;
        table::write(
            &dir.join(MEMORY),
            vec![
                Column::u64("time_ns", memory.iter().map(|m| m.time_ns).collect()),
                Column::u32("pid", memory.iter().map(|m| m.pid).collect()),
                Column::u64(
                    "rss_anon_bytes",
                    memory.iter().map(|m| m.rss_anon_bytes).collect(),
                ),
                Column::u64(
                    "rss_file_bytes",
                    memory.iter().map(|m| m.rss_file_bytes).collect(),
                ),
                Column::u64(
                    "rss_shmem_bytes",
                    memory.iter().map(|m| m.rss_shmem_bytes).collect(),
                ),
                Column::u64("swap_bytes", memory.iter().map(|m| m.swap_bytes).collect()),
                Column::u64(
                    "peak_rss_bytes",
                    memory.iter().map(|m| m.peak_rss_bytes).collect(),
                ),
            ],
        )
    }

    fn check_references(&self) -> Result<(), String> {
        for (id, mapping) in self.mappings.iter().enumerate() {
            if mapping.start >= mapping.end {
                return Err(format!("mapping {id} has start >= end"));
            }
        }
        for (id, frame) in self.frames.iter().enumerate() {
            if let Some(mapping) = frame.mapping {
                check_id("frame", id, "mapping", mapping, self.mappings.len())?;
            }
            if (frame.origin == Origin::Interpreted) != frame.interpreted.is_some() {
                return Err(format!(
                    "frame {id} must have interpreted code if and only if it is interpreted"
                ));
            }
            if let Some(interpreted) = frame.interpreted {
                let code = interpreted.code;
                check_id(
                    "frame",
                    id,
                    "interpreted code",
                    code,
                    self.interpreted_code.len(),
                )?;
            }
        }
        for (id, stack) in self.stacks.iter().enumerate() {
            if stack.is_empty() {
                return Err(format!("stack {id} has no frames"));
            }
            for &frame in stack {
                check_id("stack", id, "frame", frame, self.frames.len())?;
            }
        }
        for (index, sample) in self.samples.iter().enumerate() {
            check_id("sample", index, "stack", sample.stack, self.stacks.len())?;
        }
        for (index, sample) in self.page_faults.iter().enumerate() {
            check_id(
                "page-fault sample",
                index,
                "stack",
                sample.stack,
                self.stacks.len(),
            )?;
        }
        for (index, interval) in self.off_cpu.iter().enumerate() {
            if interval.start_ns > interval.end_ns {
                return Err(format!("off-CPU interval {index} ends before it starts"));
            }
            if let Some(stack) = interval.stack {
                check_id("off-CPU interval", index, "stack", stack, self.stacks.len())?;
            }
        }
        for (index, symbol) in self.kernel_symbols.iter().enumerate() {
            if symbol.start >= symbol.end {
                return Err(format!("kernel symbol {index} has start >= end"));
            }
            if index > 0 && self.kernel_symbols[index - 1].end > symbol.start {
                return Err(format!(
                    "kernel symbol {index} starts before the one before it ends"
                ));
            }
        }
        for (index, symbol) in self.jit_symbols.iter().enumerate() {
            if symbol.start >= symbol.end {
                return Err(format!("JIT symbol {index} has start >= end"));
            }
            if let Some(before) = index.checked_sub(1).map(|i| &self.jit_symbols[i])
                && (before.pid, before.end) > (symbol.pid, symbol.start)
            {
                return Err(format!(
                    "JIT symbol {index} is not after the one before it in pid and address"
                ));
            }
        }
        for (index, calls) in self.syscall_calls.iter().enumerate() {
            if calls.latency.iter().sum::<u64>() != calls.calls {
                return Err(format!(
                    "syscall calls {index} has {} calls, but {} by latency",
                    calls.calls,
                    calls.latency.iter().sum::<u64>()
                ));
            }
        }
        if let Some(index) = self
            .memory
            .windows(2)
            .position(|pair| pair[0].time_ns > pair[1].time_ns)
        {
            return Err(format!(
                "memory reading {} comes before the one before it",
                index + 1
            ));
        }
        Ok(())
    }
}

fn read_manifest(dir: &Path) -> Result<Manifest> {
    let path = dir.join(MANIFEST);
    let text = match fs::read(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return Err(Error::NotARecording(dir.to_owned()));
        }
        Err(e) => return Err(Error::io("reading", &path)(e)),
    };

    #[derive(Deserialize)]
    struct Version {
        format_version: u32,
    }
    let version: Version = serde_json::from_slice(&text)
        .map_err(Error::manifest("reading the format version of", &path))?;
    if version.format_version != FORMAT_VERSION {
        return Err(Error::FormatVersion {
            path: dir.to_owned(),
            found: version.format_version,
        });
    }
    serde_json::from_slice(&text).map_err(Error::manifest("parsing", &path))
}

fn read_threads(dir: &Path) -> Result<Vec<Thread>> {
    let table = Table::read(&dir.join(THREADS))?;
    let pid = table.u32("pid")?;
    let tid = table.u32("tid")?;
    let parent_pid = table.optional_u32("parent_pid")?;
    let parent_tid = table.optional_u32("parent_tid")?;
    let start_ns = table.optional_u64("start_ns")?;
    let end_ns = table.optional_u64("end_ns")?;
    Ok((0..table.len())
        .map(|i| Thread {
            pid: pid[i],
            tid: tid[i],
            parent_pid: parent_pid[i],
            parent_tid: parent_tid[i],
            start_ns: start_ns[i],
            end_ns: end_ns[i],
        })
        .collect())
}

fn read_thread_names(dir: &Path) -> Result<Vec<ThreadName>> {
    let table = Table::read(&dir.join(THREAD_NAMES))?;
    let pid = table.u32("pid")?;
    let tid = table.u32("tid")?;
    let time_ns = table.optional_u64("time_ns")?;
    let mut name = table.string("name")?;
    Ok((0..table.len())
        .map(|i| ThreadName {
            pid: pid[i],
            tid: tid[i],
            time_ns: time_ns[i],
            name: std::mem::take(&mut name[i]),
        })
        .collect())
}

fn read_mappings(dir: &Path) -> Result<Vec<Mapping>> {
    let table = Table::read(&dir.join(MAPPINGS))?;
    check_ids(&table, "mapping_id")?;
    let pid = table.optional_u32("pid")?;
    let start = table.u64("start")?;
    let end = table.u64("end")?;
    let file_offset = table.u64("file_offset")?;
    let mut path = table.string("path")?;
    let mut build_id = table.optional_string("build_id")?;
    let time_ns = table.optional_u64("time_ns")?;
    Ok((0..table.len())
        .map(|i| Mapping {
            pid: pid[i],
            start: start[i],
            end: end[i],
            file_offset: file_offset[i],
            path: std::mem::take(&mut path[i]),
            build_id: build_id[i].take(),
            time_ns: time_ns[i],
        })
        .collect())
}

fn read_frames(dir: &Path) -> Result<Vec<Frame>> {
    let table = Table::read(&dir.join(FRAMES))?;
    check_ids(&table, "frame_id")?;
    let origin = table.string("origin")?;
    let address = table.u64("address")?;
    let mapping = table.optional_u32("mapping_id")?;
    let file_offset = table.optional_u64("file_offset")?;
    let return_address = table.bool("return_address")?;
    let code = table.optional_u32("code_id")?;
    let line = table.optional_u32("line")?;
    (0..table.len())
        .map(|i| {
            Ok(Frame {
                origin: Origin::parse(&origin[i]).map_err(|reason| table.invalid(reason))?,
                address: address[i],
                mapping: mapping[i],
                file_offset: file_offset[i],
                return_address: return_address[i],
                interpreted: code[i].map(|code| Interpreted {
                    code,
                    line: line[i],
                }),
            })
        })
        .collect()
}

fn read_stacks(dir: &Path) -> Result<Vec<Vec<u32>>> {
    let table = Table::read(&dir.join(STACKS))?;
    check_ids(&table, "stack_id")?;
    table.u32_lists("frame_ids")
}

fn read_samples(dir: &Path) -> Result<Vec<Sample>> {
    let table = Table::read(&dir.join(SAMPLES))?;
    let time_ns = table.u64("time_ns")?;
    let pid = table.u32("pid")?;
    let tid = table.u32("tid")?;
    let cpu = table.optional_u32("cpu")?;
    let mode = table.string("mode")?;
    let stack = table.u32("stack_id")?;
    let cpu_ns = table.u64("cpu_ns")?;
    (0..table.len())
        .map(|i| {
            Ok(Sample {
                time_ns: time_ns[i],
                pid: pid[i],
                tid: tid[i],
                cpu: cpu[i],
                mode: Mode::parse(&mode[i]).map_err(|reason| table.invalid(reason))?,
                stack: stack[i],
                cpu_ns: cpu_ns[i],
            })
        })
        .collect()
}

fn read_page_faults(dir: &Path) -> Result<Vec<FaultSample>> {
    let table = Table::read(&dir.join(PAGE_FAULTS))?;
    let time_ns = table.u64("time_ns")?;
    let pid = table.u32("pid")?;
    let tid = table.u32("tid")?;
    let cpu = table.optional_u32("cpu")?;
    let mode = table.string("mode")?;
    let stack = table.u32("stack_id")?;
    let faults = table.u64("faults")?;
    (0..table.len())
        .map(|i| {
            Ok(FaultSample {
                time_ns: time_ns[i],
                pid: pid[i],
                tid: tid[i],
                cpu: cpu[i],
                mode: Mode::parse(&mode[i]).map_err(|reason| table.invalid(reason))?,
                stack: stack[i],
                faults: faults[i],
            })
        })
        .collect()
}

fn read_off_cpu(dir: &Path) -> Result<Vec<OffCPUInterval>> {
    let table = Table::read(&dir.join(OFF_CPU))?;
    let start_ns = table.u64("start_ns")?;
    let end_ns = table.u64("end_ns")?;
    let pid = table.u32("pid")?;
    let tid = table.u32("tid")?;
    let state = table.string("state")?;
    let stack = table.optional_u32("stack_id")?;
    (0..table.len())
        .map(|i| {
            Ok(OffCPUInterval {
                start_ns: start_ns[i],
                end_ns: end_ns[i],
                pid: pid[i],
                tid: tid[i],
                state: ThreadState::parse(&state[i]).map_err(|reason| table.invalid(reason))?,
                stack: stack[i],
            })
        })
        .collect()
}

/// The tag and name of a BPF program, from its kernel symbol
/// `bpf_prog_<tag>` or `bpf_prog_<tag>_<name>`. The name tells apart
/// functions with the same instructions.
pub(crate) fn bpf_program(name: &str) -> Option<&str> {
    let program = name.strip_prefix("bpf_prog_")?;
    let tag = program.get(..16)?;
    let tagged = tag.bytes().all(|b| b.is_ascii_hexdigit())
        && matches!(program.as_bytes().get(16), None | Some(b'_'));
    tagged.then_some(program)
}

fn read_kernel_symbols(dir: &Path) -> Result<Vec<KernelSymbol>> {
    let table = Table::read(&dir.join(KERNEL_SYMBOLS))?;
    let start = table.u64("start")?;
    let end = table.u64("end")?;
    let mut name = table.string("name")?;
    let mut module = table.optional_string("module")?;
    Ok((0..table.len())
        .map(|i| KernelSymbol {
            start: start[i],
            end: end[i],
            name: std::mem::take(&mut name[i]),
            module: module[i].take(),
        })
        .collect())
}

fn read_jit_symbols(dir: &Path) -> Result<Vec<JitSymbol>> {
    let table = Table::read(&dir.join(JIT_SYMBOLS))?;
    let pid = table.u32("pid")?;
    let start = table.u64("start")?;
    let end = table.u64("end")?;
    let mut name = table.string("name")?;
    Ok((0..table.len())
        .map(|i| JitSymbol {
            pid: pid[i],
            start: start[i],
            end: end[i],
            name: std::mem::take(&mut name[i]),
        })
        .collect())
}

fn read_interpreted_code(dir: &Path) -> Result<Vec<InterpretedCode>> {
    let table = Table::read(&dir.join(INTERPRETED_CODE))?;
    check_ids(&table, "code_id")?;
    let pid = table.u32("pid")?;
    let mut runtime = table.string("runtime")?;
    let address = table.u64("address")?;
    let mut name = table.optional_string("name")?;
    let mut file = table.optional_string("file")?;
    let first_line = table.optional_u32("first_line")?;
    let first_column = table.optional_u32("first_column")?;
    Ok((0..table.len())
        .map(|i| InterpretedCode {
            pid: pid[i],
            runtime: std::mem::take(&mut runtime[i]),
            address: address[i],
            name: name[i].take(),
            file: file[i].take(),
            first_line: first_line[i],
            first_column: first_column[i],
        })
        .collect())
}

fn read_syscall_calls(dir: &Path) -> Result<Vec<SyscallCalls>> {
    let table = Table::read(&dir.join(SYSCALL_CALLS))?;
    let pid = table.u32("pid")?;
    let tid = table.u32("tid")?;
    let number = table.u32("number")?;
    let mut name = table.optional_string("name")?;
    let calls = table.u64("calls")?;
    let time_ns = table.u64("time_ns")?;
    let mut latency = table.u64_lists("latency")?;
    let unfinished_ns = table.optional_u64("unfinished_ns")?;
    Ok((0..table.len())
        .map(|i| SyscallCalls {
            pid: pid[i],
            tid: tid[i],
            number: number[i],
            name: name[i].take(),
            calls: calls[i],
            time_ns: time_ns[i],
            latency: std::mem::take(&mut latency[i]),
            unfinished_ns: unfinished_ns[i],
        })
        .collect())
}

fn read_memory(dir: &Path) -> Result<Vec<MemoryReading>> {
    let table = Table::read(&dir.join(MEMORY))?;
    let time_ns = table.u64("time_ns")?;
    let pid = table.u32("pid")?;
    let rss_anon_bytes = table.u64("rss_anon_bytes")?;
    let rss_file_bytes = table.u64("rss_file_bytes")?;
    let rss_shmem_bytes = table.u64("rss_shmem_bytes")?;
    let swap_bytes = table.u64("swap_bytes")?;
    let peak_rss_bytes = table.u64("peak_rss_bytes")?;
    Ok((0..table.len())
        .map(|i| MemoryReading {
            time_ns: time_ns[i],
            pid: pid[i],
            rss_anon_bytes: rss_anon_bytes[i],
            rss_file_bytes: rss_file_bytes[i],
            rss_shmem_bytes: rss_shmem_bytes[i],
            swap_bytes: swap_bytes[i],
            peak_rss_bytes: peak_rss_bytes[i],
        })
        .collect())
}

fn ids(len: usize) -> Vec<u32> {
    (0..len as u32).collect()
}

fn check_ids(table: &Table, column: &str) -> Result<()> {
    let ids = table.u32(column)?;
    if ids.iter().enumerate().any(|(i, &id)| id as usize != i) {
        return Err(table.invalid(format!("{column} must count up from 0 in row order")));
    }
    Ok(())
}

fn check_id(kind: &str, index: usize, target: &str, id: u32, len: usize) -> Result<(), String> {
    if id as usize >= len {
        return Err(format!(
            "{kind} {index} refers to {target} {id}, but there are only {len}"
        ));
    }
    Ok(())
}
