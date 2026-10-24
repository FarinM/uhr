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
    /// Sorted by start, and not overlapping.
    pub kernel_symbols: Vec<KernelSymbol>,
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
}

/// Where the code lives, decided from the mappings at record time. Whether
/// a frame got a name is a separate question, answered by symbolization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    Binary,
    Kernel,
    /// No known code mapping contains the address.
    Unresolved,
}

impl Origin {
    pub fn as_str(self) -> &'static str {
        match self {
            Origin::Binary => "binary",
            Origin::Kernel => "kernel",
            Origin::Unresolved => "unresolved",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        Ok(match value {
            "binary" => Origin::Binary,
            "kernel" => Origin::Kernel,
            "unresolved" => Origin::Unresolved,
            _ => return Err(format!("unknown frame origin {value:?}")),
        })
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
            kernel_symbols: read_kernel_symbols(dir)?,
        };
        recording
            .check_references()
            .map_err(|reason| Error::Invalid {
                path: dir.to_owned(),
                reason,
            })?;
        Ok(recording)
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
    (0..table.len())
        .map(|i| {
            Ok(Frame {
                origin: Origin::parse(&origin[i]).map_err(|reason| table.invalid(reason))?,
                address: address[i],
                mapping: mapping[i],
                file_offset: file_offset[i],
                return_address: return_address[i],
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
