//! Finds the interpreters of the target's processes while recording, tells
//! uhr's eBPF programs how to walk their frames, and reads the code those
//! frames run while the processes still have it.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};

use aya::maps::{HashMap as BpfHashMap, MapData};
use tracing::{debug, warn};
use uhr_core::recording::Mapping;
use uhr_core::runtimes::{self, Code, Interpreter, Memory, Process, WalkedFrame};
use uhr_ebpf::{MAX_PATH, MAX_WALKED_BYTES, ONE_LIST, walk};

use crate::launch::monotonic_ns;

/// What a sample says of its process and interpreter frames.
pub(crate) struct Walked {
    pub(crate) pid: u32,
    /// How many times the process had exec'd, 0 where unknown.
    pub(crate) exec: u32,
    /// How many times it had mapped a file's code.
    pub(crate) mapped: u32,
    pub(crate) time_ns: u64,
    /// Of `uhr_ebpf::walk`.
    pub(crate) status: u32,
    pub(crate) frame_bytes: u32,
    pub(crate) frames: Vec<u8>,
}

/// A program a process ran: its pid, and how many times it had exec'd.
pub(crate) type Program = (u32, u32);

/// The interpreters found, and the code their frames ran.
#[derive(Default)]
pub(crate) struct Interpreters {
    /// By program, each with when uhr told the programs to walk its frames.
    /// Where uhr can't tell how many times a process exec'd, its programs
    /// share an entry, and the latest interpreter found holds.
    pub(crate) programs: Programs,
    /// By program and address. `None` for code that could not be read.
    pub(crate) code: HashMap<(Program, u64), Option<Code>>,
    /// Programs that run a runtime uhr cannot read the frames of, and why.
    pub(crate) unsupported: HashMap<Program, String>,
}

type Programs = HashMap<Program, Vec<(u64, Box<dyn Interpreter>)>>;

impl Interpreters {
    /// The interpreter of `program` that walked the frames of a sample of it
    /// at `time_ns`, and if none had yet, the first found.
    pub(crate) fn of(
        &self,
        program: Program,
        time_ns: u64,
    ) -> (Option<&dyn Interpreter>, Option<&dyn Interpreter>) {
        interpreter_of(&self.programs, program, time_ns)
    }
}

fn interpreter_of(
    programs: &Programs,
    program: Program,
    time_ns: u64,
) -> (Option<&dyn Interpreter>, Option<&dyn Interpreter>) {
    let Some(found) = programs.get(&program) else {
        return (None, None);
    };
    let index = found.partition_point(|(since, _)| *since <= time_ns);
    let walked = index.checked_sub(1).map(|i| &*found[i].1);
    (walked, found.first().map(|(_, first)| &**first))
}

/// Runs while the programs sample, on a thread of its own, as finding a
/// runtime reads its files.
pub(crate) struct Finder {
    sender: Sender<Walked>,
    thread: JoinHandle<Interpreters>,
}

/// uhr's programs' maps of how to walk each process's frames, and of the
/// state each thread runs in.
pub(crate) struct Maps {
    pub(crate) walks: BpfHashMap<MapData, u32, uhr_ebpf::Walk>,
    pub(crate) threads: BpfHashMap<MapData, u32, u64>,
}

impl Finder {
    pub(crate) fn start(maps: Maps) -> Self {
        let (sender, receiver) = mpsc::channel();
        let thread = thread::spawn(move || find(receiver, maps));
        Self { sender, thread }
    }

    pub(crate) fn sender(&self) -> Sender<Walked> {
        self.sender.clone()
    }

    /// Once every sender is gone.
    pub(crate) fn finish(self) -> Interpreters {
        drop(self.sender);
        self.thread
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    }
}

enum State {
    /// Not found yet: looked for again once the process maps more code than
    /// it had at the last look, `mapped`, as a runtime's library can be
    /// mapped after the exec. And from `next_ns`, a while after each look,
    /// for code mapped where the programs don't see it.
    Looking {
        mapped: Option<u32>,
        next_ns: u64,
        wait_ns: u64,
    },
    Walking {
        since_ns: u64,
        memory: FileMemory,
        /// When uhr last told the programs where threads' states are.
        threads_ns: Option<u64>,
    },
    /// A runtime uhr cannot read.
    Done,
}

const LOOKING: State = State::Looking {
    mapped: None,
    next_ns: 0,
    wait_ns: 100_000_000,
};

/// The longest to wait before looking for a process's runtime again.
const MAX_WAIT_NS: u64 = 5_000_000_000;

/// The least time between telling the programs where a process's threads'
/// states are.
const THREADS_EVERY_NS: u64 = 200_000_000;

/// The most thread states uhr reads of a process.
const MAX_STATES: usize = 1 << 16;

fn find(receiver: Receiver<Walked>, mut maps: Maps) -> Interpreters {
    let mut found = Interpreters::default();
    // By pid: the program it runs, and how far uhr is with it.
    let mut states: HashMap<u32, (u32, State)> = HashMap::new();
    for walked in receiver {
        let pid = walked.pid;
        let (exec, state) = states.entry(pid).or_insert((walked.exec, LOOKING));
        if walked.exec < *exec {
            // A sample of the program before, which came late.
            continue;
        }
        let execed = match state {
            // Where uhr can't tell how many times it exec'd, the programs
            // forget a process's walk when it execs.
            State::Walking { since_ns, .. } if walked.exec == 0 => {
                walked.status == walk::NONE && walked.time_ns > *since_ns
            }
            _ => walked.exec > *exec,
        };
        if execed {
            *exec = walked.exec;
            *state = LOOKING;
        }
        let program = (pid, *exec);
        match state {
            State::Looking {
                mapped,
                next_ns,
                wait_ns,
            } if mapped.is_none_or(|had| walked.mapped > had) || monotonic_ns() >= *next_ns => {
                match look(program, &mut maps.walks, &mut found) {
                    Ok(Some(next)) => *state = next,
                    Ok(None) => {
                        *mapped = (*mapped).max(Some(walked.mapped));
                        *next_ns = monotonic_ns() + *wait_ns;
                        *wait_ns = (*wait_ns * 2).min(MAX_WAIT_NS);
                    }
                    Err(reason) => {
                        debug!(pid, %reason, "not reading the frames of its runtime");
                        found.unsupported.insert(program, reason);
                        *state = State::Done;
                    }
                }
            }
            State::Walking {
                memory, threads_ns, ..
            } => {
                let (Some(interpreter), _) =
                    interpreter_of(&found.programs, program, walked.time_ns)
                else {
                    continue;
                };
                if walked.status == walk::UNSEARCHED
                    && threads_ns.is_none_or(|ns| monotonic_ns() >= ns + THREADS_EVERY_NS)
                {
                    *threads_ns = Some(monotonic_ns());
                    if let Err(error) =
                        tell_threads(pid, &interpreter.walk(), memory, &mut maps.threads)
                    {
                        debug!(pid, %error, "telling uhr's eBPF programs where its threads' states are");
                    }
                }
                // Each after its address.
                let bytes = walked.frame_bytes.max(9) as usize;
                for frame in walked.frames.chunks_exact(bytes) {
                    let WalkedFrame::Code { code, .. } = interpreter.frame(&frame[8..]) else {
                        continue;
                    };
                    if found.code.contains_key(&(program, code)) {
                        continue;
                    }
                    let read = interpreter.code(memory, code);
                    if let Err(error) = &read {
                        debug!(pid, code, %error, "reading interpreted code");
                    }
                    found.code.insert((program, code), read.ok());
                }
            }
            _ => {}
        }
    }
    found
}

/// Tells uhr's programs the state each thread of `pid` runs in, which their
/// search can't reach in a process with many.
fn tell_threads(
    pid: u32,
    walk: &runtimes::Walk,
    memory: &FileMemory,
    threads: &mut BpfHashMap<MapData, u32, u64>,
) -> Result<(), runtimes::Error> {
    let states = walk.states(memory, MAX_STATES)?;
    let hosts = host_thread_ids(pid);
    let mut best: HashMap<u64, runtimes::ThreadState> = HashMap::new();
    for state in states {
        // As the programs choose: the one marked, or else the first with
        // frames.
        let better = |old: &runtimes::ThreadState| !old.active && (state.active || !old.has_frames);
        if best.get(&state.thread_id).is_none_or(better) {
            best.insert(state.thread_id, state);
        }
    }
    for (id, state) in best {
        let host = hosts
            .as_ref()
            .map_or(Some(id as u32), |hosts| hosts.get(&id).copied());
        if let Some(host) = host {
            let _ = threads.insert(host, state.address, 0);
        }
    }
    Ok(())
}

/// The ids of the threads of `pid` by their ids in its own PID namespace,
/// `None` if that is uhr's, where they are the same.
fn host_thread_ids(pid: u32) -> Option<HashMap<u64, u32>> {
    if pid_namespace(pid) == pid_namespace_of("self") {
        return None;
    }
    let tasks = fs::read_dir(format!("/proc/{pid}/task")).ok()?;
    let mut ids = HashMap::new();
    for task in tasks.flatten() {
        let status = fs::read_to_string(task.path().join("status")).unwrap_or_default();
        // The thread's id in each namespace it is in, the first one first.
        let nested = status.lines().find_map(|line| line.strip_prefix("NSpid:"));
        let nested: Vec<u64> = nested
            .map(|ids| {
                ids.split_whitespace()
                    .filter_map(|id| id.parse().ok())
                    .collect()
            })
            .unwrap_or_default();
        if let (Some(&host), Some(&own)) = (nested.first(), nested.last()) {
            ids.insert(own, host as u32);
        }
    }
    Some(ids)
}

/// A process's PID namespace, by the device and inode of its file.
fn pid_namespace(pid: u32) -> Option<(u64, u64)> {
    pid_namespace_of(&pid.to_string())
}

fn pid_namespace_of(process: &str) -> Option<(u64, u64)> {
    let file = fs::metadata(format!("/proc/{process}/ns/pid")).ok()?;
    Some((file.dev(), file.ino()))
}

/// Looks for the runtime of `program`, and tells uhr's programs how to walk
/// its frames. `None` if it runs none uhr knows yet, and an error for one
/// it cannot read.
fn look(
    program: Program,
    walks: &mut BpfHashMap<MapData, u32, uhr_ebpf::Walk>,
    found: &mut Interpreters,
) -> Result<Option<State>, String> {
    let pid = program.0;
    let Ok(process) = LiveProcess::open(pid) else {
        // Gone, or not started yet.
        return Ok(None);
    };
    let interpreter = match runtimes::interpreter(&process) {
        Ok(Some(interpreter)) => interpreter,
        Ok(None) => return Ok(None),
        Err(runtimes::Error::Read { .. }) => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    // Thread ids in states are in the process's PID namespace, which only
    // need translating where it is not uhr's.
    let namespace = pid_namespace(pid)
        .filter(|namespace| Some(*namespace) != pid_namespace_of("self"))
        .map_or([0, 0], |(dev, ino)| [dev, ino]);
    let walk = programs_walk(&interpreter.walk(), namespace).ok_or_else(|| {
        format!(
            "the frames of {} {} take more steps to walk than uhr's programs take",
            interpreter.runtime(),
            interpreter.version()
        )
    })?;
    let since_ns = monotonic_ns();
    if let Err(error) = walks.insert(pid, walk, 0) {
        warn!(pid, %error, "telling uhr's eBPF programs how to walk its frames");
        return Err(format!(
            "uhr's eBPF programs could not take its walk: {error}"
        ));
    }
    debug!(
        pid,
        runtime = interpreter.runtime(),
        version = interpreter.version(),
        "walking the frames of its runtime"
    );
    found
        .programs
        .entry(program)
        .or_default()
        .push((since_ns, interpreter));
    Ok(Some(State::Walking {
        since_ns,
        memory: process.memory,
        threads_ns: None,
    }))
}

/// The walk as uhr's programs take it, with the PID namespace of the
/// process, `None` if it has more steps than they follow.
fn programs_walk(walk: &runtimes::Walk, pid_namespace: [u64; 2]) -> Option<uhr_ebpf::Walk> {
    let path = |steps: &[u32]| {
        let mut path = [0; MAX_PATH];
        path.get_mut(..steps.len())?.copy_from_slice(steps);
        Some((path, steps.len() as u32))
    };
    let (lists, lists_len) = path(&walk.lists)?;
    let (frame, frame_len) = path(&walk.frame)?;
    let (active, active_mask) = walk.active.unwrap_or((0, 0));
    // Each frame takes its address too.
    (walk.frame_bytes as usize + 8 <= MAX_WALKED_BYTES && walk.next_frame + 8 <= walk.frame_bytes)
        .then_some(uhr_ebpf::Walk {
            base: walk.base,
            lists,
            lists_len,
            next_list: walk.next_list.unwrap_or(ONE_LIST),
            first_state: walk.first_state,
            next_state: walk.next_state,
            thread_id: walk.thread_id,
            active,
            active_mask,
            frame,
            frame_len,
            next_frame: walk.next_frame,
            frame_bytes: walk.frame_bytes,
            frame_pointers: u32::from(walk.frame_pointers),
            pad: 0,
            pid_namespace,
        })
}

/// A running process, read through `/proc`.
struct LiveProcess {
    pid: u32,
    mappings: Vec<Mapping>,
    memory: FileMemory,
}

/// A process's `/proc/<pid>/mem`, which reads the memory of the program it
/// ran when opened.
struct FileMemory(File);

impl Memory for FileMemory {
    fn read(&self, address: u64, into: &mut [u8]) -> io::Result<()> {
        self.0.read_exact_at(into, address)
    }
}

impl LiveProcess {
    fn open(pid: u32) -> io::Result<Self> {
        let maps = fs::read_to_string(format!("/proc/{pid}/maps"))?;
        let memory = FileMemory(File::open(format!("/proc/{pid}/mem"))?);
        Ok(Self {
            pid,
            mappings: maps.lines().filter_map(|line| mapping(pid, line)).collect(),
            memory,
        })
    }
}

impl Process for LiveProcess {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn mappings(&self) -> &[Mapping] {
        &self.mappings
    }

    fn file(&self, mapping: &Mapping) -> io::Result<Vec<u8>> {
        // The file mapped, even if its path now holds another.
        let mapped = format!(
            "/proc/{}/map_files/{:x}-{:x}",
            self.pid, mapping.start, mapping.end
        );
        fs::read(mapped).or_else(|_| fs::read(&mapping.path))
    }

    fn memory(&self) -> &dyn Memory {
        &self.memory
    }
}

/// A line of `/proc/<pid>/maps` that maps a file: `start-end perms offset
/// dev inode path`.
fn mapping(pid: u32, line: &str) -> Option<Mapping> {
    let mut fields = line.split_ascii_whitespace();
    let (range, _perms, offset) = (fields.next()?, fields.next()?, fields.next()?);
    let (_dev, _inode) = (fields.next()?, fields.next()?);
    let path: Vec<&str> = fields.collect();
    let path = path.join(" ");
    if !path.starts_with('/') {
        return None;
    }
    let (start, end) = range.split_once('-')?;
    Some(Mapping {
        pid: Some(pid),
        start: u64::from_str_radix(start, 16).ok()?,
        end: u64::from_str_radix(end, 16).ok()?,
        file_offset: u64::from_str_radix(offset, 16).ok()?,
        path,
        build_id: None,
        time_ns: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_files_a_process_maps() {
        let line =
            "7f1c2a000000-7f1c2a1c3000 r-xp 00028000 08:01 393 /usr/lib/x86_64-linux-gnu/libc.so.6";
        let libc = mapping(7, line).unwrap();
        assert_eq!(
            (libc.start, libc.end, libc.file_offset),
            (0x7f1c2a000000, 0x7f1c2a1c3000, 0x28000)
        );
        assert_eq!(libc.path, "/usr/lib/x86_64-linux-gnu/libc.so.6");
        let spaced = "1000-2000 r--p 00000000 08:01 7 /opt/my app/lib.so";
        assert_eq!(mapping(7, spaced).unwrap().path, "/opt/my app/lib.so");
        assert!(mapping(7, "7ffd1000-7ffd2000 rw-p 00000000 00:00 0 [stack]").is_none());
        assert!(mapping(7, "7ffd1000-7ffd2000 rw-p 00000000 00:00 0").is_none());
    }
}
