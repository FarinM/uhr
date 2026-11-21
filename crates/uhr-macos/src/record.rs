//! Recording on macOS with uhr's own sampler. At each tick it polls every
//! thread of the target's processes through their task ports, and walks
//! the stack of each that ran since the last poll; `polling` turns the
//! polls into CPU samples and time off CPU.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::fs;
use std::hash::Hash;
use std::io;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

use framehop::FrameAddress;
use tracing::{info, warn};
use uhr_core::interrupts::Interrupts;
use uhr_core::recording::{
    self, Clock, ClockReading, Collector, Exit, FORMAT_VERSION, Frame, KernelSymbols, Manifest,
    Mapping, MemoryReading, MissingSignal, Origin, Platform, Recording, Sampling, Signal,
    StackCoverage, Stream, StreamCoverage, Thread, ThreadName, Unwinding, WallClock,
};
use uhr_core::runtimes::stacks::Interpreters;
use uhr_core::symbols;

use crate::held::{Chunks, Held};
use crate::images::{Image, ImageInfos, read_listed_image};
use crate::launch::{self, Hello, Service, Waiting};
use mach2::port::mach_port_t;

use crate::mach::{
    Failed, Port, Task, ThreadInfo, monotonic_ns, realtime_ns, suspend, thread_cpu_ns, thread_id,
    thread_info, thread_self,
};
use crate::polling::{Poll, Polled, RunState, Timeline};
use crate::process;
use crate::runtime::{Runtime, Sample};
use crate::unwind::{End, Unwinding as Unwinder, Walk, in_syscall};

type Result<T, E = Error> = std::result::Result<T, E>;

/// Why recording failed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The host can't record, and `fix` says how to change that.
    #[error(
        "cannot record: {detail}{}",
        .fix.as_ref().map(|fix| format!("\nfix: {fix}")).unwrap_or_default()
    )]
    Blocked { detail: String, fix: Option<String> },
    #[error("no command to record")]
    NoCommand,
    #[error("no process has the pid {0}")]
    NoProcess(u32),
    #[error("interrupted before the capture started")]
    Interrupted,
    #[error("{} already exists", .0.display())]
    OutputExists(PathBuf),
    /// The staging directory of a recording that did not finish.
    #[error(
        "{} exists, probably from a recording that did not finish. Remove it to record again",
        .0.display()
    )]
    Unfinished(PathBuf),
    #[error("{} is not a usable output directory", .0.display())]
    UnusableOutput(PathBuf),
    #[error(transparent)]
    Launch(#[from] launch::Error),
    #[error("starting {program}")]
    Spawn {
        program: String,
        #[source]
        source: io::Error,
    },
    /// The target ended before dyld loaded uhr's library into it.
    #[error(
        "{program} exited with {status} before it loaded uhr's library, so nothing was recorded. \
         dyld leaves out the libraries DYLD_INSERT_LIBRARIES names in programs that System \
         Integrity Protection protects, that are hardened or restricted, and in all they run"
    )]
    NoHello { program: String, status: ExitStatus },
    #[error("waiting for {program}")]
    Wait {
        program: String,
        #[source]
        source: io::Error,
    },
    #[error("{action}")]
    Mach {
        action: &'static str,
        #[source]
        source: Failed,
    },
    #[error("{action} {}", .path.display())]
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    #[error(transparent)]
    Recording(#[from] recording::Error),
}

/// Returns a `map_err` argument that adds what was being done to which file.
fn io_error(action: &'static str, path: &Path) -> impl FnOnce(io::Error) -> Error {
    let path = path.to_owned();
    move |source| Error::Io {
        action,
        path,
        source,
    }
}

pub struct RecordOptions {
    pub target: Target,
    /// How often to poll each thread.
    pub frequency_hz: u64,
    /// Turn the time between polls that a thread did not run into time off
    /// CPU.
    pub off_cpu: bool,
    /// Read how much memory the target's processes have, at intervals.
    pub memory: bool,
    /// Asked for, though this sampler cannot capture them, so the recording
    /// says why they are missing: when each thread was woken, the syscalls
    /// threads made, and samples of their page faults.
    pub wakeups: bool,
    pub syscalls: bool,
    pub page_faults: bool,
}

/// What to record.
#[derive(Debug, Clone)]
pub enum Target {
    /// Start the command, with the processes it starts, and record it from
    /// before its own code runs until it exits.
    Launch(Vec<String>),
    /// Record a running process until uhr is interrupted, `duration` ends,
    /// or it exits.
    Attach {
        pid: u32,
        duration: Option<Duration>,
    },
}

/// Stacks deeper than this are cut.
const MAX_STACK_DEPTH: u32 = 512;

/// The most memory a walk of a thread's stack and its interpreter's frames
/// reads in chunks, 512 KiB; past that each read is as asked.
const MAX_HELD_CHUNKS: usize = 128;

/// How often each process's memory is read.
pub const MEMORY_INTERVAL: Duration = Duration::from_millis(100);

/// How often uhr looks at a target it stopped recording.
const WAIT_POLL: Duration = Duration::from_millis(10);

/// How long a launched program has to load uhr's library before uhr says
/// that it waits.
const HELLO_PATIENCE: Duration = Duration::from_secs(5);

/// Records `options.target` with uhr's sampler and writes the recording to
/// `out`, which must not exist. The recording is built in a sibling
/// `.partial` directory and renamed into place once complete. The first of
/// `interrupts` ends the capture, and a second kills a launched target. One
/// that comes before the capture starts ends it with nothing recorded, so
/// callers can count interrupts from before they call.
pub fn record(options: &RecordOptions, interrupts: &Interrupts, out: &Path) -> Result<Recording> {
    let ready = match &options.target {
        Target::Launch(command) => {
            let program = command.first().ok_or(Error::NoCommand)?;
            launch::check_program(program)?;
            Ready::Launch(command)
        }
        &Target::Attach { pid, duration } => {
            let task = open(pid)?;
            let command = process::command_line(pid).unwrap_or_else(|error| {
                warn!(pid, %error, "reading the command line");
                Vec::new()
            });
            Ready::Attach {
                pid,
                duration,
                task,
                command,
            }
        }
    };
    if out.exists() {
        return Err(Error::OutputExists(out.to_owned()));
    }
    if interrupts.count() > 0 {
        return Err(Error::Interrupted);
    }
    let staging = staging_dir(out)?;
    if let Some(parent) = staging.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(io_error("creating", parent))?;
    }
    // Exclusive, so two recordings to the same output can't share it.
    match fs::create_dir(&staging) {
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            return Err(Error::Unfinished(staging));
        }
        result => result.map_err(io_error("creating", &staging))?,
    }
    let wall_start = clock_reading();
    let captured = match ready {
        Ready::Launch(command) => launch(command, options, interrupts),
        Ready::Attach {
            pid,
            duration,
            task,
            command,
        } => attach(pid, task, command, duration, options, interrupts),
    };
    let wall_end = clock_reading();
    let (mut recording, system) = match captured {
        Ok(captured) => captured.recording(
            options,
            WallClock {
                start: wall_start,
                end: wall_end,
            },
        ),
        Err(error) => {
            remove_staging(&staging);
            return Err(error);
        }
    };
    // While this machine has the system that ran: an update replaces it.
    match symbols::system_symbols(&recording, &system) {
        Ok(symbols) => recording.system_symbols = symbols,
        Err(error) => warn!(
            %error,
            "reading the names of the system's functions: only this machine can name them, \
             until the system is updated"
        ),
    }
    if let Err(error) = recording.write(&staging) {
        remove_staging(&staging);
        return Err(error.into());
    }
    fs::rename(&staging, out).map_err(io_error("renaming into place", out))?;
    log_summary(&recording, out);
    Ok(recording)
}

/// A target checked and ready to record.
enum Ready<'a> {
    Launch(&'a [String]),
    Attach {
        pid: u32,
        duration: Option<Duration>,
        task: Task,
        command: Vec<String>,
    },
}

/// The task port of a running process, which macOS gives to root, or to a
/// program signed to debug, for a process that does not forbid it.
fn open(pid: u32) -> Result<Task> {
    if pid == std::process::id() {
        return Err(Error::Blocked {
            detail: "uhr cannot record itself: it would hold its own threads still".into(),
            fix: None,
        });
    }
    if !process::exists(pid) {
        return Err(Error::NoProcess(pid));
    }
    Task::for_pid(pid).map_err(|_| {
        // SAFETY: geteuid has no preconditions.
        let root = unsafe { libc::geteuid() } == 0;
        if root {
            Error::Blocked {
                detail: format!(
                    "macOS refused uhr the task port of process {pid}: System Integrity \
                     Protection protects it, or it is signed for the hardened runtime without \
                     the com.apple.security.get-task-allow entitlement"
                ),
                fix: Some(
                    "Launch the program with `uhr record -- <program>` instead, or attach to a \
                     build of it signed without the hardened runtime."
                        .into(),
                ),
            }
        } else {
            Error::Blocked {
                detail: format!(
                    "macOS gives the task port of another process, which uhr reads it through, \
                     only to root or to a program signed with the \
                     com.apple.security.cs.debugger entitlement, so uhr cannot attach to \
                     process {pid}"
                ),
                fix: Some(format!(
                    "Run `sudo uhr record --pid {pid}`, or launch the program with `uhr record \
                     -- <program>`, which needs no root."
                )),
            }
        }
    })
}

/// Starts the command with uhr's library, records it from its hello until
/// it exits or uhr is interrupted, and the processes it starts from theirs.
fn launch(
    command: &[String],
    options: &RecordOptions,
    interrupts: &Interrupts,
) -> Result<Captured> {
    let program = &command[0];
    // Before it runs, so that its first frames are read.
    uhr_core::runtimes::prepare(program, &crate::runtime::Probing);
    let service = Service::register()?;
    let environment = launch::environment(&service)?;
    let child = Command::new(program)
        .args(&command[1..])
        .envs(environment)
        .spawn()
        .map_err(|source| Error::Spawn {
            program: program.clone(),
            source,
        })?;
    let mut target = Launched {
        child,
        program: program.clone(),
        reaped: None,
    };
    let hello = first_hello(&service, &mut target, interrupts)?;
    let mut sampler = Sampler::new(options);
    sampler.add(hello.task, hello.pid, Some(hello.waiting), Start::Launched);
    let mut stopped_ns = None;
    let mut ticks = Ticks::new(options.frequency_hz);
    loop {
        // From processes the target started, and processes that exec'd.
        loop {
            match service.receive(0) {
                Ok(Some(hello)) => {
                    sampler.add(hello.task, hello.pid, Some(hello.waiting), Start::During)
                }
                Ok(None) => break,
                Err(error) => {
                    warn!(%error, "receiving hellos: processes the target starts from now on are not recorded");
                    break;
                }
            }
        }
        sampler.tick();
        if target.exited()? {
            break;
        }
        if interrupts.count() > 0 {
            stopped_ns = interrupts.first_ns();
            break;
        }
        if let Some(signal) = interrupts.take_sent() {
            target.signal(signal);
        }
        ticks.wait();
    }
    // Processes that start from now on, and hellos not yet taken, go on
    // unrecorded.
    drop(service);
    let mut captured = sampler.finish(stopped_ns, ticks);
    if !target.exited()? {
        info!("capture stopped; waiting for the target to exit, interrupt again to kill it");
    }
    let mut killed = false;
    while !target.exited()? {
        if interrupts.count() >= 2 && !killed {
            target.signal(libc::SIGKILL);
            killed = true;
        } else if let Some(signal) = interrupts.take_sent() {
            target.signal(signal);
        }
        thread::sleep(WAIT_POLL);
    }
    let status = target.reaped.expect("exited");
    captured.exit = status
        .code()
        .map(Exit::Code)
        .or_else(|| status.signal().map(Exit::Signal));
    captured.command = command.to_vec();
    captured.launched = true;
    Ok(captured)
}

/// A program uhr started. Dropped before it exits, as when its hello never
/// came, it is killed, so no held program is left behind.
struct Launched {
    child: Child,
    program: String,
    reaped: Option<ExitStatus>,
}

impl Launched {
    fn exited(&mut self) -> Result<bool> {
        if self.reaped.is_none() {
            self.reaped = self.child.try_wait().map_err(|source| Error::Wait {
                program: self.program.clone(),
                source,
            })?;
        }
        Ok(self.reaped.is_some())
    }

    fn signal(&self, signal: i32) {
        if self.reaped.is_none() {
            // SAFETY: kill has no memory preconditions, and the child is not
            // reaped, so its pid is still its own.
            unsafe { libc::kill(self.child.id() as libc::pid_t, signal) };
        }
    }
}

impl Drop for Launched {
    fn drop(&mut self) {
        if self.reaped.is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Waits for the launched program's hello.
fn first_hello(service: &Service, target: &mut Launched, interrupts: &Interrupts) -> Result<Hello> {
    let pid = target.child.id();
    let waiting = Instant::now();
    let mut told = false;
    loop {
        let hello = service.receive(10).map_err(|source| Error::Mach {
            action: "receiving the target's task port",
            source,
        })?;
        // Nothing else can have the service's name before the program runs.
        if let Some(hello) = hello.filter(|hello| hello.pid == pid) {
            return Ok(hello);
        }
        if target.exited()? {
            return Err(Error::NoHello {
                program: target.program.clone(),
                status: target.reaped.expect("exited"),
            });
        }
        if interrupts.count() > 0 {
            return Err(Error::Interrupted);
        }
        if !told && waiting.elapsed() >= HELLO_PATIENCE {
            warn!(
                pid,
                "the target has not loaded uhr's library yet: dyld may have left it out, as it \
                 does in protected, hardened and restricted programs and all they run"
            );
            told = true;
        }
    }
}

/// Records a running process until uhr is interrupted, `duration` ends, or
/// it exits. It is never signalled.
fn attach(
    pid: u32,
    task: Task,
    command: Vec<String>,
    duration: Option<Duration>,
    options: &RecordOptions,
    interrupts: &Interrupts,
) -> Result<Captured> {
    let mut sampler = Sampler::new(options);
    sampler.add(task, pid, None, Start::Attached);
    match duration {
        Some(duration) => info!(
            pid,
            seconds = duration.as_secs_f64(),
            "attached, recording for that long or until interrupted"
        ),
        None => info!(pid, "attached, recording until interrupted"),
    }
    let started = Instant::now();
    let mut ticks = Ticks::new(options.frequency_hz);
    let mut stopped_ns = None;
    loop {
        sampler.tick();
        if sampler.processes.is_empty() {
            break;
        }
        if interrupts.count() > 0 {
            stopped_ns = interrupts.first_ns();
            break;
        }
        if duration.is_some_and(|d| started.elapsed() >= d) {
            stopped_ns = Some(monotonic_ns());
            break;
        }
        ticks.wait();
    }
    let exited = sampler.processes.is_empty();
    let mut captured = sampler.finish(stopped_ns, ticks);
    captured.command = command;
    // Only its parent sees its exit status.
    captured.exit = exited.then(|| {
        Exit::Unknown(
            "it exited while uhr was attached, and only its parent sees its exit status".into(),
        )
    });
    Ok(captured)
}

/// The deadlines polls are taken at, one period apart.
struct Ticks {
    period: Duration,
    next: Instant,
    /// Deadlines a poll was taken at, and those passed while a poll took
    /// longer than a period.
    taken: u64,
    missed: u64,
}

impl Ticks {
    fn new(frequency_hz: u64) -> Self {
        let period = Duration::from_nanos(1_000_000_000 / frequency_hz.max(1));
        Self {
            period,
            next: Instant::now() + period,
            taken: 0,
            missed: 0,
        }
    }

    fn wait(&mut self) {
        let now = Instant::now();
        if self.next > now {
            thread::sleep(self.next - now);
        } else {
            let behind = (now - self.next).as_nanos() / self.period.as_nanos();
            self.missed += behind as u64;
            self.next += self.period * behind as u32;
        }
        self.taken += 1;
        self.next += self.period;
    }
}

/// How a process came to be recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Start {
    /// The program uhr launched, held at its hello until its first poll.
    Launched,
    /// A process that said hello during the capture: one the target
    /// started, or that exec'd.
    During,
    Attached,
}

/// The rows of the recording as they are found.
#[derive(Default)]
struct Tables {
    threads: Vec<Thread>,
    thread_names: Vec<ThreadName>,
    mappings: Vec<Mapping>,
    frames: Vec<Frame>,
    frame_ids: HashMap<Frame, u32>,
    stacks: Vec<Vec<u32>>,
    stack_ids: HashMap<Vec<u32>, u32>,
    polled: Polled,
    memory: Vec<MemoryReading>,
    /// Images an update of the system replaces, by path and build id, whose
    /// functions the recording keeps the names of.
    system: HashSet<(String, Option<String>)>,
    /// The code interpreted frames ran, and how the walks went.
    interpreted: Interpreters,
    /// Why uhr read the frames of no runtime a process ran, one for each.
    unsupported: Vec<String>,
}

impl Tables {
    /// The frames of a walk's stack, leaf first, each in the code of the
    /// image segment it falls in, if one does.
    fn native_stack(&mut self, code: &BTreeMap<u64, (u64, u32)>, walk: &Walk) -> Vec<u32> {
        let mut stack = Vec::with_capacity(walk.frames.len());
        for &frame in &walk.frames {
            let (address, return_address) = match frame {
                FrameAddress::InstructionPointer(address) => (address, false),
                FrameAddress::ReturnAddress(address) => (address.get(), true),
            };
            // A return address can be one past the end of the code that holds
            // the call, so find the code from the call instead.
            let lookup = address - u64::from(return_address);
            let mapping = code
                .range(..=lookup)
                .next_back()
                .filter(|(_, (end, _))| lookup < *end)
                .map(|(_, &(_, id))| id);
            let frame = match mapping {
                Some(id) => {
                    let m = &self.mappings[id as usize];
                    Frame {
                        origin: Origin::Binary,
                        address,
                        mapping: Some(id),
                        file_offset: Some(address - m.start + m.file_offset),
                        return_address,
                        interpreted: None,
                    }
                }
                None => Frame {
                    origin: Origin::Unresolved,
                    address,
                    mapping: None,
                    file_offset: None,
                    return_address,
                    interpreted: None,
                },
            };
            stack.push(intern(&mut self.frames, &mut self.frame_ids, frame));
        }
        stack
    }
}

fn intern<T: Clone + Eq + Hash>(items: &mut Vec<T>, ids: &mut HashMap<T, u32>, item: T) -> u32 {
    *ids.entry(item).or_insert_with_key(|item| {
        items.push(item.clone());
        items.len() as u32 - 1
    })
}

/// What the sampler counts for coverage.
#[derive(Default)]
struct Counts {
    walks: u64,
    at_depth: u64,
    failed: u64,
    /// How long threads were held still, in all.
    held_ns: u64,
    /// Threads whose ids don't fit the recording's.
    unnumbered: HashSet<u64>,
    /// Images whose unwind tables could not be read.
    no_unwind_tables: u64,
}

/// One of the target's processes, from its hello or the attach.
struct Process {
    pid: u32,
    task: Task,
    name: String,
    start: Start,
    infos: Option<ImageInfos>,
    /// dyld's stamp of the list as last read.
    timestamp: Option<u64>,
    /// By where their headers are.
    images: BTreeMap<u64, Image>,
    /// The images' executable segments by start: where each ends, and its
    /// mapping.
    code: BTreeMap<u64, (u64, u32)>,
    unwinder: Unwinder,
    /// What a walk read of the process's memory while it held a thread.
    chunks: Chunks,
    /// Whether each address a walk started from is just past a syscall,
    /// read once for each, as code stays where it is.
    syscalls: HashMap<u64, bool>,
    runtime: Runtime,
    /// By the name of uhr's right to each thread's port, which stays the
    /// same while uhr holds it.
    threads: HashMap<mach_port_t, Followed>,
    /// Threads whose ids don't fit the recording's, by the same names.
    unnumbered: HashMap<mach_port_t, Port>,
    memory_due: Instant,
}

struct Followed {
    port: Port,
    tid: u32,
    timeline: Timeline,
    name: String,
    /// Its row in the threads table.
    row: usize,
}

impl Process {
    /// `exec` counts the programs the process ran before, which an exec
    /// replaces.
    fn new(task: Task, pid: u32, exec: u32, start: Start) -> Self {
        let infos = task
            .dyld_info()
            .map_err(io::Error::other)
            .and_then(|info| ImageInfos::at(&task, info.all_image_info_addr))
            .inspect_err(|error| {
                warn!(pid, %error, "reading dyld's list of images: frames will not be named")
            })
            .ok();
        Self {
            pid,
            name: process::name(pid).unwrap_or_default(),
            task,
            start,
            infos,
            timestamp: None,
            images: BTreeMap::new(),
            code: BTreeMap::new(),
            unwinder: Unwinder::new(),
            chunks: Chunks::default(),
            syscalls: HashMap::new(),
            runtime: Runtime::new((pid, exec)),
            threads: HashMap::new(),
            unnumbered: HashMap::new(),
            memory_due: Instant::now(),
        }
    }

    /// Reads dyld's list again if it changed: one 8-byte read when it did
    /// not. Looks for the process's runtime again if it lists more.
    fn update_images(&mut self, tables: &mut Tables, counts: &mut Counts, time_ns: Option<u64>) {
        let Some(infos) = self.infos else {
            return;
        };
        let timestamp = infos.timestamp(&self.task).ok();
        if timestamp.is_some() && timestamp == self.timestamp {
            return;
        }
        // None while dyld changes it: read again at the next poll.
        let Ok(Some(listed)) = infos.list(&self.task) else {
            return;
        };
        let current: HashMap<u64, &str> = listed
            .images
            .iter()
            .map(|(address, path)| (*address, path.as_str()))
            .collect();
        let gone: Vec<u64> = self
            .images
            .iter()
            .filter(|(address, image)| current.get(address) != Some(&image.path.as_str()))
            .map(|(&address, _)| address)
            .collect();
        for address in gone {
            let image = self.images.remove(&address).expect("listed");
            self.unwinder.remove(&image);
            for code in image.code() {
                if self
                    .code
                    .get(&code.start)
                    .is_some_and(|&(end, _)| end == code.end)
                {
                    self.code.remove(&code.start);
                }
            }
        }
        let mut added = false;
        for (address, path) in listed.images {
            if self.images.contains_key(&address) {
                continue;
            }
            added = true;
            let pid = self.pid;
            let image = match read_listed_image(&self.task, address, path, || process::path(pid)) {
                Ok(image) => image,
                Err(error) => {
                    warn!(pid = self.pid, address, %error, "reading an image's header");
                    continue;
                }
            };
            let build_id = image.build_id();
            let replaced = image.header.in_shared_cache()
                || fs::metadata(&image.path).is_ok_and(|m| launch::protected(&m));
            if replaced {
                tables.system.insert((image.path.clone(), build_id.clone()));
            }
            for mapping in image.mappings(self.pid, time_ns) {
                let id = tables.mappings.len() as u32;
                self.code.insert(mapping.start, (mapping.end, id));
                tables.mappings.push(mapping);
            }
            if self.unwinder.add(&self.task, &image).is_err() {
                counts.no_unwind_tables += 1;
            }
            self.images.insert(address, image);
        }
        self.timestamp = Some(listed.timestamp);
        if added {
            self.look_for_runtime(tables);
        }
    }

    /// Looks for the runtime among the code the process maps.
    fn look_for_runtime(&mut self, tables: &mut Tables) {
        let mappings: Vec<Mapping> = self
            .code
            .values()
            .map(|&(_, id)| tables.mappings[id as usize].clone())
            .collect();
        self.runtime.look(
            &self.task,
            &mappings,
            &mut tables.interpreted,
            &mut tables.unsupported,
        );
    }

    /// `None` once it is gone. An exited process can have no threads left
    /// before its task goes.
    fn list_threads(&self) -> Option<Vec<Port>> {
        self.task
            .threads()
            .ok()
            .filter(|threads| !threads.is_empty())
    }

    /// Polls each thread through the port uhr holds for it, which costs an
    /// idle thread one call, and lists the task's threads only when the
    /// kernel counts others than uhr follows, or one could not be polled, as
    /// one that exited. `first` is the process's first poll. Returns whether
    /// the process is still there.
    fn poll(
        &mut self,
        tables: &mut Tables,
        counts: &mut Counts,
        off_cpu: bool,
        first: bool,
    ) -> bool {
        self.update_images(tables, counts, (!first).then(monotonic_ns));
        if self.runtime.looks_again() {
            self.look_for_runtime(tables);
        }
        let names: Vec<mach_port_t> = self.threads.keys().copied().collect();
        let mut lost = Vec::new();
        for name in names {
            let mut followed = self.threads.remove(&name).expect("followed");
            let polled = thread_info(&followed.port).ok().and_then(|info| {
                let thread = thread_name(&info, &self.name);
                Some((self.sample(tables, counts, &followed, info, first)?, thread))
            });
            match polled {
                Some((poll, thread)) => followed.add(poll, thread, self.pid, tables),
                None => lost.push(name),
            }
            self.threads.insert(name, followed);
        }
        let followed = self.threads.len() + self.unnumbered.len();
        if !first && lost.is_empty() && process::thread_count(self.pid) == Some(followed) {
            return true;
        }
        let Some(ports) = self.list_threads() else {
            return false;
        };
        let listed: HashSet<mach_port_t> = ports.iter().map(Port::name).collect();
        for (index, port) in ports.into_iter().enumerate() {
            // Its listing gave uhr a second reference to a port it holds,
            // which dropping it gives back.
            if !self.threads.contains_key(&port.name())
                && !self.unnumbered.contains_key(&port.name())
            {
                self.start_thread(tables, counts, off_cpu, first, index == 0, port);
            }
        }
        let gone: Vec<mach_port_t> = self
            .threads
            .keys()
            .filter(|name| !listed.contains(name))
            .copied()
            .collect();
        for name in gone {
            let mut followed = self.threads.remove(&name).expect("followed");
            followed.end(tables);
        }
        self.unnumbered.retain(|name, _| listed.contains(name));
        true
    }

    /// Follows a thread first seen at this poll, from the port its listing
    /// gave uhr. `oldest` is whether the kernel listed it first.
    fn start_thread(
        &mut self,
        tables: &mut Tables,
        counts: &mut Counts,
        off_cpu: bool,
        first: bool,
        oldest: bool,
        port: Port,
    ) {
        // Gone since it was listed.
        let (Ok(id), Ok(info)) = (thread_id(&port), thread_info(&port)) else {
            return;
        };
        let Ok(tid) = u32::try_from(id) else {
            if counts.unnumbered.insert(id) {
                warn!(
                    pid = self.pid,
                    id, "left out a thread whose id does not fit 32 bits"
                );
            }
            self.unnumbered.insert(port.name(), port);
            return;
        };
        let mut followed = Followed {
            port,
            tid,
            timeline: Timeline::new(self.pid, tid, off_cpu),
            name: String::new(),
            row: tables.threads.len(),
        };
        let name = thread_name(&info, &self.name);
        let Some(poll) = self.sample(tables, counts, &followed, info, first) else {
            return;
        };
        let time_ns = poll.time_ns;
        // Seen first at the process's first poll, it started before the
        // recording, or as the process did.
        let (start_ns, parent_pid) = match (first, self.start) {
            (true, Start::Launched | Start::Attached) => (None, None),
            (true, Start::During) => (Some(time_ns), process::parent(self.pid)),
            (false, _) => (Some(time_ns), Some(self.pid)),
        };
        if first {
            followed.timeline.add(poll, &mut tables.polled);
        } else {
            followed.timeline.started(poll, &mut tables.polled);
        }
        tables.thread_names.push(ThreadName {
            pid: self.pid,
            tid,
            time_ns: start_ns,
            name: name.clone(),
        });
        tables.threads.push(Thread {
            pid: self.pid,
            tid,
            parent_pid,
            parent_tid: None,
            start_ns,
            end_ns: None,
            // The kernel lists a task's threads oldest first, and at a hello
            // the process has only the one.
            main: first && oldest,
        });
        followed.name = name;
        self.threads.insert(followed.port.name(), followed);
    }

    /// A poll of one thread, whose state and CPU time `info` read: with a
    /// fresh stack if it ran since its last poll, or can run now and so may
    /// have. `None` if it could not be held still and walked, as when it
    /// exited since.
    fn sample(
        &mut self,
        tables: &mut Tables,
        counts: &mut Counts,
        followed: &Followed,
        info: ThreadInfo,
        first: bool,
    ) -> Option<Poll> {
        let port = &followed.port;
        // Its state as it was before uhr held it still.
        let state = match self.start {
            // About to run, once answered.
            Start::Launched | Start::During if first => RunState::Running,
            _ => run_state(info.run_state),
        };
        let timeline = &followed.timeline;
        if timeline.last_ns().is_some()
            && !timeline.needs_stack(info.user_ns, info.system_ns, state)
        {
            return Some(Poll {
                time_ns: monotonic_ns(),
                user_ns: info.user_ns,
                system_ns: info.system_ns,
                state,
                in_kernel: false,
                stack: None,
            });
        }
        let held_at = Instant::now();
        let held = suspend(port).ok()?;
        // Exact while it is held.
        let (user_ns, system_ns) = thread_cpu_ns(port).ok()?;
        let time_ns = monotonic_ns();
        let registers = held.registers().ok()?;
        let in_page_fault = held.in_page_fault().ok()?;
        let walk = self.unwinder.walk(
            &self.task,
            &mut self.chunks,
            registers,
            MAX_STACK_DEPTH as usize,
        );
        let memory = Held {
            task: &self.task,
            chunks: RefCell::new(&mut self.chunks),
            limit: MAX_HELD_CHUNKS,
        };
        // The kernel's id of the thread, which runtimes keep as its id.
        let walked = self
            .runtime
            .walk(&memory, u64::from(followed.tid), &walk.ends);
        drop(held);
        counts.held_ns += held_at.elapsed().as_nanos() as u64;
        counts.walks += 1;
        match walk.end {
            End::Outermost => {}
            End::Depth => counts.at_depth += 1,
            End::Failed => counts.failed += 1,
        }
        if walk.frames.is_empty() {
            return None;
        }
        if let Some(walked) = &walked {
            self.runtime.read_code(&self.task, walked);
        }
        let pc = walk.frames[0].address();
        let task = &self.task;
        let in_kernel = in_page_fault
            || *self
                .syscalls
                .entry(pc)
                .or_insert_with(|| in_syscall(task, pc));
        let mut stack = tables.native_stack(&self.code, &walk);
        self.runtime.place(
            &mut tables.interpreted,
            &mut tables.frames,
            &mut tables.frame_ids,
            &mut stack,
            Sample {
                walked: walked.as_ref(),
                ends: &walk.ends,
                cut_short: walk.end != End::Outermost,
            },
        );
        Some(Poll {
            time_ns,
            user_ns,
            system_ns,
            state,
            in_kernel,
            stack: Some(intern(&mut tables.stacks, &mut tables.stack_ids, stack)),
        })
    }

    /// Ends every thread at its last poll, as the process exited or exec'd.
    fn end(self, tables: &mut Tables) {
        for mut followed in self.threads.into_values() {
            followed.end(tables);
        }
    }

    fn read_memory(&mut self, tables: &mut Tables) {
        let now = Instant::now();
        if now < self.memory_due {
            return;
        }
        self.memory_due = now + MEMORY_INTERVAL;
        let Ok(info) = self.task.vm_info() else {
            return;
        };
        tables.memory.push(MemoryReading {
            time_ns: monotonic_ns(),
            pid: self.pid,
            rss_anon_bytes: info.internal,
            rss_file_bytes: info.external,
            rss_shmem_bytes: 0,
            swap_bytes: info.compressed,
            peak_rss_bytes: info.resident_size_peak,
            footprint_bytes: Some(info.phys_footprint),
        });
    }
}

impl Followed {
    /// Ends the thread at its last poll, as it exited.
    fn end(&mut self, tables: &mut Tables) {
        tables.threads[self.row].end_ns = self.timeline.last_ns();
        self.timeline.end(&mut tables.polled);
    }

    /// Adds a poll, at which the thread had `name`.
    fn add(&mut self, poll: Poll, name: String, pid: u32, tables: &mut Tables) {
        let time_ns = poll.time_ns;
        self.timeline.add(poll, &mut tables.polled);
        if self.name != name {
            tables.thread_names.push(ThreadName {
                pid,
                tid: self.tid,
                time_ns: Some(time_ns),
                name: name.clone(),
            });
            self.name = name;
        }
    }
}

/// A thread's name, or its process's where it gave itself none, as Linux
/// names a thread its process's by default.
fn thread_name(info: &ThreadInfo, process: &str) -> String {
    match info.name.is_empty() {
        true => process.to_owned(),
        false => info.name.clone(),
    }
}

fn run_state(state: i32) -> RunState {
    match state {
        libc::TH_STATE_RUNNING => RunState::Running,
        libc::TH_STATE_WAITING | libc::TH_STATE_UNINTERRUPTIBLE => RunState::Waiting,
        _ => RunState::Other,
    }
}

struct Sampler<'a> {
    options: &'a RecordOptions,
    tables: Tables,
    processes: Vec<Process>,
    /// How many programs each pid ran, which its execs start.
    programs: HashMap<u32, u32>,
    counts: Counts,
    start_ns: Option<u64>,
    last_ns: Option<u64>,
    /// uhr's own thread, which polls, and its CPU time before it began.
    own: Port,
    own_cpu_ns: u64,
    /// Its CPU time reading memory.
    memory_cpu_ns: u64,
}

impl<'a> Sampler<'a> {
    fn new(options: &'a RecordOptions) -> Self {
        let own = thread_self();
        let own_cpu_ns = cpu_ns(&own);
        Self {
            options,
            tables: Tables::default(),
            processes: Vec::new(),
            programs: HashMap::new(),
            counts: Counts::default(),
            start_ns: None,
            last_ns: None,
            own,
            own_cpu_ns,
            memory_cpu_ns: 0,
        }
    }

    /// Starts recording a process with a first poll, then lets it go on if
    /// it waits for uhr. A process already recorded says hello again after
    /// an exec, which gives it a new task and threads, so its earlier
    /// threads end.
    fn add(&mut self, task: Task, pid: u32, waiting: Option<Waiting>, start: Start) {
        if let Some(index) = self.processes.iter().position(|p| p.pid == pid) {
            self.processes.remove(index).end(&mut self.tables);
        }
        self.start_ns = self.start_ns.or_else(|| Some(monotonic_ns()));
        let programs = self.programs.entry(pid).or_default();
        let mut process = Process::new(task, pid, *programs, start);
        *programs += 1;
        let alive = process.poll(
            &mut self.tables,
            &mut self.counts,
            self.options.off_cpu,
            true,
        );
        if let Some(waiting) = waiting {
            waiting.answer();
        }
        if alive {
            if self.options.memory {
                read_memory(
                    &mut process,
                    &mut self.tables,
                    &self.own,
                    &mut self.memory_cpu_ns,
                );
            }
            self.processes.push(process);
        }
    }

    fn tick(&mut self) {
        let mut index = 0;
        while index < self.processes.len() {
            let process = &mut self.processes[index];
            if process.poll(
                &mut self.tables,
                &mut self.counts,
                self.options.off_cpu,
                false,
            ) {
                if self.options.memory {
                    read_memory(
                        process,
                        &mut self.tables,
                        &self.own,
                        &mut self.memory_cpu_ns,
                    );
                }
                index += 1;
            } else {
                self.processes.remove(index).end(&mut self.tables);
            }
        }
        self.last_ns = Some(monotonic_ns());
    }

    /// Ends the capture, with a last reading of the memory of the processes
    /// still running. `stopped_ns` is when uhr stopped it, if it did.
    fn finish(mut self, stopped_ns: Option<u64>, ticks: Ticks) -> Captured {
        for process in &mut self.processes {
            for followed in process.threads.values_mut() {
                followed.timeline.end(&mut self.tables.polled);
            }
        }
        if self.options.memory {
            for process in &mut self.processes {
                process.memory_due = Instant::now();
                read_memory(
                    process,
                    &mut self.tables,
                    &self.own,
                    &mut self.memory_cpu_ns,
                );
            }
        }
        let overhead_ns = cpu_ns(&self.own)
            .saturating_sub(self.own_cpu_ns)
            .saturating_sub(self.memory_cpu_ns);
        let end_ns = match (self.last_ns.or(self.start_ns), stopped_ns) {
            (Some(last), Some(stopped)) => Some(last.max(stopped)),
            (last, stopped) => last.or(stopped),
        };
        Captured {
            tables: self.tables,
            counts: self.counts,
            ticks,
            start_ns: self.start_ns,
            end_ns,
            overhead_ns,
            memory_overhead_ns: self.memory_cpu_ns,
            command: Vec::new(),
            launched: false,
            exit: None,
        }
    }
}

/// Reads `process`'s memory if it is due, and adds uhr's CPU time doing so
/// to `spent_ns`.
fn read_memory(process: &mut Process, tables: &mut Tables, own: &Port, spent_ns: &mut u64) {
    let before = cpu_ns(own);
    process.read_memory(tables);
    *spent_ns += cpu_ns(own).saturating_sub(before);
}

fn cpu_ns(thread: &Port) -> u64 {
    thread_cpu_ns(thread).map_or(0, |(user, system)| user + system)
}

/// What a capture found, and how it ended.
struct Captured {
    tables: Tables,
    counts: Counts,
    ticks: Ticks,
    start_ns: Option<u64>,
    end_ns: Option<u64>,
    /// uhr's own CPU time polling, and reading memory.
    overhead_ns: u64,
    memory_overhead_ns: u64,
    command: Vec<String>,
    launched: bool,
    exit: Option<Exit>,
}

impl Captured {
    /// The recording, and the images whose functions' names it is to keep.
    fn recording(
        self,
        options: &RecordOptions,
        wall_clock: WallClock,
    ) -> (Recording, HashSet<(String, Option<String>)>) {
        let Captured {
            tables,
            counts,
            ticks,
            ..
        } = self;
        let Tables {
            mut threads,
            thread_names,
            mappings,
            frames,
            stacks,
            polled,
            memory,
            system,
            interpreted,
            unsupported,
            ..
        } = tables;
        let Polled {
            mut samples,
            mut off_cpu,
        } = polled;
        samples.sort_by_key(|s| s.time_ns);
        off_cpu.sort_by_key(|i| (i.start_ns, i.pid, i.tid, i.end_ns));
        threads.sort_by_key(|t| (t.pid, t.tid, t.start_ns));

        let mut signals = vec![
            Signal::UserCPUSamples,
            Signal::KernelCPUSamples,
            Signal::UserStacks,
        ];
        if options.off_cpu {
            signals.extend([Signal::OffCPUTime, Signal::OffCPUStacks]);
        }
        let mut missing_signals = vec![MissingSignal {
            signal: Signal::KernelStacks,
            reason: "macOS lets no process read the kernel's stacks, but through xctrace or \
                     private interfaces, so time in the kernel is under the user stack that \
                     entered it"
                .into(),
        }];
        let mut missing = |asked: bool, signal: Signal, reason: &str| {
            if asked {
                missing_signals.push(MissingSignal {
                    signal,
                    reason: reason.into(),
                });
            }
        };
        missing(
            options.off_cpu && options.wakeups,
            Signal::Wakeups,
            "macOS does not tell another process when a thread is woken, nor by what",
        );
        missing(
            options.syscalls,
            Signal::SyscallCalls,
            "macOS lets no process count another's syscalls without DTrace, which System \
             Integrity Protection restricts",
        );
        missing(
            options.page_faults,
            Signal::PageFaults,
            "macOS lets no process sample another's page faults with their stacks",
        );
        missing(
            options.memory,
            Signal::MemoryRegions,
            "uhr does not read the regions of a process's memory on macOS yet",
        );
        missing(
            options.memory,
            Signal::RegionMemory,
            "uhr does not read how much of each kind of region is resident on macOS yet",
        );

        let period_us = ticks.period.as_micros();
        let held_us = counts.held_ns / counts.walks.max(1) / 1000;
        let mut known_biases = vec![
            format!(
                "uhr polls each thread every {period_us} µs, and samples its CPU time only at a \
                 poll that finds it running, with the stack it has then, as a CPU-clock sampler \
                 samples a thread only while it runs: each sample has the CPU time since the \
                 thread's last one, which can include code it ran before it last waited."
            ),
            "Time in the kernel is under the user stack of the code that entered it, without \
             the kernel's own frames. A thread's syscall is the function of libsystem_kernel \
             that stack ends in, which is named for the call; time in the kernel at a stack \
             that ends elsewhere, as in a page fault, is in no known syscall."
                .into(),
            format!(
                "uhr holds each thread that ran since its last poll still while it walks its \
                 stack, {held_us} µs on average, which slows a busy target."
            ),
            "The CPU time a thread used after its last poll, before it exited, is not counted, \
             and threads that start and exit between two polls are not seen."
                .into(),
        ];
        if options.off_cpu {
            known_biases.push(format!(
                "Time a thread spent off CPU between two polls at which it ran, as waits shorter \
                 than the {period_us} µs between polls, is counted, but without a stack and in \
                 an unknown state."
            ));
        }
        let stackless_ns: u64 = samples
            .iter()
            .filter(|s| s.stack.is_none())
            .map(|s| s.cpu_ns)
            .sum();
        if stackless_ns > 0 {
            let cpu_ns: u64 = samples.iter().map(|s| s.cpu_ns).sum();
            known_biases.push(format!(
                "{:.1}% of the CPU time has no stack: threads used it in a mode after the last \
                 poll that found them running in that mode, before they exited or the capture \
                 ended, as threads that run only briefly between waits do.",
                stackless_ns as f64 / cpu_ns.max(1) as f64 * 100.0
            ));
        }
        if ticks.missed > 0 {
            known_biases.push(format!(
                "{} of {} polls came late, as polling all threads took longer than a period, \
                 so their CPU time went to fewer, later stacks.",
                ticks.missed,
                ticks.missed + ticks.taken
            ));
        }
        if counts.failed > 0 {
            known_biases.push(format!(
                "{} of {} stacks end before their outermost frame, where a caller could not be \
                 found, as in code with neither unwind tables nor a frame pointer.",
                counts.failed, counts.walks
            ));
        }
        if counts.no_unwind_tables > 0 {
            known_biases.push(format!(
                "The unwind tables of {} images could not be read, so stacks through them \
                 follow frame pointers.",
                counts.no_unwind_tables
            ));
        }
        let mut reasons: BTreeMap<&str, usize> = BTreeMap::new();
        for reason in &unsupported {
            *reasons.entry(reason).or_default() += 1;
        }
        known_biases.extend(reasons.into_iter().map(|(reason, processes)| {
            format!(
                "{processes} processes ran an interpreter whose frames uhr did not read, so \
                 their stacks show only its own code: {reason}."
            )
        }));
        if !counts.unnumbered.is_empty() {
            known_biases.push(format!(
                "{} threads whose ids do not fit 32 bits are left out.",
                counts.unnumbered.len()
            ));
        }
        if !self.launched {
            known_biases.push(
                "uhr follows no process the attached one starts: only processes uhr launches \
                 load its library, which sends their task ports."
                    .into(),
            );
        }
        let mut streams = vec![Stream {
            id: "mach".into(),
            collector: Collector::Mach {
                sampling: Some(Sampling {
                    event: "thread-poll".into(),
                    frequency_hz: 1_000_000_000 / ticks.period.as_nanos() as u64,
                    requested_frequency_hz: options.frequency_hz,
                }),
            },
            signals,
            missing_signals,
            coverage: StreamCoverage {
                lost_events: 0,
                stacks: Some(StackCoverage {
                    unwinding: Unwinding::UnwindTables,
                    stack_copy_bytes: None,
                    samples: samples.len() as u64,
                    page_fault_samples: None,
                    off_cpu_intervals: options.off_cpu.then_some(off_cpu.len() as u64),
                    throttle_events: None,
                    max_stack_depth: MAX_STACK_DEPTH,
                    stacks_at_stack_limit: counts.at_depth,
                    stacks_cut_at_stack_copy: None,
                    stacks_not_unwound: None,
                    interpreters: interpreted.coverage(),
                }),
                overhead_ns: Some(self.overhead_ns),
                known_biases,
            },
        }];
        if options.memory {
            let interval_ms = MEMORY_INTERVAL.as_millis();
            streams.push(Stream {
                id: "task_info".into(),
                collector: Collector::TaskInfo {
                    interval_ns: MEMORY_INTERVAL.as_nanos() as u64,
                },
                signals: vec![Signal::ResidentMemory],
                missing_signals: Vec::new(),
                coverage: StreamCoverage {
                    lost_events: 0,
                    stacks: None,
                    overhead_ns: Some(self.memory_overhead_ns),
                    known_biases: vec![
                        format!(
                            "Memory is read every {interval_ms} ms, so what comes and goes \
                             between readings is missed, except in the peak each reading has."
                        ),
                        "A process's own memory is what the kernel calls internal, and its \
                         pages of files external. Memory it shares with others, as the system's \
                         libraries, counts in each that maps it, and none is told apart as \
                         shared."
                            .into(),
                        "Swap is the process's memory the kernel compressed, which it keeps in \
                         RAM, in less room, or moved out to disk."
                            .into(),
                    ],
                },
            });
        }
        let recording = Recording {
            manifest: Manifest {
                format_version: FORMAT_VERSION,
                platform: Platform {
                    os: env::consts::OS.into(),
                    arch: env::consts::ARCH.into(),
                },
                target: recording::Target {
                    command: self.command,
                    launched: self.launched,
                    // uhr sets none of the variables that have runtimes
                    // name the code they compile, as their perf maps are
                    // for Linux.
                    runtime_support: self.launched.then(Vec::new),
                    exit: self.exit,
                },
                clock: Clock::Monotonic,
                start_ns: self.start_ns,
                end_ns: self.end_ns,
                wall_clock: Some(wall_clock),
                streams,
                missing_signals: Vec::new(),
                kernel_symbols: KernelSymbols::Unavailable {
                    reason: "macOS keeps the kernel's symbols from other processes".into(),
                },
            },
            threads,
            thread_names,
            mappings,
            frames,
            stacks,
            samples,
            page_faults: Vec::new(),
            off_cpu,
            kernel_symbols: Vec::new(),
            jit_symbols: Vec::new(),
            interpreted_code: interpreted.code,
            syscall_calls: Vec::new(),
            memory,
            regions: Vec::new(),
            region_memory: Vec::new(),
            system_symbols: Vec::new(),
        };
        (recording, system)
    }
}

fn clock_reading() -> ClockReading {
    ClockReading::read(monotonic_ns, realtime_ns)
}

fn staging_dir(out: &Path) -> Result<PathBuf> {
    let Some(name) = out.file_name() else {
        return Err(Error::UnusableOutput(out.to_owned()));
    };
    let mut staging = name.to_owned();
    staging.push(".partial");
    Ok(out.with_file_name(staging))
}

fn remove_staging(staging: &Path) {
    if let Err(cleanup) = fs::remove_dir_all(staging) {
        warn!("removing {}: {cleanup}", staging.display());
    }
}

fn log_summary(recording: &Recording, out: &Path) {
    let cpu_ns: u64 = recording.samples.iter().map(|s| s.cpu_ns).sum();
    info!(
        samples = recording.samples.len(),
        cpu_seconds = %format!("{:.2}", cpu_ns as f64 / 1e9),
        path = %out.display(),
        "recorded"
    );
    match &recording.manifest.target.exit {
        Some(Exit::Code(code)) => info!(code, "target exited"),
        Some(Exit::Signal(signal)) => info!(signal, "target was killed by a signal"),
        Some(Exit::Unknown(reason)) => info!(%reason, "target exit status unknown"),
        None => info!("target was still running"),
    }
    for stream in &recording.manifest.streams {
        if let Some(stacks) = stream
            .coverage
            .stacks
            .as_ref()
            .filter(|s| s.stacks_at_stack_limit > 0)
        {
            warn!(
                stacks = stacks.stacks_at_stack_limit,
                max_stack_depth = stacks.max_stack_depth,
                "stacks were cut at the depth limit"
            );
        }
    }
}
