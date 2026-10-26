mod convert;
mod unwind;

pub(crate) use convert::is_dummy;

use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use rustix::io::{Errno, FdFlags, fcntl_setfd};
use rustix::pipe::{PipeFlags, pipe_with};
use rustix::process::{Pid, Signal, geteuid, kill_process, set_parent_process_death_signal};
use tracing::{debug, info, warn};

use crate::doctor;
use crate::ebpf::{self, Syscalls};
use crate::kallsyms::Kallsyms;
use crate::launch::{self, Held, Interrupts, Process, monotonic_ns};
use crate::perf_map;
use crate::runtimes;
use uhr_core::doctor::Status;
use uhr_core::perf_map::name_jit_frames;
use uhr_core::recording::{self, Collector, Exit, MissingSignal, Recording, StreamCoverage};

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
    #[error("command not found or not executable: {0}")]
    CommandNotFound(String),
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
    #[error("{path} is not a number: {value:?}")]
    NotANumber { path: &'static str, value: String },
    #[error(transparent)]
    Launch(#[from] launch::Error),
    #[error("{action} {}", .path.display())]
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    /// perf exited before it started sampling.
    #[error(
        "perf exited with {status} before it started sampling. Run `uhr doctor`, or run \
         `perf {command}` to see perf's own error"
    )]
    PerfStart { status: ExitStatus, command: String },
    /// perf failed, and what it left could not be converted.
    #[error(
        "perf exited with {status} and wrote no usable data. Run `uhr doctor`, or run \
         `perf {command}` to see perf's own error"
    )]
    NoUsableData {
        status: ExitStatus,
        command: String,
        source: Box<Error>,
    },
    #[error("converting {}, which is kept for inspection", .path.display())]
    Convert { path: PathBuf, source: Box<Error> },
    /// perf.data does not hold what the collector asked perf for.
    #[error("{0}")]
    UnexpectedData(String),
    #[error("parsing perf.data")]
    PerfData(#[source] linux_perf_data::Error),
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
    pub frequency_hz: u64,
    pub unwind: Unwind,
    /// Record every context switch, with the stack of each thread going
    /// off CPU.
    pub off_cpu: bool,
    /// Set the variables that make runtimes, such as Python 3.12 and later
    /// and Node, name the code they compile in perf maps.
    pub runtime_support: bool,
    /// Count and time the target's syscalls with uhr's eBPF programs, if
    /// this host lets uhr load them.
    pub syscalls: bool,
}

/// What to record.
#[derive(Debug, Clone)]
pub enum Target {
    /// Start the command, and record it from its first instruction until it
    /// exits.
    Launch(Vec<String>),
    /// Record a running process, and the threads and processes it starts,
    /// until uhr is interrupted, `duration` ends, or they all exit.
    Attach {
        pid: u32,
        duration: Option<Duration>,
    },
}

/// How user stacks are walked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unwind {
    FramePointers,
    /// perf copies this many bytes of user stack with each sample, and uhr
    /// unwinds them with the files' unwind tables after recording.
    Dwarf {
        stack_bytes: u32,
    },
}

/// Records `options.target` with perf and writes the recording to `out`,
/// which must not exist. The recording is built in a sibling
/// `.partial` directory and renamed into place once complete. The first of
/// `interrupts` ends the capture, and a second kills the target. One that
/// comes before the capture starts ends it with nothing recorded, so
/// callers can count interrupts from before they call.
pub fn record(options: &RecordOptions, interrupts: &Interrupts, out: &Path) -> Result<Recording> {
    // A perf map older than this, or than an attached process, belongs to
    // an earlier process with its pid.
    let since = SystemTime::now();
    let perf_version = doctor::perf_version().map_err(|detail| Error::Blocked {
        detail,
        fix: Some(doctor::INSTALL_PERF.into()),
    })?;
    if let Unwind::Dwarf { .. } = options.unwind {
        let check = doctor::check_dwarf_unwinding();
        if check.status != Status::Ok {
            return Err(Error::Blocked {
                detail: check.detail,
                fix: check.fix,
            });
        }
    }
    let (ready, command) = match &options.target {
        Target::Launch(command) => {
            let Some(program) = command.first() else {
                return Err(Error::NoCommand);
            };
            check_program(program)?;
            (Ready::Launch(command), command.clone())
        }
        &Target::Attach { pid, duration } => {
            let process = Process::open(pid).map_err(|e| no_process(pid, e))?;
            let command = command_line(pid, &process)?;
            let started = Process::started(pid).map_err(|e| no_process(pid, e))?;
            let owner = Process::file_owner(pid).map_err(|e| no_process(pid, e))?;
            let ready = Ready::Attach {
                pid,
                duration,
                process,
                started,
                owner,
            };
            (ready, command)
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

    let max_stack_depth = read_max_stack_depth()?;
    let perf_data = staging.join("perf.data");
    // Without the watch, a map counts only if it belongs to root or the
    // user the target started as.
    let watch = perf_map::watch(Path::new(perf_map::DIR))
        .inspect_err(|error| warn!(%error, "watching for perf maps"))
        .ok();
    let ended = run(&perf_data, options, interrupts, &ready);
    let map_owners = watch.map(perf_map::Watch::stop).unwrap_or_default();
    let ended = match ended {
        Ok(ended) => ended,
        Err(error) => {
            remove_staging(&staging);
            return Err(diagnose(error));
        }
    };
    // While the boot, the loaded modules and uhr's own eBPF programs are
    // still the ones recorded.
    let kallsyms = Kallsyms::read();
    let syscalls = ended.syscalls.map(|s| s.map(ebpf::Stopped::unload));

    let recording = convert::convert(convert::Input {
        perf_data: &perf_data,
        command: &command,
        launched_pid: ended.launched_pid,
        runtime_support: ended.runtime_support,
        exit: ended.exit,
        stopped_ns: ended.stopped_ns,
        attached_ns: ended.attached_ns,
        perf_version,
        requested_frequency_hz: options.frequency_hz,
        max_stack_depth,
        kallsyms: kallsyms.as_ref(),
    });
    let mut recording = match recording {
        Ok(recording) => recording,
        Err(error) if !finished(ended.perf) => {
            remove_staging(&staging);
            return Err(Error::NoUsableData {
                status: ended.perf,
                command: diagnosis(options),
                source: Box::new(error),
            });
        }
        Err(error) => {
            return Err(Error::Convert {
                path: perf_data,
                source: Box::new(error),
            });
        }
    };

    // While the maps are still there and the processes' own.
    let since_for = |pid| match ready {
        Ready::Attach {
            pid: attached,
            started,
            ..
        } if attached == pid => started,
        _ => since,
    };
    let started_as = match ready {
        Ready::Launch(_) => geteuid().as_raw(),
        Ready::Attach { owner, .. } => owner,
    };
    let owners = |pid| map_owners.of(pid, started_as);
    let named = name_jit_frames(&mut recording, |pid| {
        perf_map::read(pid, since_for(pid), &owners(pid)).unwrap_or_else(|error| {
            warn!(pid, %error, "reading the perf map");
            None
        })
    });
    if !named.is_empty() {
        info!(
            processes = named.len(),
            "named JIT code from the runtimes' perf maps"
        );
    }

    add_syscalls(
        &mut recording,
        syscalls,
        matches!(ready, Ready::Attach { .. }),
    );

    // uhr made the runtimes it launched write them, so it cleans them up
    // once the recording holds the names.
    let clean_up = matches!(ready, Ready::Launch(_)) && options.runtime_support;
    if let Err(error) = recording.write(&staging) {
        if clean_up && !named.is_empty() {
            let maps: Vec<_> = named
                .iter()
                .map(|&pid| perf_map::path(pid).display().to_string())
                .collect();
            warn!(
                maps = maps.join(" "),
                "kept the perf maps that name the JIT code in {}",
                perf_data.display()
            );
        }
        return Err(match error {
            // What it was converted from is all there is to look into.
            error @ recording::Error::Invalid { .. } => Error::Convert {
                path: perf_data,
                source: Box::new(error.into()),
            },
            error => error.into(),
        });
    }
    if clean_up {
        let pids: BTreeSet<u32> = recording.threads.iter().map(|t| t.pid).collect();
        remove_runtime_files(pids, since, owners);
    }
    fs::remove_file(&perf_data).map_err(io_error("removing", &perf_data))?;
    fs::rename(&staging, out).map_err(io_error("renaming into place", out))?;
    log_summary(&recording, out);
    Ok(recording)
}

/// Adds what the eBPF programs counted as a stream of its own, or says why
/// there is none.
fn add_syscalls(
    recording: &mut Recording,
    counted: Option<Result<ebpf::Counted, ebpf::Error>>,
    attached: bool,
) {
    match counted {
        Some(Ok(counted)) => {
            let mut known_biases = vec![
                "Each call's time includes part of what the eBPF programs take, which for a \
                 quick syscall is more than the call itself."
                    .to_owned(),
                "Syscalls of 32-bit code are named from the 64-bit table, so their names are \
                 wrong."
                    .to_owned(),
            ];
            if attached {
                known_biases.push(
                    "Calls a thread was already in when uhr attached are left out.".to_owned(),
                );
            }
            recording.manifest.streams.push(recording::Stream {
                id: "ebpf".into(),
                collector: Collector::Ebpf,
                signals: vec![recording::Signal::SyscallCalls],
                missing_signals: Vec::new(),
                coverage: StreamCoverage {
                    lost_events: counted.lost,
                    stacks: None,
                    overhead_ns: None,
                    known_biases,
                },
            });
            recording.syscall_calls = counted.calls;
        }
        Some(Err(error)) => recording.manifest.missing_signals.push(MissingSignal {
            signal: recording::Signal::SyscallCalls,
            reason: error.reason(),
        }),
        None => {}
    }
}

/// Removes the perf maps the processes `pids` wrote since `since`, and the
/// logs V8 writes beside them.
fn remove_runtime_files(pids: BTreeSet<u32>, since: SystemTime, owners: impl Fn(u32) -> Vec<u32>) {
    let started_in = env::current_dir();
    for pid in pids {
        match (perf_map::remove(pid, since, &owners(pid)), &started_in) {
            (Ok(Some("node")), Ok(dir)) => match runtimes::remove_v8_logs(dir, pid, since) {
                Ok(0) => warn!(
                    pid,
                    "a Node process left V8's log outside {}",
                    dir.display()
                ),
                Ok(_) => {}
                Err(error) => warn!(pid, %error, "removing V8's logs"),
            },
            (Ok(Some("node")), Err(error)) => {
                warn!(pid, %error, "finding V8's logs: reading the working directory")
            }
            (Ok(_), _) => {}
            (Err(error), _) => warn!(pid, %error, "removing the perf map"),
        }
    }
}

/// Why perf could not start, from the doctor's checks if they find it. They
/// cost as much as a recording's start, so they run only then, and show
/// perf's own error, which `--quiet` hides.
fn diagnose(error: Error) -> Error {
    if !matches!(error, Error::PerfStart { .. }) {
        return error;
    }
    match doctor::check_perf().blocked().next() {
        Some(check) => Error::Blocked {
            detail: check.detail.clone(),
            fix: check.fix.clone(),
        },
        None => error,
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
    for missing in &recording.manifest.missing_signals {
        warn!(signal = missing.signal.as_str(), reason = %missing.reason, "signal not captured");
    }
    for stream in &recording.manifest.streams {
        if let Collector::Perf {
            frequency_hz,
            requested_frequency_hz,
            ..
        } = &stream.collector
            && frequency_hz != requested_frequency_hz
        {
            warn!(
                requested_hz = requested_frequency_hz,
                actual_hz = frequency_hz,
                "perf lowered the sampling frequency to the kernel's limit"
            );
        }
        for missing in &stream.missing_signals {
            warn!(signal = missing.signal.as_str(), reason = %missing.reason, "signal not captured");
        }
        let coverage = &stream.coverage;
        if coverage.lost_events > 0 {
            warn!(
                lost_events = coverage.lost_events,
                "the kernel dropped events"
            );
        }
        if let Some(stacks) = coverage
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

/// perf's flags, without what it records: `-p` and a pid, or a command.
pub(crate) fn perf_args(perf_data: &Path, options: &RecordOptions) -> Vec<OsString> {
    let mut args: Vec<OsString> = [
        "record",
        "--quiet",
        "--event=cpu-clock",
        &format!("--freq={}", options.frequency_hz),
        "--sample-cpu",
        "--clockid=CLOCK_MONOTONIC",
        "--buildid-mmap",
    ]
    .iter()
    .map(OsString::from)
    .collect();
    if options.off_cpu {
        // A sample at each switch gives the stack, and the switch records
        // give when the thread came back and whether it was preempted.
        args.push("--event=context-switches/period=1/".into());
        args.push("--switch-events".into());
    }
    match options.unwind {
        Unwind::FramePointers => args.push("--call-graph=fp".into()),
        Unwind::Dwarf { stack_bytes } => {
            args.push(format!("--call-graph=dwarf,{stack_bytes}").into());
            // The stack copies are most of the data, and compress well.
            args.push("-z".into());
        }
    }
    args.push("--output".into());
    args.push(perf_data.into());
    args
}

/// A perf command a person can run to see the error perf printed to
/// itself: the same flags without --quiet, launching a command itself.
fn diagnosis(options: &RecordOptions) -> String {
    let mut args = perf_args(Path::new("perf.data"), options);
    args.retain(|a| a != "--quiet");
    match &options.target {
        Target::Launch(command) => {
            args.push("--".into());
            args.extend(command.iter().map(OsString::from));
        }
        Target::Attach { pid, .. } => args.extend(["--pid".into(), pid.to_string().into()]),
    }
    join_args(&args)
}

fn join_args(args: &[OsString]) -> String {
    args.iter()
        .map(|a| a.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ")
}

fn remove_staging(staging: &Path) {
    if let Err(cleanup) = fs::remove_dir_all(staging) {
        warn!("removing {}: {cleanup}", staging.display());
    }
}

/// How a capture ended.
struct Ended {
    /// The runtimes whose perf maps were on in a target uhr launched.
    runtime_support: Option<Vec<String>>,
    /// The process uhr started, when it launched the target.
    launched_pid: Option<u32>,
    exit: Option<Exit>,
    perf: ExitStatus,
    /// When uhr stopped the capture before the target exited, on
    /// CLOCK_MONOTONIC.
    stopped_ns: Option<u64>,
    /// When perf started sampling a process uhr attached to.
    attached_ns: Option<u64>,
    /// `None` when not asked for.
    syscalls: Option<Result<ebpf::Stopped, ebpf::Error>>,
}

/// A target checked and ready to record.
enum Ready<'a> {
    Launch(&'a [String]),
    /// Opened before its command line was read, so that both and its exit
    /// are of the same process.
    Attach {
        pid: u32,
        duration: Option<Duration>,
        process: Process,
        started: SystemTime,
        /// The user its files belong to.
        owner: u32,
    },
}

fn run(
    perf_data: &Path,
    options: &RecordOptions,
    interrupts: &Interrupts,
    ready: &Ready,
) -> Result<Ended> {
    match ready {
        // Held until perf samples, so perf sees it from its first
        // instruction.
        Ready::Launch(command) => {
            let (environment, runtimes) =
                runtimes::environment(|v| env::var_os(v), options.runtime_support);
            let held = Held::spawn(command, &environment)?;
            let pid = held.pid();
            let syscalls = options.syscalls.then(|| Syscalls::start(pid, true));
            let mut sampling = sample(perf_data, options, pid)?;
            sampling.stop_if_interrupted(interrupts)?;
            let mut target = held.release()?;
            let program = Path::new(&command[0]);
            let (target, perf) =
                supervise(program, &mut target.child, &mut sampling.perf, interrupts)?;
            sampling.finish_relay();
            Ok(Ended {
                runtime_support: Some(runtimes),
                launched_pid: Some(pid),
                exit: exit(target),
                perf,
                stopped_ns: interrupts.first_ns(),
                attached_ns: None,
                syscalls: syscalls.map(|s| s.and_then(Syscalls::stop)),
            })
        }
        Ready::Attach {
            pid,
            duration,
            process,
            ..
        } => {
            let mut sampling = sample(perf_data, options, *pid)?;
            let syscalls = options.syscalls.then(|| Syscalls::start(*pid, false));
            let attached_ns = monotonic_ns();
            sampling.stop_if_interrupted(interrupts)?;
            match duration {
                Some(duration) => info!(
                    pid,
                    seconds = duration.as_secs_f64(),
                    "attached, recording for that long or until interrupted"
                ),
                None => info!(pid, "attached, recording until interrupted"),
            }
            let (perf, stopped_ns) = watch(&mut sampling.perf, interrupts, *duration)?;
            sampling.finish_relay();
            let exited = process.exited().map_err(|e| no_process(*pid, e))?;
            if stopped_ns.is_none() && !exited {
                warn!(pid, "perf stopped before the process exited");
            }
            // Only the process's parent sees its exit status.
            let exit = exited.then(|| {
                Exit::Unknown(
                    "it exited while uhr was attached, and only its parent sees its exit status"
                        .into(),
                )
            });
            Ok(Ended {
                runtime_support: None,
                launched_pid: None,
                exit,
                perf,
                stopped_ns,
                attached_ns: Some(attached_ns),
                syscalls: syscalls.map(|s| s.and_then(Syscalls::stop)),
            })
        }
    }
}

/// perf sampling a process, and the copy of its stderr if uhr relays it.
struct Sampling {
    perf: Perf,
    relay: Option<mpsc::Receiver<()>>,
}

impl Sampling {
    /// An interrupt that came before the capture started ends uhr there.
    fn stop_if_interrupted(&mut self, interrupts: &Interrupts) -> Result<()> {
        if interrupts.count() == 0 {
            return Ok(());
        }
        self.perf.stop();
        let _ = self.perf.wait();
        self.finish_relay();
        Err(Error::Interrupted)
    }

    fn finish_relay(&self) {
        if let Some(done) = &self.relay {
            let _ = done.recv_timeout(RELAY_GRACE);
        }
    }
}

/// Attaches perf to `pid` and returns once it samples.
fn sample(perf_data: &Path, options: &RecordOptions, pid: u32) -> Result<Sampling> {
    let mut args = perf_args(perf_data, options);
    args.extend(["--pid".into(), pid.to_string().into(), "--delay=-1".into()]);
    debug!(command = %format!("perf {}", join_args(&args)), "running perf");
    let stderr = if stderr_can_break() {
        Stdio::piped()
    } else {
        Stdio::inherit()
    };
    let perf_path = Path::new("perf");
    let mut perf = Perf::attach(perf_path, args, stderr).map_err(io_error("running", perf_path))?;
    let relay = perf.child.stderr.take().map(relay_stderr);
    let mut sampling = Sampling { perf, relay };
    let exited = sampling
        .perf
        .enable()
        .map_err(io_error("waiting for", perf_path))?;
    if let Some(status) = exited {
        sampling.finish_relay();
        return Err(Error::PerfStart {
            status,
            command: diagnosis(options),
        });
    }
    Ok(sampling)
}

/// perf attached to a process with sampling off.
pub(crate) struct Perf {
    pub(crate) child: Child,
    control: OwnedFd,
    ack: fs::File,
}

impl Perf {
    /// Runs perf with `args`, which name what it attaches to, and a control
    /// pipe to turn sampling on with.
    pub(crate) fn attach(perf: &Path, mut args: Vec<OsString>, stderr: Stdio) -> io::Result<Self> {
        let (control_read, control) = pipe_with(PipeFlags::CLOEXEC)?;
        let (ack, ack_write) = pipe_with(PipeFlags::CLOEXEC)?;
        let (control_fd, ack_fd) = (control_read.as_raw_fd(), ack_write.as_raw_fd());
        args.push(format!("--control=fd:{control_fd},{ack_fd}").into());
        let mut command = Command::new(perf);
        command.args(args).stderr(stderr).process_group(0);
        let inherit = move || {
            // SAFETY: both fds stay open in the child until exec.
            let (control, ack) = unsafe {
                (
                    BorrowedFd::borrow_raw(control_fd),
                    BorrowedFd::borrow_raw(ack_fd),
                )
            };
            fcntl_setfd(control, FdFlags::empty())?;
            fcntl_setfd(ack, FdFlags::empty())?;
            // If uhr dies, perf still finishes its file.
            set_parent_process_death_signal(Some(Signal::INT))?;
            Ok(())
        };
        // SAFETY: `inherit` runs between fork and exec, so it only makes
        // system calls, which are async-signal-safe.
        unsafe { command.pre_exec(inherit) };
        let child = command.spawn()?;
        Ok(Self {
            child,
            control,
            ack: ack.into(),
        })
    }

    /// Turns sampling on and waits until perf says it does. If perf exits
    /// instead, as it does when it can't attach or doesn't know the flags,
    /// returns its status.
    pub(crate) fn enable(&mut self) -> io::Result<Option<ExitStatus>> {
        let mut reply = [0; 4];
        let enabled = rustix::io::write(&self.control, b"enable\n").is_ok()
            && self.ack.read_exact(&mut reply).is_ok()
            && &reply == b"ack\n";
        if enabled {
            return Ok(None);
        }
        self.wait().map(Some)
    }

    /// Stops sampling. perf then finishes its file and exits.
    pub(crate) fn stop(&self) {
        let _ = kill_process(Pid::from_child(&self.child), Signal::INT);
    }

    pub(crate) fn wait(&mut self) -> io::Result<ExitStatus> {
        self.child.wait()
    }
}

/// Left running, perf would keep recording; exited, it would stay a zombie.
impl Drop for Perf {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            self.stop();
        }
        let _ = self.child.wait();
    }
}

/// Whether perf exited after writing its file. Stopped by SIGINT, perf
/// re-raises it once the file is written.
pub(crate) fn finished(status: ExitStatus) -> bool {
    status.success() || status.signal() == Some(Signal::INT.as_raw())
}

/// How often supervision looks at the target, perf and the interrupts.
const POLL: Duration = Duration::from_millis(10);

/// Waits for the target to exit, and stops perf then. Processes the target
/// leaves running are not followed after that. An interrupt stops perf at
/// once, but uhr still waits for the target: a terminal's Ctrl-C reaches it
/// too, and one sent to uhr alone is passed on. A second interrupt kills
/// it. If perf stops on its own first, the target is asked to stop.
fn supervise(
    program: &Path,
    target: &mut Child,
    perf: &mut Perf,
    interrupts: &Interrupts,
) -> Result<(ExitStatus, ExitStatus)> {
    let pid = Pid::from_child(target);
    let (mut target_status, mut perf_status) = (None, None);
    let (mut perf_stopped, mut target_stopped, mut killed) = (false, false, false);
    loop {
        if target_status.is_none() {
            target_status = target
                .try_wait()
                .map_err(io_error("waiting for", program))?;
        }
        if perf_status.is_none() {
            perf_status = perf
                .child
                .try_wait()
                .map_err(io_error("waiting for", Path::new("perf")))?;
        }
        let interrupted = interrupts.count();
        if (interrupted > 0 || target_status.is_some()) && perf_status.is_none() && !perf_stopped {
            perf.stop();
            perf_stopped = true;
            if target_status.is_none() {
                info!(
                    "capture stopped; waiting for the target to exit, interrupt again to kill it"
                );
            }
        }
        if perf_status.is_some() && target_status.is_none() && interrupted == 0 && !target_stopped {
            warn!("perf stopped before the target exited; asking the target to stop");
            let _ = kill_process(pid, Signal::TERM);
            target_stopped = true;
        }
        let sent = interrupts.take_sent();
        if interrupted >= 2 && target_status.is_none() && !killed {
            let _ = kill_process(pid, Signal::KILL);
            killed = true;
        } else if let Some(signal) = sent.filter(|_| target_status.is_none()) {
            let _ = kill_process(pid, signal);
        }
        if let (Some(target), Some(perf)) = (target_status, perf_status) {
            return Ok((target, perf));
        }
        thread::sleep(POLL);
    }
}

/// Waits for an interrupt or the end of `duration`, then stops perf, or
/// for perf to stop by itself once the process and all it started exit. A
/// process uhr attached to is never signalled. Returns perf's status, and
/// when uhr stopped it.
fn watch(
    perf: &mut Perf,
    interrupts: &Interrupts,
    duration: Option<Duration>,
) -> Result<(ExitStatus, Option<u64>)> {
    let started = Instant::now();
    let mut stopped_ns = None;
    loop {
        let status = perf
            .child
            .try_wait()
            .map_err(io_error("waiting for", Path::new("perf")))?;
        if let Some(status) = status {
            return Ok((status, stopped_ns));
        }
        let ended = duration.is_some_and(|d| started.elapsed() >= d);
        if stopped_ns.is_none() && (interrupts.count() > 0 || ended) {
            stopped_ns = Some(interrupts.first_ns().unwrap_or_else(monotonic_ns));
            perf.stop();
        }
        thread::sleep(POLL);
    }
}

/// Processes the target leaves running can keep its stderr open long after
/// perf exits, so the relay gets this long to copy what perf wrote.
const RELAY_GRACE: Duration = Duration::from_millis(200);

/// perf shares uhr's stderr. If it is a pipe or socket whose reader has
/// gone, the first warning perf prints kills perf with SIGPIPE. Terminals
/// and files can't break that way, so they are passed straight through.
fn stderr_can_break() -> bool {
    let Ok(fd) = io::stderr().as_fd().try_clone_to_owned() else {
        return false;
    };
    fs::File::from(fd).metadata().is_ok_and(|metadata| {
        let kind = metadata.file_type();
        kind.is_fifo() || kind.is_socket()
    })
}

/// Copies perf's stderr to uhr's byte for byte. Once uhr's stderr fails, it
/// keeps reading, so perf never sees a broken pipe.
fn relay_stderr(mut from: ChildStderr) -> mpsc::Receiver<()> {
    let (done, finished) = mpsc::channel();
    thread::spawn(move || {
        let mut to = io::stderr();
        let mut writable = true;
        let mut buffer = [0; 8192];
        loop {
            match from.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => writable = writable && to.write_all(&buffer[..n]).is_ok(),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
        let _ = done.send(());
    });
    finished
}

/// uhr is the target's parent, so its status is the target's own.
fn exit(status: ExitStatus) -> Option<Exit> {
    status
        .code()
        .map(Exit::Code)
        .or_else(|| status.signal().map(Exit::Signal))
}

fn no_process(pid: u32, error: io::Error) -> Error {
    match Errno::from_io_error(&error) {
        Some(Errno::SRCH) => Error::NoProcess(pid),
        _ => Error::Io {
            action: "watching",
            path: PathBuf::from(format!("/proc/{pid}")),
            source: error,
        },
    }
}

/// The command line of `process`, whose pid is `pid`.
fn command_line(pid: u32, process: &Process) -> Result<Vec<String>> {
    let path = PathBuf::from(format!("/proc/{pid}/cmdline"));
    let bytes = fs::read(&path);
    // Gone, its pid may already be another process's.
    if process.exited().map_err(|e| no_process(pid, e))? {
        return Err(Error::NoProcess(pid));
    }
    let bytes = bytes.map_err(io_error("reading", &path))?;
    Ok(arguments(&bytes))
}

/// Each argument in /proc/<pid>/cmdline ends with a NUL, so an empty one is
/// a NUL alone. A kernel thread has none at all.
fn arguments(cmdline: &[u8]) -> Vec<String> {
    if cmdline.is_empty() {
        return Vec::new();
    }
    cmdline
        .strip_suffix(&[0])
        .unwrap_or(cmdline)
        .split(|&b| b == 0)
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
        .collect()
}

/// perf is quiet about a missing command and just exits with 255.
fn check_program(program: &str) -> Result<()> {
    let is_executable = |path: &Path| {
        path.metadata()
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    };
    let found = if program.contains('/') {
        is_executable(Path::new(program))
    } else {
        env::var_os("PATH").is_some_and(|paths| {
            env::split_paths(&paths).any(|dir| is_executable(&dir.join(program)))
        })
    };
    if !found {
        return Err(Error::CommandNotFound(program.to_owned()));
    }
    Ok(())
}

fn staging_dir(out: &Path) -> Result<PathBuf> {
    let Some(name) = out.file_name() else {
        return Err(Error::UnusableOutput(out.to_owned()));
    };
    let mut staging = name.to_owned();
    staging.push(".partial");
    Ok(out.with_file_name(staging))
}

fn read_max_stack_depth() -> Result<u32> {
    let path = "/proc/sys/kernel/perf_event_max_stack";
    let text = fs::read_to_string(path).map_err(io_error("reading", Path::new(path)))?;
    text.trim().parse().map_err(|_| Error::NotANumber {
        path,
        value: text.trim().to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dropped_perf_is_stopped_and_reaped() {
        let dir = tempfile::tempdir().unwrap();
        let perf = dir.path().join("perf");
        fs::write(&perf, "#!/bin/sh\nexec sleep 30\n").unwrap();
        fs::set_permissions(&perf, fs::Permissions::from_mode(0o700)).unwrap();
        let attached = Perf::attach(&perf, Vec::new(), Stdio::null()).unwrap();
        let pid = attached.child.id();
        drop(attached);
        let gone = fs::read_to_string(format!("/proc/{pid}/stat")).is_err();
        assert!(gone, "perf {pid} was left behind");
    }

    #[test]
    fn keeps_empty_arguments() {
        assert_eq!(
            arguments(b"python3\0-c\0x\0\0last\0\0"),
            ["python3", "-c", "x", "", "last", ""]
        );
        assert_eq!(arguments(b"\0"), [""]);
        assert!(arguments(b"").is_empty());
        // A process that rewrote its command line can leave out the last
        // NUL.
        assert_eq!(arguments(b"worker: idle"), ["worker: idle"]);
    }
}
