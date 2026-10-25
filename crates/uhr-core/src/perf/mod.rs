mod convert;
mod unwind;

pub(crate) use convert::is_dummy;

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
use std::time::Duration;

use rustix::io::{FdFlags, fcntl_setfd};
use rustix::pipe::{PipeFlags, pipe_with};
use rustix::process::{Pid, Signal, kill_process, set_parent_process_death_signal};
use tracing::{debug, info, warn};

use crate::doctor;
use crate::kallsyms::Kallsyms;
use crate::launch::{self, Held, Interrupts};
use crate::recording::{self, Collector, Exit, Recording};

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
    #[error("{0}")]
    PerfVersion(String),
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
    pub command: Vec<String>,
    pub frequency_hz: u64,
    pub unwind: Unwind,
    /// Record every context switch, with the stack of each thread going
    /// off CPU.
    pub off_cpu: bool,
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

/// Records `options.command` with perf and writes the recording to `out`,
/// which must not exist. The recording is built in a sibling
/// `.partial` directory and renamed into place once complete. The first of
/// `interrupts` ends the capture, and a second kills the target.
pub fn record(options: &RecordOptions, interrupts: &Interrupts, out: &Path) -> Result<Recording> {
    let report = doctor::check_perf();
    if let Some(check) = report.blocked().next() {
        return Err(Error::Blocked {
            detail: check.detail.clone(),
            fix: check.fix.clone(),
        });
    }
    if let Unwind::Dwarf { .. } = options.unwind {
        let check = doctor::check_dwarf_unwinding();
        if check.status != doctor::Status::Ok {
            return Err(Error::Blocked {
                detail: check.detail,
                fix: check.fix,
            });
        }
    }
    let Some(program) = options.command.first() else {
        return Err(Error::NoCommand);
    };
    check_program(program)?;
    if out.exists() {
        return Err(Error::OutputExists(out.to_owned()));
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

    let perf_version = doctor::perf_version().map_err(Error::PerfVersion)?;
    let max_stack_depth = read_max_stack_depth()?;
    let perf_data = staging.join("perf.data");
    let ended = match run(&perf_data, options, interrupts) {
        Ok(ended) => ended,
        Err(error) => {
            remove_staging(&staging);
            return Err(error);
        }
    };
    // While the boot and the loaded modules are still the ones recorded.
    let kallsyms = Kallsyms::read();

    let recording = convert::convert(convert::Input {
        perf_data: &perf_data,
        command: &options.command,
        launched_pid: Some(ended.pid),
        exit: exit(ended.target),
        interrupted_ns: ended.interrupted_ns,
        perf_version,
        requested_frequency_hz: options.frequency_hz,
        max_stack_depth,
        kallsyms: kallsyms.as_ref(),
    });
    let recording = match recording {
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

    match recording.write(&staging) {
        // What it was converted from is all there is to look into.
        Err(error @ recording::Error::Invalid { .. }) => {
            return Err(Error::Convert {
                path: perf_data,
                source: Box::new(error.into()),
            });
        }
        result => result?,
    }
    fs::remove_file(&perf_data).map_err(io_error("removing", &perf_data))?;
    fs::rename(&staging, out).map_err(io_error("renaming into place", out))?;
    log_summary(&recording, out);
    Ok(recording)
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
        let Collector::Perf {
            frequency_hz,
            requested_frequency_hz,
            ..
        } = &stream.collector;
        if frequency_hz != requested_frequency_hz {
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
        if coverage.stacks_at_stack_limit > 0 {
            warn!(
                stacks = coverage.stacks_at_stack_limit,
                max_stack_depth = coverage.max_stack_depth,
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
/// itself: the same flags without --quiet, launching the command itself.
fn diagnosis(options: &RecordOptions) -> String {
    let mut args = perf_args(Path::new("perf.data"), options);
    args.retain(|a| a != "--quiet");
    args.push("--".into());
    args.extend(options.command.iter().map(OsString::from));
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
    pid: u32,
    target: ExitStatus,
    perf: ExitStatus,
    /// When uhr first got SIGINT, if it did, on CLOCK_MONOTONIC.
    interrupted_ns: Option<u64>,
}

/// Starts the target held, attaches perf to it, and lets it run once perf
/// samples, so perf sees it from its first instruction.
fn run(perf_data: &Path, options: &RecordOptions, interrupts: &Interrupts) -> Result<Ended> {
    let held = Held::spawn(&options.command)?;
    let pid = held.pid();
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
    let finish_relay = || {
        if let Some(done) = &relay {
            let _ = done.recv_timeout(RELAY_GRACE);
        }
    };
    if let Some(status) = perf.enable().map_err(io_error("waiting for", perf_path))? {
        finish_relay();
        return Err(Error::PerfStart {
            status,
            command: diagnosis(options),
        });
    }
    let program = Path::new(&options.command[0]);
    let mut target = held.release()?;
    let (target, perf_status) = supervise(program, &mut target.child, &mut perf, interrupts)?;
    finish_relay();
    Ok(Ended {
        pid,
        target,
        perf: perf_status,
        interrupted_ns: interrupts.first_ns(),
    })
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
}
