mod convert;

use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{ChildStderr, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::doctor;
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
    #[error("installing the SIGINT handler")]
    SignalHandler(#[source] io::Error),
    #[error("{action} {}", .path.display())]
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
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
}

/// Launches `options.command` under `perf record` and writes the recording
/// to `out`, which must not exist. The recording is built in a sibling
/// `.partial` directory and renamed into place once complete.
pub fn record(options: &RecordOptions, out: &Path) -> Result<Recording> {
    let report = doctor::check_perf();
    if let Some(check) = report.blocked().next() {
        return Err(Error::Blocked {
            detail: check.detail.clone(),
            fix: check.fix.clone(),
        });
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
    let args = perf_args(&perf_data, options);
    debug!(command = %format!("perf {}", join_args(&args)), "running perf");
    let (status, interrupted_ns) = run_perf(&args)?;

    let recording = convert::convert(convert::Input {
        perf_data: &perf_data,
        command: &options.command,
        exit: exit(status, interrupted_ns.is_some()),
        interrupted_ns,
        perf_version,
        requested_frequency_hz: options.frequency_hz,
        max_stack_depth,
    });
    let recording = match recording {
        Ok(recording) => recording,
        Err(error) if !status.success() => {
            if let Err(cleanup) = fs::remove_dir_all(&staging) {
                warn!("removing {}: {cleanup}", staging.display());
            }
            // Without --quiet, perf prints the error it kept to itself.
            let mut retry = perf_args(Path::new("perf.data"), options);
            retry.retain(|a| a != "--quiet");
            return Err(Error::NoUsableData {
                status,
                command: join_args(&retry),
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

    recording.write(&staging)?;
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
        if coverage.samples_at_stack_limit > 0 {
            warn!(
                samples = coverage.samples_at_stack_limit,
                max_stack_depth = coverage.max_stack_depth,
                "stacks were cut at the depth limit"
            );
        }
    }
}

pub(crate) fn perf_args(perf_data: &Path, options: &RecordOptions) -> Vec<OsString> {
    let mut args: Vec<OsString> = [
        "record",
        "--quiet",
        "--event=cpu-clock",
        &format!("--freq={}", options.frequency_hz),
        "--call-graph=fp",
        "--sample-cpu",
        "--clockid=CLOCK_MONOTONIC",
        "--buildid-mmap",
        "--output",
    ]
    .iter()
    .map(OsString::from)
    .collect();
    args.push(perf_data.into());
    args.push("--".into());
    args.extend(options.command.iter().map(OsString::from));
    args
}

fn join_args(args: &[OsString]) -> String {
    args.iter()
        .map(|a| a.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Ctrl-C reaches the whole process group. The target stops and perf
/// finishes writing; this process has to outlive both to convert the data.
/// A handler rather than SIG_IGN, because ignored signals stay ignored in
/// the target after exec.
///
/// Returns perf's status, and when this process first got SIGINT, if it
/// did, on CLOCK_MONOTONIC.
fn run_perf(args: &[OsString]) -> Result<(ExitStatus, Option<u64>)> {
    let interrupted_ns = Arc::new(AtomicU64::new(0));
    let first = Arc::clone(&interrupted_ns);
    let action = move || {
        let _ = first.compare_exchange(0, monotonic_ns(), Ordering::Relaxed, Ordering::Relaxed);
    };
    // SAFETY: the action only reads the clock and swaps an atomic, which
    // are both async-signal-safe.
    let handler = unsafe { signal_hook::low_level::register(signal_hook::consts::SIGINT, action) }
        .map_err(Error::SignalHandler)?;
    let status = spawn_perf(args);
    signal_hook::low_level::unregister(handler);
    let interrupted_ns = interrupted_ns.load(Ordering::Relaxed);
    Ok((status?, (interrupted_ns != 0).then_some(interrupted_ns)))
}

/// The clock perf stamps events with, given `--clockid=CLOCK_MONOTONIC`.
fn monotonic_ns() -> u64 {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    now.tv_sec as u64 * 1_000_000_000 + now.tv_nsec as u64
}

/// Processes the target leaves running can keep its stderr open long after
/// perf exits, so the relay gets this long to copy what perf wrote.
const RELAY_GRACE: Duration = Duration::from_millis(200);

fn spawn_perf(args: &[OsString]) -> Result<ExitStatus> {
    let mut command = Command::new("perf");
    command.args(args);
    if stderr_can_break() {
        command.stderr(Stdio::piped());
    }
    let mut child = command
        .spawn()
        .map_err(io_error("running", Path::new("perf")))?;
    let relay = child.stderr.take().map(relay_stderr);
    let status = child
        .wait()
        .map_err(io_error("waiting for", Path::new("perf")))?;
    if let Some(done) = relay {
        let _ = done.recv_timeout(RELAY_GRACE);
    }
    Ok(status)
}

/// perf and the target share uhr's stderr. If it is a pipe or socket whose
/// reader has gone, the first warning perf prints kills perf with SIGPIPE.
/// Terminals and files can't break that way, so they are passed straight
/// through.
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

/// Numeric exit codes come from the target. A signal can instead belong to
/// perf itself, even when uhr did not receive it, so it cannot name the
/// signal that killed the target.
fn exit(status: ExitStatus, interrupted: bool) -> Option<Exit> {
    if interrupted {
        return Some(Exit::Unknown(
            "interrupted while recording: perf then reports its own signal, not the target's \
             status"
                .into(),
        ));
    }
    status.code().map(Exit::Code).or_else(|| {
        status.signal().map(|signal| {
            Exit::Unknown(format!(
                "perf exited on signal {signal}: it may have received that signal itself, \
                     so the target's exit status is unknown"
            ))
        })
    })
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
