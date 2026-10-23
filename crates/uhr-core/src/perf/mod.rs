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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tracing::{debug, info, warn};

use crate::doctor;
use crate::recording::{Collector, Exit, Recording};

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
        let fix = check.fix.as_deref().map(|f| format!("\nfix: {f}"));
        bail!("cannot record: {}{}", check.detail, fix.unwrap_or_default());
    }
    let Some(program) = options.command.first() else {
        bail!("no command to record");
    };
    check_program(program)?;
    if out.exists() {
        bail!("{} already exists", out.display());
    }
    let staging = staging_dir(out)?;
    if let Some(parent) = staging.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    // Exclusive, so two recordings to the same output can't share it.
    match fs::create_dir(&staging) {
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => bail!(
            "{} exists, probably from a recording that did not finish. Remove it to record again",
            staging.display()
        ),
        result => result.with_context(|| format!("creating {}", staging.display()))?,
    }

    let perf_version = doctor::perf_version().map_err(anyhow::Error::msg)?;
    let max_stack_depth = read_max_stack_depth()?;
    let perf_data = staging.join("perf.data");
    let args = perf_args(&perf_data, options);
    debug!(command = %format!("perf {}", join_args(&args)), "running perf");
    let (status, interrupted) = run_perf(&args)?;

    let recording = convert::convert(convert::Input {
        perf_data: &perf_data,
        command: &options.command,
        exit: exit(status, interrupted),
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
            return Err(error.context(format!(
                "perf exited with {status} and wrote no usable data. Run `uhr doctor`, or run \
                 `perf {}` to see perf's own error",
                join_args(&retry)
            )));
        }
        Err(error) => {
            return Err(error.context(format!(
                "converting {}, which is kept for inspection",
                perf_data.display()
            )));
        }
    };

    recording.write(&staging)?;
    fs::remove_file(&perf_data).with_context(|| format!("removing {}", perf_data.display()))?;
    fs::rename(&staging, out)
        .with_context(|| format!("renaming {} to {}", staging.display(), out.display()))?;
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
            warn!(signal = ?missing.signal, reason = %missing.reason, "signal not captured");
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
/// Returns perf's status, and whether this process got SIGINT meanwhile.
fn run_perf(args: &[OsString]) -> Result<(ExitStatus, bool)> {
    let interrupted = Arc::new(AtomicBool::new(false));
    let handler =
        signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&interrupted))?;
    let status = spawn_perf(args);
    signal_hook::low_level::unregister(handler);
    Ok((status?, interrupted.load(Ordering::Relaxed)))
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
    let mut child = command.spawn().context("running perf")?;
    let relay = child.stderr.take().map(relay_stderr);
    let status = child.wait().context("waiting for perf")?;
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
        bail!("command not found or not executable: {program}");
    }
    Ok(())
}

fn staging_dir(out: &Path) -> Result<PathBuf> {
    let Some(name) = out.file_name() else {
        bail!("{} is not a usable output directory", out.display());
    };
    let mut staging = name.to_owned();
    staging.push(".partial");
    Ok(out.with_file_name(staging))
}

fn read_max_stack_depth() -> Result<u32> {
    let path = "/proc/sys/kernel/perf_event_max_stack";
    let text = fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
    text.trim()
        .parse()
        .with_context(|| format!("{path} is not a number: {:?}", text.trim()))
}
