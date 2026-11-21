//! A program uhr runs itself to learn where a runtime keeps what uhr reads,
//! for one that publishes no offsets: the runtime's own binary, with a
//! script that holds things uhr knows and waits where uhr reads them. Each
//! platform says how to run it so that uhr can read its memory.

use std::ffi::OsString;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::ops::Range;
use std::path::PathBuf;
use std::process::{ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use super::Process;

/// How long a probe can take from its start to the last place it waits.
const PATIENCE: Duration = Duration::from_secs(10);

/// What a probe of a runtime runs: its program, with only `environment`.
#[derive(Debug, Clone)]
pub struct ProbeCommand {
    pub program: String,
    pub args: Vec<OsString>,
    /// Where it runs, which it may change.
    pub dir: PathBuf,
    /// A directory of uhr's for what uhr gives it, as its script, which it
    /// can read but not change.
    pub files: PathBuf,
    pub environment: Vec<(OsString, OsString)>,
    /// The user and group it runs as: those of the process it probes the
    /// runtime of, so that it can do no more than that process's owner.
    pub user: Option<(u32, u32)>,
}

/// Runs probes so that uhr can read their memory, as each platform does,
/// from any thread.
pub trait Prober: Sync {
    /// Runs `command`, and returns once it first waits.
    fn probe(&self, command: &ProbeCommand) -> io::Result<Box<dyn Probe>>;
}

/// A probe that waits, whose memory uhr can read.
pub trait Probe: Process {
    /// The line it wrote where it waits.
    fn said(&self) -> &str;
    /// Lets it go on to the next place it waits.
    fn resume(&mut self) -> io::Result<()>;
    /// Where its main thread's stack is: at least from the frame it waits
    /// in to the outermost. Some of it may not be readable.
    fn stack(&self) -> io::Result<Range<u64>>;
}

/// A probe's process, as uhr runs it: it writes a line where it waits, and
/// goes on when uhr writes a byte. Ended when dropped.
pub struct Child {
    child: std::process::Child,
    stdin: ChildStdin,
    lines: mpsc::Receiver<String>,
    errors: mpsc::Receiver<Vec<u8>>,
    deadline: Instant,
}

impl Child {
    /// Starts `command`, with `added` added to its environment.
    pub fn spawn(command: &ProbeCommand, added: &[(OsString, OsString)]) -> io::Result<Self> {
        let mut run = Command::new(&command.program);
        run.args(&command.args)
            .current_dir(&command.dir)
            .env_clear()
            .envs(command.environment.iter().chain(added).cloned())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // As root, std drops the other groups too.
        #[cfg(unix)]
        if let Some((uid, gid)) = command.user {
            use std::os::unix::process::CommandExt;
            run.uid(uid).gid(gid);
        }
        let mut child = run.spawn()?;
        let stdin = child.stdin.take().expect("piped");
        let stdout = child.stdout.take().expect("piped");
        let mut stderr = child.stderr.take().expect("piped");
        let (send, lines) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if send.send(line).is_err() {
                    break;
                }
            }
        });
        let (send, errors) = mpsc::channel();
        thread::spawn(move || {
            let mut written = Vec::new();
            let _ = stderr.read_to_end(&mut written);
            let _ = send.send(written);
        });
        Ok(Self {
            child,
            stdin,
            lines,
            errors,
            deadline: Instant::now() + PATIENCE,
        })
    }

    pub fn id(&self) -> u32 {
        self.child.id()
    }

    /// How much longer it may take.
    pub fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    /// The next line it writes, once it waits after it.
    pub fn line(&mut self) -> io::Result<String> {
        match self.lines.recv_timeout(self.remaining()) {
            Ok(line) => Ok(line),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "it did not get to where it waits within {} s",
                    PATIENCE.as_secs()
                ),
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                // Its output closed, so it ended or is ending, unless it
                // closed that itself.
                let status = loop {
                    if let Some(status) = self.child.try_wait()? {
                        break status;
                    }
                    if self.remaining().is_zero() {
                        self.child.kill()?;
                        break self.child.wait()?;
                    }
                    thread::sleep(Duration::from_millis(10));
                };
                let errors = self
                    .errors
                    .recv_timeout(self.remaining())
                    .unwrap_or_default();
                let errors = String::from_utf8_lossy(&errors);
                Err(io::Error::other(format!(
                    "it ended before it waited, with {status}: {}",
                    errors.trim()
                )))
            }
        }
    }

    /// Lets it go on past where it waits.
    pub fn resume(&mut self) -> io::Result<()> {
        self.stdin.write_all(b"\n")?;
        self.stdin.flush()
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn shell(script: &str) -> ProbeCommand {
        ProbeCommand {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            dir: std::env::temp_dir(),
            files: std::env::temp_dir(),
            environment: Vec::new(),
            user: None,
        }
    }

    #[test]
    fn says_where_it_waits_and_goes_on_when_resumed() {
        let script = "echo first; read go; echo second; read go";
        let mut child = Child::spawn(&shell(script), &[]).unwrap();
        assert_eq!(child.line().unwrap(), "first");
        child.resume().unwrap();
        assert_eq!(child.line().unwrap(), "second");
    }

    #[test]
    fn says_why_it_ended_before_it_waited() {
        let mut child = Child::spawn(&shell("echo broken >&2; exit 3"), &[]).unwrap();
        let error = child.line().unwrap_err().to_string();
        assert!(error.contains("broken") && error.contains('3'), "{error}");
    }

    #[test]
    fn runs_with_only_the_environment_it_is_given() {
        let command = ProbeCommand {
            environment: vec![("UHR_PROBE".into(), "given".into())],
            ..shell("echo \"$UHR_PROBE-$UHR_ADDED-$HOME\"; read go")
        };
        let added = [("UHR_ADDED".into(), "too".into())];
        let mut child = Child::spawn(&command, &added).unwrap();
        assert_eq!(child.line().unwrap(), "given-too-");
    }
}
