use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, ErrorKind, Read};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::Errno;
use rustix::pipe::{PipeFlags, pipe_with};
use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open};

use crate::procfs;

/// Why a target could not be started.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("starting {program}")]
    Spawn {
        program: String,
        #[source]
        source: io::Error,
    },
}

/// A target started but held before it runs any of its own code, so
/// collectors can attach to it first. Dropping it without releasing it ends
/// the target without running it.
pub(crate) struct Held {
    pid: u32,
    program: String,
    release: OwnedFd,
    started: mpsc::Receiver<io::Result<Child>>,
    starter: Starter,
}

/// The thread that started a target. The kernel sends a target's
/// parent-death signal when that thread exits, not when uhr does, so it
/// lives until the target is reaped.
struct Starter {
    done: Option<mpsc::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for Starter {
    fn drop(&mut self) {
        self.done.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A target that runs, and the thread that started it. Reap the target
/// before dropping this.
pub(crate) struct Launched {
    pub(crate) child: Child,
    _starter: Starter,
}

impl Held {
    /// Starts `command` with `environment` added to uhr's own.
    pub(crate) fn spawn(
        command: &[String],
        environment: &[(&str, OsString)],
    ) -> Result<Self, Error> {
        let program = command[0].clone();
        let error = |source| Error::Spawn {
            program: program.clone(),
            source,
        };
        let (pid_read, pid_write) = pipe_with(PipeFlags::CLOEXEC).map_err(|e| error(e.into()))?;
        let (go_read, go_write) = pipe_with(PipeFlags::CLOEXEC).map_err(|e| error(e.into()))?;
        let go_write_fd = go_write.as_raw_fd();
        let mut target = Command::new(&program);
        target.args(&command[1..]).envs(environment.iter().cloned());
        let hold = move || {
            // The child's copy of the release end would keep it waiting
            // even after uhr is gone.
            // SAFETY: the child owns its copy of the fd, and nothing in the
            // child uses it.
            unsafe { rustix::io::close(go_write_fd) };
            let pid = rustix::process::getpid().as_raw_pid() as u32;
            rustix::io::write(&pid_write, &pid.to_ne_bytes())?;
            let mut go = [0];
            match rustix::io::read(&go_read, &mut go)? {
                1 => Ok(()),
                _ => Err(Errno::CANCELED.into()),
            }
        };
        // SAFETY: `hold` runs between fork and exec, so it only makes system
        // calls, which are async-signal-safe.
        unsafe { target.pre_exec(hold) };
        let (started_send, started) = mpsc::channel();
        let (done, until_done) = mpsc::channel::<()>();
        // spawn returns only once the child has exec'd, which it does only
        // when released.
        let thread = thread::spawn(move || {
            let child = target.spawn();
            let runs = child.is_ok();
            if started_send.send(child).is_ok() && runs {
                let _ = until_done.recv();
            }
        });
        let starter = Starter {
            done: Some(done),
            thread: Some(thread),
        };
        let mut pid = [0; 4];
        if let Err(read) = File::from(pid_read).read_exact(&mut pid) {
            let source = match started.recv() {
                Ok(Err(spawn)) => spawn,
                _ => read,
            };
            return Err(error(source));
        }
        Ok(Self {
            pid: u32::from_ne_bytes(pid),
            program,
            release: go_write,
            started,
            starter,
        })
    }

    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }

    /// Lets the target run.
    pub(crate) fn release(self) -> Result<Launched, Error> {
        let Held {
            program,
            release,
            started,
            starter,
            ..
        } = self;
        let error = |source| Error::Spawn {
            program: program.clone(),
            source,
        };
        let released = rustix::io::write(&release, &[1]);
        // Closed, the target ends even if the write failed, so the starter
        // can end too.
        drop(release);
        released.map_err(|e| error(e.into()))?;
        let child = started
            .recv()
            .unwrap_or_else(|_| Err(io::Error::other("the thread starting the target ended")))
            .map_err(error)?;
        Ok(Launched {
            child,
            _starter: starter,
        })
    }
}

/// A running process uhr did not start, by a pidfd, which unlike its pid
/// can't come to mean another process.
pub(crate) struct Process(OwnedFd);

impl Process {
    pub(crate) fn open(pid: u32) -> io::Result<Self> {
        let pid = i32::try_from(pid)
            .ok()
            .and_then(Pid::from_raw)
            .ok_or(Errno::SRCH)?;
        Ok(Self(pidfd_open(pid, PidfdFlags::empty())?))
    }

    /// When the process with the pid `pid` started.
    pub(crate) fn started(pid: u32) -> io::Result<SystemTime> {
        let mut stat = Vec::new();
        procfs::read(format!("/proc/{pid}/stat"), &mut stat)?;
        let unreadable = || io::Error::new(ErrorKind::InvalidData, "unreadable /proc/<pid>/stat");
        let ticks = procfs::stat(&stat).ok_or_else(unreadable)?.start_ticks;
        let boot: u64 = fs::read_to_string("/proc/stat")?
            .lines()
            .find_map(|line| line.strip_prefix("btime ")?.trim().parse().ok())
            .ok_or_else(unreadable)?;
        let per_second = rustix::param::clock_ticks_per_second();
        let since_boot = Duration::from_secs_f64(ticks as f64 / per_second as f64);
        Ok(UNIX_EPOCH + Duration::from_secs(boot) + since_boot)
    }

    /// The user that files the process with the pid `pid` creates belong to.
    pub(crate) fn file_owner(pid: u32) -> io::Result<u32> {
        let mut status = Vec::new();
        procfs::read(format!("/proc/{pid}/status"), &mut status)?;
        // Its real, effective, saved and filesystem user ids.
        procfs::status_field(&status, "Uid")
            .and_then(|ids| ids.split_whitespace().nth(3)?.parse().ok())
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "unreadable /proc/<pid>/status"))
    }

    pub(crate) fn exited(&self) -> io::Result<bool> {
        // A pidfd is readable once its process has exited.
        let mut fds = [PollFd::new(&self.0, PollFlags::IN)];
        poll(&mut fds, Some(&Timespec::default()))?;
        Ok(fds[0].revents().contains(PollFlags::IN))
    }
}

/// The interrupts that end a capture. Whoever owns the process's signals,
/// such as the CLI, records them here, from a signal handler if need be.
#[derive(Debug, Default)]
pub struct Interrupts {
    count: AtomicU32,
    first_ns: AtomicU64,
    sent: AtomicI32,
}

impl Interrupts {
    pub const fn new() -> Self {
        Self {
            count: AtomicU32::new(0),
            first_ns: AtomicU64::new(0),
            sent: AtomicI32::new(0),
        }
    }

    /// An interrupt the target got too, as a terminal's Ctrl-C reaches the
    /// whole process group. Async-signal-safe: it only reads the clock and
    /// changes atomics.
    pub fn interrupt(&self) {
        let _ =
            self.first_ns
                .compare_exchange(0, monotonic_ns(), Ordering::Relaxed, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// An interrupt that another process sent to uhr alone, by the number
    /// of its signal, which is passed on to the target. Async-signal-safe.
    pub fn interrupt_sent(&self, signal: i32) {
        self.interrupt();
        self.sent.store(signal, Ordering::Relaxed);
    }

    pub(crate) fn count(&self) -> u32 {
        self.count.load(Ordering::Relaxed)
    }

    /// The signal of the last one another process sent, once.
    pub(crate) fn take_sent(&self) -> Option<Signal> {
        Signal::from_named_raw(self.sent.swap(0, Ordering::Relaxed))
    }

    /// When the first came, on CLOCK_MONOTONIC.
    pub(crate) fn first_ns(&self) -> Option<u64> {
        let first = self.first_ns.load(Ordering::Relaxed);
        (first != 0).then_some(first)
    }
}

/// The clock perf stamps events with, given `--clockid=CLOCK_MONOTONIC`.
pub(crate) fn monotonic_ns() -> u64 {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    now.tv_sec as u64 * 1_000_000_000 + now.tv_nsec as u64
}
