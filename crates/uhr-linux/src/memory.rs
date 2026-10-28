//! Reads how much memory the target's processes have from `/proc`, at
//! intervals while the capture runs.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::{self, ErrorKind};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rustix::io::Errno;
use rustix::time::{ClockId, clock_gettime};

use uhr_core::recording::MemoryReading;

use crate::launch::monotonic_ns;
use crate::procfs;

/// Often enough to show how memory grows, and cheap: the kernel keeps the
/// counts read, so reading them walks no page tables.
pub(crate) const INTERVAL: Duration = Duration::from_millis(100);

/// The most pids probed for new processes at one reading. Past that,
/// listing `/proc` costs less.
const MAX_PROBES: u32 = 128;

const LOADAVG: &str = "/proc/loadavg";
const PID_MAX: &str = "/proc/sys/kernel/pid_max";

/// Why the target's memory could not be read.
#[derive(Debug, thiserror::Error)]
#[error("reading {path}: {source}")]
pub(crate) struct Error {
    path: String,
    source: io::Error,
}

/// What the reader found.
pub(crate) struct Read {
    pub(crate) readings: Vec<MemoryReading>,
    /// uhr's own CPU time reading `/proc`.
    pub(crate) cpu_ns: u64,
    /// The target's processes that could not be read, by why.
    pub(crate) unreadable: BTreeMap<String, u64>,
    /// New processes on the host that could not be checked for being the
    /// target's, by why.
    pub(crate) unchecked: BTreeMap<String, u64>,
}

/// Reads the memory of a process and the processes it starts, from `begin`
/// until ended.
pub(crate) struct Reader {
    /// Until it begins.
    processes: Option<Processes>,
    stop: Option<mpsc::Sender<()>>,
    thread: Option<JoinHandle<Read>>,
}

impl Reader {
    /// Follows `pid` and the processes it starts from now on. Fails if
    /// `pid` can't be read.
    pub(crate) fn start(pid: u32) -> Result<Self, Error> {
        let error = |path: &str| {
            let path = path.to_owned();
            move |source| Error { path, source }
        };
        let mut bytes = Vec::new();
        let status = format!("/proc/{pid}/status");
        procfs::read(&status, &mut bytes).map_err(error(&status))?;
        counts(&bytes).map_err(error(&status))?;
        let start = start_of(pid, &mut bytes).map_err(error(&main_thread_stat(pid)))?;
        let processes = Processes {
            tracked: BTreeMap::from([(pid, start)]),
            last_pid: last_pid().map_err(error(LOADAVG))?,
            pid_max: fs::read_to_string(PID_MAX)
                .and_then(|max| max.trim().parse().map_err(io::Error::other))
                .map_err(error(PID_MAX))?,
            started: boot_ticks(),
            retry: Vec::new(),
            relist: false,
            bytes,
            unreadable: BTreeMap::new(),
            unchecked: BTreeMap::new(),
        };
        Ok(Self {
            processes: Some(processes),
            stop: None,
            thread: None,
        })
    }

    /// Reads now, and every interval until ended.
    pub(crate) fn begin(&mut self) {
        let Some(mut processes) = self.processes.take() else {
            return;
        };
        let (stop, stopped) = mpsc::channel();
        self.stop = Some(stop);
        self.thread = Some(thread::spawn(move || {
            let mut readings = Vec::new();
            let start = Instant::now();
            let mut ticks = 0;
            loop {
                processes.read(&mut readings);
                // A read that took longer than an interval skips the ticks it
                // covered.
                ticks = ticks.max(start.elapsed().as_nanos() / INTERVAL.as_nanos()) + 1;
                let next = start + INTERVAL * ticks as u32;
                match stopped.recv_timeout(next.saturating_duration_since(Instant::now())) {
                    Err(RecvTimeoutError::Timeout) => {}
                    _ => break,
                }
            }
            // So the last reading is from when the capture ended.
            processes.read(&mut readings);
            let cpu = clock_gettime(ClockId::ThreadCPUTime);
            Read {
                readings,
                cpu_ns: cpu.tv_sec as u64 * 1_000_000_000 + cpu.tv_nsec as u64,
                unreadable: processes.unreadable,
                unchecked: processes.unchecked,
            }
        }));
    }

    /// Takes a last reading and stops.
    pub(crate) fn end(&mut self) {
        self.stop.take();
    }

    pub(crate) fn finish(mut self) -> Read {
        self.end();
        match self.thread.take() {
            Some(thread) => thread
                .join()
                .unwrap_or_else(|panic| std::panic::resume_unwind(panic)),
            None => Read {
                readings: Vec::new(),
                cpu_ns: 0,
                unreadable: BTreeMap::new(),
                unchecked: BTreeMap::new(),
            },
        }
    }
}

struct Processes {
    /// Each process's start, in clock ticks since boot, by its pid. The two
    /// tell it from a later process given its pid, and it holds nothing
    /// open, so the processes on the host can't use up uhr's files.
    tracked: BTreeMap<u32, u64>,
    /// The pid the kernel last gave out when new processes were looked for.
    last_pid: u32,
    /// Pids are below it.
    pid_max: u32,
    /// When the target was first followed, in clock ticks since boot.
    started: u64,
    /// Pids given out that had no process in `/proc` when probed, which a
    /// process can still be getting as it forks. Each is probed once more.
    retry: Vec<u32>,
    /// Whether to list `/proc` again, as a listing misses those processes
    /// too, and can't tell which they are.
    relist: bool,
    /// For the files read, so each read needs no new buffer.
    bytes: Vec<u8>,
    unreadable: BTreeMap<String, u64>,
    unchecked: BTreeMap<String, u64>,
}

impl Processes {
    fn read(&mut self, readings: &mut Vec<MemoryReading>) {
        if let Ok(last) = last_pid() {
            self.find_new(last);
        }
        for (pid, start) in std::mem::take(&mut self.tracked) {
            match self.counts_of(pid, start) {
                Ok(counts) => {
                    if let Some(counts) = counts {
                        readings.push(counts.at(monotonic_ns(), pid));
                    }
                    self.tracked.insert(pid, start);
                }
                Err(error) if gone(&error) => {}
                Err(error) => *self.unreadable.entry(error.to_string()).or_default() += 1,
            }
        }
    }

    /// The counts of the process with the pid `pid` that started at
    /// `start`. `None` while it has no memory of its own: a zombie, until
    /// it is reaped. Fails as gone once the pid is another process's.
    fn counts_of(&mut self, pid: u32, start: u64) -> io::Result<Option<Counts>> {
        procfs::read(format!("/proc/{pid}/status"), &mut self.bytes)?;
        let mut found = counts(&self.bytes)?;
        if found.is_none() {
            found = self.thread_counts(pid);
        }
        // Read after the counts, the start says they were of this process,
        // not of a later one given its pid.
        if start_of(pid, &mut self.bytes)? != start {
            return Err(Errno::SRCH.into());
        }
        Ok(found)
    }

    /// The counts of a process whose main thread has exited, from one of its
    /// threads that still runs, which share them: its own file describes the
    /// main thread. `None` if none runs.
    fn thread_counts(&mut self, pid: u32) -> Option<Counts> {
        for task in fs::read_dir(format!("/proc/{pid}/task")).ok()? {
            let status = task.ok()?.path().join("status");
            if procfs::read(status, &mut self.bytes).is_ok()
                && let Ok(Some(counts)) = counts(&self.bytes)
            {
                return Some(counts);
            }
        }
        None
    }

    /// Tracks the processes started since it last looked whose parent is
    /// tracked, now that `last` is the pid the kernel gave out last. It
    /// gives out pids in turn, so they are among those given out since:
    /// probing those costs by the processes and threads the host started,
    /// where listing `/proc` costs by those it runs, and reading the
    /// children of each of the target's threads costs by its threads, which
    /// can be thousands.
    fn find_new(&mut self, last: u32) {
        let given = given_since(self.last_pid, last, self.pid_max);
        self.last_pid = last;
        let retry = std::mem::take(&mut self.retry);
        // With each pid, whether to probe it again if it has no process yet.
        let candidates: Vec<(u32, bool)> = match &given {
            Some(given) if !self.relist => given
                .iter()
                .map(|&pid| (pid, true))
                .chain(retry.into_iter().map(|pid| (pid, false)))
                .collect(),
            _ => {
                let Ok(listed) = list() else {
                    self.relist = true;
                    return;
                };
                if let Some(given) = &given {
                    self.retry = given
                        .iter()
                        .filter(|pid| !listed.contains(pid))
                        .copied()
                        .collect();
                }
                listed.into_iter().map(|pid| (pid, false)).collect()
            }
        };
        self.relist = given.is_none();
        let mut new = Vec::new();
        for (pid, again) in candidates {
            match procfs::read(main_thread_stat(pid), &mut self.bytes) {
                Ok(()) => {}
                Err(error) if gone(&error) => {
                    if again {
                        self.retry.push(pid);
                    }
                    continue;
                }
                Err(error) => {
                    *self.unchecked.entry(error.to_string()).or_default() += 1;
                    continue;
                }
            }
            let Some(stat) = procfs::stat(&self.bytes) else {
                continue;
            };
            // Pids still in use are skipped as they are given out, so once
            // they wrap around, those given since can be of processes from
            // before the target was followed, as a listing has. perf and
            // uhr's eBPF programs don't follow those either.
            let tracked = self.tracked.get(&pid) == Some(&stat.start_ticks);
            if !tracked && stat.start_ticks >= self.started {
                new.push((pid, stat));
            }
        }
        // A new process's parent can be new too.
        loop {
            let (adopted, rest): (Vec<_>, Vec<_>) = new
                .into_iter()
                .partition(|(_, stat)| self.tracked.contains_key(&stat.parent));
            new = rest;
            if adopted.is_empty() {
                break;
            }
            for (pid, stat) in adopted {
                // A probed pid can be a thread's, whose parent is its
                // process's.
                let process = procfs::read(format!("/proc/{pid}/status"), &mut self.bytes).is_ok()
                    && procfs::status_field(&self.bytes, "Tgid").and_then(|t| t.parse().ok())
                        == Some(pid);
                if process {
                    // In place of a process reaped since that had its pid.
                    self.tracked.insert(pid, stat.start_ticks);
                }
            }
        }
    }
}

/// The pids the kernel gave out after `since`, up to `last`, if there are
/// no more than `MAX_PROBES`. It gives them in turn, below `pid_max`, and
/// then from the low ones again.
fn given_since(since: u32, last: u32, pid_max: u32) -> Option<Vec<u32>> {
    let wrapped = last < since;
    let count = match wrapped {
        false => last - since,
        true => pid_max.saturating_sub(since + 1) + last,
    };
    if count > MAX_PROBES {
        return None;
    }
    Some(match wrapped {
        false => (since + 1..=last).collect(),
        true => (since + 1..pid_max).chain(1..=last).collect(),
    })
}

/// The pid the kernel gave out last, from `/proc/loadavg`.
fn last_pid() -> io::Result<u32> {
    let loadavg = fs::read_to_string(LOADAVG)?;
    loadavg
        .split_ascii_whitespace()
        .last()
        .and_then(|pid| pid.parse().ok())
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "unreadable /proc/loadavg"))
}

/// Now, in the clock ticks since boot that `/proc/<pid>/stat` gives start
/// times in.
fn boot_ticks() -> u64 {
    let now = clock_gettime(ClockId::Boottime);
    let ns = now.tv_sec as u64 * 1_000_000_000 + now.tv_nsec as u64;
    ns / (1_000_000_000 / rustix::param::clock_ticks_per_second())
}

/// When the process with the pid `pid` started, in clock ticks since boot.
fn start_of(pid: u32, bytes: &mut Vec<u8>) -> io::Result<u64> {
    procfs::read(main_thread_stat(pid), bytes)?;
    procfs::stat(bytes)
        .map(|stat| stat.start_ticks)
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "unreadable /proc/<pid>/stat"))
}

/// The `stat` of the thread with the id `tid` alone, which costs the same
/// whatever its process's threads, where the process's own sums over them.
/// A main thread's start is its process's, which an exec from another
/// thread keeps.
fn main_thread_stat(tid: u32) -> String {
    format!("/proc/{tid}/task/{tid}/stat")
}

/// Counts of a process's memory, in bytes.
#[derive(Debug, PartialEq, Eq)]
struct Counts {
    rss_anon: u64,
    rss_file: u64,
    rss_shmem: u64,
    swap: u64,
    peak_rss: u64,
}

impl Counts {
    fn at(&self, time_ns: u64, pid: u32) -> MemoryReading {
        MemoryReading {
            time_ns,
            pid,
            rss_anon_bytes: self.rss_anon,
            rss_file_bytes: self.rss_file,
            rss_shmem_bytes: self.rss_shmem,
            swap_bytes: self.swap,
            peak_rss_bytes: self.peak_rss,
        }
    }
}

/// The counts in a process's `/proc/<pid>/status`. `None` for a process
/// without memory of its own: a zombie, a kernel thread, or one whose main
/// thread has exited, which its file describes.
fn counts(status: &[u8]) -> io::Result<Option<Counts>> {
    let field = |name| {
        let kb = procfs::status_field(status, name)?.strip_suffix(" kB")?;
        kb.trim().parse::<u64>().ok()
    };
    if field("VmRSS").is_none() {
        return Ok(None);
    }
    let fields = ["RssAnon", "RssFile", "RssShmem", "VmSwap", "VmHWM"].map(field);
    let [
        Some(rss_anon),
        Some(rss_file),
        Some(rss_shmem),
        Some(swap),
        Some(peak_rss),
    ] = fields
    else {
        // The kernel has listed them all since Linux 4.5.
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "it lists no RssAnon, RssFile, RssShmem, VmSwap or VmHWM, as kernels before 4.5 don't",
        ));
    };
    Ok(Some(Counts {
        rss_anon: rss_anon * 1024,
        rss_file: rss_file * 1024,
        rss_shmem: rss_shmem * 1024,
        swap: swap * 1024,
        peak_rss: peak_rss * 1024,
    }))
}

/// The processes in `/proc`, by pid.
fn list() -> io::Result<HashSet<u32>> {
    let mut pids = HashSet::new();
    for entry in fs::read_dir("/proc")? {
        if let Some(pid) = entry?.file_name().to_str().and_then(|n| n.parse().ok()) {
            pids.insert(pid);
        }
    }
    Ok(pids)
}

/// Whether a read failed because the process or thread has exited, or has
/// no entry in `/proc` yet.
fn gone(error: &io::Error) -> bool {
    matches!(
        Errno::from_io_error(error),
        Some(Errno::NOENT | Errno::SRCH)
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::process::{Child, Command};

    use super::*;

    const STATUS: &[u8] = b"Name:\tzz\xc3\xa9\xc3\nState:\tS (sleeping)\nVmPeak:\t  10000 kB\nVmHWM:\t    5120 kB\nVmRSS:\t    4096 kB\nRssAnon:\t    3072 kB\nRssFile:\t    1000 kB\nRssShmem:\t      24 kB\nVmSwap:\t       8 kB\nThreads:\t1\n";

    #[test]
    fn reads_the_counts_in_bytes_whatever_the_name() {
        assert_eq!(
            counts(STATUS).unwrap(),
            Some(Counts {
                rss_anon: 3072 * 1024,
                rss_file: 1000 * 1024,
                rss_shmem: 24 * 1024,
                swap: 8 * 1024,
                peak_rss: 5120 * 1024,
            })
        );
    }

    #[test]
    fn a_process_without_memory_has_no_counts() {
        let zombie = b"Name:\tapp\nState:\tZ (zombie)\nThreads:\t1\n";
        assert_eq!(counts(zombie).unwrap(), None);
    }

    #[test]
    fn needs_the_counts_split_by_kind() {
        let old = b"Name:\tapp\nVmHWM:\t5120 kB\nVmRSS:\t4096 kB\nVmSwap:\t0 kB\n";
        assert!(counts(old).is_err());
    }

    #[test]
    fn probes_the_pids_given_since_up_to_a_limit() {
        assert_eq!(given_since(10, 10, 100), Some(vec![]));
        assert_eq!(given_since(10, 13, 100), Some(vec![11, 12, 13]));
        assert_eq!(given_since(97, 2, 100), Some(vec![98, 99, 1, 2]));
        assert_eq!(given_since(10, 10 + MAX_PROBES + 1, 1000), None);
    }

    fn sleep() -> Child {
        Command::new("sleep").arg("10").spawn().unwrap()
    }

    fn end(mut child: Child) {
        child.kill().unwrap();
        child.wait().unwrap();
    }

    fn this_process() -> (Reader, u32) {
        let reader = Reader::start(std::process::id()).unwrap();
        let pid_max = reader.processes.as_ref().unwrap().pid_max;
        (reader, pid_max)
    }

    #[test]
    fn reads_this_process_and_the_ones_it_starts_from_the_start() {
        let before = sleep();
        let mut reader = Reader::start(std::process::id()).unwrap();
        let after = sleep();
        reader.begin();
        thread::sleep(INTERVAL * 2);
        let read = reader.finish();
        let (before_pid, after_pid) = (before.id(), after.id());
        end(before);
        end(after);
        let pids: BTreeSet<u32> = read.readings.iter().map(|r| r.pid).collect();
        assert!(pids.contains(&std::process::id()), "{pids:?}");
        assert!(pids.contains(&after_pid), "{pids:?}");
        assert!(!pids.contains(&before_pid), "{pids:?}");
        assert!(
            read.readings
                .windows(2)
                .all(|w| w[0].time_ns <= w[1].time_ns)
        );
        assert!(read.readings.iter().all(|r| r.rss_bytes() > 0));
    }

    #[test]
    fn leaves_out_a_process_from_before_it_followed_the_target() {
        let (mut reader, _) = this_process();
        let child = sleep();
        let processes = reader.processes.as_mut().unwrap();
        // As if the child had started before, and its pid been given out
        // again since, as once pids wrap around.
        processes.started = u64::MAX;
        processes.find_new(last_pid().unwrap());
        let followed = processes.tracked.contains_key(&child.id());
        end(child);
        assert!(!followed);
    }

    #[test]
    fn a_new_process_can_take_the_pid_of_one_reaped_since_it_was_read() {
        let (mut reader, _) = this_process();
        let child = sleep();
        let processes = reader.processes.as_mut().unwrap();
        let start = start_of(child.id(), &mut processes.bytes).unwrap();
        // As if a process that started before had had the child's pid.
        processes.tracked.insert(child.id(), start - 1);
        processes.find_new(last_pid().unwrap());
        let followed = processes.tracked.get(&child.id()).copied();
        end(child);
        assert_eq!(followed, Some(start));
    }

    #[test]
    fn probes_a_pid_with_no_process_yet_once_more() {
        let (mut reader, pid_max) = this_process();
        let processes = reader.processes.as_mut().unwrap();
        // The highest pid is all but never in use.
        processes.last_pid = pid_max - 2;
        processes.find_new(pid_max - 1);
        assert_eq!(processes.retry, [pid_max - 1]);
        processes.find_new(pid_max - 1);
        assert!(processes.retry.is_empty());

        // A process it found only on probing again.
        let child = sleep();
        processes.retry = vec![child.id()];
        processes.find_new(pid_max - 1);
        let followed = processes.tracked.contains_key(&child.id());
        end(child);
        assert!(followed);
    }

    #[test]
    fn lists_proc_again_after_listing_it() {
        let (mut reader, pid_max) = this_process();
        let processes = reader.processes.as_mut().unwrap();
        processes.last_pid = pid_max - MAX_PROBES - 10;
        processes.find_new(pid_max - 1);
        assert!(processes.relist);
        processes.find_new(pid_max - 1);
        assert!(!processes.relist);
    }
}
