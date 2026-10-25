use std::collections::{BTreeSet, HashMap};
use std::ffi::CStr;
use std::fs::{self, File};
use std::io::{self, Read};
use std::iter;
use std::mem::MaybeUninit;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::SystemTime;

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fs::inotify::{self, CreateFlags, WatchFlags};
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;

use crate::launch::Process;

use uhr_core::perf_map::PerfMap;
use uhr_core::runtimes::jit_code;

/// Where runtimes write perf maps.
pub(crate) const DIR: &str = "/tmp";

pub(crate) fn path(pid: u32) -> PathBuf {
    Path::new(DIR).join(format!("perf-{pid}.map"))
}

/// The users processes ran as when their perf maps appeared, and so the
/// users their maps can belong to. A process can change user before it
/// writes its map, as a command `sudo -u` runs does.
#[derive(Debug, Default)]
pub(crate) struct Owners(HashMap<u32, BTreeSet<u32>>);

impl Owners {
    /// The users the map of the process `pid` can belong to besides root:
    /// `started_as`, those the process ran as when its map appeared, and the
    /// one it runs as now, if it still runs.
    pub(crate) fn of(&self, pid: u32, started_as: u32) -> Vec<u32> {
        let seen = self.0.get(&pid).into_iter().flatten().copied();
        let now = Process::file_owner(pid).ok();
        iter::once(started_as).chain(seen).chain(now).collect()
    }
}

/// Notes the user of each process whose perf map appears in a directory,
/// until stopped.
pub(crate) struct Watch {
    stop: mpsc::Sender<()>,
    thread: JoinHandle<Owners>,
}

impl Watch {
    pub(crate) fn stop(self) -> Owners {
        drop(self.stop);
        self.thread.join().unwrap_or_default()
    }
}

pub(crate) fn watch(dir: &Path) -> io::Result<Watch> {
    let inotify = inotify::init(CreateFlags::NONBLOCK | CreateFlags::CLOEXEC)?;
    inotify::add_watch(&inotify, dir, WatchFlags::CREATE | WatchFlags::MOVED_TO)?;
    let (stop, stopped) = mpsc::channel();
    let thread = thread::Builder::new()
        .name("uhr-perf-maps".into())
        .spawn(move || {
            let mut owners = Owners::default();
            let mut buffer = [MaybeUninit::uninit(); 4096];
            let mut events = inotify::Reader::new(&inotify, &mut buffer);
            let wait = Timespec {
                tv_sec: 0,
                tv_nsec: 100_000_000,
            };
            loop {
                // Maps that appeared before the stop are queued by then.
                let stopping = stopped.try_recv() != Err(TryRecvError::Empty);
                // Until it would block.
                while let Ok(event) = events.next() {
                    let Some(pid) = event.file_name().and_then(map_pid) else {
                        continue;
                    };
                    if let Ok(user) = Process::file_owner(pid) {
                        owners.0.entry(pid).or_default().insert(user);
                    }
                }
                if stopping {
                    return owners;
                }
                let _ = poll(&mut [PollFd::new(&inotify, PollFlags::IN)], Some(&wait));
            }
        })?;
    Ok(Watch { stop, thread })
}

fn map_pid(name: &CStr) -> Option<u32> {
    let name = name.to_str().ok()?;
    name.strip_prefix("perf-")?
        .strip_suffix(".map")?
        .parse()
        .ok()
}

/// The perf map of the process `pid`, if it has one written since `since`.
/// An older one belonged to an earlier process with the same pid.
pub(crate) fn read(pid: u32, since: SystemTime, owners: &[u32]) -> io::Result<Option<PerfMap>> {
    Ok(text(&path(pid), since, owners)?.map(|text| PerfMap::parse(&text)))
}

/// Removes the perf map of the process `pid`, if it has one written since
/// `since`, and returns the runtime that wrote it, if uhr knows it.
pub(crate) fn remove(
    pid: u32,
    since: SystemTime,
    owners: &[u32],
) -> io::Result<Option<&'static str>> {
    let path = path(pid);
    let Some(text) = text(&path, since, owners)? else {
        return Ok(None);
    };
    let runtime = text
        .lines()
        .find_map(|line| jit_code(line.splitn(3, ' ').nth(2)?))
        .map(|code| code.runtime);
    fs::remove_file(path)?;
    Ok(runtime)
}

/// What the map at `path` says, if it was written since `since`. Any user
/// can create the path in `/tmp` first, so it must be a file of root or of
/// a user the process ran as, `owners`: a FIFO would block the read, and
/// another user's file could give the code false names.
fn text(path: &Path, since: SystemTime, owners: &[u32]) -> io::Result<Option<String>> {
    let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut file = match rustix::fs::open(path, flags, Mode::empty()) {
        Ok(fd) => File::from(fd),
        Err(Errno::NOENT) => return Ok(None),
        Err(Errno::LOOP) => return Err(io::Error::other("it is a symbolic link")),
        Err(errno) => return Err(errno.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::other("it is not a regular file"));
    }
    if metadata.uid() != 0 && !owners.contains(&metadata.uid()) {
        return Err(io::Error::other(format!(
            "it belongs to the user {}, whom the process did not run as",
            metadata.uid()
        )));
    }
    if metadata.modified()? < since {
        return Ok(None);
    }
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    Ok(Some(text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::fs::{CWD, FileType};

    fn me() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    #[test]
    fn leaves_out_a_map_written_before_its_process_started() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("perf-1.map");
        fs::write(&path, "10 10 py::f:/a.py\n").unwrap();
        let written = fs::metadata(&path).unwrap().modified().unwrap();
        let later = written + std::time::Duration::from_secs(1);
        assert!(text(&path, later, &[me()]).unwrap().is_none());
        let text = text(&path, written, &[me()]).unwrap().unwrap();
        assert_eq!(text, "10 10 py::f:/a.py\n");
        assert!(
            super::text(&dir.path().join("none"), written, &[me()])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn notes_the_user_of_a_process_whose_map_appears() {
        let dir = tempfile::tempdir().unwrap();
        let watch = watch(dir.path()).unwrap();
        let pid = std::process::id();
        fs::write(dir.path().join(format!("perf-{pid}.map")), "").unwrap();
        fs::write(dir.path().join("perf-x.map"), "").unwrap();
        let owners = watch.stop();
        assert_eq!(owners.0.keys().collect::<Vec<_>>(), [&pid]);
        assert_eq!(owners.of(pid, 0), [0, me(), me()]);
    }

    #[test]
    fn reads_only_a_file_of_the_processs_user() {
        let dir = tempfile::tempdir().unwrap();
        let since = SystemTime::UNIX_EPOCH;
        let fifo = dir.path().join("fifo.map");
        rustix::fs::mknodat(CWD, &fifo, FileType::Fifo, Mode::RUSR | Mode::WUSR, 0).unwrap();
        let error = text(&fifo, since, &[me()]).unwrap_err();
        assert_eq!(error.to_string(), "it is not a regular file");

        let file = dir.path().join("file.map");
        fs::write(&file, "10 10 f\n").unwrap();
        let link = dir.path().join("link.map");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        let error = text(&link, since, &[me()]).unwrap_err();
        assert_eq!(error.to_string(), "it is a symbolic link");

        // Root's files are read whoever the process's user is.
        if me() != 0 {
            let error = text(&file, since, &[me() + 1]).unwrap_err();
            assert!(error.to_string().contains("did not run as"), "{error}");
            assert!(text(&file, since, &[me() + 1, me()]).unwrap().is_some());
        }
    }
}
