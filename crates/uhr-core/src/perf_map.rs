use std::collections::{BTreeMap, BTreeSet, HashMap};
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
use tracing::warn;

use crate::launch::Process;
use crate::recording::{JitSymbol, Origin, Recording};
use crate::runtimes::jit_code;

/// The names a runtime gave the code it compiled, from its perf map, one
/// `start size name` line per piece of code, in hex. Where code took the
/// place of older code, the newer name holds.
#[derive(Debug, Default)]
pub(crate) struct PerfMap {
    /// By start: the end, exclusive, and the name.
    code: BTreeMap<u64, (u64, String)>,
}

impl PerfMap {
    pub(crate) fn parse(text: &str) -> Self {
        let mut map = Self::default();
        for line in text.lines() {
            let mut fields = line.splitn(3, ' ');
            let (Some(start), Some(size), Some(name)) =
                (fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            let (Ok(start), Ok(size)) = (
                u64::from_str_radix(start, 16),
                u64::from_str_radix(size, 16),
            ) else {
                continue;
            };
            if let Some(end) = start.checked_add(size).filter(|&end| end > start) {
                map.insert(start, end, name.trim_end());
            }
        }
        map
    }

    fn insert(&mut self, start: u64, end: u64, name: &str) {
        let older: Vec<u64> = self
            .code
            .range(..end)
            .rev()
            .take_while(|(_, (older_end, _))| *older_end > start)
            .map(|(&older_start, _)| older_start)
            .collect();
        for older_start in older {
            let (older_end, older_name) = self.code.remove(&older_start).expect("listed");
            if older_start < start {
                self.code.insert(older_start, (start, older_name.clone()));
            }
            if older_end > end {
                self.code.insert(end, (older_end, older_name));
            }
        }
        self.code.insert(start, (end, name.to_owned()));
    }

    /// The code `address` falls in: its start, end and name.
    pub(crate) fn find(&self, address: u64) -> Option<(u64, u64, &str)> {
        let (&start, (end, name)) = self.code.range(..=address).next_back()?;
        (address < *end).then_some((start, *end, name.as_str()))
    }
}

/// Names the frames of anonymous memory that a process's perf map covers,
/// making them JIT frames, and keeps the code they fall in. `since` gives
/// when a process's map has to be written after to be its own, and
/// `owners` the users it can belong to besides root. Returns the processes
/// whose maps named frames.
pub(crate) fn name_jit_frames(
    recording: &mut Recording,
    since: impl Fn(u32) -> SystemTime,
    owners: impl Fn(u32) -> Vec<u32>,
) -> Vec<u32> {
    let mut maps: HashMap<u32, Option<PerfMap>> = HashMap::new();
    let mut code = BTreeSet::new();
    for frame in &mut recording.frames {
        let pid = frame
            .mapping
            .and_then(|m| recording.mappings[m as usize].pid);
        let (Origin::Unresolved, Some(pid)) = (frame.origin, pid) else {
            continue;
        };
        let map = maps
            .entry(pid)
            .or_insert_with(|| match read(pid, since(pid), &owners(pid)) {
                Ok(map) => map,
                Err(error) => {
                    warn!(pid, %error, "reading the perf map");
                    None
                }
            });
        let address = frame
            .address
            .saturating_sub(u64::from(frame.return_address));
        if let Some((start, end, name)) = map.as_ref().and_then(|m| m.find(address)) {
            frame.origin = Origin::Jit;
            code.insert((pid, start, end, name.to_owned()));
        }
    }
    let named: BTreeSet<u32> = code.iter().map(|&(pid, ..)| pid).collect();
    recording.jit_symbols = code
        .into_iter()
        .map(|(pid, start, end, name)| JitSymbol {
            pid,
            start,
            end,
            name,
        })
        .collect();
    named.into_iter().collect()
}

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
    fn finds_the_newest_code_at_an_address() {
        let map = PerfMap::parse(
            "1000 100 py::old:/a.py\n\
             2000 10 JS:~f /b.js:1:1\n\
             1080 40 py::new:/a.py\n\
             not a line\n\
             zz 10 bad start\n",
        );
        assert_eq!(map.find(0x1000), Some((0x1000, 0x1080, "py::old:/a.py")));
        assert_eq!(map.find(0x10a0), Some((0x1080, 0x10c0, "py::new:/a.py")));
        // What is left of the older code after the newer.
        assert_eq!(map.find(0x10f0), Some((0x10c0, 0x1100, "py::old:/a.py")));
        assert_eq!(map.find(0x2009), Some((0x2000, 0x2010, "JS:~f /b.js:1:1")));
        assert_eq!(map.find(0x2010), None);
        assert_eq!(map.find(0xfff), None);
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

    #[test]
    fn newer_code_can_cover_several_older_pieces() {
        let map = PerfMap::parse("10 10 a\n20 10 b\n30 10 c\n18 20 d\n");
        assert_eq!(map.find(0x10), Some((0x10, 0x18, "a")));
        assert_eq!(map.find(0x20), Some((0x18, 0x38, "d")));
        assert_eq!(map.find(0x38), Some((0x38, 0x40, "c")));
    }
}
