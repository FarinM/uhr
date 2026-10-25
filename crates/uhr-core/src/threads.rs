use std::collections::HashMap;

use crate::recording::Recording;

/// Oldest first. Names set before the recording have no time and come first.
type History<'a> = Vec<(Option<u64>, &'a str)>;

/// The name history of every thread id, for looking up the name a thread
/// had at a given time.
pub(crate) struct ThreadNames<'a> {
    names: HashMap<(u32, u32), History<'a>>,
}

impl<'a> ThreadNames<'a> {
    pub(crate) fn new(recording: &'a Recording) -> Self {
        let mut names: HashMap<_, Vec<_>> = HashMap::new();
        for name in &recording.thread_names {
            names
                .entry((name.pid, name.tid))
                .or_default()
                .push((name.time_ns, name.name.as_str()));
        }
        for history in names.values_mut() {
            history.sort_by_key(|&(time, _)| time);
        }
        Self { names }
    }

    /// A name set at exactly `time_ns` counts. `None` if the thread had no
    /// known name yet.
    pub(crate) fn at(&self, pid: u32, tid: u32, time_ns: u64) -> Option<&'a str> {
        let history = self.names.get(&(pid, tid))?;
        let set = history.partition_point(|&(time, _)| time.is_none_or(|t| t <= time_ns));
        set.checked_sub(1).map(|i| history[i].1)
    }

    /// The names the thread had at some point in `from_ns..to_ns`, oldest
    /// first.
    pub(crate) fn during(&self, pid: u32, tid: u32, from_ns: u64, to_ns: u64) -> Vec<&'a str> {
        let Some(history) = self.names.get(&(pid, tid)).filter(|_| from_ns < to_ns) else {
            return Vec::new();
        };
        let mut names: Vec<&str> = self.at(pid, tid, from_ns).into_iter().collect();
        let later = history
            .iter()
            .filter(|&&(time, _)| time.is_some_and(|t| from_ns < t && t < to_ns));
        for &(_, name) in later {
            if names.last() != Some(&name) {
                names.push(name);
            }
        }
        names
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recording::{Clock, FORMAT_VERSION, KernelSymbols, Manifest, Target, ThreadName};

    fn recording(names: Vec<ThreadName>) -> Recording {
        Recording {
            manifest: Manifest {
                format_version: FORMAT_VERSION,
                target: Target {
                    command: vec!["app".into()],
                    launched: true,
                    exit: None,
                },
                clock: Clock::Monotonic,
                start_ns: None,
                end_ns: None,
                streams: Vec::new(),
                kernel_symbols: KernelSymbols::Saved,
            },
            threads: Vec::new(),
            thread_names: names,
            mappings: Vec::new(),
            frames: Vec::new(),
            stacks: Vec::new(),
            samples: Vec::new(),
            off_cpu: Vec::new(),
            kernel_symbols: Vec::new(),
        }
    }

    fn name(tid: u32, time_ns: Option<u64>, name: &str) -> ThreadName {
        ThreadName {
            pid: 1,
            tid,
            time_ns,
            name: name.into(),
        }
    }

    #[test]
    fn finds_the_name_in_effect() {
        let recording = recording(vec![
            name(1, Some(20), "worker"),
            name(1, None, "perf-exec"),
            name(1, Some(10), "app"),
            name(2, Some(15), "other"),
        ]);
        let names = ThreadNames::new(&recording);
        assert_eq!(names.at(1, 1, 5), Some("perf-exec"));
        assert_eq!(names.at(1, 1, 10), Some("app"));
        assert_eq!(names.at(1, 1, 19), Some("app"));
        assert_eq!(names.at(1, 1, 25), Some("worker"));
        assert_eq!(names.at(1, 2, 14), None);
        assert_eq!(names.at(1, 3, 25), None);

        assert_eq!(names.during(1, 1, 0, 100), ["perf-exec", "app", "worker"]);
        assert_eq!(names.during(1, 1, 10, 20), ["app"], "the end is exclusive");
        assert_eq!(names.during(1, 1, 12, 21), ["app", "worker"]);
        assert_eq!(names.during(1, 1, 20, 20), Vec::<&str>::new());
        assert_eq!(names.during(1, 2, 0, 15), Vec::<&str>::new());
        assert_eq!(names.during(1, 2, 0, 16), ["other"]);
    }

    #[test]
    fn skips_a_repeated_name() {
        let recording = recording(vec![
            name(1, Some(10), "app"),
            name(1, Some(20), "app"),
            name(1, Some(30), "worker"),
        ]);
        let names = ThreadNames::new(&recording);
        assert_eq!(names.during(1, 1, 0, 40), ["app", "worker"]);
    }
}
