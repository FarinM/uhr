use std::collections::{HashMap, HashSet};

use serde::Serialize;

use crate::functions::{self, Functions};
use crate::recording::{KernelSymbols, Mode, OffCPUInterval, Recording, Sample};
use crate::syscalls::{self, InSyscall};
use crate::threads::ThreadNames;

/// Which samples and off-CPU intervals a result covers. An empty list
/// matches everything. The values in one list are alternatives, and every
/// list has to match.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Filter {
    pub pids: Vec<u32>,
    /// Matches every lifetime of a reused thread id.
    pub tids: Vec<u32>,
    /// Patterns for the name the thread had when the sample was taken, or
    /// when it went off CPU. `*` matches any run of characters and `?` one
    /// character.
    pub thread_names: Vec<String>,
    /// Off-CPU time has no mode, so any mode leaves it out.
    pub modes: Vec<Mode>,
    /// Functions, by id or by a name only one function has. A sample or
    /// off-CPU interval passes if its stack contains one of them.
    pub under: Vec<String>,
    /// Syscalls by name, as `read`. A sample or off-CPU interval passes if
    /// its stack is in one of them.
    pub syscalls: Vec<String>,
    /// Offset from the recording start, inclusive. Off-CPU intervals are
    /// cut to the time range.
    pub from_ns: Option<u64>,
    /// Offset from the recording start, exclusive.
    pub to_ns: Option<u64>,
}

/// Why a filter could not be applied.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// `under` names a function that is not there, or not only once, or
    /// the filter needs names the recording does not have yet.
    #[error(transparent)]
    Function(#[from] functions::Error),
    #[error("the recording has no kernel function names, so its syscalls are unknown: {0}")]
    NoKernelNames(String),
    #[error(
        "no stack in the recording is in the syscall {name:?}. Its stacks are in: {}",
        if .known.is_empty() { "none".to_owned() } else { .known.join(", ") }
    )]
    NoSuchSyscall { name: String, known: Vec<String> },
}

impl Filter {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Fails if `under` names a function that is not in the stacks, or a
    /// name several functions share, or `syscalls` a syscall no stack is
    /// in.
    pub(crate) fn samples<'a>(
        &'a self,
        recording: &'a Recording,
        functions: &Functions,
    ) -> Result<impl Iterator<Item = &'a Sample> + 'a, Error> {
        let stacks = self.stacks(recording, functions)?;
        let mut names = (!self.thread_names.is_empty()).then(|| NameMatcher::new(recording));
        let start_ns = recording.manifest.start_ns;
        Ok(recording.samples.iter().filter(move |sample| {
            (self.pids.is_empty() || self.pids.contains(&sample.pid))
                && (self.tids.is_empty() || self.tids.contains(&sample.tid))
                && (self.modes.is_empty() || self.modes.contains(&sample.mode))
                && self.in_time_range(sample.time_ns, start_ns)
                && stacks
                    .as_ref()
                    .is_none_or(|stacks| stacks[sample.stack as usize])
                && names
                    .as_mut()
                    .is_none_or(|names| names.matches(self, sample.pid, sample.tid, sample.time_ns))
        }))
    }

    /// The off-CPU intervals that pass, each with how long it lies in the
    /// time range. Fails like `samples`.
    pub(crate) fn off_cpu<'a>(
        &'a self,
        recording: &'a Recording,
        functions: &Functions,
    ) -> Result<impl Iterator<Item = (&'a OffCPUInterval, u64)> + 'a, Error> {
        let stacks = self.stacks(recording, functions)?;
        let mut names = (!self.thread_names.is_empty()).then(|| NameMatcher::new(recording));
        let range = self.time_range(recording.manifest.start_ns);
        Ok(recording.off_cpu.iter().filter_map(move |interval| {
            let (start, end) =
                range.map(|(from, to)| (interval.start_ns.max(from), interval.end_ns.min(to)))?;
            let passes = self.modes.is_empty()
                && start < end
                && (self.pids.is_empty() || self.pids.contains(&interval.pid))
                && (self.tids.is_empty() || self.tids.contains(&interval.tid))
                && stacks.as_ref().is_none_or(|stacks| {
                    interval.stack.is_some_and(|stack| stacks[stack as usize])
                })
                && names.as_mut().is_none_or(|names| {
                    names.matches(self, interval.pid, interval.tid, interval.start_ns)
                });
            passes.then(|| (interval, end - start))
        }))
    }

    /// Whether each stack passes `under` and `syscalls`. `None` without
    /// either.
    fn stacks(
        &self,
        recording: &Recording,
        functions: &Functions,
    ) -> Result<Option<Vec<bool>>, Error> {
        let under = self.stacks_under(recording, functions)?;
        let in_syscalls = self.stacks_in_syscalls(recording, functions)?;
        Ok(match (under, in_syscalls) {
            (Some(under), Some(in_syscalls)) => {
                Some(under.iter().zip(&in_syscalls).map(|(a, b)| a & b).collect())
            }
            (under, in_syscalls) => under.or(in_syscalls),
        })
    }

    /// Whether each stack is in a syscall of `syscalls`. `None` without
    /// `syscalls`.
    fn stacks_in_syscalls(
        &self,
        recording: &Recording,
        functions: &Functions,
    ) -> Result<Option<Vec<bool>>, Error> {
        if self.syscalls.is_empty() {
            return Ok(None);
        }
        if !functions.symbolized() {
            return Err(functions::Error::NotSymbolized.into());
        }
        if let KernelSymbols::Unavailable { reason } = &recording.manifest.kernel_symbols {
            return Err(Error::NoKernelNames(reason.clone()));
        }
        let in_syscall = syscalls::of_stacks(recording, functions);
        let mut known: Vec<&str> = in_syscall
            .iter()
            .filter_map(|s| match s {
                Some(InSyscall::Named(name)) => Some(*name),
                _ => None,
            })
            .collect();
        known.sort_unstable();
        known.dedup();
        if let Some(name) = self.syscalls.iter().find(|s| !known.contains(&s.as_str())) {
            return Err(Error::NoSuchSyscall {
                name: name.clone(),
                known: known.iter().map(|&s| s.to_owned()).collect(),
            });
        }
        Ok(Some(
            in_syscall
                .iter()
                .map(|s| match s {
                    Some(InSyscall::Named(name)) => self.syscalls.iter().any(|w| w == name),
                    _ => false,
                })
                .collect(),
        ))
    }

    /// Whether each stack contains a function of `under`. `None` without
    /// `under`.
    fn stacks_under(
        &self,
        recording: &Recording,
        functions: &Functions,
    ) -> Result<Option<Vec<bool>>, functions::Error> {
        if self.under.is_empty() {
            return Ok(None);
        }
        let wanted = self
            .under
            .iter()
            .map(|wanted| functions.select(wanted))
            .collect::<Result<HashSet<u32>, _>>()?;
        Ok(Some(
            recording
                .stacks
                .iter()
                .map(|stack| functions.expand(stack).any(|f| wanted.contains(&f)))
                .collect(),
        ))
    }

    /// Whether a thread with these ids, and these names over its life, can
    /// have samples that pass.
    pub(crate) fn matches_thread<'n>(
        &self,
        pid: u32,
        tid: u32,
        mut names: impl Iterator<Item = &'n str>,
    ) -> bool {
        (self.pids.is_empty() || self.pids.contains(&pid))
            && (self.tids.is_empty() || self.tids.contains(&tid))
            && (self.thread_names.is_empty() || names.any(|name| self.matches_name(name)))
    }

    fn matches_name(&self, name: &str) -> bool {
        let name: Vec<char> = name.chars().collect();
        self.thread_names.iter().any(|pattern| {
            let pattern: Vec<char> = pattern.chars().collect();
            glob(&pattern, &name)
        })
    }

    /// The time range in absolute times, end exclusive. `None` if nothing
    /// can be in it.
    fn time_range(&self, start_ns: Option<u64>) -> Option<(u64, u64)> {
        if self.from_ns.is_none() && self.to_ns.is_none() {
            return Some((0, u64::MAX));
        }
        // Without a start, offsets are meaningless.
        let start = start_ns?;
        Some((
            start.saturating_add(self.from_ns.unwrap_or(0)),
            self.to_ns.map_or(u64::MAX, |to| start.saturating_add(to)),
        ))
    }

    fn in_time_range(&self, time_ns: u64, start_ns: Option<u64>) -> bool {
        self.time_range(start_ns)
            .is_some_and(|(from, to)| from <= time_ns && time_ns < to)
    }
}

struct NameMatcher<'a> {
    names: ThreadNames<'a>,
    /// Many samples share a name, so each name is matched once.
    matched: HashMap<&'a str, bool>,
}

impl<'a> NameMatcher<'a> {
    fn new(recording: &'a Recording) -> Self {
        Self {
            names: ThreadNames::new(recording),
            matched: HashMap::new(),
        }
    }

    fn matches(&mut self, filter: &Filter, pid: u32, tid: u32, time_ns: u64) -> bool {
        let Some(name) = self.names.at(pid, tid, time_ns) else {
            return false;
        };
        *self
            .matched
            .entry(name)
            .or_insert_with(|| filter.matches_name(name))
    }
}

fn glob(pattern: &[char], text: &[char]) -> bool {
    let (mut p, mut t) = (0, 0);
    // Where the last `*` was, and the text position it currently ends at.
    let mut star = None;
    while t < text.len() {
        match pattern.get(p) {
            Some('*') => {
                star = Some((p, t));
                p += 1;
            }
            Some(&c) if c == '?' || c == text[t] => {
                p += 1;
                t += 1;
            }
            _ => match star {
                Some((star_p, star_t)) => {
                    p = star_p + 1;
                    t = star_t + 1;
                    star = Some((star_p, star_t + 1));
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|&c| c == '*')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(pattern: &str, text: &str) -> bool {
        let pattern: Vec<char> = pattern.chars().collect();
        let text: Vec<char> = text.chars().collect();
        glob(&pattern, &text)
    }

    #[test]
    fn globs() {
        assert!(matches("pool-*", "pool-12"));
        assert!(matches("pool-*", "pool-"));
        assert!(!matches("pool-*", "pool"));
        assert!(matches("*", ""));
        assert!(matches("w?rker", "worker"));
        assert!(!matches("w?rker", "wrker"));
        assert!(matches("*-io-*", "tokio-io-3"));
        assert!(matches("a*b*c", "aXbYbZc"));
        assert!(!matches("a*b*c", "aXbYbZ"));
        assert!(matches("exact", "exact"));
        assert!(!matches("exact", "exactly"));
        assert!(matches("??", "äö"));
    }
}
