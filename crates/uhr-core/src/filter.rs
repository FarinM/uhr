use std::collections::{HashMap, HashSet};

use serde::Serialize;

use crate::functions::{self, Functions};
use crate::recording::{Mode, Recording, Sample};
use crate::threads::ThreadNames;

/// Which samples a result covers. An empty list matches everything. The
/// values in one list are alternatives, and every list has to match.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Filter {
    pub pids: Vec<u32>,
    /// Matches every lifetime of a reused thread id.
    pub tids: Vec<u32>,
    /// Patterns for the name the thread had when the sample was taken. `*`
    /// matches any run of characters and `?` one character.
    pub thread_names: Vec<String>,
    pub modes: Vec<Mode>,
    /// Functions, by id or by a name only one function has. A sample passes
    /// if its stack contains one of them.
    pub under: Vec<String>,
    /// Offset from the recording start, inclusive.
    pub from_ns: Option<u64>,
    /// Offset from the recording start, exclusive.
    pub to_ns: Option<u64>,
}

impl Filter {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Fails if `under` names a function that is not in the samples, or a
    /// name several functions share.
    pub(crate) fn samples<'a>(
        &'a self,
        recording: &'a Recording,
        functions: &Functions,
    ) -> Result<impl Iterator<Item = &'a Sample> + 'a, functions::Error> {
        let under = self.stacks_under(recording, functions)?;
        let mut names = (!self.thread_names.is_empty()).then(|| NameMatcher::new(recording));
        let start_ns = recording.manifest.start_ns;
        Ok(recording.samples.iter().filter(move |sample| {
            (self.pids.is_empty() || self.pids.contains(&sample.pid))
                && (self.tids.is_empty() || self.tids.contains(&sample.tid))
                && (self.modes.is_empty() || self.modes.contains(&sample.mode))
                && self.in_time_range(sample.time_ns, start_ns)
                && under
                    .as_ref()
                    .is_none_or(|under| under[sample.stack as usize])
                && names
                    .as_mut()
                    .is_none_or(|names| names.matches(self, sample))
        }))
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

    fn in_time_range(&self, time_ns: u64, start_ns: Option<u64>) -> bool {
        if self.from_ns.is_none() && self.to_ns.is_none() {
            return true;
        }
        // Without a start, offsets are meaningless.
        let Some(offset) = start_ns.map(|start| time_ns.saturating_sub(start)) else {
            return false;
        };
        self.from_ns.is_none_or(|from| from <= offset) && self.to_ns.is_none_or(|to| offset < to)
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

    fn matches(&mut self, filter: &Filter, sample: &Sample) -> bool {
        let Some(name) = self.names.at(sample.pid, sample.tid, sample.time_ns) else {
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
