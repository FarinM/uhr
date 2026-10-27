//! What uhr knows of each runtime it supports, a module each: the files it
//! runs from, how it names the code it compiles, and how to read its
//! interpreter's frames.

use std::ffi::OsString;
use std::io;
use std::ops::Range;

pub use process::{Memory, Process};

mod node;
mod process;
mod python;
mod text;

/// A runtime uhr supports.
pub trait Runtime: Sync {
    /// Its name in recordings and results, as in `python`.
    fn name(&self) -> &'static str;
    /// Whether a binary is the runtime's, by its file name: its program, or
    /// a library that embeds it in another.
    fn is_binary(&self, file: &str) -> bool;
    /// How it names the code it compiles in perf maps, if it does.
    fn perf_maps(&self) -> Option<&PerfMaps> {
        None
    }
    /// The runtime's interpreter in a process, whose frames uhr can read.
    /// `None` if the process does not run it.
    fn interpreter(&self, _process: &dyn Process) -> Result<Option<Box<dyn Interpreter>>, Error> {
        Ok(None)
    }
}

/// A runtime's interpreter found in one process: how uhr's sampler walks
/// its frames, and how to name them.
pub trait Interpreter: Send {
    fn runtime(&self) -> &'static str;
    fn version(&self) -> &str;
    /// Where the sampled thread's frames are, in numbers.
    fn walk(&self) -> Walk;
    /// The native code that runs interpreter frames, sorted. A stack holds
    /// one run of it each time native code called into the interpreter,
    /// and the frames that call ran go just above the run.
    fn eval_loop(&self) -> &[Range<u64>];
    /// What the bytes the sampler copied of a frame say.
    fn frame(&self, bytes: &[u8]) -> WalkedFrame;
    /// The code at `address`, read from the process's memory.
    fn code(&self, memory: &dyn Memory, address: u64) -> Result<Code, Error>;
}

/// How uhr's sampler finds and copies an interpreter's frames, in numbers:
/// where the sampled thread's innermost frame is, how to get from each
/// frame to the next outward, and what to copy of each. The sampler knows
/// no runtime, only these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Walk {
    pub thread: Thread,
    pub step: Step,
    /// How many of each frame's first bytes to copy.
    pub frame_bytes: u32,
    /// Whether the sampler should keep where each native frame is on the
    /// stack, for an interpreter that keeps its entry frames there.
    pub frame_pointers: bool,
}

/// Where the sampled thread's innermost frame is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Thread {
    /// In the thread's state, which the runtime keeps in lists.
    States(States),
}

/// How to get from a frame to the next one outward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Follow the pointer the frame holds at this offset. A null one ends
    /// the walk.
    Pointer(u32),
}

/// Thread states in lists, one for each entry of an outer list, as CPython
/// keeps one for each interpreter: the first entry is at the pointer
/// `lists[0]` past `base`, then at the pointer each next offset past the one
/// before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct States {
    pub base: u64,
    pub lists: Vec<u32>,
    /// Where an entry holds the next one, `None` for a single list.
    pub next_list: Option<u32>,
    /// Where an entry holds its first thread state, and a state the next
    /// one.
    pub first_state: u32,
    pub next_state: u32,
    /// Where a state holds its thread's id, as a 64-bit number.
    pub thread_id: u32,
    /// Where a state holds a 32-bit word with a bit of the mask set while
    /// its thread runs in it, for a runtime that marks it so. A thread can
    /// have a state in several lists. Without a mark, the one with frames
    /// is it.
    pub active: Option<(u32, u32)>,
    /// The pointers to follow from a thread's state to its innermost frame,
    /// as for `lists`.
    pub frame: Vec<u32>,
}

/// A thread's state, as `States::search` reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadState {
    pub address: u64,
    /// In the process's PID namespace.
    pub thread_id: u64,
    pub active: bool,
    pub has_frames: bool,
}

impl States {
    /// The first `limit` thread states, read from the process's memory, as
    /// the sampler searches them but further.
    pub fn search(&self, memory: &dyn Memory, limit: usize) -> Result<Vec<ThreadState>, Error> {
        let word = |address: u64| process::u64_at(memory, "a thread state", address);
        let follow = |mut address: u64, path: &[u32]| {
            for &offset in path {
                if address == 0 {
                    break;
                }
                address = word(address.wrapping_add(u64::from(offset)))?;
            }
            Ok::<_, Error>(address)
        };
        let mut found = Vec::new();
        let mut list = follow(self.base, &self.lists)?;
        // Bounded, as memory that changes as it is read can loop.
        for _ in 0..limit {
            if list == 0 || found.len() >= limit {
                break;
            }
            let mut state = word(list.wrapping_add(u64::from(self.first_state)))?;
            while state != 0 && found.len() < limit {
                let active = match self.active {
                    Some((at, mask)) => {
                        let status =
                            process::u32_at(memory, "a thread's status", state + u64::from(at))?;
                        status & mask != 0
                    }
                    None => false,
                };
                found.push(ThreadState {
                    address: state,
                    thread_id: word(state.wrapping_add(u64::from(self.thread_id)))?,
                    active,
                    has_frames: follow(state, &self.frame)? != 0,
                });
                state = word(state.wrapping_add(u64::from(self.next_state)))?;
            }
            let Some(next) = self.next_list else {
                break;
            };
            list = word(list.wrapping_add(u64::from(next)))?;
        }
        Ok(found)
    }
}

/// A frame the sampler walked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkedFrame {
    /// A frame of the program's code: the code it ran and where in it.
    /// `entered` if native code called into it, so that it is the
    /// outermost frame of that call.
    Code {
        code: u64,
        instruction: u64,
        entered: bool,
    },
    /// A frame the runtime puts where native code calls into it, which
    /// ends the frames of that call. `native` if it keeps the frame in the
    /// native frame of that call, so that where it is says which one.
    Entry { native: bool },
}

/// A piece of the program's code, as its interpreter keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Code {
    pub name: String,
    pub file: String,
    pub first_line: u32,
    /// The column it starts at, where the runtime says.
    pub first_column: Option<u32>,
    /// The line of each range of instructions, by address, sorted.
    pub lines: Vec<(Range<u64>, u32)>,
}

impl Code {
    pub fn line(&self, instruction: u64) -> Option<u32> {
        let after = self
            .lines
            .partition_point(|(range, _)| range.start <= instruction);
        let (range, line) = self.lines.get(after.checked_sub(1)?)?;
        range.contains(&instruction).then_some(*line)
    }
}

/// Why a runtime's interpreter or code could not be read.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("reading {what} at {address:#x}")]
    Read {
        what: &'static str,
        address: u64,
        #[source]
        source: io::Error,
    },
    #[error("reading {path}")]
    File {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("{runtime} {version} is not a version uhr can read the frames of")]
    Unsupported {
        runtime: &'static str,
        version: String,
    },
    #[error("{0}")]
    Invalid(String),
}

/// The interpreter of the first runtime found in `process`.
pub fn interpreter(process: &dyn Process) -> Result<Option<Box<dyn Interpreter>>, Error> {
    for runtime in RUNTIMES {
        if let Some(interpreter) = runtime.interpreter(process)? {
            return Ok(Some(interpreter));
        }
    }
    Ok(None)
}

/// How a runtime names the code it compiles in a perf map when its
/// environment tells it to.
pub struct PerfMaps {
    /// The variable in its environment that turns them on.
    pub variable: &'static str,
    pub setting: Setting,
    /// Whether the variable's value turns them on.
    pub on: fn(&str) -> bool,
    /// What a name in its map says. `None` for one it did not write.
    pub code: for<'a> fn(&'a str) -> Option<JitCode<'a>>,
    /// Whether its names say where each function starts.
    pub starts: bool,
}

pub enum Setting {
    /// What uhr sets the variable to, when it is not set.
    Value(&'static str),
    /// Options uhr adds to the variable's, each with the options that do
    /// its work instead. One that is there already, or turned off with
    /// `--no-`, is left alone. `split` reads the options of a value.
    Options {
        wanted: &'static [&'static [&'static str]],
        split: fn(&str) -> Vec<String>,
    },
}

pub static RUNTIMES: [&dyn Runtime; 2] = [&python::Python, &node::Node];

/// The runtime a binary is, by its file name.
pub fn binary_runtime(file: &str) -> Option<&'static str> {
    RUNTIMES
        .iter()
        .find(|runtime| runtime.is_binary(file))
        .map(|runtime| runtime.name())
}

/// What a runtime's perf map says about a piece of the code it compiled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JitCode<'a> {
    pub runtime: &'static str,
    /// The program's function, or `None` for the runtime's own code, such as
    /// V8's builtins.
    pub function: Option<JitFunction<'a>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JitFunction<'a> {
    /// `None` for an anonymous function.
    pub name: Option<&'a str>,
    pub file: &'a str,
    /// Where it starts, as `line` or `line:column`, when the runtime says.
    pub start: Option<&'a str>,
}

/// Whether functions of `runtime` that share a name and file are told apart
/// by where they start. Not those of a runtime whose perf maps don't say,
/// which group by name alone, so that its maps and its interpreter's frames
/// name a function alike.
pub fn starts_tell_apart(runtime: &str) -> bool {
    RUNTIMES
        .iter()
        .find(|r| r.name() == runtime)
        .and_then(|r| r.perf_maps())
        .is_none_or(|maps| maps.starts)
}

/// Reads a name from a perf map. `None` for one no runtime uhr knows wrote.
pub fn jit_code(name: &str) -> Option<JitCode<'_>> {
    RUNTIMES
        .iter()
        .filter_map(|runtime| runtime.perf_maps())
        .find_map(|maps| (maps.code)(name))
}

/// What to add to a target's environment, read with `get`, so that runtimes
/// write perf maps, unless `add` is false, and the runtimes whose maps are on
/// then. A variable that is set already is left alone, unless it holds
/// options to add to.
pub fn environment(
    get: impl Fn(&str) -> Option<OsString>,
    add: bool,
) -> (Vec<(&'static str, OsString)>, Vec<String>) {
    let mut set = Vec::new();
    let mut on = Vec::new();
    for runtime in RUNTIMES {
        let Some(maps) = runtime.perf_maps() else {
            continue;
        };
        let current = get(maps.variable);
        let value = match (current, &maps.setting) {
            (Some(current), _) if !add => current,
            (None, _) if !add => continue,
            (Some(current), Setting::Value(_)) => current,
            (None, Setting::Value(value)) => {
                set.push((maps.variable, value.into()));
                value.into()
            }
            (current, Setting::Options { wanted, split }) => {
                let mut value = current.unwrap_or_default();
                let present = split(&value.to_string_lossy());
                let missing: Vec<&str> = wanted
                    .iter()
                    .filter(|alternatives| !has(&present, alternatives))
                    .map(|alternatives| alternatives[0])
                    .collect();
                for option in &missing {
                    if !value.is_empty() {
                        value.push(" ");
                    }
                    value.push(option);
                }
                if !missing.is_empty() {
                    set.push((maps.variable, value.clone()));
                }
                value
            }
        };
        if (maps.on)(&value.to_string_lossy()) {
            on.push(runtime.name().to_owned());
        }
    }
    (set, on)
}

/// Whether `present` holds one of `alternatives`, or turns one off.
fn has(present: &[String], alternatives: &[&str]) -> bool {
    present.iter().any(|option| {
        let option = match option.strip_prefix("--no-") {
            Some(name) => format!("--{name}"),
            None => option.clone(),
        };
        alternatives.contains(&option.as_str())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(variables: &[(&str, &str)]) -> (Vec<(&'static str, String)>, Vec<String>) {
        environment_of(variables, true)
    }

    fn environment_of(
        variables: &[(&str, &str)],
        add: bool,
    ) -> (Vec<(&'static str, String)>, Vec<String>) {
        let (set, on) = environment(
            |name| {
                variables
                    .iter()
                    .find(|(n, _)| *n == name)
                    .map(|(_, v)| v.into())
            },
            add,
        );
        let set = set
            .into_iter()
            .map(|(n, v)| (n, v.to_string_lossy().into_owned()))
            .collect();
        (set, on)
    }

    #[test]
    fn turns_on_every_runtime_by_default() {
        let (set, on) = with(&[]);
        assert_eq!(
            set,
            [
                ("PYTHONPERFSUPPORT", "1".to_owned()),
                (
                    "NODE_OPTIONS",
                    "--perf-basic-prof --interpreted-frames-native-stack".to_owned()
                ),
            ]
        );
        assert_eq!(on, ["python", "node"]);
    }

    #[test]
    fn keeps_what_the_user_set() {
        let (set, on) = with(&[
            ("PYTHONPERFSUPPORT", "0"),
            ("NODE_OPTIONS", "--max-old-space-size=4096"),
        ]);
        assert_eq!(
            set,
            [(
                "NODE_OPTIONS",
                "--max-old-space-size=4096 --perf-basic-prof --interpreted-frames-native-stack"
                    .to_owned()
            )]
        );
        assert_eq!(on, ["node"]);

        let (set, on) = with(&[
            ("PYTHONPERFSUPPORT", "2"),
            ("NODE_OPTIONS", "--perf-basic-prof"),
        ]);
        assert_eq!(
            set,
            [(
                "NODE_OPTIONS",
                "--perf-basic-prof --interpreted-frames-native-stack".to_owned()
            )]
        );
        assert_eq!(on, ["python", "node"]);
    }

    #[test]
    fn adds_no_option_that_is_set_or_turned_off() {
        let options = "--perf_basic_prof_only_functions --no-interpreted-frames-native-stack";
        let (set, on) = with(&[("PYTHONPERFSUPPORT", "1"), ("NODE_OPTIONS", options)]);
        assert!(set.is_empty(), "{set:?}");
        assert_eq!(on, ["python", "node"]);

        let (set, on) = with(&[
            ("PYTHONPERFSUPPORT", "1"),
            ("NODE_OPTIONS", "--perf-basic-prof --no-perf-basic-prof"),
        ]);
        assert_eq!(
            set,
            [(
                "NODE_OPTIONS",
                "--perf-basic-prof --no-perf-basic-prof --interpreted-frames-native-stack"
                    .to_owned()
            )]
        );
        assert_eq!(on, ["python"]);
    }

    #[test]
    fn reads_quoted_node_options() {
        let (set, on) = with(&[
            ("PYTHONPERFSUPPORT", "1"),
            (
                "NODE_OPTIONS",
                r#""--no-perf-basic-prof" "--interpreted-frames-native-stack""#,
            ),
        ]);
        assert!(set.is_empty(), "{set:?}");
        assert_eq!(on, ["python"]);
        let (_, on) = environment_of(&[("NODE_OPTIONS", r#""--perf-basic-prof""#)], false);
        assert_eq!(on, ["node"]);
    }

    #[test]
    fn only_reports_what_is_on_when_told_not_to_add() {
        let (set, on) = environment_of(&[("PYTHONPERFSUPPORT", "1")], false);
        assert!(set.is_empty());
        assert_eq!(on, ["python"]);
    }

    #[test]
    fn tells_runtimes_by_their_binaries() {
        assert_eq!(binary_runtime("python3.12"), Some("python"));
        assert_eq!(binary_runtime("libpython3.13.so.1.0"), Some("python"));
        assert_eq!(binary_runtime("node"), Some("node"));
        assert_eq!(binary_runtime("libnode.so.115"), Some("node"));
        assert_eq!(binary_runtime("nodemon"), None);
    }
}
