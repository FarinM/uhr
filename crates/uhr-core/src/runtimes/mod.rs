//! What uhr knows of each runtime it supports, a module each: the files it
//! runs from, and how it names the code it compiles.

use std::ffi::OsString;

mod node;
mod python;

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
