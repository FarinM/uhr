use std::ffi::OsString;

/// A runtime that names the code it compiles in a perf map when its
/// environment tells it to.
struct Runtime {
    name: &'static str,
    variable: &'static str,
    setting: Setting,
    /// Whether the variable's value turns the map on.
    on: fn(&str) -> bool,
}

enum Setting {
    /// What uhr sets the variable to, when it is not set.
    Value(&'static str),
    /// Options uhr adds to the variable's, each with the options that do
    /// its work instead. One that is there already, or turned off with
    /// `--no-`, is left alone.
    Options(&'static [&'static [&'static str]]),
}

const RUNTIMES: [Runtime; 2] = [
    Runtime {
        name: "python",
        variable: "PYTHONPERFSUPPORT",
        setting: Setting::Value("1"),
        on: python_on,
    },
    Runtime {
        name: "node",
        variable: "NODE_OPTIONS",
        // Without the second, code V8 interprets has no frame of its own.
        setting: Setting::Options(&[
            &["--perf-basic-prof", "--perf-basic-prof-only-functions"],
            &["--interpreted-frames-native-stack"],
        ]),
        on: node_on,
    },
];

/// CPython reads the value as a number with C's `strtol`, after the
/// whitespace C knows, and any but 0 turns the map on.
fn python_on(value: &str) -> bool {
    value
        .trim_start_matches([' ', '\t', '\n', '\x0b', '\x0c', '\r'])
        .parse::<i32>()
        .is_ok_and(|n| n != 0)
}

/// V8 takes the last of an option and its `--no-` form.
fn node_on(value: &str) -> bool {
    let (mut all, mut functions) = (false, false);
    for option in options(value) {
        match option.as_str() {
            "--perf-basic-prof" => all = true,
            "--no-perf-basic-prof" => all = false,
            "--perf-basic-prof-only-functions" => functions = true,
            "--no-perf-basic-prof-only-functions" => functions = false,
            _ => {}
        }
    }
    all || functions
}

/// The options in `NODE_OPTIONS`, split as Node splits them: at spaces
/// outside double quotes, in which `\` escapes the next character. V8 reads
/// its options with `_` and `-` alike.
fn options(value: &str) -> Vec<String> {
    let mut options: Vec<String> = Vec::new();
    let (mut quoted, mut next) = (false, true);
    let mut chars = value.chars();
    while let Some(mut c) = chars.next() {
        match c {
            '\\' if quoted => match chars.next() {
                Some(escaped) => c = escaped,
                None => break,
            },
            ' ' if !quoted => {
                next = true;
                continue;
            }
            '"' => {
                quoted = !quoted;
                continue;
            }
            _ => {}
        }
        match options.last_mut() {
            Some(option) if !next => option.push(c),
            _ => options.push(c.to_string()),
        }
        next = false;
    }
    options
        .iter()
        .map(|option| option.replace('_', "-"))
        .collect()
}

/// What to add to a target's environment, read with `get`, so that runtimes
/// write perf maps, unless `add` is false, and the runtimes whose maps are on
/// then. A variable that is set already is left alone, unless it holds
/// options to add to.
pub(crate) fn environment(
    get: impl Fn(&str) -> Option<OsString>,
    add: bool,
) -> (Vec<(&'static str, OsString)>, Vec<String>) {
    let mut set = Vec::new();
    let mut on = Vec::new();
    for runtime in &RUNTIMES {
        let current = get(runtime.variable);
        let value = match (current, &runtime.setting) {
            (Some(current), _) if !add => current,
            (None, _) if !add => continue,
            (Some(current), Setting::Value(_)) => current,
            (None, Setting::Value(value)) => {
                set.push((runtime.variable, value.into()));
                value.into()
            }
            (current, Setting::Options(wanted)) => {
                let mut value = current.unwrap_or_default();
                let present = options(&value.to_string_lossy());
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
                    set.push((runtime.variable, value.clone()));
                }
                value
            }
        };
        if (runtime.on)(&value.to_string_lossy()) {
            on.push(runtime.name.to_owned());
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
    fn reads_pythons_setting_as_a_number() {
        for value in ["1", "2", "01", "-1", " \t1"] {
            assert!(python_on(value), "{value:?}");
        }
        for value in ["0", "00", "", "yes", "1x", "1 ", "99999999999", "\u{a0}1"] {
            assert!(!python_on(value), "{value:?}");
        }
    }

    #[test]
    fn splits_node_options_as_node_does() {
        assert_eq!(
            options(r#"--a "--b c" --d_e="f\"g"  "--no-perf_basic_prof""#),
            ["--a", "--b c", "--d-e=f\"g", "--no-perf-basic-prof"]
        );
        assert_eq!(options("--a\t--b"), ["--a\t--b"]);
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
}
