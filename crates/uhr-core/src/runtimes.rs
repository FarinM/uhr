use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::Path;
use std::time::SystemTime;

/// A runtime that names the code it compiles in a perf map when its
/// environment tells it to.
struct Runtime {
    name: &'static str,
    variable: &'static str,
    setting: Setting,
    /// Whether the variable's value turns the map on.
    on: fn(&str) -> bool,
    /// Its own binaries, by file name.
    binary: fn(&str) -> bool,
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
        binary: python_binary,
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
        binary: node_binary,
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

/// `python3.12`, or a `libpython3.12.so` another program embeds it with.
fn python_binary(file: &str) -> bool {
    file.starts_with("python3") || file.starts_with("libpython3")
}

fn node_binary(file: &str) -> bool {
    file == "node" || file == "nodejs" || file.starts_with("libnode.so")
}

/// The runtime a binary is, by its file name.
pub(crate) fn binary_runtime(file: &str) -> Option<&'static str> {
    RUNTIMES
        .iter()
        .find(|runtime| (runtime.binary)(file))
        .map(|runtime| runtime.name)
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

/// What a runtime's perf map says about a piece of the code it compiled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct JitCode<'a> {
    pub(crate) runtime: &'static str,
    /// The program's function, or `None` for the runtime's own code, such as
    /// V8's builtins.
    pub(crate) function: Option<JitFunction<'a>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct JitFunction<'a> {
    /// `None` for an anonymous function.
    pub(crate) name: Option<&'a str>,
    pub(crate) file: &'a str,
    /// Where it starts, as `line` or `line:column`, when the runtime says.
    pub(crate) start: Option<&'a str>,
}

/// V8's kinds of code that run the program's JavaScript.
const V8_PROGRAM: [&str; 6] = [
    "JS",
    "LazyCompile",
    "Function",
    "InterpretedFunction",
    "Eval",
    "Script",
];

const V8_RUNTIME: [&str; 5] = ["Builtin", "BytecodeHandler", "Stub", "RegExp", "Handler"];

/// Reads a name from a perf map: CPython's `py::<qualname>:<file>`, or V8's
/// `<kind>:<tier><name> <file>:<line>[:<column>]`. `None` for one no runtime
/// uhr knows wrote.
pub(crate) fn jit_code(name: &str) -> Option<JitCode<'_>> {
    if let Some(function) = name.strip_prefix("py::") {
        let (name, file) = function.split_once(':')?;
        return Some(JitCode {
            runtime: "python",
            function: Some(JitFunction {
                name: Some(name),
                file,
                start: None,
            }),
        });
    }
    let (kind, code) = name.split_once(':')?;
    if V8_RUNTIME.contains(&kind) {
        return Some(JitCode {
            runtime: "node",
            function: None,
        });
    }
    if !V8_PROGRAM.contains(&kind) {
        return None;
    }
    let (code, start) = split_start(strip_tier(code));
    let (name, file) = split_script(code)?;
    Some(JitCode {
        runtime: "node",
        function: Some(JitFunction {
            name: Some(name).filter(|n| !n.is_empty()),
            file,
            start,
        }),
    })
}

/// Strips V8's mark of how far it compiled the code: `~` interpreted, `^`
/// baseline, `+` Maglev and `*` TurboFan, the last two with `'` after for
/// code specialized to one context, or `o` before for code a running loop
/// switched to. Code V8 won't optimize has none. A name that starts with one
/// of these marks can't be told from a mark.
fn strip_tier(code: &str) -> &str {
    let unspecialized = code
        .strip_prefix(['~', '^'])
        .or_else(|| code.strip_prefix("o+"))
        .or_else(|| code.strip_prefix("o*"));
    if let Some(rest) = unspecialized {
        return rest;
    }
    match code.strip_prefix(['+', '*']) {
        Some(rest) => rest.strip_prefix('\'').unwrap_or(rest),
        None => code,
    }
}

/// Splits `<name> <script>`. Both can hold spaces, as `get x` and
/// `/my app/x.js` do, so the script starts at the space before a path or a
/// URL, such as `file:` or `node:`, or else at the last space. `None` when
/// several spaces come before one, as in `GET /api /app/x.js`, which can't
/// be told apart.
fn split_script(code: &str) -> Option<(&str, &str)> {
    let script = |s: &str| s.starts_with('/') || has_scheme(s);
    let mut starts = code
        .match_indices(' ')
        .map(|(at, _)| at)
        .filter(|&at| script(&code[at + 1..]));
    let at = match (starts.next(), starts.next()) {
        (Some(at), None) => at,
        (None, _) => code.rfind(' ')?,
        (Some(_), Some(_)) => return None,
    };
    Some((&code[..at], &code[at + 1..]))
}

fn has_scheme(s: &str) -> bool {
    s.split_once(':').is_some_and(|(scheme, _)| {
        let mut chars = scheme.chars();
        chars.next().is_some_and(|c| c.is_ascii_alphabetic())
            && chars.all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
    })
}

/// Splits off `:line` or `:line:column`.
fn split_start(code: &str) -> (&str, Option<&str>) {
    let numeric = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let Some((before, last)) = code.rsplit_once(':').filter(|(_, n)| numeric(n)) else {
        return (code, None);
    };
    match before.rsplit_once(':').filter(|(_, n)| numeric(n)) {
        Some((rest, _)) => (rest, Some(&code[rest.len() + 1..])),
        None => (before, Some(last)),
    }
}

/// Removes the logs V8 writes beside a perf map, `isolate-0x<isolate>-<pid>-v8.log`,
/// that the process `pid` wrote in `dir` since `since`, and returns how many.
/// Node takes no option in its environment to move or stop them.
pub(crate) fn remove_v8_logs(dir: &Path, pid: u32, since: SystemTime) -> io::Result<usize> {
    let suffix = format!("-{pid}-v8.log");
    let mut removed = 0;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(isolate) = name
            .to_str()
            .and_then(|n| n.strip_prefix("isolate-0x")?.strip_suffix(suffix.as_str()))
        else {
            continue;
        };
        let written = entry.metadata()?.modified()?;
        if isolate.bytes().all(|b| b.is_ascii_hexdigit()) && written >= since {
            fs::remove_file(entry.path())?;
            removed += 1;
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn function(name: &str) -> Option<JitFunction<'_>> {
        jit_code(name).unwrap().function
    }

    #[test]
    fn removes_only_the_v8_logs_of_the_process() {
        let dir = tempfile::tempdir().unwrap();
        let since = SystemTime::now() - std::time::Duration::from_secs(1);
        for name in [
            "isolate-0x2e2d5000-41-v8.log",
            "isolate-0x3ae9a000-41-v8.log",
            "isolate-0x3ae9a000-410-v8.log",
            "isolate-0xzz-41-v8.log",
            "notes-41-v8.log",
        ] {
            fs::write(dir.path().join(name), "").unwrap();
        }
        assert_eq!(remove_v8_logs(dir.path(), 41, since).unwrap(), 2);
        let mut left: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(
            left,
            [
                "isolate-0x3ae9a000-410-v8.log",
                "isolate-0xzz-41-v8.log",
                "notes-41-v8.log"
            ]
        );
    }

    #[test]
    fn reads_the_names_runtimes_write() {
        assert_eq!(
            function("py::Pool.acquire:/app/pool.py"),
            Some(JitFunction {
                name: Some("Pool.acquire"),
                file: "/app/pool.py",
                start: None
            })
        );
        // Node 18, and Node 24 with columns.
        assert_eq!(
            function("LazyCompile:*parse /app/x.js:42"),
            Some(JitFunction {
                name: Some("parse"),
                file: "/app/x.js",
                start: Some("42")
            })
        );
        assert_eq!(
            function("JS:~outer /app/x.js:6:15"),
            Some(JitFunction {
                name: Some("outer"),
                file: "/app/x.js",
                start: Some("6:15")
            })
        );
        assert_eq!(
            function("JS:+'inner /app/x.js:1:15"),
            Some(JitFunction {
                name: Some("inner"),
                file: "/app/x.js",
                start: Some("1:15")
            })
        );
        // What V8 marks is not part of the name.
        let name = |code| function(code).unwrap().name;
        assert_eq!(name("JS:~*crunch /app/x.js:1:1"), Some("*crunch"));
        assert_eq!(name("JS:*'+ /app/x.js:1:1"), Some("+"));
        assert_eq!(name("JS:o*outer /app/x.js:1:1"), Some("outer"));
        assert_eq!(name("JS:outer /app/x.js:1:1"), Some("outer"));
        // Spaces in names and scripts, unless the boundary can't be told.
        assert_eq!(jit_code("JS:*GET /api /app/x.js:1:1"), None);
        assert_eq!(jit_code("JS:*stage file:parse /app/x.js:1:1"), None);
        assert_eq!(
            function("JS:~get x /app/has space.js:3:5"),
            Some(JitFunction {
                name: Some("get x"),
                file: "/app/has space.js",
                start: Some("3:5")
            })
        );
        assert_eq!(
            function("JS:^bound f file:///my%20app/x.mjs:2"),
            Some(JitFunction {
                name: Some("bound f"),
                file: "file:///my%20app/x.mjs",
                start: Some("2")
            })
        );
        assert_eq!(
            function("Eval:~get x [eval]:1:1"),
            Some(JitFunction {
                name: Some("get x"),
                file: "[eval]",
                start: Some("1:1")
            })
        );
        assert_eq!(
            function("JS:^ /app/x.js:1:28"),
            Some(JitFunction {
                name: None,
                file: "/app/x.js",
                start: Some("1:28")
            })
        );
        assert_eq!(
            jit_code("Builtin:ArrayPrototypePush"),
            Some(JitCode {
                runtime: "node",
                function: None
            })
        );
        assert_eq!(jit_code("[OptimizedTier1] Main()"), None);
        assert_eq!(jit_code("Lcom/example/Main;.run"), None);
    }

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
