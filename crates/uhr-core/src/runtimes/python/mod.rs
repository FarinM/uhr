//! CPython.

use super::{Error, Interpreter, JitCode, JitFunction, PerfMaps, Process, Runtime, Setting};

mod interpreter;

pub(super) struct Python;

static PERF_MAPS: PerfMaps = PerfMaps {
    variable: "PYTHONPERFSUPPORT",
    setting: Setting::Value("1"),
    on,
    code,
};

impl Runtime for Python {
    fn name(&self) -> &'static str {
        "python"
    }

    /// `python3.12`, or a `libpython3.12.so` another program embeds it with.
    fn is_binary(&self, file: &str) -> bool {
        file.starts_with("python3") || file.starts_with("libpython3")
    }

    fn perf_maps(&self) -> Option<&PerfMaps> {
        Some(&PERF_MAPS)
    }

    fn interpreter(&self, process: &dyn Process) -> Result<Option<Box<dyn Interpreter>>, Error> {
        interpreter::find(self, process)
    }
}

/// CPython reads the value as a number with C's `strtol`, after the
/// whitespace C knows, and any but 0 turns the map on.
fn on(value: &str) -> bool {
    value
        .trim_start_matches([' ', '\t', '\n', '\x0b', '\x0c', '\r'])
        .parse::<i32>()
        .is_ok_and(|n| n != 0)
}

/// CPython names a function `py::<qualname>:<file>`.
fn code(name: &str) -> Option<JitCode<'_>> {
    let (name, file) = name.strip_prefix("py::")?.split_once(':')?;
    Some(JitCode {
        runtime: "python",
        function: Some(JitFunction {
            name: Some(name),
            file,
            start: None,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_its_setting_as_a_number() {
        for value in ["1", "2", "01", "-1", " \t1"] {
            assert!(on(value), "{value:?}");
        }
        for value in ["0", "00", "", "yes", "1x", "1 ", "99999999999", "\u{a0}1"] {
            assert!(!on(value), "{value:?}");
        }
    }

    #[test]
    fn reads_the_names_it_writes() {
        assert_eq!(
            code("py::Pool.acquire:/app/pool.py").unwrap().function,
            Some(JitFunction {
                name: Some("Pool.acquire"),
                file: "/app/pool.py",
                start: None
            })
        );
        assert_eq!(code("JS:~outer /app/x.js:6:15"), None);
    }
}
