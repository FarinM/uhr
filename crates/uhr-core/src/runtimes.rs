/// The runtime a binary is, by its file name: `python3.12`, or a
/// `libpython3.12.so` another program embeds it with, or Node's.
pub fn binary_runtime(file: &str) -> Option<&'static str> {
    if file.starts_with("python3") || file.starts_with("libpython3") {
        Some("python")
    } else if file == "node" || file == "nodejs" || file.starts_with("libnode.so") {
        Some("node")
    } else {
        None
    }
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
pub fn jit_code(name: &str) -> Option<JitCode<'_>> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn function(name: &str) -> Option<JitFunction<'_>> {
        jit_code(name).unwrap().function
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
}
