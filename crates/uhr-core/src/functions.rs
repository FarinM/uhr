use std::collections::HashMap;

use serde::Serialize;

use crate::recording::{InterpretedCode, KERNEL, Origin, Recording, bpf_program};
use crate::runtimes::{JitCode, RUNTIMES, binary_runtime, jit_code, starts_tell_apart};
use crate::symbols::{FrameName, Symbols};

/// One function, or the unnamed code of one module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Function {
    /// The build-id, or the module path when there is none, and the function
    /// start, as in `3f9a01c2+0x1550`. Starts come from symbols or the
    /// binary's unwind tables, so the id stays the same across results and
    /// when symbols are resolved again. A kernel function's start counts
    /// from the kernel's or its module's mapping, which stays the same
    /// across boots. An inlined function has no start: its id is the
    /// build-id or path and a hash of its name and the file and line it is
    /// declared at, as in `3f9a01c2+inline:5d2c91a04e7b33f0`. A BPF program
    /// has the tag and name of its kernel symbol, as in
    /// `bpf+6deef7357e7b4530_sd_fw_egress`. `None` for code with none of
    /// these: other kernel code outside every mapping, a recording not yet
    /// symbolized, and the range a stripped binary's `EntryPoint`
    /// placeholder covers.
    pub id: Option<String>,
    /// `None` for frames without a name.
    #[serde(rename = "function")]
    pub name: Option<String>,
    /// The label wholesym made up from the address when there is no name,
    /// such as `fun_1200`. Counted as unnamed.
    pub placeholder: Option<String>,
    /// Code inlined into other functions, from debug info. It has no
    /// machine code of its own. A copy of the function that was called
    /// rather than inlined is a separate function.
    pub inlined: bool,
    /// Path of the file the code was mapped from. The first one seen, when
    /// copies of one binary ran from several paths.
    pub module: Option<String>,
    pub build_id: Option<String>,
    /// Function start relative to the binary's image base, when known.
    /// `None` for inlined code.
    pub function_address: Option<u32>,
    /// The source file the function is declared in, from debug info.
    pub file: Option<String>,
    pub origin: Origin,
}

/// A place in source code, from debug info.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct SourceLine {
    /// As written in the debug info, usually absolute.
    pub file: String,
    pub line: u32,
}

/// The placeholder wholesym gives the range from a stripped binary's entry
/// point to the next function start it knows. That range is not one
/// function, and debug symbols split it up.
const ENTRY_POINT: &str = "EntryPoint";

/// What identifies a function's file. Copies of one binary at different
/// paths share a build-id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Module<'a> {
    BuildId(&'a str),
    /// For a file whose build-id was not recorded.
    Path(&'a str),
}

impl Module<'_> {
    fn as_str(&self) -> &str {
        match self {
            Module::BuildId(id) | Module::Path(id) => id,
        }
    }
}

/// What identifies a function's code within its file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Code<'a> {
    /// Machine code, by its start when known.
    Start(Option<u32>),
    /// Kernel code outside every mapping has no start to count from. A BPF
    /// program goes by its tag and name: the tag hashes its instructions,
    /// so it stays the same when the program is loaded again.
    Bpf(&'a str),
    /// Other such code, such as a BPF trampoline, by where its saved
    /// function starts.
    Unmapped(u64),
    /// Code inlined from the function of this name, declared here.
    Inlined {
        name: Option<&'a str>,
        file: Option<&'a str>,
        line: Option<u32>,
    },
    /// Code a runtime compiled or interpreted, which moves from run to run,
    /// by what the runtime called it.
    Jit(Jit<'a>),
    /// Interpreted code of this runtime that could not be read.
    Unnamed(&'a str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Jit<'a> {
    /// One of the program's functions, as its id names it.
    Function {
        runtime: &'a str,
        file: &'a str,
        name: Option<&'a str>,
        start: Option<Start>,
    },
    /// The runtime's own code, or code of a runtime uhr can't read the
    /// names of, by its name in the map.
    Named(&'a str),
}

/// Where one of the program's functions starts in its file, which tells
/// apart functions of one name, as two classes' methods can be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Start {
    line: u32,
    column: Option<u32>,
}

impl Start {
    /// `line` or `line:column`, as a perf map says.
    fn parse(start: &str) -> Option<Start> {
        let (line, column) = match start.split_once(':') {
            Some((line, column)) => (line, Some(column.parse().ok()?)),
            None => (start, None),
        };
        Some(Start {
            line: line.parse().ok()?,
            column,
        })
    }
}

impl std::fmt::Display for Start {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.column {
            Some(column) => write!(f, "{}:{column}", self.line),
            None => write!(f, "{}", self.line),
        }
    }
}

/// A runtime's code has no origin in its key: a function is the same
/// whether a perf map named its compiled code or uhr read it from the
/// interpreter's frames.
type Key<'a> = (Option<Origin>, Option<Module<'a>>, Code<'a>);

/// Why no single function matched what was asked for.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the recording has no function names or ids yet: run `uhr symbolize`")]
    NotSymbolized,
    #[error("no function in the recorded stacks has the id or name {0:?}")]
    NotFound(String),
    #[error(
        "{} functions are named {name:?}. Pass one of their ids: {}",
        .ids.len(),
        .ids.join(", ")
    )]
    Ambiguous { name: String, ids: Vec<String> },
}

/// The frames of a recording, grouped into functions by build-id (or path
/// without one) and function start, or by name and declaration for inlined
/// code. Mapping ids change across processes and reloads, and build-ids
/// tell apart different binaries at the same path.
pub(crate) struct Functions {
    /// The functions of each frame, innermost inlined call first. The last
    /// is the function the frame's machine code belongs to.
    chains: Vec<Vec<Step>>,
    /// Whether each frame is an interpreter's.
    interpreted: Vec<bool>,
    functions: Vec<Function>,
    roles: Vec<Role>,
    /// The line, and column where known, each function starts or is
    /// declared at, where its key says.
    starts: Vec<Option<Start>>,
    lines: Vec<SourceLine>,
    symbolized: bool,
}

/// What a function is to the runtime that compiled the program's code, if
/// one did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// One of the program's functions, which this runtime compiled.
    Program(&'static str),
    /// This runtime's own code, as its interpreter or V8's builtins.
    Runtime(&'static str),
    Other,
}

/// A function in a frame's chain, and the line the frame is at in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Step {
    pub(crate) function: u32,
    /// Index of the line, `None` without line info.
    pub(crate) line: Option<u32>,
}

impl Functions {
    pub(crate) fn new<'a>(recording: &'a Recording, symbols: Option<&'a Symbols>) -> Self {
        let mut ids: HashMap<Key<'a>, u32> = HashMap::new();
        let mut functions = Vec::new();
        let mut roles = Vec::new();
        let mut starts = Vec::new();
        let mut line_ids: HashMap<(&'a str, u32), u32> = HashMap::new();
        let mut lines = Vec::new();
        let mut line = |place: Option<(&'a str, u32)>| {
            let place = place?;
            Some(*line_ids.entry(place).or_insert_with(|| {
                lines.push(SourceLine {
                    file: place.0.to_owned(),
                    line: place.1,
                });
                lines.len() as u32 - 1
            }))
        };
        let chains = recording
            .frames
            .iter()
            .enumerate()
            .map(|(frame_id, frame)| {
                let mapping = frame.mapping.map(|m| &recording.mappings[m as usize]);
                let module = mapping.map(|m| match &m.build_id {
                    Some(id) => Module::BuildId(id),
                    None => Module::Path(&m.path),
                });
                let inline = symbols.map_or(&[][..], |s| &s.inline[frame_id]);
                let mut function = |code: Code<'a>, make: &dyn Fn() -> Function| {
                    // The same runtime code in other processes, or other
                    // copies of it, is one function.
                    let runtime = matches!(code, Code::Jit(_) | Code::Unnamed(_));
                    let module = module.filter(|_| !runtime);
                    let origin = (!runtime).then_some(frame.origin);
                    *ids.entry((origin, module, code)).or_insert_with(|| {
                        let function = make();
                        roles.push(role(&function, code));
                        starts.push(match code {
                            Code::Jit(Jit::Function { start, .. }) => start,
                            Code::Inlined { line, .. } => {
                                line.map(|line| Start { line, column: None })
                            }
                            _ => None,
                        });
                        functions.push(function);
                        functions.len() as u32 - 1
                    })
                };
                if let Some(interpreted) = frame.interpreted.filter(|_| symbols.is_some()) {
                    let code = &recording.interpreted_code[interpreted.code as usize];
                    let key = match (&code.name, &code.file) {
                        (Some(name), Some(file)) => Code::Jit(Jit::Function {
                            runtime: &code.runtime,
                            file,
                            name: Some(name.as_str()).filter(|name| !name.is_empty()),
                            start: interpreted_start(code),
                        }),
                        _ => Code::Unnamed(&code.runtime),
                    };
                    let id = function(key, &|| interpreted_function(code));
                    let place = code.file.as_deref().zip(interpreted.line);
                    return vec![Step {
                        function: id,
                        line: line(place),
                    }];
                }
                if let Some(symbol) = symbols.and(recording.jit_symbol(frame)) {
                    let code = jit_code(&symbol.name);
                    let key = match code {
                        Some(JitCode {
                            runtime,
                            function: Some(f),
                        }) => Jit::Function {
                            runtime,
                            file: f.file,
                            name: f.name,
                            start: f.start.and_then(Start::parse),
                        },
                        _ => Jit::Named(&symbol.name),
                    };
                    let id = function(Code::Jit(key), &|| jit_function(&symbol.name, code));
                    return vec![Step {
                        function: id,
                        line: None,
                    }];
                }
                if frame.mapping.is_none()
                    && let Some(symbol) = symbols.and(recording.kernel_symbol(frame))
                {
                    let program = bpf_program(&symbol.name);
                    let code = match program {
                        Some(program) => Code::Bpf(program),
                        None => Code::Unmapped(symbol.start),
                    };
                    let name = symbols
                        .and_then(|s| s.names[frame_id].as_ref())
                        .and_then(FrameName::symbol);
                    let id = function(code, &|| Function {
                        id: program.map(|program| format!("bpf+{program}")),
                        name: name.map(str::to_owned),
                        placeholder: None,
                        inlined: false,
                        module: Some(match &symbol.module {
                            Some(module) => format!("[{module}]"),
                            None => KERNEL.to_owned(),
                        }),
                        build_id: None,
                        function_address: None,
                        file: None,
                        origin: frame.origin,
                    });
                    return vec![Step {
                        function: id,
                        line: None,
                    }];
                }
                let mut chain: Vec<Step> = inline
                    .iter()
                    .take(inline.len().saturating_sub(1))
                    .map(|call| {
                        let (name, file, declared_at) = (
                            call.function.as_deref(),
                            call.decl_file.as_deref(),
                            call.decl_line,
                        );
                        let code = Code::Inlined {
                            name,
                            file,
                            line: declared_at,
                        };
                        let id = function(code, &|| Function {
                            id: module.zip(name).map(|(module, name)| {
                                let at = declared_at.map(|l| l.to_string()).unwrap_or_default();
                                let hash = fnv1a(&[name, file.unwrap_or_default(), &at]);
                                format!("{}+inline:{hash:016x}", module.as_str())
                            }),
                            name: name.map(str::to_owned),
                            placeholder: None,
                            inlined: true,
                            module: mapping.map(|m| m.path.clone()),
                            build_id: mapping.and_then(|m| m.build_id.clone()),
                            function_address: None,
                            file: file.map(str::to_owned),
                            origin: frame.origin,
                        });
                        Step {
                            function: id,
                            line: line(call.file.as_deref().zip(call.line)),
                        }
                    })
                    .collect();
                let address = symbols.and_then(|s| s.function_addresses[frame_id]);
                let id = function(Code::Start(address), &|| {
                    let name = symbols.and_then(|s| s.names[frame_id].as_ref());
                    let placeholder = match name {
                        Some(FrameName::Placeholder(label)) => Some(label.clone()),
                        _ => None,
                    };
                    let boundary = placeholder.as_deref() != Some(ENTRY_POINT);
                    Function {
                        id: module
                            .zip(address)
                            .filter(|_| boundary)
                            .map(|(module, address)| format!("{}+0x{address:x}", module.as_str())),
                        name: name.and_then(FrameName::symbol).map(str::to_owned),
                        placeholder,
                        inlined: false,
                        module: mapping.map(|m| m.path.clone()),
                        build_id: mapping.and_then(|m| m.build_id.clone()),
                        function_address: address,
                        file: inline.last().and_then(|outer| outer.decl_file.clone()),
                        origin: frame.origin,
                    }
                });
                chain.push(Step {
                    function: id,
                    line: line(inline.last().and_then(|o| o.file.as_deref().zip(o.line))),
                });
                chain
            })
            .collect();
        Self {
            chains,
            interpreted: recording
                .frames
                .iter()
                .map(|frame| frame.interpreted.is_some())
                .collect(),
            functions,
            roles,
            starts,
            lines,
            symbolized: symbols.is_some(),
        }
    }

    /// The functions of a stack and their lines, leaf first, with inlined
    /// calls expanded.
    pub(crate) fn steps<'a>(&'a self, stack: &'a [u32]) -> impl Iterator<Item = Step> + 'a {
        // A runtime that names its code in perf maps can run each call
        // through code of its own, so that a call shows twice: as the
        // interpreter's frame, and outward of it, past only the runtime's
        // code, as the frame the perf map names. It is one call.
        let mut interpreted: Option<u32> = None;
        stack
            .iter()
            .filter(move |&&frame| {
                let Some(function) = self.chains[frame as usize].last().map(|s| s.function) else {
                    return true;
                };
                if self.interpreted[frame as usize] {
                    interpreted = Some(function);
                    return true;
                }
                match self.roles[function as usize] {
                    Role::Runtime(_) => true,
                    Role::Program(_) if interpreted == Some(function) => {
                        interpreted = None;
                        false
                    }
                    _ => {
                        interpreted = None;
                        true
                    }
                }
            })
            .flat_map(|&frame| self.chains[frame as usize].iter().copied())
    }

    /// The functions of a stack, leaf first, with inlined calls expanded.
    pub(crate) fn expand<'a>(&'a self, stack: &'a [u32]) -> impl Iterator<Item = u32> + 'a {
        self.steps(stack).map(|step| step.function)
    }

    /// The function running at the top of a stack.
    pub(crate) fn leaf(&self, stack: &[u32]) -> u32 {
        self.chains[stack[0] as usize][0].function
    }

    /// The function a stack's self time counts for: its leaf, unless that is
    /// a runtime's own code, run for one of the program's functions the
    /// runtime compiled. Then it is the innermost such function, so an
    /// interpreter's time counts for the code it interprets. Native code and
    /// the kernel keep theirs.
    pub(crate) fn own(&self, stack: &[u32]) -> u32 {
        let leaf = self.leaf(stack);
        let mut runtime = None;
        for function in self.expand(stack) {
            match self.roles[function as usize] {
                Role::Program(of) if runtime.is_none_or(|r| r == of) => return function,
                Role::Runtime(of) if runtime.is_none_or(|r| r == of) => runtime = Some(of),
                _ => return leaf,
            }
        }
        leaf
    }

    /// Where a function starts or is declared in its file, as `line` or
    /// `line:column`, where known.
    pub(crate) fn start(&self, id: u32) -> Option<String> {
        self.starts[id as usize].map(|start| start.to_string())
    }

    pub(crate) fn line(&self, id: u32) -> &SourceLine {
        &self.lines[id as usize]
    }

    /// The function with the id `wanted`, or the only one named `wanted`.
    pub(crate) fn select(&self, wanted: &str) -> Result<u32, Error> {
        if !self.symbolized {
            return Err(Error::NotSymbolized);
        }
        let all = || (0..self.len() as u32).map(|id| (id, self.get(id)));
        if let Some((id, _)) = all().find(|(_, f)| f.id.as_deref() == Some(wanted)) {
            return Ok(id);
        }
        let named: Vec<_> = all()
            .filter(|(_, f)| f.name.as_deref() == Some(wanted))
            .collect();
        match named[..] {
            [] => Err(Error::NotFound(wanted.to_owned())),
            [(id, _)] => Ok(id),
            _ => Err(Error::Ambiguous {
                name: wanted.to_owned(),
                ids: named
                    .iter()
                    .map(|(_, f)| f.id.clone().unwrap_or_else(|| "<no id>".into()))
                    .collect(),
            }),
        }
    }

    pub(crate) fn symbolized(&self) -> bool {
        self.symbolized
    }

    pub(crate) fn len(&self) -> usize {
        self.functions.len()
    }

    pub(crate) fn get(&self, id: u32) -> &Function {
        &self.functions[id as usize]
    }
}

fn role(function: &Function, code: Code) -> Role {
    let known = |name: &str| RUNTIMES.iter().find(|r| r.name() == name).map(|r| r.name());
    match code {
        Code::Jit(Jit::Function { runtime, .. }) | Code::Unnamed(runtime) => {
            known(runtime).map_or(Role::Other, Role::Program)
        }
        Code::Jit(Jit::Named(name)) => match jit_code(name) {
            Some(JitCode {
                runtime,
                function: None,
            }) => Role::Runtime(runtime),
            _ => Role::Other,
        },
        _ if function.origin == Origin::Binary => function
            .module
            .as_deref()
            .and_then(|path| binary_runtime(path.rsplit('/').next().unwrap_or(path)))
            .map_or(Role::Other, Role::Runtime),
        _ => Role::Other,
    }
}

/// A function of code a runtime compiled. One of the program's functions is
/// in the runtime's module, as in `[python]`, and has an id from its name,
/// file and start, which stays the same from run to run. Code the map names
/// in another way keeps that name.
fn jit_function(name: &str, code: Option<JitCode>) -> Function {
    let (id, display, file) = match code {
        Some(JitCode {
            runtime,
            function: Some(function),
        }) => (
            program_id(
                runtime,
                function.name,
                function.start.and_then(Start::parse),
                function.file,
            ),
            function.name.unwrap_or("(anonymous)").to_owned(),
            Some(function.file.to_owned()),
        ),
        Some(JitCode { runtime, .. }) => (format!("jit+{runtime}+{name}"), name.to_owned(), None),
        None => (format!("jit:{name}"), name.to_owned(), None),
    };
    Function {
        id: Some(id),
        name: Some(display),
        placeholder: None,
        inlined: false,
        module: code.map(|code| format!("[{}]", code.runtime)),
        build_id: None,
        function_address: None,
        file,
        origin: Origin::Jit,
    }
}

fn interpreted_function(code: &InterpretedCode) -> Function {
    let named = code.name.as_deref().zip(code.file.as_deref());
    Function {
        id: named.map(|(name, file)| {
            let name = Some(name).filter(|name| !name.is_empty());
            program_id(&code.runtime, name, interpreted_start(code), file)
        }),
        name: code.name.as_deref().map(|name| match name {
            "" => "(anonymous)".to_owned(),
            name => name.to_owned(),
        }),
        placeholder: None,
        inlined: false,
        module: Some(format!("[{}]", code.runtime)),
        build_id: None,
        function_address: None,
        file: code.file.clone(),
        origin: Origin::Interpreted,
    }
}

/// Where interpreted code starts, if that tells functions of its runtime
/// apart.
fn interpreted_start(code: &InterpretedCode) -> Option<Start> {
    let line = code.first_line.filter(|&line| line > 0)?;
    starts_tell_apart(&code.runtime).then_some(Start {
        line,
        column: code.first_column,
    })
}

/// The id of one of the program's functions, which a runtime compiled or
/// interpreted.
fn program_id(runtime: &str, name: Option<&str>, start: Option<Start>, file: &str) -> String {
    let start = start.map(|start| escape(&start.to_string()));
    let named = match (name, start) {
        (Some(name), Some(start)) => format!("{}@{start}", escape(name)),
        (Some(name), None) => escape(name),
        (None, start) => format!("@{}", start.unwrap_or_default()),
    };
    format!("jit+{runtime}:{named}:{file}")
}

/// Escapes what ends a name in a JIT id, so that no two functions share one.
fn escape(name: &str) -> String {
    let mut escaped = String::with_capacity(name.len());
    for c in name.chars() {
        match c {
            '%' => escaped.push_str("%25"),
            ':' => escaped.push_str("%3A"),
            '@' => escaped.push_str("%40"),
            c => escaped.push(c),
        }
    }
    escaped
}

/// 64-bit FNV-1a over the parts, each ended by a zero byte. Part of the
/// inline id format, so it must not change.
pub(crate) fn fnv1a(parts: &[&str]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in parts.iter().flat_map(|part| part.bytes().chain([0])) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtimes::JitFunction;

    fn id(name: Option<&str>, file: &str, start: Option<&str>) -> String {
        let code = JitCode {
            runtime: "node",
            function: Some(JitFunction { name, file, start }),
        };
        jit_function("", Some(code)).id.unwrap()
    }

    #[test]
    fn gives_every_jit_function_its_own_id() {
        assert_eq!(id(Some("hot"), "/a.js", None), "jit+node:hot:/a.js");
        assert_eq!(
            id(Some("hot"), "/a.js", Some("6:15")),
            "jit+node:hot@6%3A15:/a.js"
        );
        assert_ne!(
            id(Some("b:hot"), "/a.js", None),
            id(Some("hot"), "/a.js:b", None)
        );
        assert_eq!(id(None, "/a.js", Some("6:15")), "jit+node:@6%3A15:/a.js");
        assert_ne!(id(None, "/a.js", Some("6")), id(Some("@6"), "/a.js", None));
        assert_ne!(
            jit_function("Builtin:X", jit_code("Builtin:X")).id,
            id(Some("Builtin"), "X", None).into()
        );
        assert_ne!(
            jit_function("node+Builtin:X", None).id,
            jit_function("Builtin:X", jit_code("Builtin:X")).id
        );
    }
}
