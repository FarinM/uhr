use std::collections::HashMap;

use serde::Serialize;

use crate::recording::{KERNEL, Origin, Recording};
use crate::symbols::{FrameName, InlineFrame, Symbols};

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
}

type Key<'a> = (Origin, Option<Module<'a>>, Code<'a>);

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
    functions: Vec<Function>,
    lines: Vec<SourceLine>,
    symbolized: bool,
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
        let mut line_ids: HashMap<(&'a str, u32), u32> = HashMap::new();
        let mut lines = Vec::new();
        let mut line = |call: &'a InlineFrame| {
            let place = call.file.as_deref().zip(call.line)?;
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
                    *ids.entry((frame.origin, module, code)).or_insert_with(|| {
                        functions.push(make());
                        functions.len() as u32 - 1
                    })
                };
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
                            line: line(call),
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
                    line: inline.last().and_then(&mut line),
                });
                chain
            })
            .collect();
        Self {
            chains,
            functions,
            lines,
            symbolized: symbols.is_some(),
        }
    }

    /// The functions of a stack and their lines, leaf first, with inlined
    /// calls expanded.
    pub(crate) fn steps<'a>(&'a self, stack: &'a [u32]) -> impl Iterator<Item = Step> + 'a {
        stack
            .iter()
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

    pub(crate) fn len(&self) -> usize {
        self.functions.len()
    }

    pub(crate) fn get(&self, id: u32) -> &Function {
        &self.functions[id as usize]
    }
}

/// The tag and name of a BPF program, from its kernel symbol
/// `bpf_prog_<tag>` or `bpf_prog_<tag>_<name>`. The name tells apart
/// functions with the same instructions.
fn bpf_program(name: &str) -> Option<&str> {
    let program = name.strip_prefix("bpf_prog_")?;
    let tag = program.get(..16)?;
    let tagged = tag.bytes().all(|b| b.is_ascii_hexdigit())
        && matches!(program.as_bytes().get(16), None | Some(b'_'));
    tagged.then_some(program)
}

/// 64-bit FNV-1a over the parts, each ended by a zero byte. Part of the
/// inline id format, so it must not change.
fn fnv1a(parts: &[&str]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in parts.iter().flat_map(|part| part.bytes().chain([0])) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}
