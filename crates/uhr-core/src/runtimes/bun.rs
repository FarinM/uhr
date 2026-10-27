//! Bun, and the JavaScriptCore it runs on, whose frames are on the native
//! stack: the frame of each JavaScript function holds its `CodeBlock`, whose
//! executable names it.
//!
//! Bun's releases keep no symbols and JavaScriptCore publishes no offsets,
//! so they are those found in each release Bun publishes with symbols, by
//! its build id. That build, kept where the system keeps debug info by build
//! id, also names the interpreter's code.

use std::ops::Range;

use super::process::{bytes_at, debug_symbols, mapped_build_id, u32_at, u64_at};
use super::text;
use super::{
    Code, Copy, Error, Frames, Interpreter, Memory, Process, Read, Runtime, Walk, WalkedFrame,
};
use crate::recording::Mapping;

pub(super) struct Bun;

impl Runtime for Bun {
    fn name(&self) -> &'static str {
        "bun"
    }

    fn is_binary(&self, file: &str) -> bool {
        file == "bun" || file == "bun-profile"
    }

    fn interpreter(&self, process: &dyn Process) -> Result<Option<Box<dyn Interpreter>>, Error> {
        find(self, process)
    }
}

/// Where one build keeps what uhr reads.
#[derive(Debug, Clone, Copy)]
struct Layout {
    version: &'static str,
    /// The type a `JSCell` says it is, in its sixth byte, for a `CodeBlock`.
    code_block_type: u8,
    /// In a `CodeBlock`: its `UnlinkedCodeBlock`, whose word at
    /// `unlinked_flags` holds its code type at `code_type_shift`, and its
    /// executable.
    unlinked: u64,
    unlinked_flags: u64,
    code_type_shift: u32,
    executable: u64,
    /// In a `FunctionExecutable`, its `UnlinkedFunctionExecutable`, which
    /// holds the function's name. In any executable, its `SourceProvider`,
    /// which holds the script's URL.
    unlinked_function: u64,
    function_name: u64,
    provider: u64,
    url: u64,
}

const LAYOUTS: [([u8; 20], Layout); 1] = [(
    [
        0xa9, 0xea, 0x37, 0x07, 0xc3, 0x2f, 0x24, 0x2d, 0xc5, 0xec, 0x7f, 0xee, 0x3c, 0x5f, 0xdd,
        0x9b, 0xc9, 0x98, 0x93, 0xb3,
    ],
    Layout {
        version: "1.4.3",
        code_block_type: 18,
        unlinked: 0x38,
        unlinked_flags: 0x18,
        code_type_shift: 44,
        executable: 0x40,
        unlinked_function: 0x50,
        function_name: 0x40,
        provider: 0x28,
        url: 0x48,
    },
)];

/// JavaScriptCore's `CallFrame`, from its frame pointer: the `CodeBlock`,
/// then the callee.
const FRAME_CODE_BLOCK: i32 = 16;
const FRAME_COPY: u32 = 16;

/// The kinds of code a `CodeBlock` runs.
const GLOBAL_CODE: u64 = 0;
const EVAL_CODE: u64 = 1;
const FUNCTION_CODE: u64 = 2;

/// In `WTF::StringImpl`: its length, where its characters are, and its
/// flags, of which one says they are a byte each.
const STRING_LENGTH: u64 = 4;
const STRING_CHARS: u64 = 8;
const STRING_FLAGS: u64 = 16;
const STRING_8_BIT: u32 = 1 << 2;
const MAX_STRING: u64 = 4096;

struct JavaScriptCore {
    layout: Layout,
    walk: Walk,
    eval_loop: Vec<Range<u64>>,
}

fn find(bun: &dyn Runtime, process: &dyn Process) -> Result<Option<Box<dyn Interpreter>>, Error> {
    let file_name = |m: &Mapping| m.path.rsplit('/').next().unwrap_or(&m.path).to_owned();
    let Some(mapping) = process
        .mappings()
        .iter()
        .find(|m| bun.is_binary(&file_name(m)) && m.file_offset == 0)
    else {
        return Ok(None);
    };
    let build_id = mapped_build_id(process.memory(), mapping).unwrap_or_default();
    let Some(&(_, layout)) = LAYOUTS.iter().find(|(id, _)| id[..] == build_id[..]) else {
        let id: String = build_id.iter().map(|b| format!("{b:02x}")).collect();
        return Err(Error::Unsupported {
            runtime: "bun",
            version: format!("with build id {id}"),
        });
    };
    // A release keeps no symbols but those other code links to.
    let symbols = debug_symbols(process, mapping, &build_id, |name| {
        matches!(name, "llintPCRangeStart" | "llintPCRangeEnd")
    });
    let start = symbols.get("llintPCRangeStart").map(|range| range.start);
    let end = symbols.get("llintPCRangeEnd").map(|range| range.start);
    let eval_loop = start
        .zip(end)
        .map(|(start, end)| start..end)
        .into_iter()
        .collect();
    let walk = Walk {
        frames: Frames::Native,
        copy: Copy {
            from: FRAME_CODE_BLOCK,
            bytes: FRAME_COPY,
            // The first word of what the frame holds as its `CodeBlock`,
            // whose sixth byte says if it is one.
            reads: vec![Read { word: 0, offset: 0 }],
        },
        frame_pointers: true,
    };
    Ok(Some(Box::new(JavaScriptCore {
        layout,
        walk,
        eval_loop,
    })))
}

impl JavaScriptCore {
    fn string(&self, memory: &dyn Memory, string: u64) -> Result<String, Error> {
        let length = u64::from(u32_at(
            memory,
            "a JavaScriptCore string",
            string + STRING_LENGTH,
        )?);
        if length > MAX_STRING {
            return Err(Error::Invalid(format!("a string of {length} characters")));
        }
        let chars = u64_at(memory, "a JavaScriptCore string", string + STRING_CHARS)?;
        let flags = u32_at(memory, "a JavaScriptCore string", string + STRING_FLAGS)?;
        if flags & STRING_8_BIT != 0 {
            let bytes = bytes_at(memory, "a JavaScriptCore string", chars, length as usize)?;
            return Ok(text::chars(bytes.iter().map(|&b| u32::from(b))));
        }
        let bytes = bytes_at(
            memory,
            "a JavaScriptCore string",
            chars,
            2 * length as usize,
        )?;
        let units = bytes
            .chunks_exact(2)
            .map(|unit| u16::from_ne_bytes([unit[0], unit[1]]));
        Ok(text::utf16(units))
    }
}

impl Interpreter for JavaScriptCore {
    fn runtime(&self) -> &'static str {
        "bun"
    }

    fn version(&self) -> &str {
        self.layout.version
    }

    fn walk(&self) -> &Walk {
        &self.walk
    }

    fn eval_loop(&self) -> &[Range<u64>] {
        &self.eval_loop
    }

    fn frame(&self, bytes: &[u8]) -> WalkedFrame {
        let word = |at: usize| {
            bytes
                .get(at..at + 8)
                .map_or(0, |b| u64::from_ne_bytes(b.try_into().unwrap()))
        };
        let (code_block, header) = (word(0), word(FRAME_COPY as usize));
        if code_block == 0 || (header >> 40) as u8 != self.layout.code_block_type {
            return WalkedFrame::Native;
        }
        WalkedFrame::Code {
            code: code_block,
            instruction: 0,
            entered: false,
        }
    }

    fn code(&self, memory: &dyn Memory, code_block: u64) -> Result<Code, Error> {
        let layout = &self.layout;
        let kind = bytes_at(memory, "a CodeBlock", code_block + 5, 1)?[0];
        if kind != layout.code_block_type {
            return Err(Error::Invalid(format!("no CodeBlock at {code_block:#x}")));
        }
        let unlinked = u64_at(memory, "a CodeBlock", code_block + layout.unlinked)?;
        let flags = u64_at(
            memory,
            "an UnlinkedCodeBlock",
            unlinked + layout.unlinked_flags,
        )?;
        let executable = u64_at(memory, "a CodeBlock", code_block + layout.executable)?;
        let name = match (flags >> layout.code_type_shift) & 3 {
            GLOBAL_CODE => "<global>".to_owned(),
            EVAL_CODE => "<eval>".to_owned(),
            FUNCTION_CODE => {
                let function = u64_at(
                    memory,
                    "a function's executable",
                    executable + layout.unlinked_function,
                )?;
                let name = u64_at(memory, "a function", function + layout.function_name)?;
                match name {
                    0 => String::new(),
                    name => self.string(memory, name)?,
                }
            }
            _ => "<module>".to_owned(),
        };
        let provider = u64_at(memory, "an executable", executable + layout.provider)?;
        let file = match u64_at(memory, "a script", provider + layout.url)? {
            0 => String::new(),
            url => self.string(memory, url)?,
        };
        // Bun runs what it compiled the script to, whose lines are not the
        // script's.
        Ok(Code {
            name,
            file,
            first_line: 0,
            first_column: None,
            lines: Vec::new(),
        })
    }
}
