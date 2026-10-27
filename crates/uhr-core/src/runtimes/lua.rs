//! Lua 5.4, as its `lua` program runs it: the program keeps the state it
//! runs a script in, for its signal handler, in `globalL`, whose innermost
//! call is a list of the calls that led to it.
//!
//! `globalL` is static, so only the program's debug info names it. The
//! offsets are those of Lua 5.4's headers, which it does not publish.

use std::ops::Range;

use super::process::{bytes_at, symbols, u32_at, u64_at};
use super::text;
use super::{
    Code, Copy, Error, Frames, Interpreter, Memory, Process, Read, Runtime, Step, Thread, Walk,
    WalkedFrame,
};
use crate::recording::Mapping;

pub(super) struct Lua;

impl Runtime for Lua {
    fn name(&self) -> &'static str {
        "lua"
    }

    /// `lua5.4`, or `lua`.
    fn is_binary(&self, file: &str) -> bool {
        file == "lua" || file.starts_with("lua5.")
    }

    fn interpreter(&self, process: &dyn Process) -> Result<Option<Box<dyn Interpreter>>, Error> {
        find(self, process)
    }
}

/// In `lua_State`, its innermost call.
const STATE_CALL: u32 = 32;

/// In `CallInfo`: the stack slot of the function it called, the call
/// before, the next instruction of a Lua function's, and its status.
const CALL_FUNCTION: u32 = 0;
const CALL_PREVIOUS: u32 = 16;
const CALL_PC: usize = 32;
const CALL_STATUS: usize = 62;
const CALL_COPY: u32 = 64;

/// A call's status: of a C function, and one C called into.
const CALL_C: u16 = 1 << 1;
const CALL_FRESH: u16 = 1 << 2;

/// In a `TValue`, its type, of which a Lua closure's, with the bit of
/// collected values.
const VALUE_TYPE: i32 = 8;
const LUA_CLOSURE: u64 = 6;

/// In an `LClosure` and its `Proto`.
const CLOSURE_PROTO: u64 = 24;
const PROTO_CODE_SIZE: u64 = 24;
const PROTO_LINE_INFO_SIZE: u64 = 28;
const PROTO_ABSOLUTE_LINES_SIZE: u64 = 40;
const PROTO_FIRST_LINE: u64 = 44;
const PROTO_CODE: u64 = 64;
const PROTO_LINE_INFO: u64 = 88;
const PROTO_ABSOLUTE_LINES: u64 = 96;
const PROTO_SOURCE: u64 = 112;

/// A line info entry that says to take the next of the absolute lines,
/// each of which is an instruction and its line, 32 bits each.
const ABSOLUTE_LINE: i8 = -0x80;
const ABSOLUTE_LINE_SIZE: u64 = 8;

/// In `TString`: its type, a short string's length, a long one's, and its
/// characters.
const STRING_TYPE: u64 = 8;
const SHORT_STRING: u8 = 4;
const SHORT_LENGTH: u64 = 11;
const LONG_LENGTH: u64 = 16;
const STRING_CHARS: u64 = 24;

const MAX_STRING: u64 = 4096;
const MAX_CODE: u64 = 1 << 24;

struct PucLua {
    version: String,
    walk: Walk,
    eval_loop: Vec<Range<u64>>,
}

fn find(lua: &dyn Runtime, process: &dyn Process) -> Result<Option<Box<dyn Interpreter>>, Error> {
    let file_name = |m: &Mapping| m.path.rsplit('/').next().unwrap_or(&m.path).to_owned();
    let Some(mapping) = process
        .mappings()
        .iter()
        .find(|m| lua.is_binary(&file_name(m)))
    else {
        return Ok(None);
    };
    let symbols = symbols(process, mapping, |name| {
        matches!(name, "globalL" | "luaV_execute" | "lua_ident")
    })?;
    let (Some(state), Some(ident)) = (symbols.get("globalL"), symbols.get("lua_ident")) else {
        return Err(Error::Invalid(format!(
            "only debug info for {} names where Lua keeps its state",
            mapping.path
        )));
    };
    // As in "$LuaVersion: Lua 5.4.6  Copyright ...".
    let ident = bytes_at(process.memory(), "Lua's version", ident.start, 32)?;
    let ident = String::from_utf8_lossy(&ident);
    let version = ident
        .split_whitespace()
        .nth(2)
        .unwrap_or_default()
        .to_owned();
    if !version.starts_with("5.4.") {
        return Err(Error::Unsupported {
            runtime: "lua",
            version,
        });
    }
    let walk = Walk {
        frames: Frames::Memory {
            thread: Thread::Global {
                state: state.start,
                frame: vec![0, STATE_CALL],
            },
            step: Step::Pointer(CALL_PREVIOUS),
        },
        copy: Copy {
            from: 0,
            bytes: CALL_COPY,
            // The function the call called, and its type.
            reads: vec![
                Read {
                    word: CALL_FUNCTION,
                    offset: 0,
                },
                Read {
                    word: CALL_FUNCTION,
                    offset: VALUE_TYPE,
                },
            ],
        },
        frame_pointers: false,
    };
    Ok(Some(Box::new(PucLua {
        version,
        walk,
        eval_loop: symbols.get("luaV_execute").cloned().into_iter().collect(),
    })))
}

impl PucLua {
    fn string(&self, memory: &dyn Memory, string: u64) -> Result<String, Error> {
        let kind = bytes_at(memory, "a Lua string", string + STRING_TYPE, 1)?[0];
        let length = match kind & 0x3f {
            SHORT_STRING => {
                u64::from(bytes_at(memory, "a Lua string", string + SHORT_LENGTH, 1)?[0])
            }
            _ => u64_at(memory, "a Lua string", string + LONG_LENGTH)?,
        };
        if length > MAX_STRING {
            return Err(Error::Invalid(format!("a Lua string of {length} bytes")));
        }
        let bytes = bytes_at(
            memory,
            "a Lua string",
            string + STRING_CHARS,
            length as usize,
        )?;
        Ok(text::utf8(&bytes))
    }
}

impl Interpreter for PucLua {
    fn runtime(&self) -> &'static str {
        "lua"
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn walk(&self) -> &Walk {
        &self.walk
    }

    fn eval_loop(&self) -> &[Range<u64>] {
        &self.eval_loop
    }

    fn saves_instruction_on_calls(&self) -> bool {
        true
    }

    fn frame(&self, bytes: &[u8]) -> WalkedFrame {
        let word = |at: usize| {
            bytes
                .get(at..at + 8)
                .map_or(0, |b| u64::from_ne_bytes(b.try_into().unwrap()))
        };
        let status = bytes
            .get(CALL_STATUS..CALL_STATUS + 2)
            .map_or(0, |b| u16::from_ne_bytes([b[0], b[1]]));
        let (closure, kind) = (word(CALL_COPY as usize), word(CALL_COPY as usize + 8));
        if status & CALL_C != 0 || kind & 0x3f != LUA_CLOSURE || closure == 0 {
            return WalkedFrame::Native;
        }
        WalkedFrame::Code {
            code: closure,
            // The call points past the instruction it runs.
            instruction: word(CALL_PC).saturating_sub(4),
            entered: status & CALL_FRESH != 0,
        }
    }

    fn code(&self, memory: &dyn Memory, closure: u64) -> Result<Code, Error> {
        let proto = u64_at(memory, "a Lua closure", closure + CLOSURE_PROTO)?;
        let field = |offset: u64| u64_at(memory, "a Lua function", proto + offset);
        let int = |offset: u64| u32_at(memory, "a Lua function", proto + offset);
        let source = self.string(memory, field(PROTO_SOURCE)?)?;
        // A file's name follows an `@`.
        let file = source.strip_prefix('@').unwrap_or(&source).to_owned();
        let first_line = int(PROTO_FIRST_LINE)?;
        let name = match first_line {
            0 => "main chunk".to_owned(),
            line => format!("function <{file}:{line}>"),
        };
        let size = u64::from(int(PROTO_CODE_SIZE)?);
        let mut lines = Vec::new();
        if size <= MAX_CODE && u64::from(int(PROTO_LINE_INFO_SIZE)?) == size {
            let code = field(PROTO_CODE)?;
            let deltas = bytes_at(
                memory,
                "a Lua function's lines",
                field(PROTO_LINE_INFO)?,
                size as usize,
            )?;
            let absolute = u64::from(int(PROTO_ABSOLUTE_LINES_SIZE)?).min(size);
            let absolute = bytes_at(
                memory,
                "a Lua function's lines",
                field(PROTO_ABSOLUTE_LINES)?,
                (absolute * ABSOLUTE_LINE_SIZE) as usize,
            )?;
            let mut absolute = absolute
                .chunks_exact(ABSOLUTE_LINE_SIZE as usize)
                .map(|entry| u32::from_ne_bytes(entry[4..8].try_into().unwrap()));
            let mut line = i64::from(first_line);
            for (i, &delta) in deltas.iter().enumerate() {
                match delta as i8 {
                    ABSOLUTE_LINE => line = absolute.next().map_or(line, i64::from),
                    delta => line += i64::from(delta),
                }
                let at = code + 4 * i as u64;
                if let Ok(line) = u32::try_from(line) {
                    lines.push((at..at + 4, line));
                }
            }
        }
        Ok(Code {
            name,
            file,
            first_line,
            first_column: None,
            lines,
        })
    }
}
