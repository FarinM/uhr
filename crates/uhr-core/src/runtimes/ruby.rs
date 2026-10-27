//! CRuby, whose frames are an array in each thread's execution context,
//! which the thread-local `ruby_current_ec` points to. They grow down from
//! the end of the context's stack, so the next frame outward is the next in
//! the array, up to that end, and the outermost is a placeholder without
//! code.
//!
//! The offsets are those of Ruby 3.2's headers, which it does not publish.

use std::ops::Range;

use super::process::{bytes_at, symbols, thread_local, u32_at, u64_at};
use super::text;
use super::{
    ArrayEnd, Code, Copy, Error, Frames, Interpreter, Memory, Process, Read, Runtime, Step, Thread,
    Walk, WalkedFrame,
};
use crate::recording::Mapping;

pub(super) struct Ruby;

impl Runtime for Ruby {
    fn name(&self) -> &'static str {
        "ruby"
    }

    /// `ruby`, or a `libruby-3.2.so` it and other programs run it from.
    fn is_binary(&self, file: &str) -> bool {
        file == "ruby" || file.starts_with("libruby")
    }

    fn interpreter(&self, process: &dyn Process) -> Result<Option<Box<dyn Interpreter>>, Error> {
        find(self, process)
    }
}

/// The longest name or file read, and the most lines of one function.
const MAX_STRING: u64 = 4096;
const MAX_LINES: u64 = 1 << 20;

/// In `rb_execution_context_t`, its stack, which its frames end the stack
/// of, its size in 8-byte words, and where its innermost frame is.
const EC_STACK: u32 = 0;
const EC_STACK_SIZE: u32 = 8;
const EC_FRAME: u32 = 16;

/// In `rb_control_frame_t`, of 8-byte words, the next instruction, the
/// code, and where the frame's flags are.
const FRAME_SIZE: i32 = 64;
const FRAME_PC: usize = 0;
const FRAME_ISEQ: u32 = 16;
const FRAME_EP: u32 = 32;
const FRAME_COPY: u32 = 40;

/// The frame flags: its kind, of which a placeholder's, a frame of C code,
/// and one native code called into.
const FRAME_MAGIC: u64 = 0x7fff_0001;
const FRAME_DUMMY: u64 = 0x7999_0001;
const FRAME_CFRAME: u64 = 0x80;
const FRAME_FINISH: u64 = 0x20;

/// In `rb_iseq_t` and its body.
const ISEQ_BODY: u64 = 16;
const BODY_SIZE: u64 = 4;
const BODY_ENCODED: u64 = 8;
const BODY_PATH: u64 = 64;
const BODY_LABEL: u64 = 80;
const BODY_FIRST_LINE: u64 = 88;
/// Where its code starts, from 0.
const BODY_FIRST_COLUMN: u64 = 100;
const BODY_LINES: u64 = 112;
const BODY_LINES_SIZE: u64 = 128;
const BODY_LINES_INDEX: u64 = 136;

/// What every object starts with, its flags, and how they say its type.
const FLAGS_TYPE: u64 = 0x1f;
const TYPE_STRING: u64 = 0x05;
const TYPE_ARRAY: u64 = 0x07;
const TYPE_IMEMO: u64 = 0x1a;
const IMEMO_ISEQ: u64 = 7;
const FLAGS_USER: u32 = 12;
/// `RSTRING_NOEMBED` and `RARRAY_EMBED_FLAG`.
const FLAG_USER1: u64 = 1 << 13;
const STRING_LENGTH: u64 = 16;
const STRING_CHARS: u64 = 24;
const ARRAY_ELEMENTS: u64 = 16;
const ARRAY_HEAP_ELEMENTS: u64 = 32;

/// A line table entry: the line, a node and events, 32 bits each.
const LINE_ENTRY: u64 = 12;

/// In a `succ_index_table`, which says where each line table entry starts
/// in the instructions: the first positions as ranks, 7 bits each, nine to
/// a word, then the rest in blocks of 512 bits, each after its rank and the
/// ranks of its 64-bit words.
const IMMEDIATE_POSITIONS: u64 = 54;
const IMMEDIATE_WORDS: u64 = 6;
const BLOCK_BYTES: u64 = 80;
const BLOCK_BITS: u64 = 16;

struct CRuby {
    version: String,
    walk: Walk,
    eval_loop: Vec<Range<u64>>,
}

fn find(ruby: &dyn Runtime, process: &dyn Process) -> Result<Option<Box<dyn Interpreter>>, Error> {
    let file_name = |m: &Mapping| m.path.rsplit('/').next().unwrap_or(&m.path).to_owned();
    let mut files: Vec<&Mapping> = Vec::new();
    for mapping in process.mappings() {
        if ruby.is_binary(&file_name(mapping)) && !files.iter().any(|m| m.path == mapping.path) {
            files.push(mapping);
        }
    }
    files.sort_by_key(|m| !file_name(m).starts_with("libruby"));
    for mapping in files {
        let symbols = symbols(process, mapping, |name| {
            matches!(name, "ruby_version" | "vm_exec_core" | "rb_vm_exec")
        })?;
        let Some(version) = symbols.get("ruby_version") else {
            continue;
        };
        let version = bytes_at(process.memory(), "Ruby's version", version.start, 16)?;
        let end = version
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(version.len());
        let version = String::from_utf8_lossy(&version[..end]).into_owned();
        if !version.starts_with("3.2.") {
            return Err(Error::Unsupported {
                runtime: "ruby",
                version,
            });
        }
        let Some(state) = thread_local(process, mapping, "ruby_current_ec")? else {
            return Ok(None);
        };
        // The eval loop is a static function, which only a stripped
        // library's debug info names. Without it, the function it is
        // called from stands in, which puts the program's frames just
        // above the eval loop, as its callers.
        let eval_loop = symbols
            .get("vm_exec_core")
            .or_else(|| symbols.get("rb_vm_exec"))
            .cloned()
            .into_iter()
            .collect();
        let walk = Walk {
            frames: Frames::Memory {
                thread: Thread::ThreadPointer {
                    state,
                    frame: vec![EC_FRAME],
                },
                step: Step::Stride {
                    bytes: FRAME_SIZE,
                    end: ArrayEnd {
                        start: EC_STACK,
                        count: EC_STACK_SIZE,
                        scale: 8,
                    },
                },
            },
            copy: Copy {
                from: 0,
                bytes: FRAME_COPY,
                reads: vec![Read {
                    word: FRAME_EP,
                    offset: 0,
                }],
            },
            frame_pointers: false,
        };
        return Ok(Some(Box::new(CRuby {
            version,
            walk,
            eval_loop,
        })));
    }
    Ok(None)
}

impl CRuby {
    /// A string, or the first element of an array of strings, as a path
    /// can be.
    fn string(&self, memory: &dyn Memory, value: u64) -> Result<String, Error> {
        let flags = u64_at(memory, "a Ruby object's flags", value)?;
        let value = match flags & FLAGS_TYPE {
            TYPE_STRING => value,
            TYPE_ARRAY => match flags & FLAG_USER1 {
                0 => {
                    let elements = u64_at(memory, "a Ruby array", value + ARRAY_HEAP_ELEMENTS)?;
                    u64_at(memory, "a Ruby array", elements)?
                }
                _ => u64_at(memory, "a Ruby array", value + ARRAY_ELEMENTS)?,
            },
            _ => return Err(Error::Invalid(format!("no Ruby string at {value:#x}"))),
        };
        let flags = u64_at(memory, "a Ruby string's flags", value)?;
        if flags & FLAGS_TYPE != TYPE_STRING {
            return Err(Error::Invalid(format!("no Ruby string at {value:#x}")));
        }
        let length = u64_at(memory, "a Ruby string's length", value + STRING_LENGTH)?;
        if length > MAX_STRING {
            return Err(Error::Invalid(format!("a Ruby string of {length} bytes")));
        }
        let chars = match flags & FLAG_USER1 {
            0 => value + STRING_CHARS,
            _ => u64_at(memory, "a Ruby string", value + STRING_CHARS)?,
        };
        let bytes = bytes_at(memory, "a Ruby string", chars, length as usize)?;
        Ok(text::utf8(&bytes))
    }

    /// Where each line table entry starts, in instructions.
    fn positions(
        &self,
        memory: &dyn Memory,
        body: u64,
        size: u64,
        entries: u64,
    ) -> Result<Vec<u64>, Error> {
        let table = u64_at(memory, "a Ruby line index", body + BODY_LINES_INDEX)?;
        if table == 0 {
            return Err(Error::Invalid(
                "a Ruby function without a line index".into(),
            ));
        }
        let mut positions = Vec::new();
        let immediate = bytes_at(
            memory,
            "a Ruby line index",
            table,
            8 * IMMEDIATE_WORDS as usize,
        )?;
        let mut rank = 0;
        for position in 0..IMMEDIATE_POSITIONS.min(size) {
            let word = u64::from_ne_bytes(
                immediate[8 * (position / 9) as usize..][..8]
                    .try_into()
                    .unwrap(),
            );
            let now = (word >> (7 * (position % 9))) & 0x7f;
            if now > rank {
                positions.push(position);
            }
            rank = now;
        }
        if size > IMMEDIATE_POSITIONS {
            let blocks = (size - IMMEDIATE_POSITIONS).div_ceil(512);
            let at = table + 8 * IMMEDIATE_WORDS;
            let bytes = bytes_at(
                memory,
                "a Ruby line index",
                at,
                (blocks * BLOCK_BYTES) as usize,
            )?;
            for block in 0..blocks {
                for word in 0..8 {
                    let at = (block * BLOCK_BYTES + BLOCK_BITS + 8 * word) as usize;
                    let bits = u64::from_ne_bytes(bytes[at..at + 8].try_into().unwrap());
                    for bit in 0..64 {
                        if bits >> bit & 1 == 1 {
                            positions.push(IMMEDIATE_POSITIONS + 512 * block + 64 * word + bit);
                        }
                    }
                }
            }
        }
        positions.truncate(entries as usize);
        Ok(positions)
    }
}

impl Interpreter for CRuby {
    fn runtime(&self) -> &'static str {
        "ruby"
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

    fn frame(&self, bytes: &[u8]) -> WalkedFrame {
        let word = |at: usize| {
            bytes
                .get(at..at + 8)
                .map_or(0, |b| u64::from_ne_bytes(b.try_into().unwrap()))
        };
        let (pc, iseq) = (word(FRAME_PC), word(FRAME_ISEQ as usize));
        let flags = word(FRAME_COPY as usize);
        // A C function's frame holds what it is in place of code, and a
        // placeholder's runs none.
        let magic = flags & FRAME_MAGIC;
        if flags & FRAME_CFRAME != 0 || magic == FRAME_DUMMY || iseq == 0 || pc == 0 {
            return WalkedFrame::Native;
        }
        WalkedFrame::Code {
            code: iseq,
            // The frame points past the instruction it runs.
            instruction: pc.saturating_sub(8),
            entered: flags & FRAME_FINISH != 0,
        }
    }

    fn code(&self, memory: &dyn Memory, iseq: u64) -> Result<Code, Error> {
        let flags = u64_at(memory, "a Ruby iseq's flags", iseq)?;
        let imemo = (flags >> FLAGS_USER) & 0xf;
        if flags & FLAGS_TYPE != TYPE_IMEMO || imemo != IMEMO_ISEQ {
            return Err(Error::Invalid(format!("no Ruby code at {iseq:#x}")));
        }
        let body = u64_at(memory, "a Ruby iseq", iseq + ISEQ_BODY)?;
        let field = |offset: u64| u64_at(memory, "a Ruby iseq's body", body + offset);
        let name = self.string(memory, field(BODY_LABEL)?)?;
        let file = self.string(memory, field(BODY_PATH)?)?;
        let first_line = u32_at(memory, "a Ruby iseq's first line", body + BODY_FIRST_LINE)?;
        let first_column = u32_at(
            memory,
            "a Ruby iseq's first column",
            body + BODY_FIRST_COLUMN,
        )?;
        let size = u64::from(u32_at(memory, "a Ruby iseq's size", body + BODY_SIZE)?);
        let encoded = field(BODY_ENCODED)?;
        let entries = u64::from(u32_at(memory, "a Ruby line table", body + BODY_LINES_SIZE)?);
        let mut lines = Vec::new();
        if entries <= MAX_LINES && size <= MAX_LINES * 64 {
            let table = field(BODY_LINES)?;
            let table = bytes_at(
                memory,
                "a Ruby line table",
                table,
                (entries * LINE_ENTRY) as usize,
            )?;
            let positions = self.positions(memory, body, size, entries)?;
            let ends = positions.iter().skip(1).copied().chain([size]);
            for (i, (start, end)) in positions.iter().zip(ends).enumerate() {
                let at = i * LINE_ENTRY as usize;
                let line = i32::from_ne_bytes(table[at..at + 4].try_into().unwrap());
                if let Ok(line) = u32::try_from(line) {
                    lines.push((encoded + 8 * start..encoded + 8 * end, line));
                }
            }
        }
        Ok(Code {
            name,
            file,
            first_line,
            first_column: first_column.checked_add(1),
            lines,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    struct Bytes {
        at: u64,
        bytes: Vec<u8>,
    }

    impl Memory for Bytes {
        fn read(&self, address: u64, into: &mut [u8]) -> io::Result<()> {
            let start = address
                .checked_sub(self.at)
                .ok_or(io::ErrorKind::InvalidInput)? as usize;
            let bytes = self.bytes.get(start..start + into.len());
            into.copy_from_slice(bytes.ok_or(io::ErrorKind::InvalidInput)?);
            Ok(())
        }
    }

    #[test]
    fn reads_where_lines_start_from_the_succinct_table() {
        // As Ruby builds it for positions 0, 3, 53, 54 and 600 of 700.
        let wanted = [0u64, 3, 53, 54, 600];
        let size = 700;
        let mut table = vec![0u8; (8 * IMMEDIATE_WORDS + 2 * BLOCK_BYTES) as usize];
        let mut rank = 0u64;
        for word in 0..IMMEDIATE_WORDS {
            let mut value = 0u64;
            for i in 0..9 {
                if wanted.contains(&(word * 9 + i)) {
                    rank += 1;
                }
                value |= rank << (7 * i);
            }
            table[8 * word as usize..][..8].copy_from_slice(&value.to_ne_bytes());
        }
        for &position in wanted.iter().filter(|&&p| p >= IMMEDIATE_POSITIONS) {
            let bit = position - IMMEDIATE_POSITIONS;
            let at = (8 * IMMEDIATE_WORDS
                + (bit / 512) * BLOCK_BYTES
                + BLOCK_BITS
                + 8 * ((bit % 512) / 64)) as usize;
            let mut word = u64::from_ne_bytes(table[at..at + 8].try_into().unwrap());
            word |= 1 << (bit % 64);
            table[at..at + 8].copy_from_slice(&word.to_ne_bytes());
        }
        // The body, whose line index is at 0x2000.
        let mut bytes = vec![0u8; 0x1000];
        bytes[BODY_LINES_INDEX as usize..][..8].copy_from_slice(&0x2000u64.to_ne_bytes());
        let mut memory = Bytes { at: 0x1000, bytes };
        memory.bytes.extend(table);
        let ruby = CRuby {
            version: "3.2.3".into(),
            walk: Walk {
                frames: Frames::Native,
                copy: Copy {
                    from: 0,
                    bytes: 0,
                    reads: Vec::new(),
                },
                frame_pointers: false,
            },
            eval_loop: Vec::new(),
        };
        let positions = ruby.positions(&memory, 0x1000, size, 5).unwrap();
        assert_eq!(positions, wanted);
    }
}
