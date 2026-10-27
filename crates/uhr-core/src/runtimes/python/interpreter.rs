//! CPython's frames, which it keeps in its memory: each thread's state has
//! its innermost frame, and each frame the one that called it.
//!
//! 3.13 and later say where their structures keep what uhr reads, in
//! `_Py_DebugOffsets` at the start of `_PyRuntime`. For 3.11 and 3.12 the
//! offsets are those of each version's headers, which stay the same within
//! a version: those of 3.11.1 and 3.11.17 agree, as do those of 3.12.0 and
//! 3.12.15. Earlier versions keep frames another way.

use std::collections::HashMap;
use std::iter::Peekable;
use std::ops::Range;

use super::super::process::{bytes_at, symbols, u32_at, u64_at};
use super::super::text;
use super::super::{Code, Error, Interpreter, Memory, Process, Runtime, Walk, WalkedFrame};
use crate::recording::Mapping;

/// The longest name or file read, and the longest line table, in bytes.
const MAX_STRING: u64 = 4096;
const MAX_LINE_TABLE: u64 = 1 << 20;

/// The bit of `PyThreadState._status` that 3.12 and later set while the
/// thread runs in that state and holds the GIL.
const ACTIVE: u32 = 0x10;

/// What uhr reads of `PyObject`, `PyBytesObject` and `PyASCIIObject`, the
/// same in every version uhr reads.
const OB_TYPE: u64 = 8;
const BYTES_SIZE: u64 = 16;
const BYTES_DATA: u64 = 32;
const STRING_LENGTH: u64 = 16;
const STRING_STATE: u64 = 32;

/// Where one version's structures keep what uhr reads.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Layout {
    /// In `_PyRuntimeState`, `PyInterpreterState` and `PyThreadState`.
    interpreters_head: u32,
    interpreter_next: u32,
    threads_head: u32,
    thread_next: u32,
    native_thread_id: u32,
    /// Where a thread state keeps its status, whose bit `ACTIVE` is set
    /// while its thread runs in it and holds the GIL. 3.11 has none.
    thread_status: Option<u32>,
    /// From a thread's state to its innermost frame.
    current_frame: Vec<u32>,
    frame: FrameLayout,
    code: CodeLayout,
    /// Where a compact string's characters start, if all ASCII and if not.
    ascii_data: u32,
    compact_data: u32,
}

/// In `_PyInterpreterFrame`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FrameLayout {
    code: u32,
    previous: u32,
    instruction: u32,
    owner: u32,
    entry: Entry,
    /// Bits of the code pointer that tag it rather than point.
    tag_bits: u64,
}

/// How a version marks where native code called into the interpreter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Entry {
    /// A flag at this offset in the outermost frame of the call.
    Flag(u32),
    /// A frame of its own below the call's, whose owner is at least this.
    Owner(u8),
}

/// In `PyCodeObject`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CodeLayout {
    filename: u32,
    qualname: u32,
    first_line: u32,
    line_table: u32,
    instructions: u32,
}

fn python311() -> Layout {
    Layout {
        interpreters_head: 40,
        interpreter_next: 0,
        threads_head: 16,
        thread_next: 8,
        native_thread_id: 160,
        thread_status: None,
        current_frame: vec![56, 8],
        frame: FrameLayout {
            code: 32,
            previous: 48,
            instruction: 56,
            owner: 69,
            entry: Entry::Flag(68),
            tag_bits: 0,
        },
        code: CodeLayout {
            filename: 112,
            qualname: 128,
            first_line: 72,
            line_table: 136,
            instructions: 184,
        },
        ascii_data: 48,
        compact_data: 72,
    }
}

fn python312() -> Layout {
    Layout {
        interpreters_head: 40,
        interpreter_next: 0,
        threads_head: 72,
        thread_next: 8,
        native_thread_id: 144,
        thread_status: Some(24),
        current_frame: vec![56, 0],
        frame: FrameLayout {
            code: 0,
            previous: 8,
            instruction: 56,
            owner: 70,
            // FRAME_OWNED_BY_CSTACK.
            entry: Entry::Owner(3),
            tag_bits: 0,
        },
        code: CodeLayout {
            filename: 112,
            qualname: 128,
            first_line: 68,
            line_table: 136,
            instructions: 192,
        },
        ascii_data: 40,
        compact_data: 56,
    }
}

/// Where `_Py_DebugOffsets` holds each offset uhr reads, which differs from
/// version to version.
struct DebugOffsets {
    size: usize,
    interpreters_head: usize,
    interpreter_next: usize,
    threads_head: usize,
    thread_next: usize,
    current_frame: usize,
    native_thread_id: usize,
    thread_status: usize,
    frame_previous: usize,
    frame_code: usize,
    frame_instruction: usize,
    frame_owner: usize,
    code_filename: usize,
    code_qualname: usize,
    code_line_table: usize,
    code_first_line: usize,
    code_instructions: usize,
    ob_type: usize,
    bytes_data: usize,
    string_state: usize,
    string_length: usize,
    ascii_size: usize,
}

const DEBUG_OFFSETS_313: DebugOffsets = DebugOffsets {
    size: 584,
    interpreters_head: 40,
    interpreter_next: 64,
    threads_head: 72,
    thread_next: 168,
    current_frame: 184,
    native_thread_id: 200,
    thread_status: 216,
    frame_previous: 232,
    frame_code: 240,
    frame_instruction: 248,
    frame_owner: 264,
    code_filename: 280,
    code_qualname: 296,
    code_line_table: 304,
    code_first_line: 312,
    code_instructions: 344,
    ob_type: 360,
    bytes_data: 528,
    string_state: 544,
    string_length: 552,
    ascii_size: 560,
};

const DEBUG_OFFSETS_314: DebugOffsets = DebugOffsets {
    size: 760,
    interpreters_head: 40,
    interpreter_next: 64,
    threads_head: 72,
    thread_next: 192,
    current_frame: 208,
    native_thread_id: 224,
    thread_status: 240,
    frame_previous: 256,
    frame_code: 264,
    frame_instruction: 272,
    frame_owner: 288,
    code_filename: 320,
    code_qualname: 336,
    code_line_table: 344,
    code_first_line: 352,
    code_instructions: 384,
    ob_type: 408,
    bytes_data: 608,
    string_state: 624,
    string_length: 632,
    ascii_size: 640,
};

/// Reads the layout of 3.13 or later from its `_Py_DebugOffsets`, at
/// `runtime`.
fn debug_layout(memory: &dyn Memory, runtime: u64, minor: u8) -> Result<Layout, Error> {
    let (positions, tag_bits) = match minor {
        13 => (&DEBUG_OFFSETS_313, 0),
        // Frames hold their code as a `_PyStackRef`, tagged in its low bits.
        _ => (&DEBUG_OFFSETS_314, 3),
    };
    let bytes = bytes_at(memory, "CPython's debug offsets", runtime, positions.size)?;
    if &bytes[..8] != b"xdebugpy" {
        return Err(Error::Invalid(
            "CPython's debug offsets are not where its runtime starts".into(),
        ));
    }
    let field = |at: usize| u64::from_ne_bytes(bytes[at..at + 8].try_into().unwrap());
    if field(16) != 0 {
        return Err(Error::Unsupported {
            runtime: "python",
            version: format!("3.{minor} without the GIL"),
        });
    }
    let offset = |at: usize| u32::try_from(field(at)).unwrap_or(u32::MAX);
    // What every version has in the same place, to catch a layout uhr has
    // wrong.
    let same = field(positions.ob_type) == OB_TYPE
        && field(positions.bytes_data) == BYTES_DATA
        && field(positions.string_state) == STRING_STATE
        && field(positions.string_length) == STRING_LENGTH;
    if !same {
        return Err(Error::Invalid(format!(
            "CPython 3.{minor}'s debug offsets are not laid out as uhr expects"
        )));
    }
    // In 3.14, FRAME_OWNED_BY_INTERPRETER, and FRAME_OWNED_BY_CSTACK after
    // it. In 3.13 FRAME_OWNED_BY_CSTACK.
    let entry = Entry::Owner(3);
    let ascii_data = offset(positions.ascii_size);
    Ok(Layout {
        interpreters_head: offset(positions.interpreters_head),
        interpreter_next: offset(positions.interpreter_next),
        threads_head: offset(positions.threads_head),
        thread_next: offset(positions.thread_next),
        native_thread_id: offset(positions.native_thread_id),
        thread_status: Some(offset(positions.thread_status)),
        current_frame: vec![offset(positions.current_frame)],
        frame: FrameLayout {
            code: offset(positions.frame_code),
            previous: offset(positions.frame_previous),
            instruction: offset(positions.frame_instruction),
            owner: offset(positions.frame_owner),
            entry,
            tag_bits,
        },
        code: CodeLayout {
            filename: offset(positions.code_filename),
            qualname: offset(positions.code_qualname),
            first_line: offset(positions.code_first_line),
            line_table: offset(positions.code_line_table),
            instructions: offset(positions.code_instructions),
        },
        ascii_data,
        // `PyCompactUnicodeObject` adds the length and pointer of its UTF-8.
        compact_data: ascii_data + 16,
    })
}

struct CPython {
    version: String,
    layout: Layout,
    /// Where `_PyRuntime` and `PyCode_Type` are.
    runtime: u64,
    code_type: u64,
    eval_loop: Vec<Range<u64>>,
}

/// The CPython in `process`: in a `libpython` it maps, which can embed it
/// in any program, or else in a `python3` program.
pub(super) fn find(
    python: &dyn Runtime,
    process: &dyn Process,
) -> Result<Option<Box<dyn Interpreter>>, Error> {
    let file_name = |m: &Mapping| m.path.rsplit('/').next().unwrap_or(&m.path).to_owned();
    let mut files: Vec<&Mapping> = Vec::new();
    for mapping in process.mappings() {
        let name = file_name(mapping);
        if python.is_binary(&name) && !files.iter().any(|m| m.path == mapping.path) {
            files.push(mapping);
        }
    }
    files.sort_by_key(|m| !file_name(m).starts_with("libpython"));
    for mapping in files {
        let symbols = symbols(process, mapping, |name| {
            matches!(
                name,
                "_PyRuntime" | "Py_Version" | "PyCode_Type" | "_PyEval_EvalFrameDefault"
            ) || name.starts_with("_TAIL_CALL_")
        })?;
        if symbols.contains_key("_PyRuntime") {
            let cpython = CPython::new(process.memory(), &symbols)?;
            return Ok(Some(Box::new(cpython)));
        }
    }
    Ok(None)
}

impl CPython {
    fn new(memory: &dyn Memory, symbols: &HashMap<String, Range<u64>>) -> Result<Self, Error> {
        let at = |name: &str| symbols.get(name).map(|range| range.start);
        let runtime = at("_PyRuntime").expect("found by its runtime");
        // 3.11 and later say their version here.
        let Some(version) = at("Py_Version") else {
            return Err(Error::Unsupported {
                runtime: "python",
                version: "before 3.11".into(),
            });
        };
        let hex = u64_at(memory, "CPython's version", version)?;
        let (major, minor, micro) = ((hex >> 24) as u8, (hex >> 16) as u8, (hex >> 8) as u8);
        let version = format!("{major}.{minor}.{micro}");
        let layout = match (major, minor) {
            (3, 11) => python311(),
            (3, 12) => python312(),
            (3, 13 | 14) => debug_layout(memory, runtime, minor)?,
            _ => {
                return Err(Error::Unsupported {
                    runtime: "python",
                    version,
                });
            }
        };
        let code_type = at("PyCode_Type")
            .ok_or_else(|| Error::Invalid("CPython has no PyCode_Type symbol".into()))?;
        // Builds that dispatch by tail calls run the program's bytecode in
        // a function per instruction, called from the eval loop.
        let mut eval_loop: Vec<Range<u64>> = symbols
            .iter()
            .filter(|(name, _)| {
                *name == "_PyEval_EvalFrameDefault" || name.starts_with("_TAIL_CALL_")
            })
            .map(|(_, range)| range.clone())
            .filter(|range| !range.is_empty())
            .collect();
        eval_loop.sort_by_key(|range| range.start);
        Ok(Self {
            version,
            layout,
            runtime,
            code_type,
            eval_loop,
        })
    }

    /// A compact string, as names are.
    fn string(
        &self,
        memory: &dyn Memory,
        what: &'static str,
        address: u64,
    ) -> Result<String, Error> {
        let state = u32_at(memory, what, address + STRING_STATE)?;
        let length = u64_at(memory, what, address + STRING_LENGTH)?;
        let (kind, compact, ascii) = ((state >> 2) & 7, (state >> 5) & 1, (state >> 6) & 1);
        let width = u64::from(kind);
        if compact == 0 || !matches!(width, 1 | 2 | 4) || length > MAX_STRING {
            return Err(Error::Invalid(format!(
                "no string uhr can read at {address:#x}"
            )));
        }
        let data = match ascii {
            1 => self.layout.ascii_data,
            _ => self.layout.compact_data,
        };
        let bytes = bytes_at(
            memory,
            what,
            address + u64::from(data),
            (length * width) as usize,
        )?;
        let chars = bytes.chunks_exact(width as usize).map(|c| match c {
            [a] => u32::from(*a),
            [a, b] => u32::from(u16::from_ne_bytes([*a, *b])),
            _ => u32::from_ne_bytes(c.try_into().unwrap()),
        });
        // CPython keeps the bytes of a file name that are not UTF-8 as
        // lone surrogates, which are no characters.
        Ok(text::chars(chars))
    }
}

impl Interpreter for CPython {
    fn runtime(&self) -> &'static str {
        "python"
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn walk(&self) -> Walk {
        let layout = &self.layout;
        let frame = &layout.frame;
        let flag = match frame.entry {
            Entry::Flag(at) => at + 1,
            Entry::Owner(_) => 0,
        };
        let end = [
            frame.code + 8,
            frame.previous + 8,
            frame.instruction + 8,
            frame.owner + 1,
            flag,
        ];
        Walk {
            base: self.runtime,
            lists: vec![layout.interpreters_head],
            next_list: Some(layout.interpreter_next),
            first_state: layout.threads_head,
            next_state: layout.thread_next,
            thread_id: layout.native_thread_id,
            active: layout.thread_status.map(|status| (status, ACTIVE)),
            frame: layout.current_frame.clone(),
            next_frame: frame.previous,
            frame_bytes: end.into_iter().max().unwrap_or(0).next_multiple_of(8),
            frame_pointers: matches!(frame.entry, Entry::Owner(_)),
        }
    }

    fn eval_loop(&self) -> &[Range<u64>] {
        &self.eval_loop
    }

    fn frame(&self, bytes: &[u8]) -> WalkedFrame {
        let frame = &self.layout.frame;
        let word = |at: u32| {
            let at = at as usize;
            bytes
                .get(at..at + 8)
                .map_or(0, |b| u64::from_ne_bytes(b.try_into().unwrap()))
        };
        let byte = |at: u32| bytes.get(at as usize).copied().unwrap_or(0);
        let entered = match frame.entry {
            // A local of the eval loop's call, on the native stack.
            Entry::Owner(first) if byte(frame.owner) >= first => {
                return WalkedFrame::Entry { native: true };
            }
            Entry::Owner(_) => false,
            Entry::Flag(at) => byte(at) != 0,
        };
        WalkedFrame::Code {
            code: word(frame.code) & !frame.tag_bits,
            instruction: word(frame.instruction),
            entered,
        }
    }

    fn code(&self, memory: &dyn Memory, address: u64) -> Result<Code, Error> {
        let code = &self.layout.code;
        let field = |offset: u32| address + u64::from(offset);
        if u64_at(memory, "a code object's type", address + OB_TYPE)? != self.code_type {
            return Err(Error::Invalid(format!("no code object at {address:#x}")));
        }
        let name = u64_at(memory, "a code object's name", field(code.qualname))?;
        let file = u64_at(memory, "a code object's file", field(code.filename))?;
        let first_line = u32_at(memory, "a code object's first line", field(code.first_line))?;
        let table = u64_at(memory, "a code object's line table", field(code.line_table))?;
        let size = u64_at(memory, "a line table's size", table + BYTES_SIZE)?;
        if size > MAX_LINE_TABLE {
            return Err(Error::Invalid(format!("a line table of {size} bytes")));
        }
        let table = bytes_at(memory, "a line table", table + BYTES_DATA, size as usize)?;
        Ok(Code {
            name: self.string(memory, "a code object's name", name)?,
            file: self.string(memory, "a code object's file", file)?,
            first_line,
            lines: lines(&table, field(code.instructions), first_line),
        })
    }
}

/// A number in 6-bit pieces, low first, with the 0x40 bit set in all but
/// the last, which never runs into the next entry.
fn varint(bytes: &mut Peekable<impl Iterator<Item = u8>>) -> u64 {
    let (mut value, mut shift) = (0u64, 0);
    while let Some(byte) = bytes.next_if(|b| b & 0x80 == 0) {
        value |= u64::from(byte & 63) << shift;
        shift += 6;
        if byte & 64 == 0 || shift > 60 {
            break;
        }
    }
    value
}

/// The lines of the instructions starting at `start`, from the line table
/// 3.11 and later keep: entries of a first byte, with the 0x80 bit set,
/// the kind in the next four bits and how many 2-byte instructions it
/// covers, less 1, in the last three, then what the kind says follows.
fn lines(table: &[u8], start: u64, first_line: u32) -> Vec<(Range<u64>, u32)> {
    let mut lines: Vec<(Range<u64>, u32)> = Vec::new();
    let mut line = i64::from(first_line);
    let mut at = start;
    let mut bytes = table.iter().copied().peekable();
    while let Some(first) = bytes.next() {
        let kind = (first >> 3) & 15;
        let end = at + 2 * (u64::from(first & 7) + 1);
        let delta = match kind {
            // No line.
            15 => None,
            // The line, end line and columns, or the line alone.
            13 | 14 => {
                let value = varint(&mut bytes);
                let delta = if value & 1 == 1 {
                    -((value >> 1) as i64)
                } else {
                    (value >> 1) as i64
                };
                if kind == 14 {
                    for _ in 0..3 {
                        varint(&mut bytes);
                    }
                }
                Some(delta)
            }
            // The next one, two or three lines, with two bytes of columns.
            10..=12 => {
                bytes.next_if(|b| b & 0x80 == 0);
                bytes.next_if(|b| b & 0x80 == 0);
                Some(i64::from(kind) - 10)
            }
            // The same line, with a byte of columns.
            _ => {
                bytes.next_if(|b| b & 0x80 == 0);
                Some(0)
            }
        };
        if let Some(delta) = delta {
            line += delta;
            if let Ok(line) = u32::try_from(line) {
                lines.push((at..end, line));
            }
        }
        at = end;
    }
    lines
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    /// Memory of `bytes` from `at` on.
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
    fn keeps_names_with_no_characters_apart() {
        let python = CPython {
            version: "3.12.3".into(),
            layout: python312(),
            runtime: 0,
            code_type: 0,
            eval_loop: Vec::new(),
        };
        // A compact string of 2-byte characters at 0x1000, as 3.12 keeps
        // `mod-\xff\\.py` decoded with surrogateescape.
        let units: Vec<u16> = "mod-"
            .encode_utf16()
            .chain([0xdcff])
            .chain("\\.py".encode_utf16())
            .collect();
        let mut bytes = vec![0; 56];
        bytes[16..24].copy_from_slice(&(units.len() as u64).to_ne_bytes());
        // Kind 2, compact, not ASCII.
        bytes[32..36].copy_from_slice(&(2u32 << 2 | 1 << 5).to_ne_bytes());
        bytes.extend(units.iter().flat_map(|u| u.to_ne_bytes()));
        let memory = Bytes { at: 0x1000, bytes };
        let name = python.string(&memory, "a name", 0x1000).unwrap();
        assert_eq!(name, "mod-\\udcff\\\\.py");
    }

    #[test]
    fn reads_line_tables() {
        // `compile(src, "f", "exec")` on 3.12, of "x = 1\n\ny = (\n  2)\nfor
        // i in range(3):\n    x += i\nprint(x)\n", with the line of each
        // instruction from its `co_lines()`. The loop jumps back to line 5.
        let table = [
            240, 3, 1, 1, 1, 216, 4, 5, 128, 1, 240, 6, 0, 3, 4, 240, 3, 0, 1, 2, 225, 9, 14, 136,
            113, 139, 24, 242, 0, 1, 1, 11, 128, 65, 216, 4, 5, 136, 17, 129, 70, 129, 65, 240, 3,
            1, 1, 11, 225, 0, 5, 128, 97, 133, 8,
        ];
        let mut expected = vec![0, 1, 1, 4, 3];
        expected.extend([5; 11]);
        expected.extend([6; 6]);
        expected.push(5);
        expected.extend([7; 9]);
        let code = Code {
            name: "<module>".into(),
            file: "f".into(),
            first_line: 1,
            lines: lines(&table, 0x1000, 1),
        };
        let found: Vec<_> = (0..expected.len() as u64)
            .map(|unit| code.line(0x1000 + 2 * unit))
            .collect();
        assert_eq!(found, expected.into_iter().map(Some).collect::<Vec<_>>());
        assert_eq!(code.line(0x1000 + 2 * 32), None);
        assert_eq!(code.line(0xfff), None);
    }
}
