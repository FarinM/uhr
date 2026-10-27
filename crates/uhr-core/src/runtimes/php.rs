//! PHP, built without thread safety as its command line is, whose frames
//! are a list from `executor_globals.current_execute_data`, each frame with
//! the one that called it.
//!
//! The offsets are those of PHP 8.3's headers, which it does not publish.

use std::ops::Range;

use super::process::{bytes_at, symbols, u32_at, u64_at};
use super::text;
use super::{
    Code, Copy, Error, Frames, Interpreter, Memory, Process, Read, Runtime, Step, Thread, Walk,
    WalkedFrame,
};
use crate::recording::Mapping;

pub(super) struct Php;

impl Runtime for Php {
    fn name(&self) -> &'static str {
        "php"
    }

    /// `php8.3`, `php`, or a `libphp.so` another program embeds it with.
    fn is_binary(&self, file: &str) -> bool {
        file == "php" || file.starts_with("php8") || file.starts_with("libphp")
    }

    fn interpreter(&self, process: &dyn Process) -> Result<Option<Box<dyn Interpreter>>, Error> {
        find(self, process)
    }
}

/// The longest name or file read, and the most instructions of one
/// function.
const MAX_STRING: u64 = 4096;
const MAX_OPS: u64 = 1 << 20;

/// In `zend_executor_globals`, the innermost frame.
const GLOBALS_FRAME: u32 = 488;

/// In `zend_execute_data`: the next instruction, the function, the call's
/// flags, in its `This`, and the frame that called it.
const FRAME_OPLINE: usize = 0;
const FRAME_FUNCTION: u32 = 24;
const FRAME_CALL_INFO: usize = 40;
const FRAME_PREVIOUS: u32 = 48;
const FRAME_COPY: u32 = 56;

/// The call's flag of a frame native code called into.
const CALL_TOP: u32 = 1 << 17;

/// What `zend_function` starts with, its type, of which a function of C.
const INTERNAL_FUNCTION: u64 = 1;

/// In `zend_op_array`, and `zend_class_entry`'s name.
const FUNCTION_NAME: u64 = 8;
const FUNCTION_SCOPE: u64 = 16;
const FUNCTION_OPS: u64 = 76;
const FUNCTION_OPCODES: u64 = 80;
const FUNCTION_FILE: u64 = 144;
const FUNCTION_FIRST_LINE: u64 = 152;
const CLASS_NAME: u64 = 8;

/// `zend_op`, which keeps its line 24 bytes in.
const OP_SIZE: u64 = 32;
const OP_LINE: usize = 24;

/// In `zend_string`.
const STRING_LENGTH: u64 = 16;
const STRING_CHARS: u64 = 24;

struct ZendEngine {
    version: String,
    walk: Walk,
    eval_loop: Vec<Range<u64>>,
}

fn find(php: &dyn Runtime, process: &dyn Process) -> Result<Option<Box<dyn Interpreter>>, Error> {
    let file_name = |m: &Mapping| m.path.rsplit('/').next().unwrap_or(&m.path).to_owned();
    let mut files: Vec<&Mapping> = Vec::new();
    for mapping in process.mappings() {
        if php.is_binary(&file_name(mapping)) && !files.iter().any(|m| m.path == mapping.path) {
            files.push(mapping);
        }
    }
    for mapping in files {
        let symbols = symbols(process, mapping, |name| {
            matches!(name, "executor_globals" | "execute_ex" | "php_version_id")
        })?;
        let Some(globals) = symbols.get("executor_globals") else {
            continue;
        };
        let version = symbols
            .get("php_version_id")
            .and_then(|id| version(process.memory(), id.start))
            .or_else(|| file_name(mapping).strip_prefix("php").map(str::to_owned))
            .unwrap_or_default();
        if !version.starts_with("8.3") {
            return Err(Error::Unsupported {
                runtime: "php",
                version,
            });
        }
        let walk = Walk {
            frames: Frames::Memory {
                thread: Thread::Global {
                    state: globals.start,
                    frame: vec![GLOBALS_FRAME],
                },
                step: Step::Pointer(FRAME_PREVIOUS),
            },
            copy: Copy {
                from: 0,
                bytes: FRAME_COPY,
                // The function's type, in its first byte.
                reads: vec![Read {
                    word: FRAME_FUNCTION,
                    offset: 0,
                }],
            },
            frame_pointers: false,
        };
        return Ok(Some(Box::new(ZendEngine {
            version,
            walk,
            eval_loop: symbols.get("execute_ex").cloned().into_iter().collect(),
        })));
    }
    Ok(None)
}

/// The version `php_version_id` returns, as x86-64 code: an optional
/// `endbr64`, then `mov eax, <id>` and `ret`, with the id as in 80306 for
/// 8.3.6.
fn version(memory: &dyn Memory, function: u64) -> Option<String> {
    let code = bytes_at(memory, "php_version_id", function, 10).ok()?;
    let code = code
        .strip_prefix(&[0xf3, 0x0f, 0x1e, 0xfa])
        .unwrap_or(&code);
    let (&[0xb8], rest) = code.split_at(1) else {
        return None;
    };
    let id = u32::from_le_bytes(rest.get(..4)?.try_into().ok()?);
    (rest.get(4) == Some(&0xc3)).then(|| format!("{}.{}.{}", id / 10000, id / 100 % 100, id % 100))
}

impl ZendEngine {
    fn string(&self, memory: &dyn Memory, string: u64) -> Result<String, Error> {
        let length = u64_at(memory, "a PHP string's length", string + STRING_LENGTH)?;
        if length > MAX_STRING {
            return Err(Error::Invalid(format!("a PHP string of {length} bytes")));
        }
        let bytes = bytes_at(
            memory,
            "a PHP string",
            string + STRING_CHARS,
            length as usize,
        )?;
        Ok(text::utf8(&bytes))
    }
}

impl Interpreter for ZendEngine {
    fn runtime(&self) -> &'static str {
        "php"
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
        let (opline, function) = (word(FRAME_OPLINE), word(FRAME_FUNCTION as usize));
        let call_info = word(FRAME_CALL_INFO) as u32;
        let kind = word(FRAME_COPY as usize) & 0xff;
        // A function of C runs as the native code it is.
        if function == 0 || kind == INTERNAL_FUNCTION {
            return WalkedFrame::Native;
        }
        WalkedFrame::Code {
            code: function,
            instruction: opline,
            entered: call_info & CALL_TOP != 0,
        }
    }

    fn code(&self, memory: &dyn Memory, function: u64) -> Result<Code, Error> {
        let field = |offset: u64| u64_at(memory, "a PHP function", function + offset);
        let name = match field(FUNCTION_NAME)? {
            // A file's own code.
            0 => "{main}".to_owned(),
            name => self.string(memory, name)?,
        };
        let name = match field(FUNCTION_SCOPE)? {
            0 => name,
            class => {
                let class = u64_at(memory, "a PHP class", class + CLASS_NAME)?;
                format!("{}::{name}", self.string(memory, class)?)
            }
        };
        let file = self.string(memory, field(FUNCTION_FILE)?)?;
        let first_line = u32_at(memory, "a PHP function", function + FUNCTION_FIRST_LINE)?;
        let ops = u64::from(u32_at(memory, "a PHP function", function + FUNCTION_OPS)?);
        let mut lines = Vec::new();
        if ops <= MAX_OPS {
            let opcodes = field(FUNCTION_OPCODES)?;
            let code = bytes_at(
                memory,
                "a PHP function's code",
                opcodes,
                (ops * OP_SIZE) as usize,
            )?;
            for (i, op) in code.chunks_exact(OP_SIZE as usize).enumerate() {
                let line = u32::from_ne_bytes(op[OP_LINE..OP_LINE + 4].try_into().unwrap());
                let at = opcodes + OP_SIZE * i as u64;
                lines.push((at..at + OP_SIZE, line));
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

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    struct Bytes(Vec<u8>);

    impl Memory for Bytes {
        fn read(&self, address: u64, into: &mut [u8]) -> io::Result<()> {
            let bytes = self.0.get(address as usize..address as usize + into.len());
            into.copy_from_slice(bytes.ok_or(io::ErrorKind::InvalidInput)?);
            Ok(())
        }
    }

    #[test]
    fn reads_the_version_its_function_returns() {
        let with_branch_target = Bytes(vec![
            0xf3, 0x0f, 0x1e, 0xfa, 0xb8, 0xb2, 0x39, 0x01, 0x00, 0xc3,
        ]);
        assert_eq!(version(&with_branch_target, 0).as_deref(), Some("8.3.6"));
        let other = Bytes(vec![0x55, 0x48, 0x89, 0xe5, 0xb8, 0, 0, 0, 0, 0xc3]);
        assert_eq!(version(&other, 0), None);
    }
}
