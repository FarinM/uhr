//! HotSpot, the JVM of OpenJDK, whose interpreter keeps each method's frame
//! on the native stack, with the `Method` it runs and where in its
//! bytecode.
//!
//! HotSpot publishes where its structures keep what uhr reads, for its
//! serviceability agent, in tables `libjvm` exports, which uhr reads from
//! the process. Those don't say where in its frame the interpreter keeps
//! each slot, only where one of them is, and the rest are as HotSpot's
//! x86-64 headers lay them out below it.
//!
//! Code it compiled keeps no `Method` in its frame, and without
//! `-XX:+PreserveFramePointer` keeps no frame pointer, so only interpreted
//! frames are read.

use std::collections::HashMap;
use std::ops::Range;

use super::process::{bytes_at, symbols, u32_at, u64_at};
use super::text;
use super::{
    Code, Copy, Error, Frames, Interpreter, Memory, Process, Read, Runtime, Walk, WalkedFrame,
};
use crate::recording::Mapping;

pub(super) struct Jvm;

impl Runtime for Jvm {
    fn name(&self) -> &'static str {
        "java"
    }

    fn is_binary(&self, file: &str) -> bool {
        file == "libjvm.so"
    }

    fn interpreter(&self, process: &dyn Process) -> Result<Option<Box<dyn Interpreter>>, Error> {
        find(self, process)
    }
}

/// The interpreter's slots below where it keeps the stack pointer of its
/// last call, in 8-byte words: the `Method`, its class's mirror, the
/// profile data, the cache, the locals, then where in the bytecode it is.
const SLOTS_BELOW_LAST_SP_TO_METHOD: i32 = 1;
const SLOTS_BELOW_LAST_SP_TO_BYTECODE: i32 = 6;

/// How far past the start of its `ConstMethod` an interpreted frame's
/// bytecode can be, which tells its frames from those of other code that
/// hold a `Method` where it does, as the stub that calls into Java.
const MAX_BYTECODE: u64 = 1 << 16;

const MAX_STRING: u64 = 4096;
const MAX_LINES: usize = 1 << 16;
const MAX_LINE_TABLE: u64 = 1 << 20;

/// Where HotSpot's structures keep what uhr reads.
#[derive(Debug, Clone)]
struct Layout {
    method_const: u64,
    const_constants: u64,
    const_name: u64,
    const_signature: u64,
    const_code_size: u64,
    /// In 8-byte words.
    const_method_size: u64,
    const_flags: u64,
    const_size: u64,
    pool_holder: u64,
    pool_source_file: u64,
    pool_size: u64,
    klass_name: u64,
    klass_constants: u64,
    symbol_length: u64,
    symbol_body: u64,
    has_line_table: u32,
    /// From the frame pointer.
    method_slot: i32,
    bytecode_slot: i32,
}

struct HotSpot {
    version: String,
    layout: Layout,
    walk: Walk,
}

/// HotSpot's tables of where its structures keep their fields, of the
/// sizes of its types, and of its constants, as `vmStructs` publishes them.
struct Tables {
    fields: HashMap<String, u64>,
    statics: HashMap<String, u64>,
    sizes: HashMap<String, u64>,
    constants: HashMap<String, i32>,
}

fn find(jvm: &dyn Runtime, process: &dyn Process) -> Result<Option<Box<dyn Interpreter>>, Error> {
    let file_name = |m: &Mapping| m.path.rsplit('/').next().unwrap_or(&m.path).to_owned();
    let Some(mapping) = process
        .mappings()
        .iter()
        .find(|m| jvm.is_binary(&file_name(m)))
    else {
        return Ok(None);
    };
    let symbols = symbols(process, mapping, |name| name.starts_with("gHotSpotVM"))?;
    let memory = process.memory();
    let tables = Tables::read(memory, &symbols)?;
    let field = |name: &str| {
        tables
            .fields
            .get(name)
            .copied()
            .ok_or_else(|| Error::Invalid(format!("HotSpot does not say where {name} is")))
    };
    let size = |name: &str| {
        tables
            .sizes
            .get(name)
            .copied()
            .ok_or_else(|| Error::Invalid(format!("HotSpot does not say how big {name} is")))
    };
    let constant = |name: &str| {
        tables
            .constants
            .get(name)
            .copied()
            .ok_or_else(|| Error::Invalid(format!("HotSpot does not say what {name} is")))
    };
    let last_sp = constant("frame::interpreter_frame_last_sp_offset")?;
    let layout = Layout {
        method_const: field("Method::_constMethod")?,
        const_constants: field("ConstMethod::_constants")?,
        const_name: field("ConstMethod::_name_index")?,
        const_signature: field("ConstMethod::_signature_index")?,
        const_code_size: field("ConstMethod::_code_size")?,
        const_method_size: field("ConstMethod::_constMethod_size")?,
        const_flags: field("ConstMethod::_flags._flags")?,
        const_size: size("ConstMethod")?,
        pool_holder: field("ConstantPool::_pool_holder")?,
        pool_source_file: field("ConstantPool::_source_file_name_index")?,
        pool_size: size("ConstantPool")?,
        klass_name: field("Klass::_name")?,
        klass_constants: field("InstanceKlass::_constants")?,
        symbol_length: field("Symbol::_length")?,
        symbol_body: field("Symbol::_body")?,
        has_line_table: tables
            .constants
            .get("ConstMethodFlags::_misc_has_linenumber_table")
            .map_or(0, |&flag| flag as u32),
        method_slot: 8 * (last_sp - SLOTS_BELOW_LAST_SP_TO_METHOD),
        bytecode_slot: 8 * (last_sp - SLOTS_BELOW_LAST_SP_TO_BYTECODE),
    };
    let version = match tables.statics.get("Abstract_VM_Version::_s_vm_release") {
        Some(&at) => {
            let release = u64_at(memory, "HotSpot's version", at)?;
            c_string(memory, release)?
        }
        None => String::new(),
    };
    let slots = [layout.bytecode_slot, layout.method_slot];
    let from = slots.into_iter().min().unwrap_or(0);
    let to = slots.into_iter().max().unwrap_or(0) + 8;
    let walk = Walk {
        frames: Frames::Native,
        copy: Copy {
            from,
            bytes: (to - from) as u32,
            // The `ConstMethod`, which the bytecode follows.
            reads: vec![Read {
                word: (layout.method_slot - from) as u32,
                offset: layout.method_const as i32,
            }],
        },
        frame_pointers: true,
    };
    Ok(Some(Box::new(HotSpot {
        version,
        layout,
        walk,
    })))
}

/// The NUL-terminated string at `address`.
fn c_string(memory: &dyn Memory, address: u64) -> Result<String, Error> {
    let mut text = Vec::new();
    while text.len() < MAX_STRING as usize {
        let chunk = bytes_at(memory, "a C string", address + text.len() as u64, 64)?;
        match chunk.iter().position(|&b| b == 0) {
            Some(end) => {
                text.extend(&chunk[..end]);
                break;
            }
            None => text.extend(chunk),
        }
    }
    Ok(String::from_utf8_lossy(&text).into_owned())
}

impl Tables {
    fn read(memory: &dyn Memory, symbols: &HashMap<String, Range<u64>>) -> Result<Self, Error> {
        let at = |name: &str| {
            symbols
                .get(&format!("gHotSpotVM{name}"))
                .map(|range| range.start)
                .ok_or_else(|| Error::Invalid(format!("libjvm has no gHotSpotVM{name}")))
        };
        let int = |name: &str| -> Result<u64, Error> {
            Ok(u64::from(u32_at(
                memory,
                "a HotSpot table's layout",
                at(name)?,
            )?))
        };
        let mut tables = Tables {
            fields: HashMap::new(),
            statics: HashMap::new(),
            sizes: HashMap::new(),
            constants: HashMap::new(),
        };
        // Each table ends with an entry without a name.
        let entries = |table: &str, stride: &str| -> Result<(u64, u64), Error> {
            let first = u64_at(memory, "a HotSpot table", at(table)?)?;
            Ok((first, int(stride)?))
        };
        let (mut entry, stride) = entries("Structs", "StructEntryArrayStride")?;
        let (type_name, field_name) = (
            int("StructEntryTypeNameOffset")?,
            int("StructEntryFieldNameOffset")?,
        );
        let (is_static, offset, address) = (
            int("StructEntryIsStaticOffset")?,
            int("StructEntryOffsetOffset")?,
            int("StructEntryAddressOffset")?,
        );
        for _ in 0..1 << 16 {
            let name = u64_at(memory, "a HotSpot table", entry + type_name)?;
            if name == 0 {
                break;
            }
            let field = u64_at(memory, "a HotSpot table", entry + field_name)?;
            let name = format!("{}::{}", c_string(memory, name)?, c_string(memory, field)?);
            if u32_at(memory, "a HotSpot table", entry + is_static)? != 0 {
                let at = u64_at(memory, "a HotSpot table", entry + address)?;
                tables.statics.insert(name, at);
            } else {
                let at = u64_at(memory, "a HotSpot table", entry + offset)?;
                tables.fields.insert(name, at);
            }
            entry += stride;
        }
        let (mut entry, stride) = entries("Types", "TypeEntryArrayStride")?;
        let (type_name, size) = (int("TypeEntryTypeNameOffset")?, int("TypeEntrySizeOffset")?);
        for _ in 0..1 << 16 {
            let name = u64_at(memory, "a HotSpot table", entry + type_name)?;
            if name == 0 {
                break;
            }
            let bytes = u64_at(memory, "a HotSpot table", entry + size)?;
            tables.sizes.insert(c_string(memory, name)?, bytes);
            entry += stride;
        }
        let (mut entry, stride) = entries("IntConstants", "IntConstantEntryArrayStride")?;
        let (name_at, value) = (
            int("IntConstantEntryNameOffset")?,
            int("IntConstantEntryValueOffset")?,
        );
        for _ in 0..1 << 16 {
            let name = u64_at(memory, "a HotSpot table", entry + name_at)?;
            if name == 0 {
                break;
            }
            let value = u32_at(memory, "a HotSpot table", entry + value)? as i32;
            tables.constants.insert(c_string(memory, name)?, value);
            entry += stride;
        }
        Ok(tables)
    }
}

impl HotSpot {
    /// A `Symbol`'s text, in Java's modified UTF-8.
    fn symbol(&self, memory: &dyn Memory, symbol: u64) -> Result<String, Error> {
        let length = bytes_at(
            memory,
            "a HotSpot symbol",
            symbol + self.layout.symbol_length,
            2,
        )?;
        let length = u64::from(u16::from_ne_bytes([length[0], length[1]]));
        if length > MAX_STRING {
            return Err(Error::Invalid(format!(
                "a HotSpot symbol of {length} bytes"
            )));
        }
        let bytes = bytes_at(
            memory,
            "a HotSpot symbol",
            symbol + self.layout.symbol_body,
            length as usize,
        )?;
        Ok(text::modified_utf8(&bytes))
    }

    /// The symbol at `index` of the constant pool at `pool`.
    fn pool_symbol(&self, memory: &dyn Memory, pool: u64, index: u64) -> Result<String, Error> {
        let symbol = u64_at(
            memory,
            "a constant pool",
            pool + self.layout.pool_size + 8 * index,
        )?;
        self.symbol(memory, symbol)
    }
}

/// A number of the line table, in the variable-length encoding HotSpot's
/// compressed streams use: the last byte is below 192, and each byte before
/// adds 6 more bits, with 0 never used.
fn unsigned5(bytes: &mut impl Iterator<Item = u8>) -> Option<u32> {
    const LOW: u32 = 191;
    let mut sum = u32::from(bytes.next()?).checked_sub(1)?;
    if sum < LOW {
        return Some(sum);
    }
    let mut shift = 6;
    for i in 1..5 {
        let byte = u32::from(bytes.next()?).checked_sub(1)?;
        sum = sum.wrapping_add(byte << shift);
        if byte < LOW || i == 4 {
            break;
        }
        shift += 6;
    }
    Some(sum)
}

fn signed5(bytes: &mut impl Iterator<Item = u8>) -> Option<i32> {
    let value = unsigned5(bytes)?;
    Some((value >> 1) as i32 ^ -((value & 1) as i32))
}

/// The bytecode indexes where each line starts, from a compressed line
/// table: pairs of increments, a byte each where small, else after a 0xff,
/// ending with a 0. `None` for a table that does not end within `table`,
/// whose entries left could start anywhere.
fn line_table(table: &[u8]) -> Option<Vec<(u32, u32)>> {
    let mut lines = Vec::new();
    let (mut index, mut line) = (0i64, 0i64);
    let mut bytes = table.iter().copied();
    while lines.len() < MAX_LINES {
        match bytes.next()? {
            0 => return Some(lines),
            0xff => {
                index += i64::from(signed5(&mut bytes)?);
                line += i64::from(signed5(&mut bytes)?);
            }
            pair => {
                index += i64::from(pair >> 3);
                line += i64::from(pair & 7);
            }
        }
        lines.push((u32::try_from(index).ok()?, u32::try_from(line).ok()?));
    }
    None
}

/// The parameters of a method's descriptor, as Java writes their types, as
/// in `int, java.lang.String[]` for `(I[Ljava/lang/String;)V`.
fn parameters(descriptor: &str) -> Option<String> {
    let mut rest = descriptor.strip_prefix('(')?;
    let mut parameters = Vec::new();
    while !rest.starts_with(')') {
        let dimensions = rest.len() - rest.trim_start_matches('[').len();
        rest = &rest[dimensions..];
        let (kind, after) = match rest.as_bytes().first()? {
            b'L' => {
                let (class, after) = rest[1..].split_once(';')?;
                (class.replace('/', "."), after)
            }
            &primitive => {
                let kind = match primitive {
                    b'Z' => "boolean",
                    b'B' => "byte",
                    b'C' => "char",
                    b'S' => "short",
                    b'I' => "int",
                    b'J' => "long",
                    b'F' => "float",
                    b'D' => "double",
                    _ => return None,
                };
                (kind.to_owned(), &rest[1..])
            }
        };
        parameters.push(kind + &"[]".repeat(dimensions));
        rest = after;
    }
    Some(parameters.join(", "))
}

impl Interpreter for HotSpot {
    fn runtime(&self) -> &'static str {
        "java"
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn walk(&self) -> &Walk {
        &self.walk
    }

    fn eval_loop(&self) -> &[Range<u64>] {
        // The interpreter's code is generated, in no file.
        &[]
    }

    fn saves_instruction_on_calls(&self) -> bool {
        true
    }

    fn frame(&self, bytes: &[u8]) -> WalkedFrame {
        let copy = &self.walk.copy;
        let word = |at: usize| {
            bytes
                .get(at..at + 8)
                .map_or(0, |b| u64::from_ne_bytes(b.try_into().unwrap()))
        };
        let slot = |offset: i32| word((offset - copy.from) as usize);
        let (method, constant) = (slot(self.layout.method_slot), word(copy.bytes as usize));
        let bytecode = slot(self.layout.bytecode_slot);
        let into = bytecode.wrapping_sub(constant + self.layout.const_size);
        if method == 0 || method % 8 != 0 || constant == 0 || into >= MAX_BYTECODE {
            return WalkedFrame::Native;
        }
        WalkedFrame::Code {
            code: method,
            instruction: bytecode,
            entered: false,
        }
    }

    fn code(&self, memory: &dyn Memory, method: u64) -> Result<Code, Error> {
        let layout = &self.layout;
        let word = |at: u64| u64_at(memory, "a HotSpot method", at);
        let half = |at: u64| -> Result<u64, Error> {
            let bytes = bytes_at(memory, "a HotSpot method", at, 2)?;
            Ok(u64::from(u16::from_ne_bytes([bytes[0], bytes[1]])))
        };
        let constant = word(method + layout.method_const)?;
        let pool = word(constant + layout.const_constants)?;
        let holder = word(pool + layout.pool_holder)?;
        // A class's pool says the class is its holder.
        if word(holder + layout.klass_constants)? != pool {
            return Err(Error::Invalid(format!("no HotSpot method at {method:#x}")));
        }
        let class = self.symbol(memory, word(holder + layout.klass_name)?)?;
        let name = self.pool_symbol(memory, pool, half(constant + layout.const_name)?)?;
        // Overloads share a name, and differ in their parameters.
        let descriptor =
            self.pool_symbol(memory, pool, half(constant + layout.const_signature)?)?;
        let name = match parameters(&descriptor) {
            Some(parameters) => format!("{}.{name}({parameters})", class.replace('/', ".")),
            None => format!("{}.{name}{descriptor}", class.replace('/', ".")),
        };
        let file = match half(pool + layout.pool_source_file)? {
            0 => String::new(),
            index => self.pool_symbol(memory, pool, index)?,
        };
        // The bytecode follows the `ConstMethod`, and the line table, where
        // it has one, the bytecode.
        let code = constant + layout.const_size;
        let size = half(constant + layout.const_code_size)?;
        let flags = u32_at(memory, "a HotSpot method", constant + layout.const_flags)?;
        let mut lines = Vec::new();
        if flags & layout.has_line_table != 0 {
            // The table ends before the `ConstMethod` does, which tables
            // after it fill from its end.
            let words = u32_at(
                memory,
                "a HotSpot method",
                constant + layout.const_method_size,
            )?;
            let end = constant + 8 * u64::from(words);
            let length = end.saturating_sub(code + size).min(MAX_LINE_TABLE);
            let table = bytes_at(memory, "a HotSpot line table", code + size, length as usize)?;
            let mut starts = line_table(&table).unwrap_or_default();
            // A class file can list its lines in any order.
            starts.sort_by_key(|&(index, _)| index);
            starts.dedup_by_key(|(index, _)| *index);
            let ends = starts
                .iter()
                .skip(1)
                .map(|&(index, _)| u64::from(index))
                .chain([size]);
            for (&(index, line), end) in starts.iter().zip(ends) {
                let start = code + u64::from(index);
                lines.push((start..code + end, line));
            }
        }
        let first_line = lines.first().map_or(0, |(_, line)| *line);
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
    use super::*;

    #[test]
    fn reads_compressed_line_tables() {
        // bci 0 at line 5, bci 4 at line 6, then bci 300 at line 2, which
        // needs the long form: 0xff, then 296 and -4, signed, which are 592
        // and 7, as HotSpot writes them.
        let table = [5, 4 << 3 | 1, 0xff, 209, 7, 8, 0];
        assert_eq!(line_table(&table).unwrap(), [(0, 5), (4, 6), (300, 2)]);
        // Without its end, what follows is not known.
        assert_eq!(line_table(&table[..6]), None);
    }

    #[test]
    fn writes_parameters_as_java_does() {
        assert_eq!(parameters("()V").unwrap(), "");
        assert_eq!(
            parameters("(I[[JLjava/lang/String;[Ljava/util/Map$Entry;)V").unwrap(),
            "int, long[][], java.lang.String, java.util.Map$Entry[]"
        );
        assert_eq!(parameters("(Q)V"), None);
        assert_eq!(parameters("(I"), None);
    }
}
