//! V8's frames, which it keeps on the native stack: the frame of each
//! JavaScript function holds its context and its `JSFunction`, whose
//! `SharedFunctionInfo` names it.
//!
//! V8 says where its structures keep most of what uhr reads, for debuggers,
//! in its `v8dbg_` symbols. Those don't say how a `ScopeInfo` lays out what
//! follows its fixed fields, which is that of V8 13's headers.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ops::Range;

use super::super::process::{bytes_at, symbols, u32_at, u64_at};
use super::super::text;
use super::super::{
    Code, Copy, Error, Frames, Interpreter, Memory, Process, Read, Runtime, Walk, WalkedFrame,
};
use crate::recording::Mapping;

/// The longest name or file read, and the longest source read to find
/// lines in, in characters, and the most lines of a script read.
const MAX_NAME: usize = 4096;
const MAX_SOURCE: usize = 16 << 20;
const MAX_LINES: usize = 1 << 24;

/// How deep a string of strings is read.
const MAX_PARTS: usize = 64;

/// Below this, no address is an object's.
const MIN_ADDRESS: u64 = 4096;

/// What V8 13 keeps in a `ScopeInfo` past its map, of 8-byte tagged
/// values: its flags, the number of context locals and where the function
/// starts in its script, then the parts its flags say it has.
const SCOPE_FLAGS: u64 = 8;
const SCOPE_CONTEXT_LOCALS: u64 = 24;
const SCOPE_START: u64 = 32;
const SCOPE_PARTS: u64 = 48;
/// Context locals past this many keep their names in a table of their own.
const SCOPE_MAX_INLINED_NAMES: u64 = 75;
const MODULE_SCOPE: u32 = 5;

/// The `v8dbg_` constants uhr reads, by name or by the start of one.
#[derive(Debug, Clone)]
struct Layout {
    fp_context: i32,
    fp_function: i32,
    heap_object_tag: u64,
    heap_object_tag_mask: u64,
    smi_tag_mask: u64,
    smi_shift: u32,
    map: u64,
    instance_type: u64,
    function_shared: u64,
    shared_name: u64,
    shared_script: u64,
    script_name: u64,
    script_source: u64,
    script_line_ends: u64,
    string_length: u64,
    one_byte_chars: u64,
    two_byte_chars: u64,
    cons_first: u64,
    cons_second: u64,
    thin_actual: u64,
    sliced_parent: u64,
    sliced_offset: u64,
    external_resource: u64,
    array_length: u64,
    array_data: u64,
    shared_type: u16,
    scope_type: u16,
    script_type: u16,
    array_type: u16,
    first_nonstring_type: u16,
    representation_mask: u16,
    encoding_mask: u16,
    one_byte_tag: u16,
    seq_tag: u16,
    cons_tag: u16,
    thin_tag: u16,
    sliced_tag: u16,
    external_tag: u16,
    /// The bit of the type of an external string that keeps no address of
    /// its characters.
    uncached: u16,
}

impl Layout {
    fn read(memory: &dyn Memory, symbols: &HashMap<String, Range<u64>>) -> Result<Self, Error> {
        let at = |name: &str| {
            let exact = symbols.get(&format!("v8dbg_{name}"));
            // Field names end with their type, which changes across
            // versions.
            let field = || {
                let prefix = format!("v8dbg_{name}__");
                symbols
                    .iter()
                    .find(|(symbol, _)| symbol.starts_with(&prefix))
                    .map(|(_, range)| range)
            };
            exact
                .or_else(field)
                .map(|range| range.start)
                .ok_or_else(|| Error::Invalid(format!("V8 has no v8dbg_{name}")))
        };
        let int = |name: &str| -> Result<i32, Error> {
            Ok(u32_at(memory, "a V8 constant", at(name)?)? as i32)
        };
        let offset = |name: &str| -> Result<u64, Error> {
            u64::try_from(int(name)?)
                .map_err(|_| Error::Invalid(format!("V8's {name} is negative")))
        };
        let small = |name: &str| -> Result<u16, Error> { Ok(int(name)? as u16) };
        if int("TaggedSize")? != 8 || int("SystemPointerSize")? != 8 {
            return Err(Error::Invalid(
                "V8 compresses its pointers, which uhr can't read yet".into(),
            ));
        }
        Ok(Self {
            fp_context: int("off_fp_context")?,
            fp_function: int("off_fp_function")?,
            heap_object_tag: offset("HeapObjectTag")?,
            heap_object_tag_mask: offset("HeapObjectTagMask")?,
            smi_tag_mask: offset("SmiTagMask")?,
            smi_shift: (int("SmiShiftSize")? + int("SmiValueShift")?) as u32,
            map: offset("class_HeapObject__map")?,
            instance_type: offset("class_Map__instance_type")?,
            function_shared: offset("class_JSFunction__shared")?,
            shared_name: offset("class_SharedFunctionInfo__name_or_scope_info")?,
            shared_script: offset("class_SharedFunctionInfo__script")?,
            script_name: offset("class_Script__name")?,
            script_source: offset("class_Script__source")?,
            script_line_ends: offset("class_Script__line_ends")?,
            string_length: offset("class_String__length")?,
            one_byte_chars: offset("class_SeqOneByteString__chars")?,
            two_byte_chars: offset("class_SeqTwoByteString__chars")?,
            cons_first: offset("class_ConsString__first")?,
            cons_second: offset("class_ConsString__second")?,
            thin_actual: offset("class_ThinString__actual")?,
            sliced_parent: offset("class_SlicedString__parent")?,
            sliced_offset: offset("class_SlicedString__offset")?,
            external_resource: offset("class_ExternalString__resource")?,
            array_length: offset("class_FixedArrayBase__length")?,
            array_data: offset("class_FixedArray__data")?,
            shared_type: small("type_SharedFunctionInfo__SHARED_FUNCTION_INFO_TYPE")?,
            scope_type: small("type_ScopeInfo__SCOPE_INFO_TYPE")?,
            script_type: small("type_Script__SCRIPT_TYPE")?,
            array_type: small("type_FixedArray__FIXED_ARRAY_TYPE")?,
            first_nonstring_type: small("FirstNonstringType")?,
            representation_mask: small("StringRepresentationMask")?,
            encoding_mask: small("StringEncodingMask")?,
            one_byte_tag: small("OneByteStringTag")?,
            seq_tag: small("SeqStringTag")?,
            cons_tag: small("ConsStringTag")?,
            thin_tag: small("ThinStringTag")?,
            sliced_tag: small("SlicedStringTag")?,
            external_tag: small("ExternalStringTag")?,
            uncached: small("type_UncachedExternalString__UNCACHED_EXTERNAL_ONE_BYTE_STRING_TYPE")?
                ^ small("type_ExternalOneByteString__EXTERNAL_ONE_BYTE_STRING_TYPE")?,
        })
    }
}

struct V8 {
    version: String,
    layout: Layout,
    walk: Walk,
    eval_loop: Vec<Range<u64>>,
    /// The lines of each script, by its address, `None` for one whose
    /// lines could not be read.
    lines: RefCell<HashMap<u64, Option<Lines>>>,
}

/// Where each line of a script ends, as far as uhr read its source.
struct Lines {
    ends: Vec<u32>,
    read: u64,
}

/// The V8 in `process`: in a `libnode` it maps, or else in a `node`
/// program.
pub(super) fn find(
    node: &dyn Runtime,
    process: &dyn Process,
) -> Result<Option<Box<dyn Interpreter>>, Error> {
    let file_name = |m: &Mapping| m.path.rsplit('/').next().unwrap_or(&m.path).to_owned();
    let mut files: Vec<&Mapping> = Vec::new();
    for mapping in process.mappings() {
        if node.is_binary(&file_name(mapping)) && !files.iter().any(|m| m.path == mapping.path) {
            files.push(mapping);
        }
    }
    files.sort_by_key(|m| !file_name(m).starts_with("libnode"));
    for mapping in files {
        let symbols = symbols(process, mapping, |name| {
            name.starts_with("v8dbg_")
                || name.starts_with("_ZN2v88internal7Version")
                || name.starts_with("Builtins_Interpreter")
                || (name.starts_with("Builtins_") && name.ends_with("Handler"))
        })?;
        if symbols.contains_key("v8dbg_off_fp_function") {
            return Ok(Some(Box::new(V8::new(process.memory(), &symbols)?)));
        }
    }
    Ok(None)
}

impl V8 {
    fn new(memory: &dyn Memory, symbols: &HashMap<String, Range<u64>>) -> Result<Self, Error> {
        let part = |name: &str| -> Result<u32, Error> {
            let symbol = format!("_ZN2v88internal7Version{name}_E");
            let at = symbols
                .get(&symbol)
                .ok_or_else(|| Error::Invalid("V8 does not say its version".into()))?;
            u32_at(memory, "V8's version", at.start)
        };
        let (major, minor) = (part("6major")?, part("6minor")?);
        let version = format!("{major}.{minor}.{}.{}", part("6build")?, part("6patch")?);
        if major != 13 {
            return Err(Error::Unsupported {
                runtime: "node",
                version: format!("V8 {version}"),
            });
        }
        let layout = Layout::read(memory, symbols)?;
        let mut eval_loop: Vec<Range<u64>> = symbols
            .iter()
            .filter(|(name, _)| name.starts_with("Builtins_"))
            .map(|(_, range)| range.clone())
            .filter(|range| !range.is_empty())
            .collect();
        eval_loop.sort_by_key(|range| range.start);
        // From the lowest slot uhr reads up to the frame pointer.
        let from = layout.fp_context.min(layout.fp_function);
        let walk = Walk {
            frames: Frames::Native,
            copy: Copy {
                from,
                bytes: from.unsigned_abs(),
                // The `SharedFunctionInfo`, as the garbage collector can
                // move the `JSFunction` before uhr reads it.
                reads: vec![Read {
                    word: (layout.fp_function - from) as u32,
                    path: vec![(layout.function_shared - layout.heap_object_tag) as i32],
                }],
            },
            frame_pointers: true,
        };
        Ok(Self {
            version,
            layout,
            walk,
            eval_loop,
            lines: RefCell::new(HashMap::new()),
        })
    }

    /// Whether `value` points to an object.
    fn is_object(&self, value: u64) -> bool {
        value & self.layout.heap_object_tag_mask == self.layout.heap_object_tag
            && value >= MIN_ADDRESS
    }

    fn smi(&self, value: u64) -> Option<i64> {
        (value & self.layout.smi_tag_mask == 0).then_some(value as i64 >> self.layout.smi_shift)
    }

    /// Where the object `value` points to starts.
    fn start(&self, value: u64) -> u64 {
        value - self.layout.heap_object_tag
    }

    /// The tagged value of the field at `offset` of the object at `object`.
    fn field(&self, memory: &dyn Memory, object: u64, offset: u64) -> Result<u64, Error> {
        u64_at(memory, "a V8 object's field", self.start(object) + offset)
    }

    /// The instance type of the object `value` points to, `None` for no
    /// object.
    fn type_of(&self, memory: &dyn Memory, value: u64) -> Result<Option<u16>, Error> {
        if !self.is_object(value) {
            return Ok(None);
        }
        let map = self.field(memory, value, self.layout.map)?;
        if !self.is_object(map) {
            return Ok(None);
        }
        let at = self.start(map) + self.layout.instance_type;
        let bytes = bytes_at(memory, "a V8 map's instance type", at, 2)?;
        Ok(Some(u16::from_ne_bytes([bytes[0], bytes[1]])))
    }

    fn is_string(&self, memory: &dyn Memory, value: u64) -> Result<bool, Error> {
        Ok(self
            .type_of(memory, value)?
            .is_some_and(|t| t < self.layout.first_nonstring_type))
    }

    /// The first `limit` UTF-16 code units of the string `value` points to.
    fn units(&self, memory: &dyn Memory, value: u64, limit: usize) -> Result<Vec<u16>, Error> {
        let mut units = Vec::new();
        // Each with where in it to start, and how many units to take.
        let mut parts = vec![(value, 0usize, usize::MAX)];
        let mut taken = 0;
        while let Some((part, skip, take)) = parts.pop() {
            if units.len() >= limit {
                break;
            }
            taken += 1;
            if taken > MAX_PARTS {
                return Err(Error::Invalid("a V8 string of too many parts".into()));
            }
            let Some(kind) = self.type_of(memory, part)? else {
                return Err(Error::Invalid(format!("no V8 string at {part:#x}")));
            };
            let layout = &self.layout;
            if kind >= layout.first_nonstring_type {
                return Err(Error::Invalid(format!("no V8 string at {part:#x}")));
            }
            let length = u32_at(
                memory,
                "a V8 string's length",
                self.start(part) + layout.string_length,
            )? as usize;
            let take = take
                .min(length.saturating_sub(skip))
                .min(limit - units.len());
            let one_byte = kind & layout.encoding_mask == layout.one_byte_tag;
            let chars = match kind & layout.representation_mask {
                tag if tag == layout.seq_tag => match one_byte {
                    true => self.start(part) + layout.one_byte_chars,
                    false => self.start(part) + layout.two_byte_chars,
                },
                // As Node keeps its own modules' source. Without pointer
                // compression, the address of its characters follows its
                // resource.
                tag if tag == layout.external_tag && kind & layout.uncached == 0 => u64_at(
                    memory,
                    "a V8 external string",
                    self.start(part) + layout.external_resource + 8,
                )?,
                tag if tag == layout.cons_tag => {
                    let first = self.field(memory, part, layout.cons_first)?;
                    let second = self.field(memory, part, layout.cons_second)?;
                    let first_length = u32_at(
                        memory,
                        "a V8 string's length",
                        self.start(first) + layout.string_length,
                    )? as usize;
                    // The second after the first, which goes on top.
                    if skip + take > first_length {
                        let skip = skip.saturating_sub(first_length);
                        parts.push((second, skip, take));
                    }
                    if skip < first_length {
                        parts.push((first, skip, take));
                    }
                    continue;
                }
                tag if tag == layout.thin_tag => {
                    parts.push((self.field(memory, part, layout.thin_actual)?, skip, take));
                    continue;
                }
                tag if tag == layout.sliced_tag => {
                    let parent = self.field(memory, part, layout.sliced_parent)?;
                    let offset = self.field(memory, part, layout.sliced_offset)?;
                    let offset = self.smi(offset).unwrap_or(0).max(0) as usize;
                    parts.push((parent, offset + skip, take));
                    continue;
                }
                _ => {
                    return Err(Error::Invalid(
                        "a V8 string kept where only its embedder can read it".into(),
                    ));
                }
            };
            let width = if one_byte { 1 } else { 2 };
            let at = chars + (skip * width) as u64;
            let bytes = bytes_at(memory, "a V8 string", at, take * width)?;
            match one_byte {
                true => units.extend(bytes.iter().map(|&b| u16::from(b))),
                false => units.extend(
                    bytes
                        .chunks_exact(2)
                        .map(|unit| u16::from_ne_bytes([unit[0], unit[1]])),
                ),
            }
        }
        Ok(units)
    }

    fn string(&self, memory: &dyn Memory, value: u64) -> Result<String, Error> {
        Ok(text::utf16(self.units(memory, value, MAX_NAME)?))
    }

    /// The name a `ScopeInfo` gives its function, as V8's
    /// `FunctionDebugName` takes it, and where the function starts in its
    /// script.
    fn scope(&self, memory: &dyn Memory, scope: u64) -> Result<(String, Option<u64>), Error> {
        let start = self.start(scope);
        let flags = u32_at(memory, "a V8 scope's flags", start + SCOPE_FLAGS)?;
        let word = |offset: u64| u64_at(memory, "a V8 scope", start + offset);
        let is_empty = (flags >> 29) & 1 == 1;
        if is_empty {
            return Ok((String::new(), None));
        }
        let position = self
            .smi(word(SCOPE_START)?)
            .and_then(|p| u64::try_from(p).ok());
        let locals = self
            .smi(word(SCOPE_CONTEXT_LOCALS)?)
            .and_then(|n| u64::try_from(n).ok())
            .filter(|&n| n < 1 << 20)
            .ok_or_else(|| Error::Invalid(format!("no V8 scope at {scope:#x}")))?;
        let mut at = SCOPE_PARTS;
        if flags & 15 == MODULE_SCOPE {
            at += 8;
        }
        // The names of the locals, or a table of them, then their kinds.
        at += 8 * if locals < SCOPE_MAX_INLINED_NAMES {
            locals
        } else {
            1
        };
        at += 8 * locals;
        if (flags >> 10) & 1 == 1 {
            at += 8;
        }
        let mut name = None;
        if (flags >> 12) & 3 != 0 {
            name = Some(word(at)?);
            at += 16;
        }
        let inferred = ((flags >> 14) & 1 == 1).then(|| word(at)).transpose()?;
        for candidate in [name, inferred].into_iter().flatten() {
            if self.is_string(memory, candidate)? {
                let text = self.string(memory, candidate)?;
                if !text.is_empty() {
                    return Ok((text, position));
                }
            }
        }
        Ok((String::new(), position))
    }

    /// The line and column of `position` in the script `script` points to,
    /// from 1.
    fn place(&self, memory: &dyn Memory, script: u64, position: u64) -> Option<(u32, u32)> {
        let mut lines = self.lines.borrow_mut();
        let lines = lines
            .entry(script)
            .or_insert_with(|| self.lines(memory, script).ok())
            .as_ref()?;
        if position >= lines.read {
            return None;
        }
        let line = lines.ends.partition_point(|&end| u64::from(end) < position);
        let starts = match line {
            0 => 0,
            line => u64::from(lines.ends[line - 1]) + 1,
        };
        let column = position.checked_sub(starts)? + 1;
        Some((u32::try_from(line + 1).ok()?, u32::try_from(column).ok()?))
    }

    /// Where each line of a script ends: as V8 keeps them once it needs
    /// them, or else from its source.
    fn lines(&self, memory: &dyn Memory, script: u64) -> Result<Lines, Error> {
        let layout = &self.layout;
        let ends = self.field(memory, script, layout.script_line_ends)?;
        if self.type_of(memory, ends)? == Some(layout.array_type) {
            let length = self.field(memory, ends, layout.array_length)?;
            let length = self.smi(length).unwrap_or(0).max(0) as usize;
            let bytes = bytes_at(
                memory,
                "a V8 script's line ends",
                self.start(ends) + layout.array_data,
                8 * length.min(MAX_LINES),
            )?;
            let ends: Vec<u32> = bytes
                .chunks_exact(8)
                .filter_map(|word| self.smi(u64::from_ne_bytes(word.try_into().unwrap())))
                .map(|end| end.max(0) as u32)
                .collect();
            // Past the ends read, which line a position is on is not known.
            let read = match length > MAX_LINES {
                true => ends.last().map_or(0, |&end| u64::from(end) + 1),
                false => u64::MAX,
            };
            return Ok(Lines { ends, read });
        }
        let source = self.field(memory, script, layout.script_source)?;
        let units = self.units(memory, source, MAX_SOURCE)?;
        // Short of the limit, that is all of it.
        let read = match units.len() < MAX_SOURCE {
            true => u64::MAX,
            false => units.len() as u64,
        };
        Ok(Lines {
            ends: line_ends(&units),
            read,
        })
    }
}

/// Where each line of source ends, as V8 finds them: at each line
/// terminator JavaScript has, with a CR before an LF ending none.
fn line_ends(units: &[u16]) -> Vec<u32> {
    let (lf, cr) = (u16::from(b'\n'), u16::from(b'\r'));
    units
        .iter()
        .enumerate()
        .filter(|&(at, &unit)| match unit {
            0x2028 | 0x2029 => true,
            unit if unit == cr => units.get(at + 1) != Some(&lf),
            unit => unit == lf,
        })
        .map(|(at, _)| at as u32)
        .collect()
}

impl Interpreter for V8 {
    fn runtime(&self) -> &'static str {
        "node"
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
        let copy = &self.walk.copy;
        let word = |at: usize| {
            bytes
                .get(at..at + 8)
                .map_or(0, |b| u64::from_ne_bytes(b.try_into().unwrap()))
        };
        let slot = |offset: i32| word((offset - copy.from) as usize);
        let (context, function) = (slot(self.layout.fp_context), slot(self.layout.fp_function));
        let shared = word(copy.bytes as usize);
        // Other frames hold a marker of their type where JavaScript's hold
        // the context, which is no object's address.
        if !self.is_object(context) || !self.is_object(function) || !self.is_object(shared) {
            return WalkedFrame::Native;
        }
        WalkedFrame::Code {
            code: shared,
            instruction: 0,
            entered: false,
        }
    }

    fn code(&self, memory: &dyn Memory, shared: u64) -> Result<Code, Error> {
        let layout = &self.layout;
        if self.type_of(memory, shared)? != Some(layout.shared_type) {
            return Err(Error::Invalid(format!("no V8 function at {shared:#x}")));
        }
        let name = self.field(memory, shared, layout.shared_name)?;
        let (name, position) = match self.type_of(memory, name)? {
            Some(kind) if kind < layout.first_nonstring_type => (self.string(memory, name)?, None),
            Some(kind) if kind == layout.scope_type => self.scope(memory, name)?,
            // A function without a name of its own.
            _ => (String::new(), None),
        };
        let script = self.field(memory, shared, layout.shared_script)?;
        let mut file = String::new();
        let mut start = None;
        if self.type_of(memory, script)? == Some(layout.script_type) {
            let script_name = self.field(memory, script, layout.script_name)?;
            if self.is_string(memory, script_name)? {
                file = self.string(memory, script_name)?;
            }
            if let Some(position) = position {
                start = self.place(memory, script, position);
            }
        }
        Ok(Code {
            name,
            file,
            first_line: start.map_or(0, |(line, _)| line),
            first_column: start.map(|(_, column)| column),
            lines: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ends_lines_where_javascript_does() {
        let units: Vec<u16> = "a\nb\r\nc\rd\u{2028}e\u{2029}f".encode_utf16().collect();
        assert_eq!(line_ends(&units), [1, 4, 6, 8, 10]);
    }
}
