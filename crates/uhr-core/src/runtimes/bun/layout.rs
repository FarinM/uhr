//! Where one build of Bun keeps what uhr reads, learned by running that
//! build with `probe.mjs`, which holds functions, strings and promises uhr
//! knows and says where they are. Each offset is the only one that leads
//! from what the probe holds to what uhr knows of it, as a function's name,
//! its frame or the promise of its result. Where none does, or more than
//! one, uhr reads no frames of the build, or for how async functions wait,
//! reads none of their waits.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;
use std::ops::Range;

use serde::Deserialize;
use serde::de::DeserializeOwned;
use tracing::debug;

use super::super::Memory;
use super::super::probe::Probe;
use super::super::text;

/// Where a cell's first word says its type, which is a byte, as
/// JavaScriptCore lays out every cell: after its structure's id and how it
/// indexes.
pub(super) const CELL_TYPE_SHIFT: u32 = 40;

/// A pointer's bits, under the flags JavaScriptCore keeps in a word with
/// one.
pub(super) const POINTER_BITS: u32 = 48;

/// The most characters of a string uhr reads.
pub(super) const MAX_STRING: u64 = 4096;

/// How far into an object uhr looks for a field.
const FIELDS: u64 = 0x100;
/// How far into a frame uhr looks for a slot.
const SLOTS: u64 = 0x60;
/// Where in a string uhr looks for its length, characters and flags.
const STRING_FIELDS: u64 = 0x20;
/// How much of the probe's stack uhr reads at a time, and the least.
const CHUNK: u64 = 0x1_0000;
const PAGE: u64 = 0x1000;

/// The name `probe.mjs` gives the code it runs from a string.
const PROGRAM_URL: &str = "uhr-probe-program";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Layout {
    pub version: String,
    /// In a frame, from its frame pointer: its `CodeBlock`, how many
    /// arguments it has with `this`, and its first argument after `this`.
    pub frame_code_block: i32,
    pub frame_arguments: i32,
    pub frame_first_argument: i32,
    pub code_block_type: u8,
    /// In a `CodeBlock`, its executable, whose type says what code it is.
    pub code_block_executable: u64,
    pub kinds: Kinds,
    /// In a `JSFunction`, its executable, and in that its `CodeBlock` for a
    /// call.
    pub function_executable: i32,
    pub executable_code_block: i32,
    /// From a function's executable to its name, and from any executable to
    /// its script's URL, through what each points to.
    pub name: [u64; 2],
    pub url: [u64; 2],
    pub string: Strings,
    /// How async functions wait, where the probe showed it.
    pub waiting: Option<Waiting>,
}

/// How async functions wait, and for which promises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Waiting {
    /// The type of an async function's state, which holds the function it
    /// resumes and the promise of its result, and of a promise.
    pub state_type: u8,
    pub state_next: i32,
    pub state_promise: i32,
    pub promise_type: u8,
    /// In a promise: the word of its flags, above a pointer, and the state
    /// of the function that waits for it.
    pub promise_flags: i32,
    pub promise_waiter: i32,
    /// The flags of a pending promise an async function waits for, and of
    /// one `Promise.all`, `allSettled` or `any` waits for, under the mask.
    /// The pointer of the second leads to what holds the promise of them
    /// all, at `group_promise`.
    pub flags_mask: u64,
    pub awaited_flags: u64,
    pub group_flags: Vec<u64>,
    pub group_promise: i32,
}

/// The types of the executables of each kind of code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Kinds {
    pub function: u8,
    pub program: u8,
    pub eval: u8,
    pub module: u8,
}

/// A `WTF::StringImpl`: its length, where its characters are, and the bit
/// of its flags that says they are a byte each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Strings {
    pub length: u64,
    pub chars: u64,
    pub flags: u64,
    pub one_byte: u32,
}

/// What the probe says where it first waits.
#[derive(Deserialize)]
struct Module {
    version: String,
    path: String,
    url: String,
    names: Vec<(String, String)>,
    promises: Promises,
    #[serde(flatten)]
    frames: Frames,
}

#[derive(Deserialize)]
struct Promises {
    pending: String,
    fulfilled: String,
    awaited: Vec<String>,
    groups: BTreeMap<String, Group>,
}

#[derive(Deserialize)]
struct Group {
    members: Vec<String>,
    of: String,
}

/// The functions whose frames it waits in, and their first argument.
#[derive(Deserialize)]
struct Frames {
    phase: String,
    inner: String,
    outer: String,
    marker: String,
}

#[derive(Deserialize)]
struct Async {
    awaited: String,
    awaiter: String,
    #[serde(flatten)]
    frames: Frames,
}

/// Learns the layout from a probe that waits where it first does.
pub(super) fn learn(probe: &mut dyn Probe) -> Result<Layout, String> {
    let module: Module = said(probe, "module")?;
    let memory = Reader::new(probe.memory());
    let inner = address(&module.frames.inner)?;
    let outer = address(&module.frames.outer)?;
    let functions = functions(&memory, inner, outer)?;
    let names = module
        .names
        .iter()
        .map(|(at, name)| Ok((address(at)?, name.as_str())))
        .collect::<Result<Vec<_>, String>>()?;
    let (name, string) = names_of(&memory, &functions, &names)?;
    let urls = urls(&memory, &functions, string, [&module.path, &module.url]);
    let stack = Stack::read(&*probe)?;
    let (slots, at) = frame(&stack, &functions, &module.frames)?;
    let module_kind = memory
        .cell_type(caller_executable(&memory, &stack, &functions, slots, at)?)
        .ok_or("reading the type of an executable")?;

    let (stack, at) = waits(probe, &functions, slots, "program")?;
    let memory = Reader::new(probe.memory());
    let executable = caller_executable(&memory, &stack, &functions, slots, at)?;
    let program_kind = memory
        .cell_type(executable)
        .ok_or("reading the type of an executable")?;
    // The name it gave code it ran from a string is that code's URL.
    let url = only("URL of a script", urls, |path| {
        string_at(&memory, executable, path, string).as_deref() == Some(PROGRAM_URL)
    })?;

    let (stack, at) = waits(probe, &functions, slots, "eval")?;
    let memory = Reader::new(probe.memory());
    let executable = caller_executable(&memory, &stack, &functions, slots, at)?;
    let eval_kind = memory
        .cell_type(executable)
        .ok_or("reading the type of an executable")?;
    let kinds = Kinds {
        function: functions.executable_type,
        program: program_kind,
        eval: eval_kind,
        module: module_kind,
    };
    let mut types = [kinds.function, kinds.program, kinds.eval, kinds.module];
    types.sort_unstable();
    if types.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(format!(
            "two kinds of code had one type of executable: {kinds:?}"
        ));
    }

    let waiting = waiting(probe, &functions, slots, &module.promises)
        .inspect_err(|reason| debug!(%reason, "not reading the async functions that wait"))
        .ok();

    Ok(Layout {
        version: module.version,
        frame_code_block: slots.code_block as i32,
        frame_arguments: slots.arguments as i32,
        frame_first_argument: slots.first_argument as i32,
        code_block_type: functions.code_block_type,
        code_block_executable: functions.code_block_executable,
        kinds,
        function_executable: functions.function_executable as i32,
        executable_code_block: functions.executable_code_block as i32,
        name,
        url,
        string,
        waiting,
    })
}

/// How async functions wait, from where the probe waits in one resumed.
fn waiting(
    probe: &mut dyn Probe,
    functions: &Functions,
    slots: Slots,
    promises: &Promises,
) -> Result<Waiting, String> {
    probe.resume().map_err(|error| error.to_string())?;
    let resumed: Async = said(&*probe, "async")?;
    let stack = Stack::read(&*probe)?;
    let (found, at) = frame(&stack, functions, &resumed.frames)?;
    if found != slots {
        return Err(format!("frames in async code had other slots: {found:x?}"));
    }
    let memory = Reader::new(probe.memory());
    awaits(&memory, &stack, functions, slots, at, promises, &resumed)
}

fn said<T: DeserializeOwned>(probe: &dyn Probe, phase: &str) -> Result<T, String> {
    let said = probe.said();
    let frames: Frames = serde_json::from_str(said).map_err(|error| error.to_string())?;
    if frames.phase != phase {
        return Err(format!(
            "it waited in {} code, not {phase} code",
            frames.phase
        ));
    }
    serde_json::from_str(said).map_err(|error| format!("what it said: {error}"))
}

fn address(hex: &str) -> Result<u64, String> {
    hex.strip_prefix("0x")
        .and_then(|digits| u64::from_str_radix(digits, 16).ok())
        .ok_or_else(|| format!("{hex} is no address"))
}

/// The one of `candidates` that `holds` holds for: `what` it is.
fn only<T: Copy + Debug>(
    what: &str,
    candidates: impl IntoIterator<Item = T>,
    holds: impl Fn(T) -> bool,
) -> Result<T, String> {
    let found: Vec<T> = candidates.into_iter().filter(|&c| holds(c)).collect();
    match found[..] {
        [one] => Ok(one),
        [] => Err(format!("found no {what}")),
        _ => Err(format!(
            "found {} places {what} could be: {found:x?}",
            found.len()
        )),
    }
}

fn offsets(below: u64, step: u64) -> impl Iterator<Item = u64> + Clone {
    (0..below).step_by(step as usize)
}

/// The probe's memory, each word read once.
struct Reader<'a> {
    memory: &'a dyn Memory,
    words: RefCell<HashMap<u64, Option<u64>>>,
}

impl<'a> Reader<'a> {
    fn new(memory: &'a dyn Memory) -> Self {
        Self {
            memory,
            words: RefCell::new(HashMap::new()),
        }
    }

    fn word(&self, address: u64) -> Option<u64> {
        *self.words.borrow_mut().entry(address).or_insert_with(|| {
            let mut bytes = [0; 8];
            self.memory.read(address, &mut bytes).ok()?;
            Some(u64::from_ne_bytes(bytes))
        })
    }

    fn u32(&self, address: u64) -> Option<u32> {
        let word = self.word(address & !7)?;
        Some((word >> ((address & 4) * 8)) as u32)
    }

    /// The word at `address` if it can point to an object.
    fn pointer(&self, address: u64) -> Option<u64> {
        self.word(address).filter(|&word| is_pointer(word))
    }

    fn cell_type(&self, cell: u64) -> Option<u8> {
        Some((self.word(cell)? >> CELL_TYPE_SHIFT) as u8)
    }

    fn bytes(&self, address: u64, len: usize) -> Option<Vec<u8>> {
        let mut bytes = vec![0; len];
        self.memory.read(address, &mut bytes).ok()?;
        Some(bytes)
    }
}

fn is_pointer(word: u64) -> bool {
    word.is_multiple_of(8) && word >= 0x1_0000 && word >> POINTER_BITS == 0
}

/// How a function leads to its executable and its `CodeBlock`, which point
/// to each other, and for each function to its own.
#[derive(Debug, Clone, Copy)]
struct Functions {
    function_executable: u64,
    executable_code_block: u64,
    code_block_executable: u64,
    code_block_type: u8,
    executable_type: u8,
    /// Of the two functions it waits in.
    inner: (u64, u64),
    outer: (u64, u64),
}

impl Functions {
    fn executable(&self, memory: &Reader, function: u64) -> Option<u64> {
        memory.pointer(function + self.function_executable)
    }
}

fn functions(memory: &Reader, inner: u64, outer: u64) -> Result<Functions, String> {
    let both = |fe: u64, ec: u64, ce: u64| -> Option<((u64, u64), (u64, u64))> {
        let of = |function: u64| -> Option<(u64, u64)> {
            let executable = memory.pointer(function + fe)?;
            let code_block = memory.pointer(executable + ec)?;
            (code_block != executable && memory.word(code_block + ce)? == executable)
                .then_some((executable, code_block))
        };
        let (a, b) = (of(inner)?, of(outer)?);
        let types = |cell| memory.cell_type(cell);
        let own = a.0 != b.0 && a.1 != b.1;
        let alike = types(a.0) == types(b.0) && types(a.1) == types(b.1);
        (own && alike && types(a.0) != types(a.1)).then_some((a, b))
    };
    let candidates = offsets(0x40, 8).flat_map(|fe| {
        offsets(FIELDS, 8).flat_map(move |ec| offsets(FIELDS, 8).map(move |ce| (fe, ec, ce)))
    });
    let (fe, ec, ce) = only(
        "executable and CodeBlock of a function that point to each other",
        candidates,
        |(fe, ec, ce)| both(fe, ec, ce).is_some(),
    )?;
    let (inner, outer) = both(fe, ec, ce).ok_or("reading the functions it waits in")?;
    let types = (memory.cell_type(inner.1), memory.cell_type(inner.0));
    let (Some(code_block_type), Some(executable_type)) = types else {
        return Err("reading the types of a CodeBlock and an executable".into());
    };
    Ok(Functions {
        function_executable: fe,
        executable_code_block: ec,
        code_block_executable: ce,
        code_block_type,
        executable_type,
        inner,
        outer,
    })
}

/// Whether `string` is a string of `text`, which keeps its length and
/// where its characters are at those offsets.
fn is_string(memory: &Reader, string: u64, length: u64, chars: u64, text: &str) -> bool {
    let units: Vec<u16> = text.encode_utf16().collect();
    let one_byte = text.chars().all(|c| (c as u32) < 0x100);
    if memory.u32(string + length) != Some(units.len() as u32) {
        return false;
    }
    let Some(at) = memory.word(string + chars) else {
        return false;
    };
    let expected: Vec<u8> = if one_byte {
        units.iter().map(|&unit| unit as u8).collect()
    } else {
        units.iter().flat_map(|unit| unit.to_ne_bytes()).collect()
    };
    memory.bytes(at, expected.len()).as_deref() == Some(&expected[..])
}

/// The way from a function's executable to its name, and how a string
/// keeps its characters, by the names of the functions the probe holds.
fn names_of(
    memory: &Reader,
    functions: &Functions,
    names: &[(u64, &str)],
) -> Result<([u64; 2], Strings), String> {
    let one_byte = |name: &str| name.chars().all(|c| (c as u32) < 0x80);
    let (narrow, wide): (Vec<_>, Vec<_>) = names.iter().partition(|(_, name)| one_byte(name));
    let executables = |of: &[&(u64, &str)]| -> Result<Vec<(u64, String)>, String> {
        of.iter()
            .map(|&&(function, name)| {
                let executable = functions
                    .executable(memory, function)
                    .ok_or_else(|| format!("{name} has no executable where uhrInner's is"))?;
                Ok((executable, name.to_owned()))
            })
            .collect()
    };
    let (narrow, wide) = (executables(&narrow)?, executables(&wide)?);
    let string_of = |executable: u64, [first, second]: [u64; 2]| {
        memory.pointer(memory.pointer(executable + first)? + second)
    };
    let holds = |path: [u64; 2], length: u64, chars: u64, of: &[(u64, String)]| {
        of.iter().all(|(executable, name)| {
            string_of(*executable, path)
                .is_some_and(|string| is_string(memory, string, length, chars, name))
        })
    };
    let candidates = offsets(FIELDS, 8)
        .flat_map(|first| offsets(FIELDS, 8).map(move |second| [first, second]))
        .flat_map(|path| {
            offsets(STRING_FIELDS, 4).flat_map(move |length| {
                offsets(STRING_FIELDS, 8).map(move |chars| (path, length, chars))
            })
        });
    let (path, length, chars) = only("name of a function", candidates, |(path, length, chars)| {
        holds(path, length, chars, &narrow) && holds(path, length, chars, &wide)
    })?;
    let flags_of = |of: &[(u64, String)], flags: u64| -> Vec<Option<u32>> {
        of.iter()
            .map(|(executable, _)| memory.u32(string_of(*executable, path)? + flags))
            .collect()
    };
    let others = |flags: u64| flags != length && !(chars..chars + 8).contains(&flags);
    let candidates = offsets(STRING_FIELDS, 4)
        .filter(|&flags| others(flags))
        .flat_map(|flags| (0..8).map(move |bit| (flags, bit)));
    let (flags, bit) = only(
        "flag of a string whose characters are a byte each",
        candidates,
        |(flags, bit)| {
            let set = |word: &Option<u32>| word.is_some_and(|word| word & 1 << bit != 0);
            flags_of(&narrow, flags).iter().all(set)
                && flags_of(&wide, flags)
                    .iter()
                    .all(|word| word.is_some() && !set(word))
        },
    )?;
    let strings = Strings {
        length,
        chars,
        flags,
        one_byte: 1 << bit,
    };
    Ok((path, strings))
}

/// The string at the end of `path` from `from`.
fn string_at(
    memory: &Reader,
    from: u64,
    [first, second]: [u64; 2],
    layout: Strings,
) -> Option<String> {
    let string = memory.pointer(memory.pointer(from + first)? + second)?;
    let length = memory.u32(string + layout.length)? as usize;
    if length as u64 > MAX_STRING {
        return None;
    }
    let chars = memory.word(string + layout.chars)?;
    let one_byte = memory.u32(string + layout.flags)? & layout.one_byte != 0;
    if one_byte {
        let bytes = memory.bytes(chars, length)?;
        return Some(text::chars(bytes.iter().map(|&b| u32::from(b))));
    }
    let bytes = memory.bytes(chars, 2 * length)?;
    Some(text::utf16(
        bytes
            .chunks_exact(2)
            .map(|unit| u16::from_ne_bytes([unit[0], unit[1]])),
    ))
}

/// The ways from an executable to the URL of its script, the probe's path
/// or its URL, which code run from a string tells apart.
fn urls(
    memory: &Reader,
    functions: &Functions,
    strings: Strings,
    texts: [&str; 2],
) -> Vec<[u64; 2]> {
    let executables = [functions.inner.0, functions.outer.0];
    offsets(FIELDS, 8)
        .flat_map(|first| offsets(FIELDS, 8).map(move |second| [first, second]))
        .filter(|&path| {
            executables.iter().all(|&executable| {
                string_at(memory, executable, path, strings)
                    .is_some_and(|url| texts.contains(&url.as_str()))
            })
        })
        .collect()
}

/// The probe's stack where it waits, by address.
struct Stack {
    words: HashMap<u64, u64>,
    /// Where each word is that holds a value.
    by_value: HashMap<u64, Vec<u64>>,
}

impl Stack {
    fn read(probe: &dyn Probe) -> Result<Self, String> {
        let range = probe
            .stack()
            .map_err(|error| format!("finding its stack: {error}"))?;
        let mut stack = Self {
            words: HashMap::new(),
            by_value: HashMap::new(),
        };
        let mut chunk = vec![0; CHUNK as usize];
        let mut at = range.start & !(CHUNK - 1);
        while at < range.end {
            if probe.memory().read(at, &mut chunk).is_ok() {
                stack.add(at, &chunk, &range);
            } else {
                // A chunk can reach past the end of the stack.
                for (i, page) in chunk.chunks_exact_mut(PAGE as usize).enumerate() {
                    let page_at = at + i as u64 * PAGE;
                    if probe.memory().read(page_at, page).is_ok() {
                        stack.add(page_at, page, &range);
                    }
                }
            }
            at += CHUNK;
        }
        Ok(stack)
    }

    fn add(&mut self, at: u64, bytes: &[u8], range: &Range<u64>) {
        for (i, word) in bytes.chunks_exact(8).enumerate() {
            let word = u64::from_ne_bytes(word.try_into().expect("eight bytes"));
            let address = at + i as u64 * 8;
            if range.contains(&address) {
                self.words.insert(address, word);
                self.by_value.entry(word).or_default().push(address);
            }
        }
    }

    fn word(&self, address: u64) -> Option<u64> {
        self.words.get(&address).copied()
    }

    fn holding(&self, value: u64) -> &[u64] {
        self.by_value.get(&value).map_or(&[], Vec::as_slice)
    }
}

/// Where a frame keeps what uhr reads, from its frame pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Slots {
    code_block: u64,
    arguments: u64,
    first_argument: u64,
}

/// The frame pointer of the outer of the two functions the probe waits in.
#[derive(Debug, Clone, Copy)]
struct At {
    outer: u64,
}

/// The slots of a frame, and the frame of the outer function, which called
/// the inner with three arguments and was called with one, the same first.
fn frame(stack: &Stack, functions: &Functions, frames: &Frames) -> Result<(Slots, At), String> {
    let (inner, outer, marker) = (
        address(&frames.inner)?,
        address(&frames.outer)?,
        address(&frames.marker)?,
    );
    // Copies of a frame's words can be elsewhere on the stack: a frame is
    // one whose frame pointer holds that of a frame of its caller.
    let pairs = |code_block: u64| -> Vec<(u64, u64)> {
        stack
            .holding(functions.inner.1)
            .iter()
            .filter_map(|&slot| {
                let fp = slot.checked_sub(code_block)?;
                let caller = stack.word(fp)?;
                (stack.word(caller + code_block) == Some(functions.outer.1)).then_some((fp, caller))
            })
            .collect()
    };
    let holds = |slots: Slots, (fp, caller): (u64, u64)| {
        let both = |offset: u64, holds: &dyn Fn(u64, u64) -> bool| {
            matches!(
                (stack.word(fp + offset), stack.word(caller + offset)),
                (Some(a), Some(b)) if holds(a, b)
            )
        };
        let callee = offsets(SLOTS, 8).any(|offset| both(offset, &|a, b| a == inner && b == outer));
        callee
            && both(slots.arguments, &|a, b| a as u32 == 4 && b as u32 == 2)
            && both(slots.first_argument, &|a, b| a == marker && b == marker)
    };
    let candidates = offsets(0x40, 8).flat_map(|code_block| {
        offsets(SLOTS, 8).flat_map(move |arguments| {
            offsets(SLOTS, 8).map(move |first_argument| Slots {
                code_block,
                arguments,
                first_argument,
            })
        })
    });
    let slots = only("frame of a function on the stack", candidates, |slots| {
        pairs(slots.code_block)
            .into_iter()
            .any(|pair| holds(slots, pair))
    })?;
    let (_, outer) = only(
        "frame of the function the probe waits in",
        pairs(slots.code_block),
        |pair| holds(slots, pair),
    )?;
    Ok((slots, At { outer }))
}

/// The frame of the outer function's caller, and its `CodeBlock`.
fn caller(
    memory: &Reader,
    stack: &Stack,
    functions: &Functions,
    slots: Slots,
    at: At,
) -> Option<(u64, u64)> {
    let caller = stack.word(at.outer)?;
    let code_block = stack.word(caller + slots.code_block)?;
    (memory.cell_type(code_block)? == functions.code_block_type).then_some((caller, code_block))
}

/// The executable of the code that called the outer function.
fn caller_executable(
    memory: &Reader,
    stack: &Stack,
    functions: &Functions,
    slots: Slots,
    at: At,
) -> Result<u64, String> {
    let (_, code_block) = caller(memory, stack, functions, slots, at)
        .ok_or("the code that called the function it waits in has no CodeBlock")?;
    memory
        .pointer(code_block + functions.code_block_executable)
        .ok_or_else(|| "reading the executable of the code that called it".to_owned())
}

/// The frame it waits in once in each phase after the first, with the
/// slots learned in the first.
fn waits(
    probe: &mut dyn Probe,
    functions: &Functions,
    slots: Slots,
    phase: &str,
) -> Result<(Stack, At), String> {
    probe.resume().map_err(|error| error.to_string())?;
    let frames: Frames = said(&*probe, phase)?;
    let stack = Stack::read(&*probe)?;
    let (found, at) = frame(&stack, functions, &frames)?;
    if found != slots {
        return Err(format!(
            "frames in {phase} code had other slots: {found:x?}"
        ));
    }
    Ok((stack, at))
}

/// From the frame of the async function the probe waits in, resumed with
/// its state as the first argument, whose result another awaits.
fn awaits(
    memory: &Reader,
    stack: &Stack,
    functions: &Functions,
    slots: Slots,
    at: At,
    promises: &Promises,
    resumed: &Async,
) -> Result<Waiting, String> {
    let (frame, code_block) = caller(memory, stack, functions, slots, at)
        .ok_or("the async function that called the one it waits in has no CodeBlock")?;
    let arguments = stack
        .word(frame + slots.arguments)
        .ok_or("reading its frame")? as u32;
    let state = stack
        .word(frame + slots.first_argument)
        .filter(|_| arguments >= 2)
        .filter(|&state| is_pointer(state))
        .ok_or("the async function it resumed has no state as its first argument")?;
    let state_type = memory.cell_type(state).ok_or("reading its state")?;
    let (awaited, awaiter) = (address(&resumed.awaited)?, address(&resumed.awaiter)?);
    let state_promise = only(
        "promise of an async function's result",
        offsets(FIELDS, 8),
        |offset| memory.word(state + offset) == Some(awaited),
    )?;
    let state_next = only(
        "function an async function's state resumes",
        offsets(FIELDS, 8),
        |offset| {
            memory
                .pointer(state + offset)
                .and_then(|function| functions.executable(memory, function))
                .and_then(|executable| memory.word(executable + functions.executable_code_block))
                == Some(code_block)
        },
    )?;
    let promise_type = memory.cell_type(awaited).ok_or("reading a promise")?;
    let waiter = |offset: u64| {
        memory.pointer(awaited + offset).is_some_and(|state| {
            memory.cell_type(state) == Some(state_type)
                && memory.word(state + state_promise) == Some(awaiter)
        })
    };
    let promise_waiter = only(
        "state of the function that waits for a promise",
        offsets(FIELDS, 8),
        waiter,
    )?;

    let pending = address(&promises.pending)?;
    let fulfilled = address(&promises.fulfilled)?;
    let mut awaited_by: Vec<u64> = promises
        .awaited
        .iter()
        .map(|promise| address(promise))
        .collect::<Result<_, _>>()?;
    awaited_by.push(awaited);
    let groups: Vec<&Group> = promises.groups.values().collect();
    for promise in awaited_by.iter().chain([&pending, &fulfilled]) {
        if memory.cell_type(*promise) != Some(promise_type) {
            return Err(format!("{promise:#x} is not a promise"));
        }
    }
    let top = |promise: u64, offset: u64| {
        memory
            .word(promise + offset)
            .map(|word| word >> POINTER_BITS)
    };
    let promise_flags = only("flags of a promise", offsets(0x40, 8), |offset| {
        offset != promise_waiter
            && top(pending, offset).is_some()
            && top(pending, offset) != top(fulfilled, offset)
            && awaited_by
                .iter()
                .all(|&promise| top(promise, offset).is_some_and(|flags| flags != 0))
    })?;
    let flags = |promise: u64| top(promise, promise_flags).unwrap_or(0);
    // Bits that differ between promises waited for alike are not of how.
    let varies = |of: &[u64]| {
        of.iter()
            .fold(0, |bits, &promise| bits | (flags(promise) ^ flags(of[0])))
    };
    let members = groups
        .iter()
        .map(|group| {
            group
                .members
                .iter()
                .map(|member| address(member))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mask = !(members
        .iter()
        .fold(varies(&awaited_by), |bits, of| bits | varies(of)))
        & 0xffff;
    let awaited_flags = flags(awaited) & mask;
    let group_flags: Vec<u64> = members.iter().map(|of| flags(of[0]) & mask).collect();
    let mut all = vec![
        awaited_flags,
        flags(pending) & mask,
        flags(fulfilled) & mask,
    ];
    all.extend(&group_flags);
    let distinct = all
        .iter()
        .enumerate()
        .all(|(i, a)| all[i + 1..].iter().all(|b| a != b));
    if !distinct {
        return Err(format!(
            "the flags of promises in other states were alike: {all:x?}"
        ));
    }
    let context = |member: u64| {
        memory
            .word(member + promise_flags)
            .map(|word| word & ((1 << POINTER_BITS) - 1))
            .filter(|&context| is_pointer(context))
    };
    let group_promise = only("promise of a Promise.all", offsets(FIELDS, 8), |offset| {
        groups.iter().zip(&members).all(|(group, members)| {
            members.iter().all(|&member| {
                context(member).and_then(|context| memory.word(context + offset))
                    == address(&group.of).ok()
            })
        })
    })?;
    Ok(Waiting {
        state_type,
        state_next: state_next as i32,
        state_promise: state_promise as i32,
        promise_type,
        promise_flags: promise_flags as i32,
        promise_waiter: promise_waiter as i32,
        flags_mask: mask << POINTER_BITS,
        awaited_flags: awaited_flags << POINTER_BITS,
        group_flags: group_flags
            .into_iter()
            .map(|flags| flags << POINTER_BITS)
            .collect(),
        group_promise: group_promise as i32,
    })
}
