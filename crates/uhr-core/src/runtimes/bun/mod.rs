//! Bun, and the JavaScriptCore it runs on, whose frames are on the native
//! stack: the frame of each JavaScript function holds its `CodeBlock`, whose
//! executable names it.
//!
//! Bun's releases keep no symbols and JavaScriptCore publishes no offsets,
//! so uhr learns where each build keeps what it reads by running that
//! build with a script of its own, once for each build it records.

mod layout;

use std::any::Any;
use std::collections::HashMap;
use std::fs;
use std::ops::Range;
use std::panic;
use std::path::Path;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::thread;

use tracing::debug;

use self::layout::{CELL_TYPE_SHIFT, Layout, MAX_STRING, POINTER_BITS, Waiting};
use super::probe::{ProbeCommand, Prober};
use super::process::{
    bytes_at, debug_symbols, identity_of, mapped_build_id, section, u32_at, u64_at,
};
use super::text;
use super::{
    Awaits, Code, Copy, Error, Frames, Interpreter, Memory, PathStep, Process, Read, Runtime, Walk,
    WalkedFrame,
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
        find(process)
    }

    /// Learns before uhr starts the program, which then runs as uhr's user.
    fn prepare(&self, program: &Path, prober: &dyn Prober) {
        let program = program.to_string_lossy().into_owned();
        match learn(prober, program.clone(), None) {
            Ok((build_id, learned)) => {
                builds().insert((build_id, None), Known::Learned(Ok(learned)));
            }
            Err(reason) => debug!(%program, %reason, "learning where Bun keeps its frames"),
        }
    }
}

/// What a frame's copy holds: its `CodeBlock` and the word after, and then
/// the first word of the `CodeBlock`, whose type says it is one.
const FRAME_COPY: u32 = 16;

const PROBE: &str = include_str!("probe.mjs");

/// What uhr knows of each build it found, by build id and the user its
/// probe ran as, where not uhr's: that user can change what their probe
/// says, so what uhr learned from it is only for their processes.
static BUILDS: LazyLock<Mutex<HashMap<Build, Known>>> = LazyLock::new(Mutex::default);

type Build = (Vec<u8>, Option<(u32, u32)>);

enum Known {
    /// A probe of it runs.
    Learning,
    /// What uhr learned, or why it could not.
    Learned(Result<Learned, String>),
}

fn builds() -> MutexGuard<'static, HashMap<Build, Known>> {
    BUILDS.lock().expect("not poisoned")
}

/// What uhr learned of one build: its layout, and where its interpreter's
/// code is, from the start of the mapping of its file.
#[derive(Debug, Clone)]
struct Learned {
    layout: Arc<Layout>,
    interpreter: Option<Range<u64>>,
}

struct JavaScriptCore {
    layout: Arc<Layout>,
    walk: Walk,
    eval_loop: Vec<Range<u64>>,
}

/// The interpreter of the build `process` runs, once uhr learned where it
/// keeps what uhr reads. Learning takes a while, so it does that on a
/// thread of its own, while the process runs, and says to look again.
fn find(process: &dyn Process) -> Result<Option<Box<dyn Interpreter>>, Error> {
    let Some(mapping) = binary(process.mappings()) else {
        return Ok(None);
    };
    let probe_error = |reason| Error::Probe {
        runtime: "bun",
        program: mapping.path.clone(),
        reason,
    };
    let build_id = build_id_of(process, mapping);
    if build_id.is_empty() {
        return Err(probe_error(NO_BUILD_ID.into()));
    }
    let user = process.probe_user();
    let learned = {
        let mut known = builds();
        // What a probe of uhr's own said holds for every user's processes.
        let own = (build_id.clone(), None);
        let theirs = (build_id.clone(), user);
        match known.get(&own).or_else(|| known.get(&theirs)) {
            Some(Known::Learned(learned)) => learned.clone(),
            Some(Known::Learning) => return Err(Error::Learning { runtime: "bun" }),
            None => {
                let prober = process
                    .prober()
                    .ok_or_else(|| probe_error("uhr runs no probe on this platform".into()))?;
                let program = process.executable().unwrap_or_else(|| mapping.path.clone());
                known.insert(theirs.clone(), Known::Learning);
                thread::spawn(move || {
                    // Nothing it used is used after a panic but to say so.
                    let learning = panic::AssertUnwindSafe(|| learn(prober, program, user));
                    let learned = panic::catch_unwind(learning)
                        .unwrap_or_else(|panic| {
                            Err(format!("learning failed: {}", message(&*panic)))
                        })
                        .and_then(|(ran, learned)| {
                            (ran == build_id).then_some(learned).ok_or_else(|| {
                                "its file holds another build than the one that runs".to_owned()
                            })
                        });
                    builds().insert(theirs, Known::Learned(learned));
                });
                return Err(Error::Learning { runtime: "bun" });
            }
        }
    };
    let Learned {
        layout,
        interpreter,
    } = learned.map_err(probe_error)?;
    let eval_loop = interpreter
        .iter()
        .map(|range| range.start + mapping.start..range.end + mapping.start)
        .collect();
    let walk = Walk {
        frames: Frames::Native,
        copy: Copy {
            from: layout.frame_code_block,
            bytes: FRAME_COPY,
            // The first word of what the frame holds as its `CodeBlock`,
            // whose type says if it is one.
            reads: vec![Read { word: 0, offset: 0 }],
        },
        frame_pointers: true,
        awaits: layout
            .waiting
            .as_ref()
            .map(|waiting| awaits(&layout, waiting)),
    };
    Ok(Some(Box::new(JavaScriptCore {
        layout,
        walk,
        eval_loop,
    })))
}

const NO_BUILD_ID: &str = "its binary has no build id, by which uhr tells builds apart";

/// What a thread that panicked said.
fn message(panic: &(dyn Any + Send)) -> &str {
    panic
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("it panicked")
}

/// The mapping of the start of Bun's binary.
fn binary(mappings: &[Mapping]) -> Option<&Mapping> {
    let file_name = |m: &Mapping| m.path.rsplit('/').next().unwrap_or(&m.path).to_owned();
    mappings
        .iter()
        .find(|m| Bun.is_binary(&file_name(m)) && m.file_offset == 0)
}

/// A binary's build id: on macOS the Mach-O UUID. Empty for one with none.
fn build_id_of(process: &dyn Process, mapping: &Mapping) -> Vec<u8> {
    mapped_build_id(process.memory(), mapping)
        .or_else(|| {
            let uuid = mapping.build_id.as_deref().and_then(crate::macho::uuid)?;
            Some(uuid.to_vec())
        })
        .unwrap_or_default()
}

/// Runs `program` with the probe, as `user`, and learns from it what the
/// build it ran keeps where: that build's id, and what uhr learned.
fn learn(
    prober: &dyn Prober,
    program: String,
    user: Option<(u32, u32)>,
) -> Result<(Vec<u8>, Learned), String> {
    let failed = |what: &str, error: std::io::Error| format!("{what}: {error}");
    let mut builder = tempfile::Builder::new();
    builder.prefix("uhr-bun-probe-");
    // Where any user can reach, as uhr's own temporary directory may not
    // be, for one it runs as.
    let dir = match user {
        Some(_) => builder.tempdir_in("/tmp"),
        None => builder.tempdir(),
    }
    .map_err(|error| failed("making a directory for it", error))?;
    // Its own home in it, so that no configuration of the user's changes
    // what it runs. The rest is uhr's, which the user it runs as can read
    // but not change.
    let home = dir.path().join("home");
    fs::create_dir(&home).map_err(|error| failed("making its home", error))?;
    #[cfg(unix)]
    if let Some((uid, gid)) = user {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755))
            .and_then(|()| std::os::unix::fs::chown(&home, Some(uid), Some(gid)))
            .map_err(|error| failed("giving it its home", error))?;
    }
    let script = dir.path().join("probe.mjs");
    fs::write(&script, PROBE).map_err(|error| failed("writing its script", error))?;
    let command = ProbeCommand {
        program,
        args: vec![script.into_os_string()],
        dir: home.clone(),
        files: dir.path().to_owned(),
        environment: vec![
            ("HOME".into(), home.clone().into_os_string()),
            ("TMPDIR".into(), home.into_os_string()),
        ],
        user,
    };
    debug!(program = command.program, ?user, "running a probe of Bun");
    let mut probe = prober
        .probe(&command)
        .map_err(|error| format!("running it: {error}"))?;
    let ran = binary(probe.mappings())
        .ok_or("it maps no file of Bun's")?
        .clone();
    let build_id = build_id_of(&*probe, &ran);
    if build_id.is_empty() {
        return Err(NO_BUILD_ID.into());
    }
    let layout = layout::learn(&mut *probe)?;
    let interpreter = interpreter(&*probe, &ran, &build_id);
    debug!(
        version = layout.version,
        ?layout,
        ?interpreter,
        "learned where Bun keeps its frames"
    );
    Ok((
        build_id,
        Learned {
            layout: Arc::new(layout),
            interpreter,
        },
    ))
}

/// Where the interpreter's code is in the probe, from the start of `ran`,
/// its mapping of Bun's binary: on macOS, the section JavaScriptCore puts it
/// in; elsewhere as the build with symbols says, where the system keeps it
/// as debug info; or else from the code of its first opcode to that of its
/// last, by the table of them JavaScriptCore fills as it starts.
fn interpreter(probe: &dyn Process, ran: &Mapping, build_id: &[u8]) -> Option<Range<u64>> {
    let relative = |code: Range<u64>| code.start - ran.start..code.end - ran.start;
    let section = |name: &str| {
        section(probe, ran, name)
            .inspect_err(|error| debug!(%error, name, "reading a section of Bun's binary"))
            .ok()
            .flatten()
    };
    if let Some(code) = section("__jsc_int") {
        return Some(relative(code));
    }
    let symbols = debug_symbols(probe, ran, build_id, |name| {
        matches!(name, "llintPCRangeStart" | "llintPCRangeEnd")
    });
    if let (Some(start), Some(end)) = (
        symbols.get("llintPCRangeStart"),
        symbols.get("llintPCRangeEnd"),
    ) {
        return Some(relative(start.start..end.start));
    }
    let table = section("__DATA,__jsc_opcodes")?;
    let len = (table.end - table.start) as usize;
    let words = bytes_at(probe.memory(), "the table of opcodes", table.start, len)
        .inspect_err(|error| debug!(%error, "reading the table of Bun's opcodes"))
        .ok()?;
    let starts: Vec<u64> = words
        .chunks_exact(8)
        .map(|word| u64::from_ne_bytes(word.try_into().expect("eight bytes")))
        .filter(|&start| start != 0)
        .collect();
    let code: Vec<Range<u64>> = probe
        .mappings()
        .iter()
        .filter(|mapping| mapping.path == ran.path)
        .map(|mapping| mapping.start..mapping.end)
        .collect();
    let found = opcodes(&starts, &code);
    if found.is_none() {
        debug!("Bun's opcodes are not all in one mapping of its code");
    }
    found.map(relative)
}

/// From the code of the first opcode, by where each starts, to the end of
/// that of the last, which ends no later than the longest of the others, in
/// the one of `code` that holds them all. `None` where none does.
fn opcodes(starts: &[u64], code: &[Range<u64>]) -> Option<Range<u64>> {
    let mut starts = starts.to_vec();
    starts.sort_unstable();
    starts.dedup();
    let (&first, &last) = (starts.first()?, starts.last()?);
    let mapping = code.iter().find(|mapping| mapping.contains(&first))?;
    if !mapping.contains(&last) {
        return None;
    }
    let longest = starts
        .windows(2)
        .map(|pair| pair[1] - pair[0])
        .max()
        .unwrap_or(0);
    Some(first..(last + longest).min(mapping.end))
}

/// How the sampler finds the async functions that wait for one a thread
/// runs, as JavaScriptCore's own async stack traces do: the state of each
/// holds the promise of its result, and a pending promise the state of the
/// function that waits for it, or for the promise of the `Promise.all` it
/// is one of.
fn awaits(layout: &Layout, waiting: &Waiting) -> Awaits {
    let cell = |kind: u8| {
        PathStep::check(
            0,
            0xff << CELL_TYPE_SHIFT,
            u64::from(kind) << CELL_TYPE_SHIFT,
        )
    };
    let flags = |value: u64| PathStep::check(waiting.promise_flags, waiting.flags_mask, value);
    let awaited = flags(waiting.awaited_flags);
    let state = cell(waiting.state_type);
    let promise = [
        PathStep::to(waiting.state_promise),
        cell(waiting.promise_type),
    ];
    // A group's promise holds no state there, so this ends for one.
    let mut next = vec![
        [
            &promise[..],
            &[awaited, PathStep::to(waiting.promise_waiter), state],
        ]
        .concat(),
    ];
    for &group_flags in &waiting.group_flags {
        let group = PathStep {
            follow: Some((1 << POINTER_BITS) - 1),
            ..flags(group_flags)
        };
        let of_all = [
            group,
            PathStep::to(waiting.group_promise),
            cell(waiting.promise_type),
            awaited,
            PathStep::to(waiting.promise_waiter),
        ];
        next.push([&promise[..], &of_all].concat());
    }
    Awaits {
        // Its `CodeBlock` is one, as the frame's read says.
        frame: vec![(
            FRAME_COPY,
            0xff << CELL_TYPE_SHIFT,
            u64::from(layout.code_block_type) << CELL_TYPE_SHIFT,
        )],
        copy_code: 0,
        // The state follows `this`, in a frame with both. A frame with
        // fewer arguments holds there what an earlier one left.
        start: vec![
            PathStep {
                at_least: true,
                ..PathStep::check(layout.frame_arguments, u64::from(u32::MAX), 2)
            },
            PathStep::to(layout.frame_first_argument),
        ],
        state: vec![state],
        code: vec![
            PathStep::to(waiting.state_next),
            PathStep {
                check: Some((1, 0)),
                ..PathStep::to(layout.function_executable)
            },
            PathStep::to(layout.executable_code_block),
        ],
        next,
    }
}

impl JavaScriptCore {
    fn string(&self, memory: &dyn Memory, string: u64) -> Result<String, Error> {
        let layout = &self.layout.string;
        let what = "a JavaScriptCore string";
        let length = u64::from(u32_at(memory, what, string + layout.length)?);
        if length > MAX_STRING {
            return Err(Error::Invalid(format!("a string of {length} characters")));
        }
        let chars = u64_at(memory, what, string + layout.chars)?;
        let flags = u32_at(memory, what, string + layout.flags)?;
        if flags & layout.one_byte != 0 {
            let bytes = bytes_at(memory, what, chars, length as usize)?;
            return Ok(text::chars(bytes.iter().map(|&b| u32::from(b))));
        }
        let bytes = bytes_at(memory, what, chars, 2 * length as usize)?;
        let units = bytes
            .chunks_exact(2)
            .map(|unit| u16::from_ne_bytes([unit[0], unit[1]]));
        Ok(text::utf16(units))
    }

    /// The string at the end of `path` from `from`, empty where it has none.
    fn string_at(
        &self,
        memory: &dyn Memory,
        from: u64,
        [first, second]: [u64; 2],
    ) -> Result<String, Error> {
        let holder = u64_at(memory, "a JavaScriptCore object", from + first)?;
        match u64_at(memory, "a JavaScriptCore object", holder + second)? {
            0 => Ok(String::new()),
            string => self.string(memory, string),
        }
    }
}

impl Interpreter for JavaScriptCore {
    fn runtime(&self) -> &'static str {
        "bun"
    }

    fn version(&self) -> &str {
        &self.layout.version
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
        if code_block == 0 || (header >> CELL_TYPE_SHIFT) as u8 != self.layout.code_block_type {
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
        let header = u64_at(memory, "a CodeBlock", code_block)?;
        if (header >> CELL_TYPE_SHIFT) as u8 != layout.code_block_type {
            return Err(Error::Invalid(format!("no CodeBlock at {code_block:#x}")));
        }
        let executable = u64_at(
            memory,
            "a CodeBlock",
            code_block + layout.code_block_executable,
        )?;
        let kind = (u64_at(memory, "an executable", executable)? >> CELL_TYPE_SHIFT) as u8;
        let kinds = &layout.kinds;
        let name = match kind {
            _ if kind == kinds.function => self.string_at(memory, executable, layout.name)?,
            _ if kind == kinds.program => "<global>".to_owned(),
            _ if kind == kinds.eval => "<eval>".to_owned(),
            _ if kind == kinds.module => "<module>".to_owned(),
            _ => return Err(Error::Invalid(format!("no executable at {executable:#x}"))),
        };
        let file = self.string_at(memory, executable, layout.url)?;
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

    /// The `CodeBlock`'s type and executable, and of that its type and
    /// what holds its name and its script's URL: JavaScriptCore gives its
    /// code no number of its own, and counts in a `CodeBlock` as it runs.
    /// Code whose executable and what that points to are all where those
    /// of the code before were is taken for it.
    fn identity(&self, memory: &dyn Memory, code_block: u64) -> Result<Option<u64>, Error> {
        let layout = &self.layout;
        let words = |what, from: u64, at: &[u64]| -> Result<Vec<u64>, Error> {
            let len = at.iter().max().map_or(0, |last| last + 8) as usize;
            let bytes = bytes_at(memory, what, from, len)?;
            let word = |at: &u64| {
                let at = *at as usize;
                u64::from_ne_bytes(bytes[at..at + 8].try_into().expect("eight bytes"))
            };
            Ok(at.iter().map(word).collect())
        };
        let block = words(
            "a CodeBlock",
            code_block,
            &[0, layout.code_block_executable],
        )?;
        let executable = words(
            "an executable",
            block[1],
            &[0, layout.name[0], layout.url[0]],
        )?;
        Ok(Some(identity_of((block, executable))))
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    #[test]
    fn the_interpreter_is_the_code_of_its_opcodes() {
        let code = [0x1000..0x2000, 0x4000..0x9000];
        let starts = [0x4300, 0x4100, 0x4100, 0x4200];
        // The last ends no later than the longest of the others.
        assert_eq!(opcodes(&starts, &code), Some(0x4100..0x4400));
        // Nor than the mapping.
        assert_eq!(opcodes(&[0x4000, 0x8f00], &code), Some(0x4000..0x9000));
        assert_eq!(opcodes(&[], &code), None);
    }

    #[test]
    fn opcodes_in_more_than_one_mapping_say_no_interpreter() {
        let code = [0x1000..0x2000, 0x4000..0x9000];
        assert_eq!(opcodes(&[0x1100, 0x4100], &code), None);
        assert_eq!(opcodes(&[0x4100, 0xa000], &code), None);
    }

    struct Unreadable;

    impl Memory for Unreadable {
        fn read(&self, _address: u64, _into: &mut [u8]) -> io::Result<()> {
            Err(io::ErrorKind::NotFound.into())
        }
    }

    /// A process of a `bun` without a build id.
    struct Anonymous(Vec<Mapping>);

    impl Process for Anonymous {
        fn pid(&self) -> u32 {
            1
        }

        fn mappings(&self) -> &[Mapping] {
            &self.0
        }

        fn file(&self, _mapping: &Mapping) -> io::Result<Vec<u8>> {
            Err(io::ErrorKind::NotFound.into())
        }

        fn memory(&self) -> &dyn Memory {
            &Unreadable
        }
    }

    #[test]
    fn reads_no_build_without_a_build_id() {
        let process = Anonymous(vec![Mapping {
            pid: Some(1),
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            path: "/opt/bun".into(),
            build_id: None,
            time_ns: None,
        }]);
        let error = find(&process).err().expect("refused");
        assert!(error.to_string().contains("no build id"), "{error}");
    }
}
