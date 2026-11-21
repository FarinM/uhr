//! The runtime a process runs, found in the images dyld lists, and its
//! interpreter's frames, which uhr walks while it holds a thread still, as
//! uhr's eBPF programs do on Linux.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

use tracing::debug;
use uhr_core::recording::{Frame, Mapping};
use uhr_core::runtimes::stacks::{self, Interpreters, Program, code_addresses};
use uhr_core::runtimes::walker::{Status, Walked, Walker};
use uhr_core::runtimes::{self, Code, Frames, Interpreter, Memory, Process};

use crate::mach::Task;

/// A process as runtimes read it.
struct Live<'a> {
    pid: u32,
    task: &'a Task,
    mappings: &'a [Mapping],
}

impl Process for Live<'_> {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn mappings(&self) -> &[Mapping] {
        self.mappings
    }

    /// From its path, as macOS lets no process open the file another
    /// mapped. One that holds another build since is told apart by its
    /// UUID.
    fn file(&self, mapping: &Mapping) -> io::Result<Vec<u8>> {
        fs::read(&mapping.path)
    }

    /// The DWARF of the dSYM beside the file with that UUID, as Apple's
    /// tools leave it, `<file>.dSYM/Contents/Resources/DWARF/<name>`.
    fn debug_file(&self, build_id: &[u8]) -> Option<Vec<u8>> {
        let id: String = build_id.iter().map(|b| format!("{b:02x}")).collect();
        let mapping = self
            .mappings
            .iter()
            .find(|m| m.build_id.as_deref() == Some(&id))?;
        let path = Path::new(&mapping.path);
        let mut bundle = path.as_os_str().to_owned();
        bundle.push(".dSYM");
        let dwarf = Path::new(&bundle)
            .join("Contents/Resources/DWARF")
            .join(path.file_name()?);
        fs::read(dwarf).ok()
    }

    fn memory(&self) -> &dyn Memory {
        self.task
    }
}

/// The runtime of one program a process runs.
pub(crate) struct Runtime {
    program: Program,
    state: State,
    /// The code its frames ran, by address. `None` for code that could not
    /// be read.
    code: HashMap<u64, Option<Code>>,
}

enum State {
    /// Not found yet: looked for again when dyld lists more images, as a
    /// runtime's library can be loaded after the program starts. Counts the
    /// samples taken meanwhile.
    Looking { samples: u64 },
    Walking {
        interpreter: Box<dyn Interpreter>,
        walker: Walker,
        /// Where the process mapped code when uhr found the interpreter,
        /// which it maps while it runs the program.
        mapped: u64,
    },
    /// A runtime uhr cannot read the frames of.
    Unsupported,
}

/// The frames a walk found at one sample, and how the native stack went.
pub(crate) struct Sample<'a> {
    pub walked: Option<&'a Walked>,
    /// Where each native frame ends on the stack, where known.
    pub ends: &'a [Option<u64>],
    /// Whether the native stack lost its outer end.
    pub cut_short: bool,
}

impl Runtime {
    pub(crate) fn new(program: Program) -> Self {
        Self {
            program,
            state: State::Looking { samples: 0 },
            code: HashMap::new(),
        }
    }

    /// Looks for the runtime among the files whose code the process maps,
    /// unless it was found. Says why one is not read in `unsupported`.
    pub(crate) fn look(
        &mut self,
        task: &Task,
        mappings: &[Mapping],
        interpreters: &mut Interpreters,
        unsupported: &mut Vec<String>,
    ) {
        let (&State::Looking { samples }, Some(first)) = (&self.state, mappings.first()) else {
            return;
        };
        let (pid, _) = self.program;
        let process = Live {
            pid,
            task,
            mappings,
        };
        match runtimes::interpreter(&process) {
            Ok(Some(interpreter)) => {
                debug!(
                    pid,
                    runtime = interpreter.runtime(),
                    version = interpreter.version(),
                    "reading the frames of its runtime"
                );
                interpreters.add_before_found(self.program, &*interpreter, samples);
                self.state = State::Walking {
                    interpreter,
                    walker: Walker::default(),
                    mapped: first.start,
                };
            }
            Ok(None) => {}
            Err(error @ runtimes::Error::Read { .. }) => {
                debug!(pid, %error, "looking for its runtime again when it loads more");
            }
            Err(reason) => {
                debug!(pid, %reason, "not reading the frames of its runtime");
                unsupported.push(reason.to_string());
                self.state = State::Unsupported;
            }
        }
    }

    /// Walks the interpreter's frames of the thread with the id `thread`,
    /// which uhr holds still, whose native frames end as `ends` says. None
    /// once the program's memory is gone, as after the process exec'd but
    /// before the next program said hello: those samples are of no
    /// interpreter.
    pub(crate) fn walk(
        &mut self,
        memory: &dyn Memory,
        thread: u64,
        ends: &[Option<u64>],
    ) -> Option<Walked> {
        let State::Walking {
            interpreter,
            walker,
            mapped,
        } = &mut self.state
        else {
            return None;
        };
        let walk = interpreter.walk();
        let walked = match walk.frames {
            Frames::Memory { .. } => walker.memory(walk, memory, thread, None),
            Frames::Native => Walker::native(walk, memory, ends),
        };
        let gone = || memory.read(*mapped, &mut [0; 8]).is_err();
        (walked.status != Status::Failed || !gone()).then_some(walked)
    }

    /// Reads the code the frames of `walked` ran that uhr has not read,
    /// once the thread runs again, as code can be long.
    pub(crate) fn read_code(&mut self, memory: &dyn Memory, walked: &Walked) {
        let State::Walking { interpreter, .. } = &self.state else {
            return;
        };
        let codes = code_addresses(
            &**interpreter,
            &walked.records,
            walked.record_bytes,
            walked.awaited,
        );
        for code in codes {
            if self.code.contains_key(&code) {
                continue;
            }
            let read = interpreter.code(memory, code);
            if let Err(error) = &read {
                debug!(pid = self.program.0, code, %error, "reading interpreted code");
            }
            self.code.insert(code, read.ok());
        }
    }

    /// Puts the frames a sample's walk found into its native `stack`, leaf
    /// first. `frames` and `ids` are the recording's frames.
    pub(crate) fn place(
        &mut self,
        interpreters: &mut Interpreters,
        frames: &mut Vec<Frame>,
        ids: &mut HashMap<Frame, u32>,
        stack: &mut Vec<u32>,
        sample: Sample,
    ) {
        let interpreter = match &mut self.state {
            State::Looking { samples } => {
                *samples += 1;
                return;
            }
            State::Walking { interpreter, .. } => &**interpreter,
            State::Unsupported => return,
        };
        let Some(walked) = sample.walked else {
            return;
        };
        let code = |address| self.code.get(&address).and_then(Option::as_ref);
        let walk = stacks::Walk {
            program: self.program,
            walked: Some(interpreter),
            of: interpreter,
            status: Some(walked.status),
            records: &walked.records,
            record_bytes: walked.record_bytes,
            awaited: walked.awaited,
            code: &code,
            cut_short: sample.cut_short,
            // The ends come from unwind tables, which find frames a walk of
            // frame pointers loses.
            frame_pointers: false,
        };
        interpreters.add(frames, ids, stack, sample.ends, &walk);
    }
}
