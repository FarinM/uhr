//! Puts the frames of a runtime's program, as a walk of its interpreter
//! found them at a sample, into the sample's native stack, on every
//! platform: in place of the native frames that ran them, or just above the
//! calls into the interpreter. Keeps the code those frames ran, and how the
//! walks went.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::Hash;

use super::walker::Status;
use super::{Code, Frames, Interpreter, WalkedFrame};
use crate::recording::{Frame, Interpreted, InterpretedCode, InterpreterCoverage, Origin};

/// A program a process ran: its pid, and how many times it had exec'd.
pub type Program = (u32, u32);

/// A walk of an interpreter's frames at one sample.
pub struct Walk<'a> {
    pub program: Program,
    /// The interpreter that walked the frames, found in the program by
    /// then. `None` for a sample from before uhr found it.
    pub walked: Option<&'a dyn Interpreter>,
    /// The interpreter the program ran, by whose runtime and version the
    /// walk counts: the one that walked, or the one found later.
    pub of: &'a dyn Interpreter,
    /// How the walk went. `None` where there was none, as before uhr found
    /// the interpreter.
    pub status: Option<Status>,
    /// Each frame's record, of `record_bytes`: its address, its copy, then
    /// its reads. The last `awaited` are of functions that waited for the
    /// outermost of the program's frames, on no stack.
    pub records: &'a [u8],
    pub record_bytes: usize,
    pub awaited: usize,
    /// The code at an address, read from the process's memory. `None` where
    /// it could not be read.
    pub code: &'a dyn Fn(u64) -> Option<&'a Code>,
    /// Whether the native stack lost its outer end.
    pub cut_short: bool,
    /// Whether the native stack's ends come from walking frame pointers.
    pub frame_pointers: bool,
}

/// The interpreted code frames ran, and how the walks of each runtime and
/// version went.
#[derive(Debug, Default)]
pub struct Interpreters {
    /// The recording's `interpreted_code`.
    pub code: Vec<InterpretedCode>,
    /// Rows of `code`, by program and address.
    rows: HashMap<(Program, u64), u32>,
    walks: BTreeMap<(&'static str, String), Walks>,
}

/// How the frames of one runtime and version were read.
#[derive(Debug, Default)]
struct Walks {
    processes: BTreeSet<u32>,
    samples: u64,
    before_found: u64,
    no_thread: u64,
    unsearched: u64,
    failed: u64,
    cut: u64,
    frames: u64,
    unread_frames: u64,
    unmatched: u64,
}

impl Interpreters {
    /// Puts the frames `walk` found into `stack`, leaf first, whose native
    /// frames end on the stack as `ends` says, where known. `frames` and
    /// `ids` are the recording's frames, which this adds to.
    pub fn add(
        &mut self,
        frames: &mut Vec<Frame>,
        ids: &mut HashMap<Frame, u32>,
        stack: &mut Vec<u32>,
        ends: &[Option<u64>],
        walk: &Walk,
    ) {
        let program = walk.program;
        let mut counts = Walks {
            samples: 1,
            ..Walks::default()
        };
        match walk.status {
            None => counts.before_found = 1,
            Some(Status::NoThread) => counts.no_thread = 1,
            Some(Status::Unsearched) => counts.unsearched = 1,
            Some(Status::Failed) => counts.failed = 1,
            Some(Status::Cut) => counts.cut = 1,
            Some(Status::Done) => {}
        }
        let walked = walk.records.len() / walk.record_bytes.max(1);
        if let (Some(interpreter), true) = (walk.walked, walked > 0) {
            // The last are of functions that waited, on no stack.
            let on_stack = walked.saturating_sub(walk.awaited);
            let records = walk
                .records
                .chunks_exact(walk.record_bytes)
                .enumerate()
                .map(|(at, record)| {
                    let (address, frame) = record.split_at(8);
                    let address = u64::from_ne_bytes(address.try_into().expect("eight bytes"));
                    let frame = match interpreter.waiting(frame) {
                        _ if at < on_stack => interpreter.frame(frame),
                        Some(code) => WalkedFrame::Code {
                            code,
                            instruction: 0,
                            entered: false,
                        },
                        None => WalkedFrame::Native,
                    };
                    (address, frame)
                });
            let runs = |frame: &Frame| {
                let address = frame
                    .address
                    .saturating_sub(u64::from(frame.return_address));
                let ranges = interpreter.eval_loop();
                let after = ranges.partition_point(|range| range.start <= address);
                frame.origin == Origin::Binary
                    && after
                        .checked_sub(1)
                        .is_some_and(|i| ranges[i].contains(&address))
            };
            let mut interpreted = |code: u64, instruction: u64, counts: &mut Walks| {
                let read = (walk.code)(code);
                let row = self.row(program, interpreter, code, read);
                let frame = Frame {
                    origin: Origin::Interpreted,
                    address: instruction,
                    mapping: None,
                    file_offset: None,
                    return_address: false,
                    interpreted: Some(Interpreted {
                        code: row,
                        line: read.and_then(|code| code.line(instruction)),
                    }),
                };
                counts.frames += 1;
                counts.unread_frames += u64::from(read.is_none());
                (intern(frames, ids, frame), read.is_some())
            };
            // Where the innermost frame of the program holds only where it
            // last called, its instruction is not known. On the native
            // stack, other code above it may have been called without it
            // saving where it is.
            let mut innermost = interpreter.saves_instruction_on_calls();
            if interpreter.walk().frames == Frames::Native {
                let mut placed = HashMap::new();
                let mut awaiting = Vec::new();
                for (at, (address, frame)) in records.enumerate() {
                    let WalkedFrame::Code {
                        code, instruction, ..
                    } = frame
                    else {
                        continue;
                    };
                    let instruction = if innermost { 0 } else { instruction };
                    innermost = false;
                    let (id, read) = interpreted(code, instruction, &mut counts);
                    // A frame whose code can't be read may be no frame of
                    // the runtime's at all.
                    if read && at < on_stack {
                        placed.insert(address, id);
                    } else if read {
                        awaiting.push(id);
                    }
                }
                // Code the runtime compiled is in no file.
                let native: Vec<Native> = stack
                    .iter()
                    .zip(ends)
                    .map(|(id, end)| {
                        let frame = &frames[*id as usize];
                        Native {
                            id: *id,
                            eval: frame.origin == Origin::Unresolved || runs(frame),
                            end: *end,
                        }
                    })
                    .collect();
                *stack = place_native(&native, &placed, &awaiting);
            } else {
                let mut groups = vec![Group::default()];
                for (address, frame) in records {
                    // A call the runtime made from a frame saved where it
                    // was.
                    let saved = !std::mem::take(&mut innermost);
                    let entry = match frame {
                        WalkedFrame::Code {
                            code,
                            instruction,
                            entered,
                        } => {
                            let instruction = if saved { instruction } else { 0 };
                            let (id, _) = interpreted(code, instruction, &mut counts);
                            groups.last_mut().expect("never empty").frames.push(id);
                            entered.then_some(None)
                        }
                        WalkedFrame::Entry { native } => Some(native.then_some(address)),
                        WalkedFrame::Native => None,
                    };
                    if let Some(entry) = entry {
                        groups.last_mut().expect("never empty").entry = entry;
                        groups.push(Group::default());
                    }
                }
                let native: Vec<Native> = stack
                    .iter()
                    .zip(ends)
                    .map(|(id, end)| Native {
                        id: *id,
                        eval: runs(&frames[*id as usize]),
                        end: *end,
                    })
                    .collect();
                let user = stack
                    .iter()
                    .position(|id| frames[*id as usize].origin != Origin::Kernel)
                    .unwrap_or(stack.len());
                // A frame-pointer walk that runs into code without frames ends
                // at an address in no mapping.
                let lost_outer = walk.cut_short
                    || stack.last().is_some_and(|id| {
                        let frame = &frames[*id as usize];
                        frame.origin == Origin::Unresolved && frame.mapping.is_none()
                    });
                let from_inner = lost_outer || walk.status == Some(Status::Cut);
                let (merged, unmatched) =
                    place(&native, user, groups, from_inner, walk.frame_pointers);
                counts.unmatched = u64::from(unmatched);
                *stack = merged;
            }
        }
        let walks = self
            .walks
            .entry((walk.of.runtime(), walk.of.version().to_owned()))
            .or_default();
        walks.processes.insert(program.0);
        walks.samples += counts.samples;
        walks.before_found += counts.before_found;
        walks.no_thread += counts.no_thread;
        walks.unsearched += counts.unsearched;
        walks.failed += counts.failed;
        walks.cut += counts.cut;
        walks.frames += counts.frames;
        walks.unread_frames += counts.unread_frames;
        walks.unmatched += counts.unmatched;
    }

    /// The row of `code` for the code at `address` in `program`, named if
    /// it was read.
    fn row(
        &mut self,
        program: Program,
        interpreter: &dyn Interpreter,
        address: u64,
        read: Option<&Code>,
    ) -> u32 {
        let table = &mut self.code;
        *self.rows.entry((program, address)).or_insert_with(|| {
            table.push(InterpretedCode {
                pid: program.0,
                runtime: interpreter.runtime().to_owned(),
                address,
                name: read.map(|code| code.name.clone()),
                file: read.map(|code| code.file.clone()),
                first_line: read.map(|code| code.first_line),
                first_column: read.and_then(|code| code.first_column),
            });
            table.len() as u32 - 1
        })
    }

    /// How the walks of each runtime and version went, for a stream's
    /// coverage.
    pub fn coverage(&self) -> Vec<InterpreterCoverage> {
        self.walks
            .iter()
            .map(|((runtime, version), walks)| InterpreterCoverage {
                runtime: (*runtime).to_owned(),
                version: version.clone(),
                processes: walks.processes.len() as u64,
                samples: walks.samples,
                before_found: walks.before_found,
                no_thread: walks.no_thread,
                unsearched: walks.unsearched,
                failed: walks.failed,
                cut: walks.cut,
                frames: walks.frames,
                unread_frames: walks.unread_frames,
                unmatched: walks.unmatched,
            })
            .collect()
    }
}

fn intern<T: Clone + Eq + Hash>(items: &mut Vec<T>, ids: &mut HashMap<T, u32>, item: T) -> u32 {
    *ids.entry(item).or_insert_with_key(|item| {
        items.push(item.clone());
        items.len() as u32 - 1
    })
}

/// A native frame of a sample, as `place` and `place_native` see it.
struct Native {
    id: u32,
    /// Whether it runs the program's frames: the interpreter's eval loop,
    /// or for frames on the native stack, code the runtime compiled too.
    eval: bool,
    /// Where it ends on the stack, if known.
    end: Option<u64>,
}

/// The interpreter frames that one call native code made into the
/// interpreter ran, leaf first, and where the frame is that started the
/// call, if the interpreter keeps it in the call's native frame.
#[derive(Debug, Default)]
struct Group {
    frames: Vec<u32>,
    entry: Option<u64>,
}

/// Puts groups of interpreter frames into a native stack, both leaf first,
/// each just above its call's eval-loop frame, as the code that ran there.
///
/// Where groups say where they started, each goes just above the native
/// frame that holds where, whose function ran the call, the eval loop or
/// one it was inlined into. Where the stack's ends come from walking
/// `frame_pointers`, a user leaf outside the eval loop that holds it set up
/// no frame, so that the walk lost its caller, the eval loop, and the group
/// goes just above the leaf. One that started past the native stack's end
/// goes at its outer end, and one whose start the walk did not reach goes
/// above the next run of eval-loop frames outward of the group before it.
///
/// Otherwise groups are matched to the runs of eval-loop frames from the
/// outer end, which a whole frame-pointer stack keeps: the ones without a
/// run go just above the user leaf, at `user`. A stack or walk that lost
/// its outer end is matched `from_inner` instead. Also says whether a group
/// had no run, so that where it went is a guess.
fn place(
    native: &[Native],
    user: usize,
    mut groups: Vec<Group>,
    from_inner: bool,
    frame_pointers: bool,
) -> (Vec<u32>, bool) {
    // What follows the outermost call's start is no call.
    while groups.last().is_some_and(|group| group.frames.is_empty()) {
        groups.pop();
    }
    let mut unmatched = false;
    let mut at: Vec<(usize, Vec<u32>)> = Vec::with_capacity(groups.len());
    let mut runs = Vec::new();
    for (i, frame) in native.iter().enumerate() {
        if frame.eval && !(i > 0 && native[i - 1].eval) {
            runs.push(i);
        }
    }
    let by_entries = groups.iter().any(|group| group.entry.is_some())
        && native.iter().skip(user).any(|frame| frame.end.is_some());
    if by_entries {
        // Where the group before went, which the next is outward of.
        let mut outward = user;
        for group in groups {
            let holds = |entry: u64| {
                native
                    .iter()
                    .enumerate()
                    .skip(user)
                    .find(|(_, frame)| frame.end.is_some_and(|end| end > entry))
            };
            let position = match group.entry {
                Some(entry) => match holds(entry) {
                    Some((i, frame)) if i == user && !frame.eval && frame_pointers => i + 1,
                    Some((i, _)) => i,
                    None => native.len(),
                },
                None => match runs.iter().find(|&&run| run >= outward) {
                    Some(&run) => run,
                    None => {
                        unmatched |= !group.frames.is_empty();
                        native.len()
                    }
                },
            };
            outward = outward.max(position + 1);
            at.push((position, group.frames));
        }
    } else {
        let shift = if from_inner {
            0
        } else {
            runs.len() as isize - groups.len() as isize
        };
        let lost = (user + 1).min(runs.first().copied().unwrap_or(native.len()));
        for (k, group) in groups.into_iter().enumerate() {
            let run = usize::try_from(k as isize + shift)
                .ok()
                .and_then(|run| runs.get(run));
            let position = match run {
                Some(&position) => position,
                None => {
                    unmatched |= !group.frames.is_empty();
                    if from_inner { native.len() } else { lost }
                }
            };
            at.push((position.min(native.len()), group.frames));
        }
    }
    at.sort_by_key(|(position, _)| *position);
    let frames: usize = at.iter().map(|(_, frames)| frames.len()).sum();
    let mut merged = Vec::with_capacity(native.len() + frames);
    let mut at = at.into_iter().peekable();
    for (i, frame) in native.iter().enumerate() {
        while let Some((_, frames)) = at.next_if(|(position, _)| *position == i) {
            merged.extend(frames);
        }
        merged.push(frame.id);
    }
    merged.extend(at.flat_map(|(_, frames)| frames));
    (merged, unmatched)
}

/// Puts the frames of a runtime that keeps them on the native stack into
/// it, leaf first. `walked` has them by their frame pointer, which is
/// where the native frame that ran each ends, less 16. Each takes the
/// place of that native frame where it runs the program's frames, and
/// else goes just above it: a function that sets up no frame keeps its
/// caller's frame pointer, so that the walk of frame pointers lost the
/// caller, whose frame it is. `awaiting` are the functions that waited
/// for the outermost of those frames, nearest first, and go just above it,
/// as its callers.
fn place_native(native: &[Native], walked: &HashMap<u64, u32>, awaiting: &[u32]) -> Vec<u32> {
    let mut merged = Vec::with_capacity(native.len() + 1 + awaiting.len());
    let mut above_outermost = None;
    for frame in native {
        let found = frame.end.and_then(|end| walked.get(&end.wrapping_sub(16)));
        match found {
            Some(&walked) if frame.eval => merged.push(walked),
            Some(&walked) => merged.extend([frame.id, walked]),
            None => {
                merged.push(frame.id);
                continue;
            }
        }
        above_outermost = Some(merged.len());
    }
    if let Some(at) = above_outermost {
        merged.splice(at..at, awaiting.iter().copied());
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn puts_interpreter_frames_above_the_calls_into_the_interpreter() {
        // Native frames 0..10, interpreter frames 100 and up.
        let (leaf, c1, c2, eval0, c3, eval1, main) = (0, 1, 2, 3, 4, 5, 6);
        let frames = |ids: &[(u32, bool)]| -> Vec<Native> {
            let native = |&(id, eval): &(u32, bool)| Native {
                id,
                eval,
                end: None,
            };
            ids.iter().map(native).collect()
        };
        let groups = || {
            vec![
                Group {
                    frames: vec![100],
                    entry: None,
                },
                Group {
                    frames: vec![101, 102],
                    entry: None,
                },
                Group::default(),
            ]
        };
        // Every call shows, the leaf in the eval loop.
        let whole = frames(&[(eval0, true), (c3, false), (eval1, true), (main, false)]);
        assert_eq!(
            place(&whole, 0, groups(), false, false),
            (vec![100, eval0, c3, 101, 102, eval1, main], false)
        );
        // The leaf set up no frame, so its caller, the inner eval loop,
        // does not show.
        let lost = frames(&[
            (leaf, false),
            (c1, false),
            (c2, false),
            (eval1, true),
            (main, false),
        ]);
        assert_eq!(
            place(&lost, 0, groups(), false, false),
            (vec![leaf, 100, c1, c2, 101, 102, eval1, main], true)
        );
        // Under kernel frames.
        let kernel = frames(&[
            (7, false),
            (8, false),
            (leaf, false),
            (c1, false),
            (eval1, true),
            (main, false),
        ]);
        assert_eq!(
            place(&kernel, 2, groups(), false, false).0,
            [7, 8, leaf, 100, c1, 101, 102, eval1, main]
        );
        // A walk cut short, or a native stack that lost its outer end.
        let cut = vec![
            Group {
                frames: vec![100],
                entry: None,
            },
            Group {
                frames: vec![101],
                entry: None,
            },
            Group {
                frames: vec![102],
                entry: None,
            },
        ];
        assert_eq!(
            place(&whole, 0, cut, true, false),
            (vec![100, eval0, c3, 101, eval1, main, 102], true)
        );
        let truncated = frames(&[(eval0, true), (c1, false), (c2, false)]);
        assert_eq!(
            place(&truncated, 0, groups(), true, false),
            (vec![100, eval0, c1, c2, 101, 102], true)
        );
        // An inner call that has run none of its frames yet.
        let empty = vec![
            Group::default(),
            Group {
                frames: vec![101],
                entry: None,
            },
            Group::default(),
        ];
        assert_eq!(
            place(&whole, 0, empty, false, false),
            (vec![eval0, c3, 101, eval1, main], false)
        );
    }

    #[test]
    fn puts_frames_on_the_native_stack_in_place_of_the_code_that_ran_them() {
        // Native frames 0..10, each ending 0x100 apart, the runtime's
        // frames 100 and up.
        let frame = |id: u32, eval: bool| Native {
            id,
            eval,
            end: Some(0x1000 + 0x100 * u64::from(id)),
        };
        let at = |id: u32| 0x1000 + 0x100 * u64::from(id) - 16;
        let (jit, builtin, native, outer_jit, main) = (0, 1, 2, 3, 4);
        let stack = [
            frame(jit, true),
            frame(builtin, false),
            frame(native, false),
            frame(outer_jit, true),
            Native {
                id: main,
                eval: false,
                end: None,
            },
        ];
        // The builtin set up no frame, so the frame at its frame pointer is
        // its caller's, which the walk lost.
        let walked = HashMap::from([(at(jit), 100), (at(builtin), 101), (at(outer_jit), 102)]);
        assert_eq!(
            place_native(&stack, &walked, &[]),
            vec![100, builtin, 101, native, 102, main]
        );
        assert_eq!(
            place_native(&stack, &HashMap::new(), &[]),
            vec![jit, builtin, native, outer_jit, main]
        );
        // The functions that waited for the outermost frame of the program
        // are its callers, inside the native code that resumed it.
        assert_eq!(
            place_native(&stack, &walked, &[200, 201]),
            vec![100, builtin, 101, native, 102, 200, 201, main]
        );
        assert_eq!(
            place_native(&stack, &HashMap::new(), &[200]),
            vec![jit, builtin, native, outer_jit, main]
        );
    }

    #[test]
    fn puts_interpreter_frames_where_their_calls_started() {
        let native = |id, eval, end| Native { id, eval, end };
        let group = |frames: &[u32], entry| Group {
            frames: frames.to_vec(),
            entry: Some(entry),
        };
        // Each call started in its eval loop's frame.
        let whole = [
            native(0, false, Some(0x1000)),
            native(1, true, Some(0x1100)),
            native(2, false, Some(0x1200)),
            native(3, true, Some(0x1300)),
            native(4, false, None),
        ];
        let groups = vec![
            group(&[100], 0x10f0),
            group(&[101, 102], 0x12f0),
            Group::default(),
        ];
        assert_eq!(
            place(&whole, 0, groups, false, true),
            (vec![0, 100, 1, 2, 101, 102, 3, 4], false)
        );
        // The eval loop inlined into the function that called it, as 3.14
        // has it in gen_iternext: the call started in that one's frame.
        let (op, gen_iternext, sum, call, main) = (0, 1, 2, 3, 4);
        let inlined = [
            native(op, true, Some(0x1000)),
            native(gen_iternext, false, Some(0x1100)),
            native(sum, false, Some(0x1200)),
            native(call, true, Some(0x1300)),
            native(main, false, None),
        ];
        let groups = vec![
            group(&[100, 101], 0x10f0),
            group(&[102], 0x12f0),
            Group::default(),
        ];
        assert_eq!(
            place(&inlined, 0, groups, false, false),
            (
                vec![op, 100, 101, gen_iternext, sum, 102, call, main],
                false
            )
        );
        // Python called qsort, which called Python. The leaf set up no
        // frame, so the inner eval loop's frame is lost, and code without
        // frame pointers ended the walk before the outer one.
        let (leaf, msort, qsort, ffi) = (0, 1, 2, 3);
        let lost = [
            native(leaf, false, Some(0x1000)),
            native(msort, false, Some(0x1080)),
            native(qsort, false, Some(0x1100)),
            native(ffi, false, None),
        ];
        let groups = vec![
            group(&[100], 0x0ff0),
            group(&[101, 102], 0x2000),
            Group::default(),
        ];
        assert_eq!(
            place(&lost, 0, groups, false, true),
            (vec![leaf, 100, msort, qsort, ffi, 101, 102], false)
        );
        // The walk stopped before the outer call's start: it goes above the
        // next eval loop's frames out, not past the stack's end.
        let (eval0, qsort, eval1, start) = (0, 1, 2, 3);
        let cut = [
            native(eval0, true, Some(0x1000)),
            native(qsort, false, Some(0x1100)),
            native(eval1, true, Some(0x1200)),
            native(start, false, None),
        ];
        let groups = vec![
            group(&[100], 0x0ff0),
            Group {
                frames: vec![101, 102],
                entry: None,
            },
        ];
        assert_eq!(
            place(&cut, 0, groups, true, true),
            (vec![100, eval0, qsort, 101, 102, eval1, start], false)
        );
    }
}
