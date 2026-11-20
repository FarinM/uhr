//! Walks an interpreter's frames in its process's memory, as uhr's eBPF
//! programs do at a sample, for a sampler that holds the thread still from
//! user space, as on macOS. It knows no runtime, only what a `Walk` says,
//! and writes what it found as the programs do, so that each runtime reads
//! both alike: each frame after its address, its copy, then its reads.

use std::collections::HashMap;

use super::{Awaits, Frames, Memory, PathStep, States, Step, Thread, Walk};

/// The most frames a walk copies, as uhr's eBPF programs.
pub const MAX_FRAMES: usize = 127;

/// The most thread states searched for a thread's, as uhr's eBPF programs.
pub const MAX_STATES: usize = 256;

/// The most functions followed that wait for the one a thread runs, as
/// uhr's eBPF programs.
pub const MAX_AWAITED: usize = 32;

/// How a walk went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// It reached the outermost frame.
    Done,
    /// The frames went on past the most it copies.
    Cut,
    /// The runtime keeps no state for the thread, as for one it does not
    /// run on.
    NoThread,
    /// The thread's state was not among the first it searched.
    Unsearched,
    /// Memory it needed could not be read.
    Failed,
}

/// The frames a walk copied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Walked {
    pub status: Status,
    /// Each frame's record: its address, then its copy and its reads.
    pub records: Vec<u8>,
    /// The bytes of each record.
    pub record_bytes: usize,
    /// How many of the last records are of functions that waited for the
    /// outermost of the program's frames, on no stack.
    pub awaited: usize,
}

impl Walked {
    fn failed(walk: &Walk) -> Self {
        Self::empty(walk, Status::Failed)
    }

    fn empty(walk: &Walk, status: Status) -> Self {
        Self {
            status,
            records: Vec::new(),
            record_bytes: record_bytes(walk),
            awaited: 0,
        }
    }

    pub fn frames(&self) -> usize {
        self.records.len() / self.record_bytes
    }
}

/// A record's address, then the copy, then 8 bytes for each read.
fn record_bytes(walk: &Walk) -> usize {
    8 + walk.copy.bytes as usize + 8 * walk.copy.reads.len()
}

/// Walks the frames of the threads of one process, keeping the state each
/// thread was found to run in, so that a walk need not search for it again.
#[derive(Debug, Default)]
pub struct Walker {
    states: HashMap<u64, u64>,
}

impl Walker {
    /// Walks the frames a runtime keeps in its memory, of the thread with
    /// the id the runtime keeps for it, `thread`, whose thread pointer, from
    /// which a runtime's thread-locals are found, is `pointer`, if known.
    pub fn memory(
        &mut self,
        walk: &Walk,
        memory: &dyn Memory,
        thread: u64,
        pointer: Option<u64>,
    ) -> Walked {
        let Frames::Memory { thread: of, step } = &walk.frames else {
            return Walked::failed(walk);
        };
        let state = match of {
            Thread::Global { state, .. } => Ok(*state),
            Thread::ThreadPointer { state, .. } => match pointer {
                Some(pointer) => match follow(memory, pointer, state.iter().map(|&o| o as i64)) {
                    Some(0) => Err(Status::NoThread),
                    Some(state) => Ok(state),
                    None => Err(Status::Failed),
                },
                None => Err(Status::Failed),
            },
            Thread::States(states) => self.search(states, memory, thread),
        };
        let state = match state {
            Ok(state) => state,
            Err(status) => return Walked::empty(walk, status),
        };
        let frame_path = match of {
            Thread::Global { frame, .. } | Thread::ThreadPointer { frame, .. } => frame,
            Thread::States(states) => &states.frame,
        };
        let Some(frame) = follow(memory, state, signed(frame_path)) else {
            return Walked::failed(walk);
        };
        let end = match *step {
            Step::Stride { end, .. } => {
                let word = |offset: u32| word_at(memory, state.wrapping_add(u64::from(offset)));
                word(end.start).wrapping_add(word(end.count).wrapping_mul(u64::from(end.scale)))
            }
            Step::Pointer(_) => u64::MAX,
        };
        copy_frames(walk, memory, frame, end, *step)
    }

    /// The state the thread runs in, from the runtime's lists of them: the
    /// one the runtime marks as running, or without a mark, the one with
    /// frames, as uhr's eBPF programs search.
    fn search(&mut self, states: &States, memory: &dyn Memory, thread: u64) -> Result<u64, Status> {
        let read = |address: u64| read_word(memory, address).ok_or(Status::Failed);
        let id = |state: u64| read(state.wrapping_add(u64::from(states.thread_id)));
        let active = |state: u64| {
            states.active.is_some_and(|(at, mask)| {
                read_word(memory, state.wrapping_add(u64::from(at)))
                    .is_some_and(|word| word as u32 & mask != 0)
            })
        };
        let has_frames =
            |state: u64| follow(memory, state, signed(&states.frame)).is_some_and(|f| f != 0);
        // A state can be freed and its memory reused, or its thread run in
        // another since, so the one kept is checked.
        if let Some(&state) = self.states.get(&thread)
            && id(state) == Ok(thread)
            && (active(state) || (states.active.is_none() && has_frames(state)))
        {
            return Ok(state);
        }
        let first = |list: u64| match list {
            0 => Ok(0),
            _ => read(list.wrapping_add(u64::from(states.first_state))),
        };
        let mut list = follow(memory, states.base, signed(&states.lists)).ok_or(Status::Failed)?;
        let mut state = first(list)?;
        let mut others = Vec::new();
        let mut searched = false;
        for _ in 0..MAX_STATES {
            if state == 0 {
                let Some(next) = states.next_list.filter(|_| list != 0) else {
                    searched = true;
                    break;
                };
                list = read(list.wrapping_add(u64::from(next)))?;
                state = first(list)?;
                continue;
            }
            if id(state)? == thread {
                if active(state) {
                    self.states.insert(thread, state);
                    return Ok(state);
                }
                others.push(state);
            }
            state = read(state.wrapping_add(u64::from(states.next_state)))?;
        }
        if let Some(&state) = others.iter().find(|&&state| has_frames(state)) {
            return Ok(state);
        }
        Err(if searched {
            Status::NoThread
        } else {
            Status::Unsearched
        })
    }

    /// Copies the frames of a runtime that keeps them on the native stack:
    /// for each native frame, leaf first, at its frame pointer, which is
    /// where it `ends` on the stack, less 16. A frame whose end is not known
    /// gets no record. Then those of the functions that wait for the
    /// outermost of the program's frames, if the runtime has such.
    pub fn native(walk: &Walk, memory: &dyn Memory, ends: &[Option<u64>]) -> Walked {
        let bytes = walk.copy.bytes as usize;
        let mut walked = Walked::empty(walk, Status::Done);
        let mut copy = vec![0; bytes];
        for end in ends.iter().flatten().take(MAX_FRAMES) {
            let fp = end.wrapping_sub(16);
            let from = fp.wrapping_add(i64::from(walk.copy.from) as u64);
            if memory.read(from, &mut copy).is_err() {
                copy.fill(0);
            }
            walked.records.extend(fp.to_ne_bytes());
            walked.records.extend(&copy);
            push_reads(walk, memory, &copy, &mut walked.records);
        }
        if let Some(awaits) = &walk.awaits {
            walked.awaited = awaited(walk, awaits, memory, &mut walked.records);
        }
        walked
    }
}

/// Copies the frames in the runtime's memory from `frame`, innermost, until
/// one is null or at `end`.
fn copy_frames(walk: &Walk, memory: &dyn Memory, mut frame: u64, end: u64, step: Step) -> Walked {
    let bytes = walk.copy.bytes as usize;
    let mut walked = Walked::empty(walk, Status::Done);
    let mut copy = vec![0; bytes];
    for _ in 0..MAX_FRAMES {
        if frame == 0 || frame >= end {
            return walked;
        }
        let from = frame.wrapping_add(i64::from(walk.copy.from) as u64);
        if memory.read(from, &mut copy).is_err() {
            walked.status = Status::Failed;
            return walked;
        }
        walked.records.extend(frame.to_ne_bytes());
        walked.records.extend(&copy);
        push_reads(walk, memory, &copy, &mut walked.records);
        frame = match step {
            Step::Pointer(next) => {
                let at = next as usize;
                match copy.get(at..at + 8) {
                    Some(word) => u64::from_ne_bytes(word.try_into().expect("eight bytes")),
                    None => {
                        walked.status = Status::Failed;
                        return walked;
                    }
                }
            }
            Step::Stride { bytes, .. } => frame.wrapping_add(i64::from(bytes) as u64),
        };
    }
    if frame != 0 && frame < end {
        walked.status = Status::Cut;
    }
    walked
}

/// Adds the words a walk reads of a frame whose copy is `copy`: each at its
/// offset from the pointer the copy holds, 0 where that can't be read, as
/// from a null pointer.
fn push_reads(walk: &Walk, memory: &dyn Memory, copy: &[u8], to: &mut Vec<u8>) {
    for read in &walk.copy.reads {
        let at = read.word as usize;
        let pointer = copy.get(at..at + 8).map_or(0, |word| {
            u64::from_ne_bytes(word.try_into().expect("eight bytes"))
        });
        let value = match pointer {
            0 => 0,
            _ => word_at(memory, pointer.wrapping_add(i64::from(read.offset) as u64)),
        };
        to.extend(value.to_ne_bytes());
    }
}

/// Adds a record for each function that waits for the outermost frame of
/// the program's in `records`, nearest first, as `awaits` says to find them:
/// each as a frame that runs its code would be copied, at the address of its
/// state, but of its copy only the code. Returns how many.
fn awaited(walk: &Walk, awaits: &Awaits, memory: &dyn Memory, records: &mut Vec<u8>) -> usize {
    let each = record_bytes(walk);
    let word = |record: &[u8], at: u32| {
        let at = 8 + at as usize;
        record.get(at..at + 8).map_or(0, |word| {
            u64::from_ne_bytes(word.try_into().expect("eight bytes"))
        })
    };
    let outermost = records
        .chunks_exact(each)
        .rfind(|record| {
            awaits
                .frame
                .iter()
                .all(|&(at, mask, value)| word(record, at) & mask == value)
        })
        .map(|record| u64::from_ne_bytes(record[..8].try_into().expect("eight bytes")));
    let Some(frame) = outermost.filter(|&frame| frame != 0) else {
        return 0;
    };
    let frames = records.len() / each;
    let mut state = follow_path(memory, &awaits.start, frame);
    let mut added = 0;
    for hop in 0..MAX_AWAITED {
        state = follow_path(memory, &awaits.state, state);
        if state == 0 {
            break;
        }
        // The first is the function of the outermost frame itself.
        if hop > 0 {
            if frames + added >= MAX_FRAMES {
                break;
            }
            let mut copy = vec![0; walk.copy.bytes as usize];
            let code = follow_path(memory, &awaits.code, state);
            let held = awaits.copy_code as usize;
            if let Some(word) = copy.get_mut(held..held + 8) {
                word.copy_from_slice(&code.to_ne_bytes());
            }
            records.extend(state.to_ne_bytes());
            records.extend(&copy);
            push_reads(walk, memory, &copy, records);
            added += 1;
        }
        state = awaits
            .next
            .iter()
            .map(|path| follow_path(memory, path, state))
            .find(|&next| next != 0)
            .unwrap_or(0);
    }
    added
}

/// Where `path` ends from `address`, 0 where a step ends it, or a word
/// can't be read.
fn follow_path(memory: &dyn Memory, path: &[PathStep], mut address: u64) -> u64 {
    for step in path {
        let word = word_at(memory, address.wrapping_add(i64::from(step.offset) as u64));
        if let Some((mask, value)) = step.check {
            let checked = match step.via {
                Some(via) => word_at(memory, word.wrapping_add(i64::from(via) as u64)),
                None => word,
            } & mask;
            let holds = match step.at_least {
                true => checked >= value,
                false => checked == value,
            };
            if !holds {
                return 0;
            }
        }
        if let Some(pointer) = step.follow {
            address = word & pointer;
        }
    }
    address
}

/// A path's offsets, which uhr's eBPF programs read as signed.
fn signed(path: &[u32]) -> impl Iterator<Item = i64> + '_ {
    path.iter().map(|&offset| i64::from(offset as i32))
}

/// Follows the pointers at each signed offset from `address`, stopping at a
/// null one. `None` where one can't be read.
fn follow(memory: &dyn Memory, mut address: u64, path: impl Iterator<Item = i64>) -> Option<u64> {
    for offset in path {
        if address == 0 {
            break;
        }
        address = read_word(memory, address.wrapping_add(offset as u64))?;
    }
    Some(address)
}

fn read_word(memory: &dyn Memory, address: u64) -> Option<u64> {
    let mut word = [0; 8];
    memory.read(address, &mut word).ok()?;
    Some(u64::from_ne_bytes(word))
}

/// The word at `address`, 0 where it can't be read.
fn word_at(memory: &dyn Memory, address: u64) -> u64 {
    read_word(memory, address).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io;

    use super::super::{ArrayEnd, Copy, Read};
    use super::*;

    /// Memory of words, of which only those written can be read.
    #[derive(Default)]
    struct Fake(BTreeMap<u64, u8>);

    impl Fake {
        fn word(&mut self, address: u64, value: u64) {
            for (i, byte) in value.to_ne_bytes().into_iter().enumerate() {
                self.0.insert(address + i as u64, byte);
            }
        }
    }

    impl Memory for Fake {
        fn read(&self, address: u64, into: &mut [u8]) -> io::Result<()> {
            for (i, byte) in into.iter_mut().enumerate() {
                *byte = *self
                    .0
                    .get(&(address + i as u64))
                    .ok_or(io::ErrorKind::NotFound)?;
            }
            Ok(())
        }
    }

    fn records(walked: &Walked) -> Vec<(u64, Vec<u64>)> {
        walked
            .records
            .chunks_exact(walked.record_bytes)
            .map(|record| {
                let words: Vec<u64> = record
                    .chunks_exact(8)
                    .map(|w| u64::from_ne_bytes(w.try_into().unwrap()))
                    .collect();
                (words[0], words[1..].to_vec())
            })
            .collect()
    }

    /// CPython's shape: interpreters in a list, each with its thread
    /// states, each with its innermost frame, and each frame the next.
    fn states_walk() -> Walk {
        Walk {
            frames: Frames::Memory {
                thread: Thread::States(States {
                    base: 0x1000,
                    lists: vec![0],
                    next_list: Some(8),
                    first_state: 16,
                    next_state: 0,
                    thread_id: 8,
                    active: None,
                    frame: vec![24],
                }),
                step: Step::Pointer(0),
            },
            copy: Copy {
                from: 0,
                bytes: 16,
                reads: vec![Read { word: 8, offset: 4 }],
            },
            frame_pointers: false,
            awaits: None,
        }
    }

    #[test]
    fn walks_the_frames_of_the_state_with_the_threads_id() {
        let mut memory = Fake::default();
        // One interpreter, whose list has another thread's state, then ours.
        memory.word(0x1000, 0x2000);
        memory.word(0x2008, 0);
        memory.word(0x2010, 0x3000);
        memory.word(0x3000, 0x3100);
        memory.word(0x3008, 7);
        memory.word(0x3018, 0);
        memory.word(0x3100, 0);
        memory.word(0x3108, 42);
        memory.word(0x3118, 0x4000);
        // Two frames, the second of no code.
        memory.word(0x4000, 0x4100);
        memory.word(0x4008, 0x5000);
        memory.word(0x4100, 0);
        memory.word(0x4108, 0);
        memory.word(0x5004, 0xc0de);
        let mut walker = Walker::default();
        let walked = walker.memory(&states_walk(), &memory, 42, None);
        assert_eq!(walked.status, Status::Done);
        assert_eq!(
            records(&walked),
            [
                (0x4000, vec![0x4100, 0x5000, 0xc0de]),
                (0x4100, vec![0, 0, 0]),
            ]
        );
        // A state without frames is as none.
        for thread in [7, 9] {
            let status = walker.memory(&states_walk(), &memory, thread, None).status;
            assert_eq!(status, Status::NoThread, "{thread}");
        }
    }

    #[test]
    fn says_where_it_could_not_read_or_had_to_stop() {
        let mut memory = Fake::default();
        memory.word(0x1000, 0x2000);
        memory.word(0x2008, 0);
        memory.word(0x2010, 0x3000);
        memory.word(0x3000, 0);
        memory.word(0x3008, 42);
        // A frame that points to itself goes on until the most copied.
        memory.word(0x3018, 0x4000);
        memory.word(0x4000, 0x4000);
        memory.word(0x4008, 0);
        let walked = Walker::default().memory(&states_walk(), &memory, 42, None);
        assert_eq!(walked.status, Status::Cut);
        assert_eq!(walked.frames(), MAX_FRAMES);
        memory.word(0x4000, 0x9000);
        let walked = Walker::default().memory(&states_walk(), &memory, 42, None);
        assert_eq!((walked.status, walked.frames()), (Status::Failed, 1));
    }

    #[test]
    fn walks_an_array_of_frames_to_its_end() {
        let mut memory = Fake::default();
        // A global state, whose frames are an array that ends where the
        // state says, at a start plus a count.
        memory.word(0x1000, 0x2000);
        memory.word(0x1008, 0x2000 - 48 + 48 * 3);
        memory.word(0x1010, 0);
        for i in 0..3u64 {
            memory.word(0x2000 + 48 * i, i);
            memory.word(0x2008 + 48 * i, 0);
        }
        let walk = Walk {
            frames: Frames::Memory {
                thread: Thread::Global {
                    state: 0x1000,
                    frame: vec![0],
                },
                step: Step::Stride {
                    bytes: 48,
                    end: ArrayEnd {
                        start: 8,
                        count: 16,
                        scale: 1,
                    },
                },
            },
            copy: Copy {
                from: 0,
                bytes: 16,
                reads: Vec::new(),
            },
            frame_pointers: false,
            awaits: None,
        };
        let walked = Walker::default().memory(&walk, &memory, 0, None);
        assert_eq!(walked.status, Status::Done);
        let first: Vec<u64> = records(&walked).iter().map(|(_, w)| w[0]).collect();
        assert_eq!(first, [0, 1]);
    }

    #[test]
    fn copies_each_native_frame_at_its_frame_pointer_and_what_waits() {
        let mut memory = Fake::default();
        // A frame of the program, whose copy holds its code at 8 and its
        // marker at 0, at the frame pointer 0x7000.
        memory.word(0x7000, 1);
        memory.word(0x7008, 0xa000);
        // A native frame between.
        memory.word(0x7100, 0);
        memory.word(0x7108, 0);
        // The function its frame resumed waits for another's result, whose
        // state holds the one that waits for it at 0, and its code at 8.
        memory.word(0xa000 + 0x20, 0xb000);
        memory.word(0xb000, 0xc000);
        memory.word(0xc000, 0);
        memory.word(0xc008, 0xd000);
        let check = |offset: i32| PathStep::to(offset);
        let walk = Walk {
            frames: Frames::Native,
            copy: Copy {
                from: 0,
                bytes: 16,
                reads: Vec::new(),
            },
            frame_pointers: true,
            awaits: Some(Awaits {
                frame: vec![(0, u64::MAX, 1)],
                copy_code: 8,
                start: vec![check(8), check(0x20)],
                state: Vec::new(),
                code: vec![check(8)],
                next: vec![vec![check(0)]],
            }),
        };
        let ends = [Some(0x7010), None, Some(0x7110)];
        let walked = Walker::native(&walk, &memory, &ends);
        assert_eq!(walked.awaited, 1);
        assert_eq!(
            records(&walked),
            [
                (0x7000, vec![1, 0xa000]),
                (0x7100, vec![0, 0]),
                (0xc000, vec![0, 0xd000]),
            ]
        );
    }
}
