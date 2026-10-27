//! Copies the frames of a runtime: from its memory, where it keeps them
//! rather than on the stack, as CPython does, or from the native stack,
//! where V8 keeps them. uhr says for each process where they are, in
//! numbers; this knows no runtime.

use core::ffi::c_void;

use aya_ebpf::Global;
use aya_ebpf::bindings::bpf_pidns_info;
use aya_ebpf::helpers::bpf_get_current_task;
use aya_ebpf::helpers::generated::{
    bpf_get_ns_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_user,
};
use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, LruHashMap};
use uhr_ebpf::{
    MAX_FRAMES, MAX_PATH, MAX_READS, MAX_THREADS, MAX_WALKED_BYTES, MAX_WALKED_FRAMES, ONE_LIST,
    Read, WALKED_BYTES, Walk, frames, step, walk,
};

/// By tgid. uhr sets a process's walk once it knows its runtime.
#[map]
static WALKS: HashMap<u32, Walk> = HashMap::with_max_entries(16384, 0);

/// The state each thread runs in, by its id, so a sample need not search
/// for it again. uhr fills it too, with threads a search can't reach.
#[map]
static THREADS: LruHashMap<u32, u64> = LruHashMap::with_max_entries(16384, 0);

/// Where a task keeps its user thread pointer, which uhr sets at load from
/// the kernel's BTF. `u32::MAX` where unknown.
#[unsafe(no_mangle)]
static TASK_THREAD_POINTER: Global<u32> = Global::new(u32::MAX);

/// The current thread's user thread pointer, which its thread-locals are
/// found from.
fn thread_pointer() -> Option<u64> {
    let offset = TASK_THREAD_POINTER.load();
    if offset == u32::MAX {
        return None;
    }
    let task = unsafe { bpf_get_current_task() } as *const u8;
    let mut pointer = 0u64;
    let read = unsafe {
        bpf_probe_read_kernel(
            (&mut pointer as *mut u64).cast(),
            8,
            task.wrapping_add(offset as usize).cast(),
        )
    };
    (read == 0 && pointer != 0).then_some(pointer)
}

/// The room a sample needs for its interpreter frames. The verifier sees
/// each take as much as its address and the most bytes the mask on its
/// size lets through, which is more than they take, and checks where a
/// frame starts apart from how long it is, so the room has a frame more.
pub(crate) const ROOM: usize = (MAX_WALKED_FRAMES + 1) * (MAX_WALKED_BYTES + 8);

/// How to walk the frames of the process `tgid`, if uhr knows.
pub(crate) fn of(tgid: u32) -> Option<&'static Walk> {
    unsafe { WALKS.get(tgid) }
}

/// Forgets the walk of a process that execs or exits, whose memory is then
/// another program's or none.
pub(crate) fn forget(tgid: u32) {
    let _ = WALKS.remove(tgid);
}

fn read(address: u64) -> Option<u64> {
    let mut value = 0u64;
    let read = unsafe {
        bpf_probe_read_user((&mut value as *mut u64).cast(), 8, address as *const c_void)
    };
    (read == 0).then_some(value)
}

/// Follows the first `len` pointers of `path` from `address`. 0 where one
/// is null.
#[inline(always)]
fn follow(mut address: u64, path: &[u32; MAX_PATH], len: u32) -> Option<u64> {
    for (i, &offset) in path.iter().enumerate() {
        if i as u32 >= len || address == 0 {
            break;
        }
        address = read(address.wrapping_add(offset as i32 as i64 as u64))?;
    }
    Some(address)
}

/// How the search for a thread's state went.
enum Search {
    Found(u64),
    /// The runtime keeps no state for it.
    None,
    /// Not among the first `MAX_THREADS`.
    Unsearched,
}

/// The state the sampled thread runs in, its id `tid` in the process's PID
/// namespace and `host` in the first. `scratch` is map memory to keep what
/// the search found in.
#[inline(always)]
fn thread_state(walk: &Walk, tid: u64, host: u32, scratch: *mut u8) -> Result<Search, ()> {
    let id = |state: u64| read(state.wrapping_add(u64::from(walk.thread_id)));
    let active = |state: u64| {
        walk.active_mask != 0
            && read(state.wrapping_add(u64::from(walk.active)))
                .is_some_and(|word| word as u32 & walk.active_mask != 0)
    };
    let has_frames =
        |state: u64| follow(state, &walk.frame, walk.frame_len).is_some_and(|f| f != 0);
    // A state can be freed and its memory reused, or its thread run in
    // another state since, so the cache is checked. Without a mark of the
    // state a thread runs in, its state with frames is it.
    if let Some(&state) = unsafe { THREADS.get(host) }
        && id(state) == Some(tid)
        && (active(state) || (walk.active_mask == 0 && has_frames(state)))
    {
        return Ok(Search::Found(state));
    }
    let first = |list: u64| match list {
        0 => Some(0),
        _ => read(list.wrapping_add(u64::from(walk.first_state))),
    };
    let mut list = follow(walk.base, &walk.lists, walk.lists_len).ok_or(())?;
    let mut state = first(list).ok_or(())?;
    // The thread's states not marked as the one it runs in, which the one
    // with frames is among, checked after the search to keep it short for
    // the verifier. A thread has two at most where a runtime has a second
    // interpreter it entered. In map memory, whose contents the verifier
    // keeps no track of, they don't make each way round the loop another
    // state for it to check.
    let other = |i: usize| unsafe { scratch.add(8 * i).cast::<[u8; 8]>() };
    let get = |i| u64::from_ne_bytes(unsafe { core::ptr::read_volatile(other(i)) });
    let set = |i, state: u64| unsafe { core::ptr::write_volatile(other(i), state.to_ne_bytes()) };
    set(0, 0);
    set(1, 0);
    let mut searched = false;
    for _ in 0..MAX_THREADS {
        if state == 0 {
            if list == 0 || walk.next_list == ONE_LIST {
                searched = true;
                break;
            }
            list = read(list.wrapping_add(u64::from(walk.next_list))).ok_or(())?;
            state = first(list).ok_or(())?;
            continue;
        }
        if id(state).ok_or(())? == tid {
            if active(state) {
                let _ = THREADS.insert(host, state, 0);
                return Ok(Search::Found(state));
            }
            if get(0) == 0 {
                set(0, state);
            } else if get(1) == 0 {
                set(1, state);
            }
        }
        state = read(state.wrapping_add(u64::from(walk.next_state))).ok_or(())?;
    }
    for i in 0..2 {
        let other = get(i);
        if other != 0 && has_frames(other) {
            return Ok(Search::Found(other));
        }
    }
    Ok(if searched {
        Search::None
    } else {
        Search::Unsearched
    })
}

/// The current thread's id in the PID namespace `walk` says, `None` if it
/// is not in it.
#[inline(always)]
fn thread_id(walk: &Walk, host: u32) -> Option<u64> {
    let [dev, ino] = walk.pid_namespace;
    if dev == 0 && ino == 0 {
        return Some(u64::from(host));
    }
    let mut ids = bpf_pidns_info { pid: 0, tgid: 0 };
    let size = core::mem::size_of::<bpf_pidns_info>() as u32;
    let found = unsafe { bpf_get_ns_current_pid_tgid(dev, ino, &mut ids, size) };
    (found == 0).then_some(u64::from(ids.pid))
}

/// The current thread's state in the runtime `walk` says, for `frames` to
/// walk the frames of, or how a walk that can't go on went, of `walk`.
/// `scratch` is map memory to keep what the search found in.
#[inline(always)]
pub(crate) fn state(walk: Option<&Walk>, tid: u32, scratch: *mut u8) -> Result<u64, u32> {
    let Some(walk) = walk else {
        return Err(walk::NONE);
    };
    if walk.frames == frames::GLOBAL {
        return Ok(walk.base);
    }
    if walk.frames == frames::THREAD_POINTER {
        let pointer = thread_pointer().ok_or(walk::FAILED)?;
        return match follow(pointer, &walk.state, walk.state_len) {
            Some(0) => Err(walk::NO_THREAD),
            Some(state) => Ok(state),
            None => Err(walk::FAILED),
        };
    }
    let id = thread_id(walk, tid).ok_or(walk::FAILED)?;
    match thread_state(walk, id, tid, scratch) {
        Ok(Search::Found(state)) => Ok(state),
        Ok(Search::None) => Err(walk::NO_THREAD),
        Ok(Search::Unsearched) => Err(walk::UNSEARCHED),
        Err(()) => Err(walk::FAILED),
    }
}

/// Copies the frames of the thread whose state is `state` to `to`, which
/// has `ROOM` bytes, each after its address, and returns how the walk went,
/// of `walk`, how many frames it copied and how many bytes each takes.
#[inline(always)]
pub(crate) fn frames(walk: Option<&Walk>, state: u64, to: *mut u8) -> (u32, u32, u32) {
    let Some(walk) = walk else {
        return (walk::NONE, 0, 0);
    };
    // Bounded by masks, which the verifier keeps track of where it loses
    // the bounds of comparisons on values the compiler keeps on the stack.
    // uhr checks each walk, so they change no value.
    let bytes = walk.frame_bytes as usize & (MAX_WALKED_BYTES - 1);
    let next = walk.next_frame as usize & (MAX_WALKED_BYTES - 1);
    let reads = (walk.reads_len as usize).min(MAX_READS);
    let each = 8 + bytes + 8 * reads;
    if (walk.step == step::POINTER && next + 8 > bytes) || each > MAX_WALKED_BYTES {
        return (walk::FAILED, 0, 0);
    }
    let Some(frame) = follow(state, &walk.frame, walk.frame_len) else {
        return (walk::FAILED, 0, 0);
    };
    // Where an array of frames ends, which a walk by pointers never reaches.
    let end = match walk.step {
        step::STRIDE => {
            let start = read(state.wrapping_add(u64::from(walk.end_start))).unwrap_or(0);
            let count = read(state.wrapping_add(u64::from(walk.end_count))).unwrap_or(0);
            start.wrapping_add(count.wrapping_mul(u64::from(walk.end_scale)))
        }
        _ => u64::MAX,
    };
    // A walk without reads does none: chosen once, as for the next frame.
    let steps = Steps {
        frame,
        end,
        bytes,
        next,
        each,
    };
    match reads {
        0 => steps.copy::<false>(walk, to),
        _ => steps.copy::<true>(walk, to),
    }
}

/// A walk in the runtime's memory from its innermost `frame` until `end`,
/// each frame `each` bytes, `bytes` of them its copy, which holds the next
/// one at `next` for a walk by pointers.
struct Steps {
    frame: u64,
    end: u64,
    bytes: usize,
    next: usize,
    each: usize,
}

impl Steps {
    /// Copies the frames to `to`, and their reads if `READS`, and returns as
    /// `frames` does.
    #[inline(always)]
    fn copy<const READS: bool>(self, walk: &Walk, to: *mut u8) -> (u32, u32, u32) {
        let Steps {
            mut frame,
            end,
            bytes,
            next,
            each,
        } = self;
        // Chosen once by masks, so that no branch in each frame doubles the
        // states the verifier checks: the next frame is the pointer the
        // frame holds, or the frame and the stride.
        let by_pointer = 0u64.wrapping_sub(u64::from(walk.step == step::POINTER));
        let stride = (walk.next_frame as i32 as i64 as u64) & !by_pointer;
        let mut copied = 0;
        while copied < MAX_WALKED_FRAMES {
            if frame == 0 || frame >= end {
                return (walk::DONE, copied as u32, each as u32);
            }
            // Masked for the verifier, which loses the bound on `each`,
            // behind a barrier, as in `native`.
            let at = core::hint::black_box(copied * each) & (WALKED_BYTES - 1);
            let address = unsafe { to.add(at) };
            unsafe { address.cast::<u64>().write_unaligned(frame) };
            let into = unsafe { address.add(8) };
            let from = frame.wrapping_add(walk.copy_from as i64 as u64);
            let read =
                unsafe { bpf_probe_read_user(into.cast(), bytes as u32, from as *const c_void) };
            if read != 0 {
                return (walk::FAILED, copied as u32, each as u32);
            }
            if READS {
                read_words(walk, into, bytes);
            }
            let pointer = unsafe { into.add(next).cast::<u64>().read_unaligned() };
            frame = (pointer & by_pointer) | frame.wrapping_add(stride) & !by_pointer;
            copied += 1;
        }
        let status = if frame == 0 || frame >= end {
            walk::DONE
        } else {
            walk::CUT
        };
        (status, copied as u32, each as u32)
    }
}

/// The word at `address`, 0 where it can't be read, which the helper
/// fills its copy with then, so that no branch doubles the states the
/// verifier checks.
#[inline(always)]
fn word_at(address: u64) -> u64 {
    let mut value = 0u64;
    unsafe { bpf_probe_read_user((&mut value as *mut u64).cast(), 8, address as *const c_void) };
    value
}

/// The word `wanted` gives for a frame whose copy is at `copy`: the one at
/// its offset from the pointer the copy holds, 0 where that can't be read,
/// as from a null pointer. uhr checks that the copy holds the pointer, and
/// the mask keeps the verifier inside the room for the frame without a
/// branch.
#[inline(always)]
fn read_word(wanted: &Read, copy: *const u8) -> u64 {
    let word = wanted.word as usize & (MAX_WALKED_BYTES - 1);
    let pointer = unsafe { copy.add(word).cast::<u64>().read_unaligned() };
    word_at(pointer.wrapping_add(wanted.offset as i64 as u64))
}

/// Writes the words `walk` reads of a frame after its copy, at `into`, of
/// `bytes` bytes. All of them, whether the walk has them all or not, so that
/// no branch doubles the states the verifier checks: those it does not have
/// come past the frame, into room the next frame overwrites, or the room
/// past the last.
#[inline(always)]
fn read_words(walk: &Walk, into: *mut u8, bytes: usize) {
    for (r, wanted) in walk.reads.iter().enumerate() {
        let value = read_word(wanted, into);
        unsafe { into.add(bytes + 8 * r).cast::<u64>().write_unaligned(value) };
    }
}

/// Copies what `walk` says of each user frame of a sample whose frame
/// pointers the sampler walked: `frames` holds `kernel` kernel frames, then
/// `user` user frames, each with where it ends, its frame pointer and 16.
/// Writes to `to` as `walk` does, the address of each frame its frame
/// pointer, then its copy, then its reads. A frame whose copy could not be
/// read is all zeros.
#[inline(always)]
pub(crate) fn native(
    walk: &Walk,
    frames: &[u64; crate::samples::FRAME_WORDS],
    kernel: u32,
    user: u32,
    to: *mut u8,
) -> (u32, u32, u32) {
    let bytes = walk.frame_bytes as usize & (MAX_WALKED_BYTES - 1);
    let reads = (walk.reads_len as usize).min(MAX_READS);
    let each = 8 + bytes + 8 * reads;
    if each > MAX_WALKED_BYTES {
        return (walk::FAILED, 0, 0);
    }
    let kernel = kernel as usize & MAX_FRAMES;
    let count = (user as usize & MAX_FRAMES).min(MAX_WALKED_FRAMES);
    // A walk without reads does none, chosen once.
    match reads {
        0 => native_frames::<false>(walk, frames, kernel, count, bytes, each, to),
        _ => native_frames::<true>(walk, frames, kernel, count, bytes, each, to),
    }
}

/// Copies what `native` says of `count` frames, and their reads if `READS`.
#[inline(always)]
fn native_frames<const READS: bool>(
    walk: &Walk,
    frames: &[u64; crate::samples::FRAME_WORDS],
    kernel: usize,
    count: usize,
    bytes: usize,
    each: usize,
    to: *mut u8,
) -> (u32, u32, u32) {
    for i in 0..MAX_WALKED_FRAMES {
        if i >= count {
            break;
        }
        // 0 for the outermost frame, whose copy then fails.
        let end = frames[(kernel + 2 * i + 1) & (crate::samples::FRAME_WORDS - 1)];
        let fp = end.wrapping_sub(16);
        // Masked for the verifier, which loses the bound on `each`. All
        // frames take less, so it changes no value, and the compiler, which
        // knows that, would drop the mask without the barrier.
        let at = core::hint::black_box(i * each) & (WALKED_BYTES - 1);
        let record = unsafe { to.add(at) };
        unsafe { record.cast::<u64>().write_unaligned(fp) };
        let into = unsafe { record.add(8) };
        let from = fp.wrapping_add(walk.copy_from as i64 as u64);
        unsafe { bpf_probe_read_user(into.cast(), bytes as u32, from as *const c_void) };
        if READS {
            read_words(walk, into, bytes);
        }
    }
    (walk::DONE, count as u32, each as u32)
}
