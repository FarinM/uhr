//! Copies the frames of an interpreter that keeps them in its memory rather
//! than on the stack, as CPython does. uhr says for each process where they
//! are, in numbers; this knows no runtime.

use core::ffi::c_void;

use aya_ebpf::bindings::bpf_pidns_info;
use aya_ebpf::helpers::generated::{bpf_get_ns_current_pid_tgid, bpf_probe_read_user};
use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, LruHashMap};
use uhr_ebpf::{MAX_PATH, MAX_THREADS, MAX_WALKED_BYTES, MAX_WALKED_FRAMES, ONE_LIST, Walk, walk};

/// By tgid. uhr sets a process's walk once it knows its runtime.
#[map]
static WALKS: HashMap<u32, Walk> = HashMap::with_max_entries(16384, 0);

/// The state each thread runs in, by its id, so a sample need not search
/// for it again. uhr fills it too, with threads a search can't reach.
#[map]
static THREADS: LruHashMap<u32, u64> = LruHashMap::with_max_entries(16384, 0);

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
        address = read(address.wrapping_add(u64::from(offset)))?;
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

/// Copies the current thread's interpreter frames to `to`, which has `ROOM`
/// bytes, each after its address, and returns how the walk went, of
/// `walk`, how many frames it copied and how many bytes each takes.
#[inline(always)]
pub(crate) fn walk(walk: Option<&Walk>, tid: u32, to: *mut u8) -> (u32, u32, u32) {
    let Some(walk) = walk else {
        return (walk::NONE, 0, 0);
    };
    // Bounded by masks, which the verifier keeps track of where it loses
    // the bounds of comparisons on values the compiler keeps on the stack.
    // uhr checks each walk, so they change no value.
    let bytes = walk.frame_bytes as usize & (MAX_WALKED_BYTES - 1);
    let next = walk.next_frame as usize & (MAX_WALKED_BYTES - 1);
    let each = bytes + 8;
    if next + 8 > bytes || each > MAX_WALKED_BYTES {
        return (walk::FAILED, 0, 0);
    }
    let Some(id) = thread_id(walk, tid) else {
        return (walk::FAILED, 0, 0);
    };
    let state = match thread_state(walk, id, tid, to) {
        Ok(Search::Found(state)) => state,
        Ok(Search::None) => return (walk::NO_THREAD, 0, 0),
        Ok(Search::Unsearched) => return (walk::UNSEARCHED, 0, 0),
        Err(()) => return (walk::FAILED, 0, 0),
    };
    // Read back from the map, the verifier knows only that the search found
    // a state, so it checks the walk of its frames once, not once for each
    // way the search can end.
    unsafe { to.cast::<[u8; 8]>().write(state.to_ne_bytes()) };
    let state = u64::from_ne_bytes(unsafe { core::ptr::read_volatile(to.cast::<[u8; 8]>()) });
    let Some(mut frame) = follow(state, &walk.frame, walk.frame_len) else {
        return (walk::FAILED, 0, 0);
    };
    let mut copied = 0;
    let mut address = to;
    while copied < MAX_WALKED_FRAMES {
        if frame == 0 {
            return (walk::DONE, copied as u32, each as u32);
        }
        unsafe { address.cast::<u64>().write_unaligned(frame) };
        let into = unsafe { address.add(8) };
        let read =
            unsafe { bpf_probe_read_user(into.cast(), bytes as u32, frame as *const c_void) };
        if read != 0 {
            return (walk::FAILED, copied as u32, each as u32);
        }
        frame = unsafe { into.add(next).cast::<u64>().read_unaligned() };
        address = unsafe { address.add(each) };
        copied += 1;
    }
    let status = if frame == 0 { walk::DONE } else { walk::CUT };
    (status, copied as u32, each as u32)
}
