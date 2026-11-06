//! Counts and times the syscalls of the target's processes, per thread, the
//! name it had then, syscall and interval of time, from their first after
//! exec.

use core::ptr;

use aya_ebpf::bindings::BPF_NOEXIST;
use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_current_task, bpf_ktime_get_ns, bpf_probe_read_kernel_str_bytes,
};
use aya_ebpf::macros::{map, raw_tracepoint};
use aya_ebpf::maps::{Array, HashMap, PerCpuArray};
use aya_ebpf::programs::RawTracePointContext;
use uhr_ebpf::{BUCKETS, CALL_INTERVAL_SHIFT, CallKey, Calls, SYSCALL_NUMBERS, Start};

use crate::targets::{active, current, ids, running};

/// The syscall each of the target's threads is in, or was in last, by
/// thread id. A thread keeps its entry and writes each call over it, as
/// inserting and removing one at every call costs more than the rest of
/// the counting. It lets go of it as it exits. The entry also keeps the
/// thread's name, so the calls need not read it.
#[map]
static STARTS: HashMap<u32, Start> = HashMap::with_max_entries(65536, 0);

/// The names of the threads counted, as the kernel keeps them: up to 15
/// bytes, then zeros. By their hash, which the entries of `STARTS` and
/// `CALLS` keep in their place. uhr reads them at the end.
#[map]
static NAMES: HashMap<u64, [u8; 16]> = HashMap::with_max_entries(65536, 0);

/// uhr takes each interval out half an interval after it ends, as the
/// capture goes on, so this holds two at most: room for 65536 threads,
/// names and syscalls with calls in each.
#[map]
static CALLS: HashMap<CallKey, Calls> = HashMap::with_max_entries(131072, 0);

/// What a new entry of `CALLS` starts from, as it is too big for the stack.
#[map]
static EMPTY: PerCpuArray<Calls> = PerCpuArray::with_max_entries(1, 0);

/// 1 for each syscall, by number, that uhr was asked not to count.
#[map]
static SKIPPED: Array<u8> = Array::with_max_entries(SYSCALL_NUMBERS, 0);

/// Calls that found `CALLS` or `STARTS` full.
#[map]
static LOST: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Renames of one of the target's threads by another that the programs
/// could not follow, without the kernel's BTF to say which thread a task is.
#[map]
static MISSED_RENAMES: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

// Raw tracepoints, for which the kernel builds no trace record, and whose
// programs don't keep other BPF programs from running meanwhile, as
// tracepoints' do.
#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn sys_enter(ctx: RawTracePointContext) -> i32 {
    let (tgid, tid) = current();
    // The registers, then the syscall's number.
    let nr: i64 = ctx.arg(1);
    // A skipped call leaves the thread's entry as its last call's return
    // left it, so its own return counts nothing.
    if !running() || SKIPPED.get(nr as u32) == Some(&1) || !active(tgid) {
        return 0;
    }
    let ns = unsafe { bpf_ktime_get_ns() };
    match STARTS.get_ptr_mut(tid) {
        // Only this thread writes these, and `task_rename` the name.
        Some(slot) => unsafe {
            (*slot).ns = ns;
            (*slot).tgid = tgid;
            (*slot).nr = nr as u32;
        },
        None => {
            let start = Start {
                ns,
                tgid,
                nr: nr as u32,
                name: named(bpf_get_current_comm().unwrap_or_default()),
            };
            if STARTS.insert(tid, start, 0).is_err() {
                count(&LOST);
            }
        }
    }
    0
}

#[raw_tracepoint(tracepoint = "sys_exit")]
pub fn sys_exit(_ctx: RawTracePointContext) -> i32 {
    // Calls still running when the capture stopped are left for uhr.
    if !running() {
        return 0;
    }
    let (tgid, tid) = current();
    let Some(start) = STARTS.get_ptr_mut(tid) else {
        return 0;
    };
    let start = unsafe { &mut *start };
    // A new thread's first exit, from the clone, has no entry of its own,
    // but can find that of a thread whose id it took.
    if start.ns == 0 || start.tgid != tgid {
        return 0;
    }
    let now = unsafe { bpf_ktime_get_ns() };
    let ns = now.saturating_sub(start.ns);
    let key = CallKey {
        tgid,
        tid,
        nr: start.nr,
        interval: (now >> CALL_INTERVAL_SHIFT) as u32,
        name: unsafe { ptr::read_volatile(&start.name) },
    };
    start.ns = 0;
    let calls = match CALLS.get_ptr_mut(key) {
        Some(calls) => calls,
        None => {
            let Some(empty) = EMPTY.get(0) else {
                return 0;
            };
            if CALLS.insert(key, empty, 0).is_err() {
                count(&LOST);
                return 0;
            }
            let Some(calls) = CALLS.get_ptr_mut(key) else {
                return 0;
            };
            calls
        }
    };
    // Only this thread updates its entries, one syscall at a time.
    let calls = unsafe { &mut *calls };
    calls.calls += 1;
    calls.ns += ns;
    if let Some(bucket) = calls.buckets.get_mut(bucket(ns)) {
        *bucket += 1;
    }
    0
}

/// Keeps the name of a counted thread as the kernel renames it, by prctl,
/// a write to its `comm` file, which can come from another thread, or
/// exec. A thread that has made no call yet reads its name at its first.
#[raw_tracepoint(tracepoint = "task_rename")]
pub fn task_rename(ctx: RawTracePointContext) -> i32 {
    // The names stay as they were when the capture stopped, for the calls
    // still running then.
    if !running() {
        return 0;
    }
    let task: u64 = ctx.arg(0);
    let renamed = if task == unsafe { bpf_get_current_task() } {
        current().1
    } else if let Some((_, tid)) = ids(task as *const u8) {
        tid
    } else {
        // Only a thread of the same process can rename another.
        if active(current().0) {
            count(&MISSED_RENAMES);
        }
        return 0;
    };
    let Some(start) = STARTS.get_ptr_mut(renamed) else {
        return 0;
    };
    // Zeros after the name, as the kernel keeps it, whatever followed it
    // where it was copied from.
    let mut comm = [0u8; 16];
    let name: u64 = ctx.arg(1);
    if unsafe { bpf_probe_read_kernel_str_bytes(name as *const u8, &mut comm) }.is_ok() {
        unsafe { ptr::write_volatile(&raw mut (*start).name, named(comm)) };
    }
    0
}

/// The key of the name `comm` in `NAMES`, which keeps it from then on.
fn named(comm: [u8; 16]) -> u64 {
    // FNV-1a. Two names of one hash would share the first's.
    let mut name = 0xcbf2_9ce4_8422_2325_u64;
    for byte in comm {
        name = (name ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
    }
    // A name the map has no room for has no key there, which uhr finds.
    let _ = NAMES.insert(name, comm, u64::from(BPF_NOEXIST));
    name
}

/// Lets go of the entry of the thread `tid`, which exits.
pub(crate) fn forget(tid: u32) {
    let _ = STARTS.remove(tid);
}

/// Moves the entry of a thread that exec'd from `from` to `to`, the id
/// of the process's main thread, which it takes then. Its rename at the
/// exec came after it took that id, so the entry moved has the old name.
pub(crate) fn exec(from: u32, to: u32) {
    // The entries stay as they were when the capture stopped.
    if from == to || !running() {
        return;
    }
    if let Some(&start) = unsafe { STARTS.get(from) } {
        let _ = STARTS.remove(from);
        let start = Start {
            name: bpf_get_current_comm().map_or(start.name, named),
            ..start
        };
        if STARTS.insert(to, start, 0).is_err() {
            count(&LOST);
        }
    }
}

fn count(counter: &PerCpuArray<u64>) {
    if let Some(count) = counter.get_ptr_mut(0) {
        unsafe { *count += 1 };
    }
}

/// The base 2 log of `ns`, up to the last bucket.
fn bucket(ns: u64) -> usize {
    let (mut log, mut rest) = (0, ns);
    for shift in [32, 16, 8, 4, 2, 1] {
        if rest >> shift != 0 {
            rest >>= shift;
            log += shift;
        }
    }
    (log as usize).min(BUCKETS - 1)
}
