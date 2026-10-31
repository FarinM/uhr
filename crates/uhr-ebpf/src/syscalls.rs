//! Counts and times the syscalls of the target's processes, per thread and
//! syscall, from their first after exec.

use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::macros::{map, raw_tracepoint};
use aya_ebpf::maps::{Array, HashMap, PerCpuArray};
use aya_ebpf::programs::RawTracePointContext;
use uhr_ebpf::{BUCKETS, CallKey, Calls, SYSCALL_NUMBERS, Start};

use crate::targets::{active, current, running};

/// The syscall each of the target's threads is in, or was in last, by
/// thread id. A thread keeps its entry and writes each call over it, as
/// inserting and removing one at every call costs more than the rest of
/// the counting. It lets go of it as it exits.
#[map]
static STARTS: HashMap<u32, Start> = HashMap::with_max_entries(65536, 0);

#[map]
static CALLS: HashMap<CallKey, Calls> = HashMap::with_max_entries(65536, 0);

/// What a new entry of `CALLS` starts from, as it is too big for the stack.
#[map]
static EMPTY: PerCpuArray<Calls> = PerCpuArray::with_max_entries(1, 0);

/// 1 for each syscall, by number, that uhr was asked not to count.
#[map]
static SKIPPED: Array<u8> = Array::with_max_entries(SYSCALL_NUMBERS, 0);

/// Calls that found `CALLS` or `STARTS` full.
#[map]
static LOST: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

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
    let start = Start {
        ns: unsafe { bpf_ktime_get_ns() },
        tgid,
        nr: nr as u32,
    };
    match STARTS.get_ptr_mut(tid) {
        // Only this thread writes it.
        Some(slot) => unsafe { *slot = start },
        None => {
            if STARTS.insert(tid, start, 0).is_err() {
                lose();
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
    let ns = unsafe { bpf_ktime_get_ns() }.saturating_sub(start.ns);
    let key = CallKey {
        tgid,
        tid,
        nr: start.nr,
        pad: 0,
    };
    start.ns = 0;
    let calls = match CALLS.get_ptr_mut(key) {
        Some(calls) => calls,
        None => {
            let Some(empty) = EMPTY.get(0) else {
                return 0;
            };
            if CALLS.insert(key, empty, 0).is_err() {
                lose();
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

/// Lets go of the entry of the thread `tid`, which exits.
pub(crate) fn forget(tid: u32) {
    let _ = STARTS.remove(tid);
}

/// Moves the entry of a thread that exec'd from `from` to `to`, the id
/// of the process's main thread, which it takes then.
pub(crate) fn exec(from: u32, to: u32) {
    if from == to {
        return;
    }
    if let Some(&start) = unsafe { STARTS.get(from) } {
        let _ = STARTS.remove(from);
        if STARTS.insert(to, start, 0).is_err() {
            lose();
        }
    }
}

fn lose() {
    if let Some(lost) = LOST.get_ptr_mut(0) {
        unsafe { *lost += 1 };
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
