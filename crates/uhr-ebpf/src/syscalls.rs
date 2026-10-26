//! Counts and times the syscalls of the target's processes, per thread and
//! syscall, from their first after exec.

use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns};
use aya_ebpf::macros::{map, raw_tracepoint, tracepoint};
use aya_ebpf::maps::{HashMap, LruHashMap, PerCpuArray};
use aya_ebpf::programs::{RawTracePointContext, TracePointContext};
use uhr_ebpf::{ACTIVE, BUCKETS, CallKey, Calls, HELD, Start};

const CLONE_THREAD: u64 = 0x10000;

/// The processes to count, by tgid. uhr adds the target, and the processes
/// they start are added as they start.
#[map]
static TARGETS: HashMap<u32, u8> = HashMap::with_max_entries(16384, 0);

/// The syscall each thread is in, by thread id. A thread that exits in one
/// leaves it behind, so the oldest make room.
#[map]
static STARTS: LruHashMap<u32, Start> = LruHashMap::with_max_entries(65536, 0);

#[map]
static CALLS: HashMap<CallKey, Calls> = HashMap::with_max_entries(65536, 0);

/// What a new entry of `CALLS` starts from, as it is too big for the stack.
#[map]
static EMPTY: PerCpuArray<Calls> = PerCpuArray::with_max_entries(1, 0);

/// Calls that found `CALLS` full.
#[map]
static LOST: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

fn current() -> (u32, u32) {
    let pid_tgid = bpf_get_current_pid_tgid();
    ((pid_tgid >> 32) as u32, pid_tgid as u32)
}

// Raw tracepoints, for which the kernel builds no trace record, and whose
// programs don't keep other BPF programs from running meanwhile, as
// tracepoints' do.
#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn sys_enter(ctx: RawTracePointContext) -> i32 {
    let (tgid, tid) = current();
    if unsafe { TARGETS.get(tgid) } != Some(&ACTIVE) {
        return 0;
    }
    // The registers, then the syscall's number.
    let nr: i64 = ctx.arg(1);
    let start = Start {
        ns: unsafe { bpf_ktime_get_ns() },
        tgid,
        nr: nr as u32,
    };
    let _ = STARTS.insert(tid, start, 0);
    0
}

#[raw_tracepoint(tracepoint = "sys_exit")]
pub fn sys_exit(_ctx: RawTracePointContext) -> i32 {
    let (_, tid) = current();
    let Some(&start) = (unsafe { STARTS.get(tid) }) else {
        return 0;
    };
    let _ = STARTS.remove(tid);
    let ns = unsafe { bpf_ktime_get_ns() }.saturating_sub(start.ns);
    let key = CallKey {
        tgid: start.tgid,
        tid,
        nr: start.nr,
        pad: 0,
    };
    let calls = match CALLS.get_ptr_mut(key) {
        Some(calls) => calls,
        None => {
            let Some(empty) = EMPTY.get(0) else {
                return 0;
            };
            if CALLS.insert(key, empty, 0).is_err() {
                if let Some(lost) = LOST.get_ptr_mut(0) {
                    unsafe { *lost += 1 };
                }
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

#[tracepoint]
pub fn task_newtask(ctx: TracePointContext) -> u32 {
    // The parent runs it, so the current process is the parent.
    let (tgid, _) = current();
    let Some(&state) = (unsafe { TARGETS.get(tgid) }) else {
        return 0;
    };
    // task:task_newtask has the new task's pid at 8 and its clone flags at
    // 32. A thread belongs to a process counted already.
    let (Ok(pid), Ok(flags)) = (unsafe { ctx.read_at::<i32>(8) }, unsafe {
        ctx.read_at::<u64>(32)
    }) else {
        return 0;
    };
    if flags & CLONE_THREAD == 0 {
        let _ = TARGETS.insert(pid as u32, state, 0);
    }
    0
}

#[tracepoint]
pub fn sched_process_exec(_ctx: TracePointContext) -> u32 {
    // A target held before its exec runs uhr's code until then.
    let (tgid, _) = current();
    if unsafe { TARGETS.get(tgid) } == Some(&HELD) {
        let _ = TARGETS.insert(tgid, ACTIVE, 0);
    }
    0
}
