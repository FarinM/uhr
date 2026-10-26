//! Which processes are the target's: the target, and the processes it
//! starts as they start.

use aya_ebpf::Global;
use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_get_current_task, bpf_probe_read_kernel};
use aya_ebpf::macros::{map, tracepoint};
use aya_ebpf::maps::{Array, HashMap, PerCpuArray};
use aya_ebpf::programs::TracePointContext;
use uhr_ebpf::{ACTIVE, HELD};

const CLONE_THREAD: u64 = 0x10000;

/// By tgid. uhr adds the target.
#[map]
static TARGETS: HashMap<u32, u8> = HashMap::with_max_entries(16384, 0);

/// Processes the target started that found `TARGETS` full.
#[map]
static UNFOLLOWED: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Whether the capture runs: uhr sets the first value to 1 when it starts
/// and back to 0 when it stops. The processes are followed all along.
#[map]
static RUNNING: Array<u32> = Array::with_max_entries(1, 0);

pub(crate) fn running() -> bool {
    RUNNING.get(0) == Some(&1)
}

/// The current tgid and thread id.
pub(crate) fn current() -> (u32, u32) {
    let pid_tgid = bpf_get_current_pid_tgid();
    ((pid_tgid >> 32) as u32, pid_tgid as u32)
}

/// Whether to count and sample the process `tgid`.
pub(crate) fn active(tgid: u32) -> bool {
    let state = unsafe { TARGETS.get(tgid) };
    state == Some(&ACTIVE)
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
    if flags & CLONE_THREAD == 0
        && TARGETS.insert(pid as u32, state, 0).is_err()
        && let Some(unfollowed) = UNFOLLOWED.get_ptr_mut(0)
    {
        unsafe { *unfollowed += 1 };
    }
    0
}

/// Where a task's `signal` is in its `task_struct`, and the count of the
/// process's live threads in that `signal_struct`, which uhr sets at load
/// from the kernel's BTF.
#[unsafe(no_mangle)]
static TASK_SIGNAL: Global<u32> = Global::new(u32::MAX);
#[unsafe(no_mangle)]
static SIGNAL_LIVE: Global<u32> = Global::new(u32::MAX);

/// Lets go of a process when its last thread exits, so `TARGETS` can't fill
/// with old ones. Its id is still its own then: the kernel frees it only
/// once the process is reaped.
#[tracepoint]
pub fn sched_process_exit(_ctx: TracePointContext) -> u32 {
    let (tgid, _) = current();
    if unsafe { TARGETS.get(tgid) }.is_none() {
        return 0;
    }
    let task = unsafe { bpf_get_current_task() } as *const u8;
    let signal = task.wrapping_add(TASK_SIGNAL.load() as usize);
    let Ok(signal) = (unsafe { bpf_probe_read_kernel(signal.cast::<u64>()) }) else {
        return 0;
    };
    let live = (signal as *const u8).wrapping_add(SIGNAL_LIVE.load() as usize);
    // The exiting thread is no longer counted.
    if unsafe { bpf_probe_read_kernel(live.cast::<i32>()) } == Ok(0) {
        let _ = TARGETS.remove(tgid);
    }
    0
}

/// Lets go of a process once it is freed, where the kernel's BTF does not
/// say how to see its last thread exit. By then a new process can have
/// taken its id, and with it its place.
#[tracepoint]
pub fn sched_process_free(ctx: TracePointContext) -> u32 {
    // sched:sched_process_free has the task's id at 24. A process's last
    // task freed is its leader, whose id is the process's.
    let Ok(pid) = (unsafe { ctx.read_at::<i32>(24) }) else {
        return 0;
    };
    let _ = TARGETS.remove(pid as u32);
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
