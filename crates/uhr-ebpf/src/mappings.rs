//! Counts the times each of the target's processes maps a file's code,
//! which its samples say, so that uhr looks for its runtime again once it
//! may have loaded one.

use aya_ebpf::bindings::BPF_NOEXIST;
use aya_ebpf::macros::{map, tracepoint};
use aya_ebpf::maps::{HashMap, LruHashMap};
use aya_ebpf::programs::TracePointContext;

use crate::targets::{active, current};

const PROT_EXEC: u64 = 0x4;
const MAP_ANONYMOUS: u64 = 0x20;

/// By tgid.
#[map]
static MAPPED: HashMap<u32, u64> = HashMap::with_max_entries(16384, 0);

/// The threads in a call that maps a file's code, by id. A thread that
/// exits in one leaves it behind, so the oldest make room.
#[map]
static MAPPING: LruHashMap<u32, u8> = LruHashMap::with_max_entries(4096, 0);

/// The count of the process `tgid`, its low 32 bits.
pub(crate) fn count(tgid: u32) -> u32 {
    unsafe { MAPPED.get(tgid) }.map_or(0, |&count| count as u32)
}

pub(crate) fn forget(tgid: u32) {
    let _ = MAPPED.remove(tgid);
}

// Tracepoints of the one syscall, which run at its calls only, rather than
// raw ones at every syscall. The sampler can't run meanwhile, but mmap is
// called seldom.
#[tracepoint]
pub fn sys_enter_mmap(ctx: TracePointContext) -> u32 {
    let (tgid, tid) = current();
    if !active(tgid) {
        return 0;
    }
    // syscalls:sys_enter_mmap has `prot` at 32 and `flags` at 40.
    let (Ok(prot), Ok(flags)) = (unsafe { ctx.read_at::<u64>(32) }, unsafe {
        ctx.read_at::<u64>(40)
    }) else {
        return 0;
    };
    if prot & PROT_EXEC != 0 && flags & MAP_ANONYMOUS == 0 {
        let _ = MAPPING.insert(tid, 0, 0);
    }
    0
}

/// Counts once the call returns, so that a sample with the count is taken
/// once uhr can find what it mapped.
#[tracepoint]
pub fn sys_exit_mmap(ctx: TracePointContext) -> u32 {
    let (tgid, tid) = current();
    if unsafe { MAPPING.get(tid) }.is_none() {
        return 0;
    }
    let _ = MAPPING.remove(tid);
    // syscalls:sys_exit_mmap has what the call returned at 16, an error
    // from -4095 to -1.
    let Ok(returned) = (unsafe { ctx.read_at::<i64>(16) }) else {
        return 0;
    };
    if (-4095..0).contains(&returned) {
        return 0;
    }
    // Not over the count of a thread that made it first.
    let _ = MAPPED.insert(tgid, 0, u64::from(BPF_NOEXIST));
    let Some(count) = MAPPED.get_ptr_mut(tgid) else {
        return 0;
    };
    // Atomic, so that threads mapping at once all count, which Rust's
    // atomics can't do here, as BPF has no compare-and-swap.
    unsafe {
        core::arch::asm!(
            "lock *(u64 *)({count} + 0) += {one}",
            count = in(reg) count,
            one = in(reg) 1u64,
        );
    }
    0
}
