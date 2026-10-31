//! Counts the times each of the target's processes maps a file's code,
//! which its samples say, so that uhr looks for its runtime again once it
//! may have loaded one.

use aya_ebpf::bindings::BPF_NOEXIST;
use aya_ebpf::macros::{fexit, map};
use aya_ebpf::maps::HashMap;
use aya_ebpf::programs::FExitContext;

use crate::targets::{active, current};

const PROT_EXEC: u64 = 0x4;
const MAP_ANONYMOUS: u64 = 0x20;

/// By tgid.
#[map]
static MAPPED: HashMap<u32, u64> = HashMap::with_max_entries(16384, 0);

/// The count of the process `tgid`, its low 32 bits.
pub(crate) fn count(tgid: u32) -> u32 {
    unsafe { MAPPED.get(tgid) }.map_or(0, |&count| count as u32)
}

pub(crate) fn forget(tgid: u32) {
    let _ = MAPPED.remove(tgid);
}

/// Counts once the call returns, so that a sample with the count is taken
/// once uhr can find what it mapped. At the kernel's function behind the
/// mmap syscall, rather than the syscall's tracepoints, which would make
/// every process's every syscall take the kernel's slower path for traced
/// ones.
#[fexit(function = "ksys_mmap_pgoff")]
pub fn mmap_return(ctx: FExitContext) -> i32 {
    let (tgid, _) = current();
    if !active(tgid) {
        return 0;
    }
    // ksys_mmap_pgoff(addr, len, prot, flags, fd, pgoff), then what it
    // returned: an address, or an error from -4095 to -1.
    let prot: u64 = ctx.arg(2);
    let flags: u64 = ctx.arg(3);
    let returned: i64 = ctx.arg(6);
    if prot & PROT_EXEC == 0 || flags & MAP_ANONYMOUS != 0 || (-4095..0).contains(&returned) {
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
