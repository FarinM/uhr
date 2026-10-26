//! uhr's eBPF programs. Built for the BPF target only; elsewhere this is an
//! empty program.
#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", no_main)]

#[cfg(target_arch = "bpf")]
mod syscalls;

#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // SAFETY: the verifier rejects programs that can reach a panic.
    unsafe { core::hint::unreachable_unchecked() }
}

/// The helpers that read memory, which tracepoints and stack walks need,
/// are for GPL-compatible programs only.
#[cfg(target_arch = "bpf")]
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

#[cfg(not(target_arch = "bpf"))]
fn main() {}
