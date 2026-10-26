//! Recording on Linux: perf, uhr's eBPF programs, launching and attaching,
//! and the kernel's symbols. Elsewhere this crate is empty.
#![cfg(target_os = "linux")]

pub mod doctor;
pub mod ebpf;
pub mod kallsyms;
pub mod launch;
pub mod perf;
mod perf_map;
mod runtimes;
