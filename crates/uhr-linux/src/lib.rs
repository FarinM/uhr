//! Recording on Linux: perf, uhr's eBPF programs, launching and attaching,
//! and the kernel's symbols. Elsewhere this crate is empty.
#![cfg(target_os = "linux")]

mod btf;
pub mod doctor;
pub mod ebpf;
mod interpreters;
pub mod kallsyms;
pub mod launch;
mod memory;
pub mod perf;
mod perf_map;
mod procfs;
mod runtimes;
