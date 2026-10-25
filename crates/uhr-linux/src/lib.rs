//! Recording on Linux: perf, launching and attaching, and the kernel's
//! symbols. Elsewhere this crate is empty.
#![cfg(target_os = "linux")]

pub mod doctor;
pub mod kallsyms;
pub mod launch;
pub mod perf;
mod perf_map;
mod runtimes;
