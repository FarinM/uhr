//! Recording on macOS: uhr's sampler, which polls the threads of the
//! target's processes through their task ports, launching and attaching,
//! and what this host needs. Elsewhere this crate holds only what reads no
//! Mach API, so its tests run on any host.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

#[cfg(target_os = "macos")]
pub mod doctor;
#[cfg(target_os = "macos")]
mod held;
mod images;
#[cfg(target_os = "macos")]
mod launch;
#[cfg(target_os = "macos")]
mod mach;
mod macho;
mod polling;
#[cfg(target_os = "macos")]
mod process;
#[cfg(target_os = "macos")]
mod record;
#[cfg(target_os = "macos")]
mod runtime;
#[cfg(target_os = "macos")]
mod unwind;

#[cfg(target_os = "macos")]
pub use mach::monotonic_ns;
#[cfg(target_os = "macos")]
pub use record::{Error, MEMORY_INTERVAL, RecordOptions, Target, record};
