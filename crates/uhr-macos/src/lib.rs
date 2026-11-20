//! Recording on macOS: uhr's sampler, which polls the threads of the
//! target's processes through their task ports, launching and attaching,
//! and what this host needs. Elsewhere this crate holds only what reads no
//! Mach API, so its tests run on any host.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

mod images;
#[cfg(target_os = "macos")]
mod mach;
mod macho;
mod polling;
#[cfg(target_os = "macos")]
mod unwind;

#[cfg(target_os = "macos")]
pub use mach::monotonic_ns;
