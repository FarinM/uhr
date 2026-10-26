//! What uhr's eBPF programs and uhr share: the layout of their maps.
#![no_std]

/// Latency buckets: bucket `i` counts calls of at least `2^i` ns and less
/// than `2^(i + 1)`, and the last one also every longer call.
pub const BUCKETS: usize = 36;

/// A process's state in `TARGETS`.
pub const HELD: u8 = 0;
pub const ACTIVE: u8 = 1;

/// A syscall a thread is in, by its thread id in `STARTS`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Start {
    pub ns: u64,
    pub tgid: u32,
    pub nr: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CallKey {
    pub tgid: u32,
    pub tid: u32,
    pub nr: u32,
    pub pad: u32,
}

/// The calls a thread made to one syscall that returned.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Calls {
    pub calls: u64,
    pub ns: u64,
    pub buckets: [u64; BUCKETS],
}

#[cfg(feature = "user")]
mod user {
    // SAFETY: plain data of fixed layout without padding.
    unsafe impl aya::Pod for super::Start {}
    unsafe impl aya::Pod for super::CallKey {}
    unsafe impl aya::Pod for super::Calls {}
}
