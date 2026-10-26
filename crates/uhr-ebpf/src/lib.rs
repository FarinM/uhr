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

/// The most frames of a sample's stacks, kernel and user together, as
/// the kernel's default `perf_event_max_stack`.
pub const MAX_FRAMES: usize = 127;

/// What a CPU ran when sampled.
pub mod mode {
    pub const USER: u32 = 0;
    pub const KERNEL: u32 = 1;
    /// A virtual machine's guest, whose frames a sample has none of.
    pub const GUEST: u32 = 2;
}

/// What precedes a sample's frames in the ring buffer: its kernel frames,
/// then its user frames, each leaf first.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SampleHeader {
    pub time_ns: u64,
    /// The instruction the CPU was at.
    pub ip: u64,
    pub tgid: u32,
    pub tid: u32,
    pub cpu: u32,
    /// What the CPU ran, of `mode`.
    pub mode: u32,
    pub kernel_frames: u32,
    pub user_frames: u32,
}

#[cfg(feature = "user")]
mod user {
    // SAFETY: plain data of fixed layout without padding.
    unsafe impl aya::Pod for super::Start {}
    unsafe impl aya::Pod for super::CallKey {}
    unsafe impl aya::Pod for super::Calls {}
}
