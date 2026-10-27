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

/// The most bytes of user stack a sample copies, as perf's limit.
pub const MAX_STACK_COPY: usize = 65528;

/// What precedes a sample's frames in the ring buffer: its kernel frames,
/// then its user frames, each leaf first. A sample with a stack copy has
/// no user frames, but then `UserRegisters` and the copy.
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
    /// Bytes of user stack copied, after the user registers.
    pub stack_bytes: u32,
    /// Whether `UserRegisters` and the copy follow the frames.
    pub copy: u32,
    /// How the walk of interpreter frames went, of `walk`.
    pub walk: u32,
    /// Interpreter frames copied, innermost first, after all else, and
    /// the bytes of each: its address, then the bytes copied of it.
    pub walked_frames: u32,
    pub walked_bytes: u32,
    /// Whether each user frame is followed by where it ends on the stack,
    /// from walking its frame pointers: the frame pointer of its function
    /// and 16, as the canonical frame address. 0 for the outermost.
    pub frame_ends: u32,
    /// How many times the process had exec'd, as its task counts, so that
    /// samples of one program tell apart from those of the next. 0 where
    /// uhr can't tell.
    pub exec: u32,
    /// How many times the process had mapped a file's code since the
    /// programs started, its low 32 bits.
    pub mapped: u32,
}

/// The most interpreter frames a sample walks. Each frame's address, its
/// copy and its reads take at most `MAX_WALKED_BYTES`, a power of two, and
/// all of them less than `WALKED_BYTES`, another.
pub const MAX_WALKED_FRAMES: usize = 127;
pub const MAX_WALKED_BYTES: usize = 128;
pub const WALKED_BYTES: usize = 1 << 14;
const _: () = assert!(MAX_WALKED_FRAMES * MAX_WALKED_BYTES < WALKED_BYTES);

/// The most pointers followed to a process's lists of thread states, or
/// from a state to its innermost frame.
pub const MAX_PATH: usize = 4;

/// The most thread states searched for the sampled thread's, and lists of
/// them gone through.
pub const MAX_THREADS: usize = 256;

/// `Walk::next_list` for a process with one list of thread states.
pub const ONE_LIST: u32 = u32::MAX;

/// The most words read for each frame, after its copy.
pub const MAX_READS: usize = 2;

/// Where a walk finds the frames, of `Walk::frames`.
pub mod frames {
    /// In the runtime's memory: from the sampled thread's state, which it
    /// keeps in lists, to the innermost frame, then from frame to frame.
    pub const STATES: u32 = 0;
    /// On the native stack: each frame the sampler's walk of frame pointers
    /// finds, at its frame pointer.
    pub const NATIVE: u32 = 1;
    /// In the runtime's memory: from the sampled thread's thread pointer
    /// to the innermost frame, as for a runtime that keeps it in a
    /// thread-local, then from frame to frame.
    pub const THREAD_POINTER: u32 = 2;
    /// In the runtime's memory: from the state at `Walk::base`, for a
    /// runtime that runs on one thread, then from frame to frame.
    pub const GLOBAL: u32 = 3;
}

/// How a walk in the runtime's memory gets from a frame to the next one
/// outward, of `Walk::step`.
pub mod step {
    /// By the pointer at `Walk::next_frame` in the frame.
    pub const POINTER: u32 = 0;
    /// `Walk::next_frame` bytes on, as in an array of frames.
    pub const STRIDE: u32 = 1;
}

/// A word read at the time of a sample at a signed offset from a pointer a
/// frame's copy holds. Offsets in paths in `Walk` are signed too.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Read {
    /// Where the copy holds the pointer.
    pub word: u32,
    pub offset: i32,
}

/// How uhr's programs find and copy a runtime's frames in one process. uhr
/// sets it for each process whose runtime it knows, and the programs know
/// no runtime.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Walk {
    /// Where the frames are, of `frames`.
    pub frames: u32,
    /// Whether to walk the user stack by its frame pointers, keeping where
    /// each frame ends, which `frames::NATIVE` needs, and so that the
    /// interpreter's frames can be placed by where it keeps some of them on
    /// the native stack.
    pub frame_pointers: u32,
    /// For `frames::STATES`: the thread states are in lists, one for each
    /// entry of an outer list, as CPython keeps one for each interpreter.
    /// The first entry is at the pointer `lists[0]` past `base`, then at the
    /// pointer each next offset past the one before, and each next entry at
    /// the pointer `next_list` past it.
    pub base: u64,
    /// The process's PID namespace, by the device and inode of its file,
    /// which the thread ids in states are in.
    pub pid_namespace: [u64; 2],
    pub lists: [u32; MAX_PATH],
    pub lists_len: u32,
    pub next_list: u32,
    /// Where an entry holds its first state, and a state the next one.
    pub first_state: u32,
    pub next_state: u32,
    /// Where a state holds its thread's id, as a 64-bit number in the
    /// process's PID namespace.
    pub thread_id: u32,
    /// A thread can have a state in several lists. The one it runs in has a
    /// bit of `active_mask` set in the 32-bit word at `active`, where the
    /// runtime marks it so, and else is the first with frames. A mask of 0
    /// for a runtime that does not.
    pub active: u32,
    pub active_mask: u32,
    /// For `frames::THREAD_POINTER`: the pointers to follow from the
    /// thread pointer to the thread's state, as for `lists`.
    pub state: [u32; MAX_PATH],
    pub state_len: u32,
    /// The pointers to follow from a thread's state to its innermost frame,
    /// as for `lists`.
    pub frame: [u32; MAX_PATH],
    pub frame_len: u32,
    /// How to get from a frame to the next one outward, of `step`, and
    /// where the frame holds it or how far on it is.
    pub step: u32,
    pub next_frame: u32,
    /// For `step::STRIDE`: the frames end at the pointer the state holds at
    /// `end_start`, plus `end_scale` times the number it holds at
    /// `end_count`.
    pub end_start: u32,
    pub end_count: u32,
    pub end_scale: u32,
    /// Where each frame's copy starts, from its address, and its bytes.
    pub copy_from: i32,
    pub frame_bytes: u32,
    /// The words to read for each frame, which follow its copy.
    pub reads: [Read; MAX_READS],
    pub reads_len: u32,
    pub pad: u32,
}

// No padding, which `Pod` needs.
const _: () = assert!(core::mem::size_of::<Walk>() == 168);

/// How a sample's walk of interpreter frames went.
pub mod walk {
    /// Its process has no walk.
    pub const NONE: u32 = 0;
    /// The runtime keeps no state for the thread, as for one it does not
    /// run on.
    pub const NO_THREAD: u32 = 1;
    /// To the outermost frame.
    pub const DONE: u32 = 2;
    /// Cut at `MAX_WALKED_FRAMES`.
    pub const CUT: u32 = 3;
    /// A thread's state or frame could not be read, or the native stack's
    /// frame pointers were not walked.
    pub const FAILED: u32 = 4;
    /// The thread's state was not among the first `MAX_THREADS` searched.
    pub const UNSEARCHED: u32 = 5;
}

/// The user registers a stack copy is unwound from.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct UserRegisters {
    pub ip: u64,
    pub sp: u64,
    pub bp: u64,
    /// Whether they are those of 32-bit code.
    pub compat: u64,
}

#[cfg(feature = "user")]
mod user {
    // SAFETY: plain data of fixed layout without padding.
    unsafe impl aya::Pod for super::Start {}
    unsafe impl aya::Pod for super::CallKey {}
    unsafe impl aya::Pod for super::Calls {}
    unsafe impl aya::Pod for super::Walk {}
    unsafe impl aya::Pod for super::Read {}
}
