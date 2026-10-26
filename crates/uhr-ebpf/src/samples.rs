//! Samples the stacks of the target's threads at each tick of a CPU's
//! clock.

use core::mem::size_of;

use aya_ebpf::bindings::{BPF_F_USER_STACK, BPF_RB_NO_WAKEUP, bpf_user_pt_regs_t};
use aya_ebpf::helpers::{
    bpf_get_current_task, bpf_get_smp_processor_id, bpf_get_stack, bpf_ktime_get_ns,
    bpf_probe_read_kernel,
};
use aya_ebpf::macros::{map, perf_event, tracepoint};
use aya_ebpf::maps::{HashMap, PerCpuArray, RingBuf};
use aya_ebpf::programs::{PerfEventContext, TracePointContext};
use aya_ebpf::{EbpfContext, Global};
use uhr_ebpf::{MAX_FRAMES, SampleHeader, mode};

use crate::targets::{active, current, running};

#[map]
static SAMPLES: RingBuf = RingBuf::with_byte_size(16 << 20, 0);

/// A sample, and its kernel frames and then its user frames, leaf first.
/// The frames take at most `MAX_FRAMES`, but the verifier checks where
/// the user frames start apart from how many there can be.
#[repr(C)]
pub struct Sample {
    header: SampleHeader,
    frames: [u64; 2 * MAX_FRAMES],
}

/// Where a sample is put together, as it is too big for the stack.
#[map]
static SCRATCH: PerCpuArray<Sample> = PerCpuArray::with_max_entries(1, 0);

/// Samples that found `SAMPLES` full.
#[map]
static DROPPED: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// When each CPU last took a step of going offline, and of coming online,
/// by CPU. The kernel drops the sampling event of a CPU going offline for
/// good, so uhr opens it again once the CPU is back.
#[map]
static WENT_DOWN: HashMap<u32, u64> = HashMap::with_max_entries(4096, 0);
#[map]
static CAME_UP: HashMap<u32, u64> = HashMap::with_max_entries(4096, 0);

#[tracepoint]
pub fn cpuhp_enter(ctx: TracePointContext) -> u32 {
    // cpuhp:cpuhp_enter has the CPU at 8, the state it goes to at 12, and
    // the one whose step this is at 16, above it on the way down and below
    // on the way up.
    let read = unsafe {
        (
            ctx.read_at::<u32>(8),
            ctx.read_at::<i32>(12),
            ctx.read_at::<i32>(16),
        )
    };
    let (Ok(cpu), Ok(target), Ok(step)) = read else {
        return 0;
    };
    let steps = if target < step { &WENT_DOWN } else { &CAME_UP };
    let _ = steps.insert(cpu, unsafe { bpf_ktime_get_ns() }, 0);
    0
}

const FRAME: usize = size_of::<u64>();

/// The kernel's `perf_event_max_stack`, up to `MAX_FRAMES`, which uhr sets
/// at load. As in perf's, a sample's kernel and user frames together take
/// at most this many.
#[unsafe(no_mangle)]
static MAX_STACK: Global<u32> = Global::new(MAX_FRAMES as u32);

/// Where a task's flags are in the kernel's `task_struct`, which uhr sets
/// at load from the kernel's BTF. `u32::MAX` where unknown.
#[unsafe(no_mangle)]
static TASK_FLAGS: Global<u32> = Global::new(u32::MAX);

#[perf_event]
pub fn sample(ctx: PerfEventContext) -> u32 {
    let (tgid, tid) = current();
    if !running() || !active(tgid) {
        return 0;
    }
    let Some(sample) = SCRATCH.get_ptr_mut(0) else {
        return 0;
    };
    let sample = unsafe { &mut *sample };
    // A thread running a guest is sampled in the host's code that entered
    // it, which it does not run, so it gets no frames, as in perf.
    let (ip, mode, kernel, user) = if in_guest() {
        (0, mode::GUEST, 0, 0)
    } else {
        let (kernel, user) = stacks(&ctx, sample);
        let (ip, kernel_mode) = interrupted(unsafe { &(*ctx.ctx).regs });
        let mode = if kernel_mode {
            mode::KERNEL
        } else {
            mode::USER
        };
        (ip, mode, kernel, user)
    };
    sample.header = SampleHeader {
        time_ns: unsafe { bpf_ktime_get_ns() },
        ip,
        tgid,
        tid,
        cpu: unsafe { bpf_get_smp_processor_id() },
        mode,
        kernel_frames: kernel as u32,
        user_frames: user as u32,
    };
    let len = size_of::<SampleHeader>() + (kernel + user) * FRAME;
    if len > size_of::<Sample>() {
        return 0;
    }
    let bytes = unsafe { core::slice::from_raw_parts((sample as *const Sample).cast::<u8>(), len) };
    // uhr reads the ring buffer every few milliseconds, so waking it for
    // each sample would only cost.
    if SAMPLES
        .output::<[u8]>(bytes, BPF_RB_NO_WAKEUP as u64)
        .is_err()
        && let Some(dropped) = DROPPED.get_ptr_mut(0)
    {
        unsafe { *dropped += 1 };
    }
    0
}

/// The instruction the CPU was at, and whether it was in the kernel.
#[cfg(bpf_target_arch = "x86_64")]
fn interrupted(regs: &bpf_user_pt_regs_t) -> (u64, bool) {
    // The low bits of the code segment are the privilege level, 3 in user
    // mode.
    (regs.rip, regs.cs & 3 != 3)
}

#[cfg(bpf_target_arch = "aarch64")]
fn interrupted(regs: &bpf_user_pt_regs_t) -> (u64, bool) {
    // The low bits of the processor state are the exception level and its
    // stack, 0 in user mode.
    (regs.pc, regs.pstate & 0xf != 0)
}

/// Fills `sample` with the kernel's frames and then the user's, and
/// returns how many of each.
fn stacks(ctx: &PerfEventContext, sample: &mut Sample) -> (usize, usize) {
    let frames = sample.frames.as_mut_ptr();
    let limit = (MAX_STACK.load() as usize).min(MAX_FRAMES);
    // Like perf's, the user frames get the room the kernel's leave.
    let kernel =
        unsafe { bpf_get_stack(ctx.as_ptr(), frames.cast(), (MAX_FRAMES * FRAME) as u32, 0) };
    let kernel = (kernel.max(0) as usize / FRAME).min(limit);
    // Never more than the difference, but the verifier needs to see it is
    // no more than the room for frames.
    let room = (limit - kernel).min(MAX_FRAMES);
    let user = match room {
        0 => 0,
        _ => unsafe {
            bpf_get_stack(
                ctx.as_ptr(),
                frames.add(kernel).cast(),
                (room * FRAME) as u32,
                BPF_F_USER_STACK as u64,
            )
        },
    };
    (kernel, (user.max(0) as usize / FRAME).min(room))
}

/// Whether the current thread runs a virtual machine's guest, by the task
/// flag the kernel sets meanwhile, and counts guest time by.
fn in_guest() -> bool {
    const PF_VCPU: u32 = 0x1;
    let offset = TASK_FLAGS.load();
    if offset == u32::MAX {
        return false;
    }
    let task = unsafe { bpf_get_current_task() } as *const u8;
    let flags = unsafe { bpf_probe_read_kernel(task.wrapping_add(offset as usize).cast::<u32>()) };
    flags.is_ok_and(|flags| flags & PF_VCPU != 0)
}
