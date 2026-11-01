//! Sees the kernel wake the target's threads: when, and what woke them, with
//! its stack.

use core::mem::size_of;

use aya_ebpf::bindings::{BPF_F_USER_STACK, BPF_RB_NO_WAKEUP};
use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_current_task, bpf_get_smp_processor_id, bpf_get_stack,
    bpf_ktime_get_ns, bpf_probe_read_kernel,
};
use aya_ebpf::macros::{map, raw_tracepoint};
use aya_ebpf::maps::{Array, PerCpuArray, RingBuf};
use aya_ebpf::programs::RawTracePointContext;
use aya_ebpf::{EbpfContext, Global};
use uhr_ebpf::{
    MAX_FRAMES, MAX_STACK_COPY, SampleHeader, UserRegisters, Wakeup, event, mode, walk,
};

use crate::samples::{
    FRAME, FRAME_WORDS, MAX_STACK, PAGE, STACK_BYTES, copy_stack, saved_user_registers,
};
use crate::targets::{active, current, running};

/// Apart from the samples, so that a target that wakes its threads often
/// can't crowd them out. uhr sets its size at load.
#[map]
static WAKEUPS: RingBuf = RingBuf::with_byte_size(16 << 20, 0);

/// Wakeups that found `WAKEUPS` full.
#[map]
static WAKEUPS_DROPPED: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Where a `task_struct` keeps its process's id and its own, which uhr sets
/// at load from the kernel's BTF.
#[unsafe(no_mangle)]
static TASK_TGID: Global<u32> = Global::new(u32::MAX);
#[unsafe(no_mangle)]
static TASK_PID: Global<u32> = Global::new(u32::MAX);

/// Where a `task_struct` keeps its softirq count, which only `PREEMPT_RT` has
/// and where it counts them instead of in the preempt count. uhr sets it at
/// load from the kernel's BTF.
#[unsafe(no_mangle)]
static TASK_SOFTIRQS: Global<u32> = Global::new(u32::MAX);

/// Where the kernel keeps the preempt count, which says whether the CPU
/// runs an interrupt: this far into each CPU's area, whose addresses the
/// array at `PER_CPU_OFFSETS` holds by CPU, or into the current task where
/// that is 0. uhr sets them at load.
#[unsafe(no_mangle)]
static PREEMPT_COUNT: Global<u64> = Global::new(u64::MAX);
#[unsafe(no_mangle)]
static PER_CPU_OFFSETS: Global<u64> = Global::new(0);

/// A wakeup, as `samples::Sample` without interpreter frames.
#[repr(C)]
pub struct Woken {
    header: SampleHeader,
    wakeup: Wakeup,
    frames: [u64; FRAME_WORDS],
}

/// Where a wakeup is put together, as it is too big for the stack. Apart
/// from the sampler's, which can interrupt this program.
#[map]
static WOKEN: PerCpuArray<Woken> = PerCpuArray::with_max_entries(1, 0);

/// A wakeup with a copy of the waker's user stack, as `samples::Copy`.
#[repr(C)]
pub struct WokenCopy {
    header: SampleHeader,
    wakeup: Wakeup,
    data: [u8; MAX_FRAMES * FRAME + size_of::<UserRegisters>() + MAX_STACK_COPY + PAGE],
}

/// By CPU, as `samples::COPIES`. uhr sets how many CPUs at load.
#[map]
static WOKEN_COPIES: Array<WokenCopy> = Array::with_max_entries(1, 0);

/// The kernel's frames a raw tracepoint's stack starts with, which this
/// program and the kernel's way into it take: the program,
/// `bpf_trace_run1` and the tracepoint's `__bpf_trace_*`.
const OWN_FRAMES: u64 = 3;

#[raw_tracepoint(tracepoint = "sched_waking")]
pub fn sched_waking(ctx: RawTracePointContext) -> i32 {
    if !running() {
        return 0;
    }
    // The task woken. Not only those off a run queue: this runs before the
    // kernel locks the queue, so one still on it is often just about to sleep,
    // and uhr tells them apart by its switch out.
    let task: u64 = ctx.arg(0);
    let Some((tgid, tid)) = ids(task as *const u8) else {
        return 0;
    };
    if !active(tgid) {
        return 0;
    }
    let Some(interrupt) = in_interrupt() else {
        return 0;
    };
    let wakeup = Wakeup {
        tgid,
        tid,
        interrupt: u32::from(interrupt),
        pad: 0,
        comm: bpf_get_current_comm().unwrap_or_default(),
    };
    // What an interrupt interrupted did not wake the thread, and uhr can
    // name the user frames of the target's threads only.
    let user = !interrupt && active(current().0);
    let stack_bytes = (STACK_BYTES.load() as usize).min(MAX_STACK_COPY);
    if stack_bytes > 0 {
        woken_with_copy(&ctx, wakeup, user, stack_bytes);
    } else {
        woken(&ctx, wakeup, user);
    }
    0
}

/// The process and thread ids of `task`.
fn ids(task: *const u8) -> Option<(u32, u32)> {
    let read = |offset: u32| unsafe {
        bpf_probe_read_kernel(task.wrapping_add(offset as usize).cast::<u32>()).ok()
    };
    Some((read(TASK_TGID.load())?, read(TASK_PID.load())?))
}

/// Whether the CPU runs an interrupt: a hard one, an NMI, or the kernel's
/// work deferred from one, a softirq.
fn in_interrupt() -> Option<bool> {
    // The kernel's `SOFTIRQ_OFFSET`, which only serving a softirq sets, not
    // holding them off.
    const SOFTIRQ: u32 = 0x100;
    // And its `NMI_MASK` and `HARDIRQ_MASK`.
    const INTERRUPT: u32 = 0x00f0_0000 | 0x000f_0000 | SOFTIRQ;
    let task = unsafe { bpf_get_current_task() };
    let base = match PER_CPU_OFFSETS.load() {
        0 => task,
        offsets => {
            let cpu = u64::from(unsafe { bpf_get_smp_processor_id() });
            let at = offsets.wrapping_add(cpu * 8) as *const u64;
            unsafe { bpf_probe_read_kernel(at) }.ok()?
        }
    };
    let at = base.wrapping_add(PREEMPT_COUNT.load()) as *const u32;
    let count = unsafe { bpf_probe_read_kernel(at) }.ok()?;
    let softirqs = match TASK_SOFTIRQS.load() {
        u32::MAX => 0,
        at => {
            let at = task.wrapping_add(u64::from(at)) as *const u32;
            unsafe { bpf_probe_read_kernel(at) }.ok()?
        }
    };
    Some(count & INTERRUPT != 0 || softirqs & SOFTIRQ != 0)
}

/// Writes a wakeup with the kernel's frames, and the user's if `user`.
fn woken(ctx: &RawTracePointContext, wakeup: Wakeup, user: bool) {
    let Some(woken) = WOKEN.get_ptr_mut(0) else {
        return;
    };
    let woken = unsafe { &mut *woken };
    let frames = woken.frames.as_mut_ptr();
    let limit = (MAX_STACK.load() as usize).min(MAX_FRAMES);
    let kernel = unsafe {
        bpf_get_stack(
            ctx.as_ptr(),
            frames.cast(),
            (MAX_FRAMES * FRAME) as u32,
            OWN_FRAMES,
        )
    };
    let kernel = (kernel.max(0) as usize / FRAME).min(limit);
    // As the sampler's, the user frames get the room the kernel's leave.
    let room = (limit - kernel).min(MAX_FRAMES);
    let user = match room {
        _ if !user => 0,
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
    let user = (user.max(0) as usize / FRAME).min(room);
    woken.header = header(kernel, user, 0, false);
    woken.wakeup = wakeup;
    // Never past the room for frames, which the verifier needs to see.
    let bytes = ((kernel + user) * FRAME) & (FRAME_WORDS * FRAME - 1);
    output(
        (woken as *const Woken).cast(),
        size_of::<SampleHeader>() + size_of::<Wakeup>() + bytes,
    );
}

/// Writes a wakeup with the kernel's frames, and if `user` the user
/// registers and up to `stack_bytes` of the user stack, for uhr to unwind.
fn woken_with_copy(ctx: &RawTracePointContext, wakeup: Wakeup, user: bool, stack_bytes: usize) {
    let cpu = unsafe { bpf_get_smp_processor_id() };
    let Some(woken) = WOKEN_COPIES.get_ptr_mut(cpu) else {
        return;
    };
    let woken = unsafe { &mut *woken };
    let data = woken.data.as_mut_ptr();
    let limit = (MAX_STACK.load() as usize).min(MAX_FRAMES);
    let kernel = unsafe {
        bpf_get_stack(
            ctx.as_ptr(),
            data.cast(),
            (MAX_FRAMES * FRAME) as u32,
            OWN_FRAMES,
        )
    };
    let kernel = (kernel.max(0) as usize / FRAME).min(limit) & MAX_FRAMES;
    let registers = if user { saved_user_registers() } else { None };
    let mut copied = 0;
    if let Some(registers) = registers {
        let at = kernel * FRAME;
        unsafe {
            data.add(at)
                .cast::<UserRegisters>()
                .write_unaligned(registers)
        };
        let at = at + size_of::<UserRegisters>();
        copied = copy_stack(registers.sp, unsafe { data.add(at) }, stack_bytes);
    }
    woken.header = header(kernel, 0, copied, registers.is_some());
    woken.wakeup = wakeup;
    // Bounded by the most of each part, which the verifier needs to see.
    let bytes = kernel * FRAME
        + match registers {
            Some(_) => size_of::<UserRegisters>() + (copied & 0xffff),
            None => 0,
        };
    let len = size_of::<SampleHeader>() + size_of::<Wakeup>() + bytes;
    if len <= size_of::<WokenCopy>() {
        output((woken as *const WokenCopy).cast(), len);
    }
}

/// Writes a wakeup of `len` bytes to the ring buffer.
fn output(wakeup: *const u8, len: usize) {
    let bytes = unsafe { core::slice::from_raw_parts(wakeup, len) };
    // As the samples', read every few milliseconds.
    if WAKEUPS
        .output::<[u8]>(bytes, BPF_RB_NO_WAKEUP as u64)
        .is_err()
        && let Some(dropped) = WAKEUPS_DROPPED.get_ptr_mut(0)
    {
        unsafe { *dropped += 1 };
    }
}

/// The header of a wakeup with `kernel` and `user` frames, and `copied`
/// bytes of user stack if `copy`.
fn header(kernel: usize, user: usize, copied: usize, copy: bool) -> SampleHeader {
    let (tgid, tid) = current();
    SampleHeader {
        time_ns: unsafe { bpf_ktime_get_ns() },
        ip: 0,
        period: 0,
        address: 0,
        event: event::WAKEUP,
        tgid,
        tid,
        cpu: unsafe { bpf_get_smp_processor_id() },
        mode: mode::KERNEL,
        kernel_frames: kernel as u32,
        user_frames: user as u32,
        stack_bytes: copied as u32,
        copy: u32::from(copy),
        walk: walk::NONE,
        walked_frames: 0,
        walked_bytes: 0,
        frame_ends: 0,
        exec: 0,
        mapped: 0,
    }
}
