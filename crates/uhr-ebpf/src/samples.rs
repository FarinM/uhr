//! Samples the stacks of the target's threads at each tick of a CPU's
//! clock.

use core::mem::size_of;

use aya_ebpf::bindings::{BPF_F_USER_STACK, BPF_RB_NO_WAKEUP, bpf_user_pt_regs_t};
use aya_ebpf::helpers::generated::bpf_probe_read_user;
use aya_ebpf::helpers::{
    bpf_get_current_task, bpf_get_smp_processor_id, bpf_get_stack, bpf_ktime_get_ns,
    bpf_probe_read_kernel,
};
#[cfg(bpf_target_arch = "x86_64")]
use aya_ebpf::helpers::{bpf_get_current_task_btf, bpf_task_pt_regs};
use aya_ebpf::macros::{map, perf_event, tracepoint};
use aya_ebpf::maps::{Array, HashMap, PerCpuArray, RingBuf};
use aya_ebpf::programs::{PerfEventContext, TracePointContext};
use aya_ebpf::{EbpfContext, Global};
use uhr_ebpf::{MAX_FRAMES, MAX_STACK_COPY, SampleHeader, UserRegisters, mode};

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

const PAGE: usize = 4096;

/// A sample with a copy of its user stack: the header, then the kernel
/// frames, the user registers and the copy, with no room between them.
/// The room is for the most of each, and a page more, as the verifier
/// checks where a part starts apart from how long it is.
#[repr(C)]
pub struct Copy {
    header: SampleHeader,
    data: [u8; MAX_FRAMES * FRAME + size_of::<UserRegisters>() + MAX_STACK_COPY + PAGE],
}

/// Where a sample with a copy of its stack is put together, by CPU, as it
/// is too big for a per-CPU map. uhr sets how many CPUs at load.
#[map]
static COPIES: Array<Copy> = Array::with_max_entries(1, 0);

/// The bytes of user stack to copy with each sample, which uhr sets at
/// load. 0 to walk user stacks with frame pointers instead.
#[unsafe(no_mangle)]
static STACK_BYTES: Global<u32> = Global::new(0);

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
    let stack_bytes = (STACK_BYTES.load() as usize).min(MAX_STACK_COPY);
    if stack_bytes > 0 {
        return sample_with_copy(&ctx, tgid, tid, stack_bytes);
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
        stack_bytes: 0,
        copy: 0,
    };
    let len = size_of::<SampleHeader>() + (kernel + user) * FRAME;
    if len <= size_of::<Sample>() {
        output((sample as *const Sample).cast(), len);
    }
    0
}

/// Samples with the kernel's frames and a copy of the user stack, for uhr
/// to unwind.
fn sample_with_copy(ctx: &PerfEventContext, tgid: u32, tid: u32, stack_bytes: usize) -> u32 {
    let cpu = unsafe { bpf_get_smp_processor_id() };
    let Some(sample) = COPIES.get_ptr_mut(cpu) else {
        return 0;
    };
    let sample = unsafe { &mut *sample };
    let data = sample.data.as_mut_ptr();
    let regs = unsafe { &(*ctx.ctx).regs };
    let (ip, kernel_mode) = interrupted(regs);
    let (ip, mode, kernel, user) = if in_guest() {
        (0, mode::GUEST, 0, None)
    } else {
        let limit = (MAX_STACK.load() as usize).min(MAX_FRAMES);
        let kernel =
            unsafe { bpf_get_stack(ctx.as_ptr(), data.cast(), (MAX_FRAMES * FRAME) as u32, 0) };
        let kernel = (kernel.max(0) as usize / FRAME).min(limit);
        let mode = if kernel_mode {
            mode::KERNEL
        } else {
            mode::USER
        };
        (ip, mode, kernel, user_registers(regs, kernel_mode))
    };
    let mut len = kernel * FRAME;
    let mut copied = 0;
    if let Some(user) = user {
        unsafe { data.add(len).cast::<UserRegisters>().write_unaligned(user) };
        len += size_of::<UserRegisters>();
        copied = copy_stack(user.sp, unsafe { data.add(len) }, stack_bytes);
        len += copied;
    }
    sample.header = SampleHeader {
        time_ns: unsafe { bpf_ktime_get_ns() },
        ip,
        tgid,
        tid,
        cpu,
        mode,
        kernel_frames: kernel as u32,
        user_frames: 0,
        stack_bytes: copied as u32,
        copy: u32::from(user.is_some()),
    };
    let len = size_of::<SampleHeader>() + len;
    if len <= size_of::<Copy>() {
        output((sample as *const Copy).cast(), len);
    }
    0
}

/// Copies the user stack from `sp` up, a page at a time, until `limit`
/// bytes or the end of the stack, where reading fails, and returns how many
/// bytes it copied.
fn copy_stack(sp: u64, to: *mut u8, limit: usize) -> usize {
    let mut copied = 0;
    for _ in 0..MAX_STACK_COPY / PAGE + 2 {
        if copied >= limit {
            break;
        }
        let from = sp.wrapping_add(copied as u64);
        // To the next page, but never more than a page, for the verifier.
        let chunk = (PAGE - from as usize % PAGE).min(limit - copied).min(PAGE);
        let at = copied.min(MAX_STACK_COPY);
        let read = unsafe {
            bpf_probe_read_user(
                to.add(at).cast(),
                chunk as u32,
                from as *const core::ffi::c_void,
            )
        };
        if read < 0 {
            break;
        }
        copied += chunk;
    }
    copied
}

/// Writes a sample of `len` bytes to the ring buffer.
fn output(sample: *const u8, len: usize) {
    let bytes = unsafe { core::slice::from_raw_parts(sample, len) };
    // uhr reads the ring buffer every few milliseconds, so waking it for
    // each sample would only cost.
    if SAMPLES
        .output::<[u8]>(bytes, BPF_RB_NO_WAKEUP as u64)
        .is_err()
        && let Some(dropped) = DROPPED.get_ptr_mut(0)
    {
        unsafe { *dropped += 1 };
    }
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

/// The user registers of the sampled thread: `regs` in user mode, and
/// those the kernel saved on entry otherwise. `None` for a kernel thread.
#[cfg(bpf_target_arch = "x86_64")]
fn user_registers(regs: &bpf_user_pt_regs_t, kernel_mode: bool) -> Option<UserRegisters> {
    // The code segments of 64-bit user code, natively and in a Xen PV
    // guest. As in the kernel's `user_64bit_mode`, any other is 32-bit
    // code, such as one from the LDT.
    const USER_CS: u16 = 0x33;
    const XEN_PV_USER_CS: u16 = 0xe033;
    let regs = if kernel_mode {
        let saved = unsafe { bpf_task_pt_regs(bpf_get_current_task_btf()) };
        unsafe { bpf_probe_read_kernel(saved as *const bpf_user_pt_regs_t) }.ok()?
    } else {
        *regs
    };
    (regs.cs & 3 == 3).then_some(UserRegisters {
        ip: regs.rip,
        sp: regs.rsp,
        bp: regs.rbp,
        // With FRED, the bits above the selector hold more of the state.
        compat: u64::from(!matches!(regs.cs as u16, USER_CS | XEN_PV_USER_CS)),
    })
}

/// uhr unwinds copies of x86-64 stacks only.
#[cfg(bpf_target_arch = "aarch64")]
fn user_registers(_regs: &bpf_user_pt_regs_t, _kernel_mode: bool) -> Option<UserRegisters> {
    None
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
