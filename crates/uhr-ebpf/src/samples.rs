//! Samples the stacks of the target's threads at each tick of a CPU's
//! clock, and at page faults.

use core::mem::size_of;

use aya_ebpf::bindings::{BPF_F_USER_STACK, BPF_RB_NO_WAKEUP, bpf_user_pt_regs_t};
use aya_ebpf::helpers::generated::{
    bpf_probe_read_kernel as bpf_probe_read_kernel_raw, bpf_probe_read_user,
};
use aya_ebpf::helpers::{
    bpf_get_current_task, bpf_get_smp_processor_id, bpf_get_stack, bpf_ktime_get_ns,
    bpf_probe_read_kernel,
};
#[cfg(bpf_target_arch = "x86_64")]
use aya_ebpf::helpers::{bpf_get_current_task_btf, bpf_task_pt_regs};
use aya_ebpf::macros::{map, perf_event, tracepoint};
use aya_ebpf::maps::{Array, HashMap, PerCpuArray, ProgramArray, RingBuf};
use aya_ebpf::programs::{PerfEventContext, TracePointContext};
use aya_ebpf::{EbpfContext, Global};
use uhr_ebpf::{
    MAX_FRAMES, MAX_STACK_COPY, SampleHeader, UserRegisters, WALKED_BYTES, Walk, event, frames,
    mode, walk,
};

use crate::mappings;
use crate::targets::{active, current, running};
use crate::walk::{self as walker, ROOM};

#[map]
static SAMPLES: RingBuf = RingBuf::with_byte_size(16 << 20, 0);

/// A sample, and its kernel frames and then its user frames, leaf first,
/// each user frame with where it ends if the frame pointers were walked,
/// then its interpreter frames. The frames take at most `MAX_FRAMES`, but
/// the verifier checks where the user frames start apart from how many
/// there can be.
#[repr(C)]
pub struct Sample {
    header: SampleHeader,
    frames: [u64; FRAME_WORDS],
    walked: [u8; ROOM],
}

/// Room for twice the frames, a power of two for the verifier.
pub(crate) const FRAME_WORDS: usize = 256;
const _: () = assert!(FRAME_WORDS >= 2 * MAX_FRAMES);

/// Where a sample is put together, as it is too big for the stack.
#[map]
static SCRATCH: PerCpuArray<Sample> = PerCpuArray::with_max_entries(1, 0);

const PAGE: usize = 4096;

/// A sample with a copy of its user stack: the header, then the kernel
/// frames, the user registers and the copy, and the interpreter frames,
/// with no room between them. The room is for the most of each, and a page
/// more, as the verifier checks where a part starts apart from how long it
/// is.
#[repr(C)]
pub struct Copy {
    header: SampleHeader,
    data: [u8; MAX_FRAMES * FRAME + size_of::<UserRegisters>() + MAX_STACK_COPY + PAGE + ROOM],
}

/// Where a sample with a copy of its stack is put together, by CPU, as it
/// is too big for a per-CPU map. uhr sets how many CPUs at load.
#[map]
static COPIES: Array<Copy> = Array::with_max_entries(1, 0);

/// The bytes of user stack to copy with each sample, which uhr sets at
/// load. 0 to walk user stacks with frame pointers instead.
#[unsafe(no_mangle)]
static STACK_BYTES: Global<u32> = Global::new(0);

/// `walk_frames`, which uhr puts at 0, `walk_native` at 1 and
/// `walk_memory` at 2.
#[map]
static PROGRAMS: ProgramArray = ProgramArray::with_max_entries(3, 0);

/// The state of the thread `walk_frames` found, for `walk_memory`.
#[map]
static STATES: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Where `walk_frames` walks a sample's interpreter frames before it copies
/// them into the sample, so that the verifier checks the walk once, not for
/// each kind of sample.
#[repr(C)]
pub struct Walked {
    frames: [u8; ROOM],
}

#[map]
static WALKED: PerCpuArray<Walked> = PerCpuArray::with_max_entries(1, 0);

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

/// Where a task's count of the execs of its process is, as for
/// `TASK_FLAGS`.
#[unsafe(no_mangle)]
static TASK_EXEC_ID: Global<u32> = Global::new(u32::MAX);

/// The current task's count of execs, its low 32 bits, or 0 where unknown.
fn exec() -> u32 {
    let offset = TASK_EXEC_ID.load();
    if offset == u32::MAX {
        return 0;
    }
    let task = unsafe { bpf_get_current_task() } as *const u8;
    let count = unsafe { bpf_probe_read_kernel(task.wrapping_add(offset as usize).cast::<u32>()) };
    count.unwrap_or(0)
}

#[perf_event]
pub fn sample(ctx: PerfEventContext) -> u32 {
    take(&ctx, event::CPU_CLOCK)
}

/// At page faults: one in every period of those the kernel counts on each
/// CPU.
#[perf_event]
pub fn sample_fault(ctx: PerfEventContext) -> u32 {
    take(&ctx, event::PAGE_FAULT)
}

/// Samples the thread the CPU runs at `event`, if it is the target's.
#[inline(always)]
fn take(ctx: &PerfEventContext, event: u32) -> u32 {
    let (tgid, tid) = current();
    if !running() || !active(tgid) {
        return 0;
    }
    let process = walker::of(tgid);
    let stack_bytes = (STACK_BYTES.load() as usize).min(MAX_STACK_COPY);
    if stack_bytes > 0 {
        let cpu = unsafe { bpf_get_smp_processor_id() };
        let Some(sample) = COPIES.get_ptr_mut(cpu) else {
            return 0;
        };
        let sample = unsafe { &mut *sample };
        let len = fill_copy(ctx, event, sample, stack_bytes);
        // Here, in the program: the verifier takes tail calls only from a
        // function that returns a number, and the compiler need not keep
        // `fill_copy` returning one.
        if sample.header.mode != mode::GUEST
            && let Some(process) = process
        {
            walk_next(ctx, process, &mut sample.header);
        }
        let len = size_of::<SampleHeader>() + len;
        if len <= size_of::<Copy>() {
            output((sample as *const Copy).cast(), len);
        }
        return 0;
    }
    let Some(sample) = SCRATCH.get_ptr_mut(0) else {
        return 0;
    };
    let sample = unsafe { &mut *sample };
    // A thread running a guest is sampled in the host's code that entered
    // it, which it does not run, so it gets no frames, as in perf.
    let (ip, mode, kernel, user, ends) = if in_guest() {
        (0, mode::GUEST, 0, 0, false)
    } else {
        let (ip, kernel_mode) = interrupted(unsafe { &(*ctx.ctx).regs });
        let (kernel, user, ends) = stacks(ctx, sample, process, kernel_mode);
        let mode = if kernel_mode {
            mode::KERNEL
        } else {
            mode::USER
        };
        (ip, mode, kernel, user, ends)
    };
    sample.header = SampleHeader {
        time_ns: unsafe { bpf_ktime_get_ns() },
        ip,
        period: unsafe { (*ctx.ctx).sample_period },
        address: fault_address(ctx, event),
        event,
        tgid,
        tid,
        cpu: unsafe { bpf_get_smp_processor_id() },
        mode,
        kernel_frames: kernel as u32,
        user_frames: user as u32,
        stack_bytes: 0,
        copy: 0,
        walk: walk::NONE,
        walked_frames: 0,
        walked_bytes: 0,
        frame_ends: u32::from(ends),
        exec: exec(),
        mapped: mappings::count(tgid),
    };
    if mode != mode::GUEST
        && let Some(process) = process
    {
        walk_next(ctx, process, &mut sample.header);
    }
    let len = size_of::<SampleHeader>() + native_frames(&sample.header);
    if len <= size_of::<Sample>() {
        output((sample as *const Sample).cast(), len);
    }
    0
}

/// Has `walk_frames` or `walk_native` walk the sampled thread's interpreter
/// frames, as `process` says, and write the sample, which keeps each
/// program short enough for the verifier. Returns only where it can't, and
/// says so in `header`. Inline, as the verifier takes tail calls only from
/// a function that returns a number.
#[inline(always)]
fn walk_next(ctx: &PerfEventContext, process: &Walk, header: &mut SampleHeader) {
    let next = u32::from(process.frames == frames::NATIVE);
    unsafe { PROGRAMS.tail_call(ctx, next) };
    header.walk = walk::FAILED;
}

/// The bytes of a sample's frames, which interpreter frames go after,
/// never past the room for them, which the verifier needs to see.
fn native_frames(header: &SampleHeader) -> usize {
    let (kernel, user) = (header.kernel_frames as usize, header.user_frames as usize);
    let words = kernel + user * (1 + header.frame_ends as usize);
    (words * FRAME) & (FRAME_WORDS * FRAME - 1)
}

/// The bytes of a sample with a copy of its stack before its interpreter
/// frames, bounded by the most of each part, as the verifier needs.
fn copied(header: &SampleHeader) -> usize {
    let kernel = header.kernel_frames as usize & MAX_FRAMES;
    let copy = match header.copy {
        0 => 0,
        _ => size_of::<UserRegisters>() + (header.stack_bytes as usize & 0xffff),
    };
    kernel * FRAME + copy
}

/// The rest of a sample of a process whose runtime uhr knows, after what
/// `sample` put together: finds the state of the thread in the runtime, and
/// has `walk_memory` walk its frames, so that the verifier checks the
/// search and the walk apart. Writes the sample where it can't go on.
#[perf_event]
pub fn walk_frames(ctx: PerfEventContext) -> u32 {
    let (tgid, tid) = current();
    let Some(walked) = WALKED.get_ptr_mut(0) else {
        return 0;
    };
    let walked = unsafe { (*walked).frames.as_mut_ptr() };
    let status = match walker::state(walker::of(tgid), tid, walked) {
        Ok(state) => match STATES.get_ptr_mut(0) {
            Some(states) => {
                unsafe { *states = state };
                unsafe { PROGRAMS.tail_call(&ctx, 2) };
                walk::FAILED
            }
            None => walk::FAILED,
        },
        Err(status) => status,
    };
    finish((status, 0, 0), walked);
    0
}

/// Walks the frames in the runtime's memory of the thread whose state
/// `walk_frames` found, and writes the sample.
#[perf_event]
pub fn walk_memory(_ctx: PerfEventContext) -> u32 {
    let (tgid, _) = current();
    let Some(walked) = WALKED.get_ptr_mut(0) else {
        return 0;
    };
    let walked = unsafe { (*walked).frames.as_mut_ptr() };
    let found = match STATES.get_ptr(0) {
        Some(state) => walker::frames(walker::of(tgid), unsafe { *state }, walked),
        None => (walk::FAILED, 0, 0),
    };
    finish(found, walked);
    0
}

/// As `walk_frames`, for a runtime that keeps its frames on the native
/// stack, which needs the frame pointers the sampler walked.
#[perf_event]
pub fn walk_native(_ctx: PerfEventContext) -> u32 {
    let (tgid, _) = current();
    let Some(walked) = WALKED.get_ptr_mut(0) else {
        return 0;
    };
    let walked = unsafe { (*walked).frames.as_mut_ptr() };
    let mut found = (walk::FAILED, 0, 0);
    if STACK_BYTES.load() == 0
        && let (Some(process), Some(sample)) = (walker::of(tgid), SCRATCH.get_ptr(0))
    {
        let sample = unsafe { &*sample };
        let header = &sample.header;
        if header.frame_ends != 0 {
            found = walker::native(
                process,
                &sample.frames,
                header.kernel_frames,
                header.user_frames,
                walked,
            );
        }
    }
    finish(found, walked);
    0
}

/// Copies the frames a walk found, `frames` of `each` bytes at `walked`,
/// into the sample `sample` put together, and writes it.
#[inline(always)]
fn finish((status, frames, each): (u32, u32, u32), walked: *mut u8) {
    let into = |header: &mut SampleHeader, to: *mut u8| {
        header.walk = status;
        header.walked_frames = frames;
        header.walked_bytes = each;
        // Never more than there is room for, which the verifier needs to
        // see. Read back from the map, so that the compiler keeps the mask
        // where it knows the walk wrote less.
        let (frames, each) = unsafe {
            (
                core::ptr::read_volatile(&header.walked_frames),
                core::ptr::read_volatile(&header.walked_bytes),
            )
        };
        let bytes = (frames as usize * each as usize) & (WALKED_BYTES - 1);
        let read = unsafe { bpf_probe_read_kernel_raw(to.cast(), bytes as u32, walked.cast()) };
        if read == 0 {
            return bytes;
        }
        // So that the sample says no more than it holds.
        header.walked_frames = 0;
        0
    };
    if STACK_BYTES.load() > 0 {
        let cpu = unsafe { bpf_get_smp_processor_id() };
        let Some(sample) = COPIES.get_ptr_mut(cpu) else {
            return;
        };
        let sample = unsafe { &mut *sample };
        let at = copied(&sample.header);
        let bytes = into(&mut sample.header, unsafe {
            sample.data.as_mut_ptr().add(at)
        });
        let len = size_of::<SampleHeader>() + at + bytes;
        if len <= size_of::<Copy>() {
            output((sample as *const Copy).cast(), len);
        }
    } else {
        let Some(sample) = SCRATCH.get_ptr_mut(0) else {
            return;
        };
        let sample = unsafe { &mut *sample };
        let at = native_frames(&sample.header);
        let frames = sample.frames.as_mut_ptr().cast::<u8>();
        let bytes = into(&mut sample.header, unsafe { frames.add(at) });
        let len = size_of::<SampleHeader>() + at + bytes;
        if len <= size_of::<Sample>() {
            output((sample as *const Sample).cast(), len);
        }
    }
}

/// Puts together a sample with the kernel's frames and a copy of the user
/// stack, for uhr to unwind, and returns the bytes after its header.
fn fill_copy(ctx: &PerfEventContext, event: u32, sample: &mut Copy, stack_bytes: usize) -> usize {
    // Not passed in, as a BPF function takes at most five arguments.
    let (tgid, tid) = current();
    let cpu = unsafe { bpf_get_smp_processor_id() };
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
        period: unsafe { (*ctx.ctx).sample_period },
        address: fault_address(ctx, event),
        event,
        tgid,
        tid,
        cpu,
        mode,
        kernel_frames: kernel as u32,
        user_frames: 0,
        stack_bytes: copied as u32,
        copy: u32::from(user.is_some()),
        walk: walk::NONE,
        walked_frames: 0,
        walked_bytes: 0,
        frame_ends: 0,
        exec: exec(),
        mapped: mappings::count(tgid),
    };
    len
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

/// Where the page fault `ctx` is a sample of was, the memory touched, and
/// 0 for a tick. The kernel sets the address only for an event that has
/// one: a tick's holds what was there before.
#[inline(always)]
fn fault_address(ctx: &PerfEventContext, event: u32) -> u64 {
    if event == event::PAGE_FAULT {
        unsafe { (*ctx.ctx).addr }
    } else {
        0
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

/// The instruction and frame pointer of the sampled thread's 64-bit user
/// code, as for `user_registers`.
#[cfg(bpf_target_arch = "x86_64")]
fn frame_registers(regs: &bpf_user_pt_regs_t, kernel_mode: bool) -> Option<(u64, u64)> {
    let user = user_registers(regs, kernel_mode)?;
    (user.compat == 0).then_some((user.ip, user.bp))
}

/// On arm64 a function's frame record can be anywhere in its frame, so
/// where it is says nothing of where the frame ends, and the saved return
/// addresses can carry pointer authentication codes, which the kernel's walk
/// strips. That walk stays.
#[cfg(bpf_target_arch = "aarch64")]
fn frame_registers(_regs: &bpf_user_pt_regs_t, _kernel_mode: bool) -> Option<(u64, u64)> {
    None
}

/// Walks the user stack by its frame pointers, from the instruction `ip`
/// and the frame pointer `fp`, into `frames` after the `kernel` frames:
/// each frame's address, then where it ends. A function keeps its caller's
/// frame pointer at its own, and the address it returns to just above, as
/// the kernel's walk takes them.
fn walk_frame_pointers(
    mut ip: u64,
    mut fp: u64,
    frames: *mut u64,
    kernel: usize,
    room: usize,
) -> usize {
    let mut count = 0;
    while count < room.min(MAX_FRAMES) {
        // Never past the room for frames, which the verifier needs to see.
        let at = (kernel + 2 * count) & (FRAME_WORDS - 1);
        let end = if fp == 0 { 0 } else { fp.wrapping_add(16) };
        unsafe {
            frames.add(at).write(ip);
            frames.add(at + 1).write(end);
        }
        count += 1;
        if fp == 0 || fp % 8 != 0 {
            break;
        }
        let mut record = [0u64; 2];
        let read = unsafe {
            bpf_probe_read_user(
                record.as_mut_ptr().cast(),
                16,
                fp as *const core::ffi::c_void,
            )
        };
        let [next, address] = record;
        // A frame's caller is further up the stack.
        if read != 0 || address == 0 || (next != 0 && next <= fp) {
            break;
        }
        (ip, fp) = (address, next);
    }
    count
}

/// Fills `sample` with the kernel's frames and then the user's, and
/// returns how many of each, and whether each user frame comes with where
/// it ends, as the walk of `process` asks.
fn stacks(
    ctx: &PerfEventContext,
    sample: &mut Sample,
    process: Option<&Walk>,
    kernel_mode: bool,
) -> (usize, usize, bool) {
    let frames = sample.frames.as_mut_ptr();
    let limit = (MAX_STACK.load() as usize).min(MAX_FRAMES);
    // Like perf's, the user frames get the room the kernel's leave.
    let kernel =
        unsafe { bpf_get_stack(ctx.as_ptr(), frames.cast(), (MAX_FRAMES * FRAME) as u32, 0) };
    let kernel = (kernel.max(0) as usize / FRAME).min(limit);
    // Never more than the difference, but the verifier needs to see it is
    // no more than the room for frames.
    let room = (limit - kernel).min(MAX_FRAMES);
    let regs = unsafe { &(*ctx.ctx).regs };
    if process.is_some_and(|walk| walk.frame_pointers != 0)
        && let Some((ip, fp)) = frame_registers(regs, kernel_mode)
    {
        let user = walk_frame_pointers(ip, fp, frames, kernel, room);
        // Read back from the map, the verifier knows only how many frames
        // there can be, so it checks what follows once, not once for each
        // number the walk can stop at.
        sample.header.user_frames = user as u32;
        let user = unsafe { core::ptr::read_volatile(&sample.header.user_frames) } as usize;
        return (kernel, user.min(room), true);
    }
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
    (kernel, (user.max(0) as usize / FRAME).min(room), false)
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
