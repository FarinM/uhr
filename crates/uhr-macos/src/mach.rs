//! The Mach calls uhr makes on other processes, through their task ports.

use std::ffi::CStr;
use std::fmt;
use std::io;
use std::mem::{self, MaybeUninit};
use std::ops::Deref;
use std::ptr;
use std::slice;

use mach2::kern_return::{KERN_SUCCESS, kern_return_t};
use mach2::mach_port::mach_port_deallocate;
use mach2::mach_types::thread_act_array_t;
use mach2::message::mach_msg_type_number_t;
use mach2::port::{MACH_PORT_NULL, mach_port_t};
#[cfg(target_arch = "aarch64")]
use mach2::structs::arm_thread_state64_t;
#[cfg(target_arch = "x86_64")]
use mach2::structs::x86_thread_state64_t;
use mach2::task::{task_info, task_threads};
use mach2::task_info::{
    TASK_DYLD_INFO, TASK_DYLD_INFO_COUNT, TASK_VM_INFO, task_dyld_info, task_vm_info,
};
use mach2::thread_act::{thread_get_state, thread_resume, thread_suspend};
#[cfg(target_arch = "aarch64")]
use mach2::thread_status::{ARM_EXCEPTION_STATE64, ARM_THREAD_STATE64};
#[cfg(target_arch = "x86_64")]
use mach2::thread_status::{x86_EXCEPTION_STATE64, x86_THREAD_STATE64};
use mach2::traps::{mach_task_self, task_for_pid};
use mach2::vm::{mach_vm_deallocate, mach_vm_read, mach_vm_read_overwrite};
use mach2::vm_types::{mach_vm_address_t, mach_vm_size_t, natural_t};
use uhr_core::runtimes::Memory;

/// A Mach call that failed, by name and code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failed {
    pub call: &'static str,
    pub code: kern_return_t,
}

impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // SAFETY: mach_error_string returns a static string for any code.
        let text = unsafe { CStr::from_ptr(mach_error_string(self.code)) };
        write!(
            f,
            "{} failed: {} ({})",
            self.call,
            text.to_string_lossy(),
            self.code
        )
    }
}

impl std::error::Error for Failed {}

unsafe extern "C" {
    fn mach_error_string(code: kern_return_t) -> *const libc::c_char;
    fn pid_for_task(task: mach_port_t, pid: *mut libc::c_int) -> kern_return_t;
}

pub(crate) fn check(call: &'static str, code: kern_return_t) -> Result<(), Failed> {
    match code {
        KERN_SUCCESS => Ok(()),
        code => Err(Failed { call, code }),
    }
}

/// A send right of uhr's, given back when dropped.
#[derive(Debug)]
pub(crate) struct Port(mach_port_t);

impl Port {
    /// Takes over a right uhr was given.
    pub(crate) fn new(name: mach_port_t) -> Self {
        Self(name)
    }

    pub(crate) fn name(&self) -> mach_port_t {
        self.0
    }
}

impl Drop for Port {
    fn drop(&mut self) {
        if self.0 != MACH_PORT_NULL {
            // SAFETY: uhr owns this right, and nothing uses it after.
            unsafe { mach_port_deallocate(mach_task_self(), self.0) };
        }
    }
}

/// A process, by its task port.
#[derive(Debug)]
pub(crate) struct Task {
    port: Port,
}

impl Task {
    /// Asks the kernel for the task of `pid`, which it gives to root, or to
    /// a program signed to debug, for a process that does not forbid it.
    pub(crate) fn for_pid(pid: u32) -> Result<Self, Failed> {
        let mut task = MACH_PORT_NULL;
        // SAFETY: `task` is valid to write.
        let code = unsafe { task_for_pid(mach_task_self(), pid as libc::c_int, &mut task) };
        check("task_for_pid", code)?;
        Ok(Self {
            port: Port::new(task),
        })
    }

    /// A task port a process sent uhr itself.
    pub(crate) fn from_port(port: Port) -> Self {
        Self { port }
    }

    pub(crate) fn pid(&self) -> Result<u32, Failed> {
        let mut pid = 0;
        // SAFETY: `pid` is valid to write.
        check("pid_for_task", unsafe {
            pid_for_task(self.port.name(), &mut pid)
        })?;
        Ok(pid as u32)
    }

    pub(crate) fn threads(&self) -> Result<Vec<Port>, Failed> {
        let mut list: thread_act_array_t = ptr::null_mut();
        let mut count: mach_msg_type_number_t = 0;
        // SAFETY: both are valid to write.
        let code = unsafe { task_threads(self.port.name(), &mut list, &mut count) };
        check("task_threads", code)?;
        // SAFETY: the kernel gave `count` ports at `list`, which uhr owns,
        // as it does the array.
        let threads = unsafe { slice::from_raw_parts(list, count as usize) }
            .iter()
            .map(|&port| Port::new(port))
            .collect();
        let size = count as usize * mem::size_of::<mach_port_t>();
        // SAFETY: the array was allocated in uhr's space for it.
        unsafe { mach_vm_deallocate(mach_task_self(), list as mach_vm_address_t, size as u64) };
        Ok(threads)
    }

    /// Copies the process's memory at `address` into `into`.
    pub(crate) fn read(&self, address: u64, into: &mut [u8]) -> Result<(), Failed> {
        let mut read: mach_vm_size_t = 0;
        // SAFETY: `into` is valid for its length.
        let code = unsafe {
            mach_vm_read_overwrite(
                self.port.name(),
                address,
                into.len() as u64,
                into.as_mut_ptr() as mach_vm_address_t,
                &mut read,
            )
        };
        check("mach_vm_read_overwrite", code)?;
        if read as usize != into.len() {
            return Err(Failed {
                call: "mach_vm_read_overwrite",
                code: mach2::kern_return::KERN_INVALID_ADDRESS,
            });
        }
        Ok(())
    }

    /// The process's memory at `address`, mapped copy-on-write into uhr's
    /// space rather than copied, for large reads.
    pub(crate) fn map(&self, address: u64, len: u64) -> Result<Mapped, Failed> {
        let page = page_size();
        let start = address - address % page;
        let size = (address + len).next_multiple_of(page) - start;
        let mut data = 0;
        let mut count: mach_msg_type_number_t = 0;
        // SAFETY: both are valid to write.
        let code = unsafe { mach_vm_read(self.port.name(), start, size, &mut data, &mut count) };
        check("mach_vm_read", code)?;
        Ok(Mapped {
            address: data as u64,
            size: u64::from(count),
            offset: (address - start) as usize,
            len: len as usize,
        })
    }

    pub(crate) fn dyld_info(&self) -> Result<task_dyld_info, Failed> {
        self.info(
            "task_info(TASK_DYLD_INFO)",
            TASK_DYLD_INFO,
            TASK_DYLD_INFO_COUNT,
        )
    }

    pub(crate) fn vm_info(&self) -> Result<task_vm_info, Failed> {
        let count = (mem::size_of::<task_vm_info>() / mem::size_of::<natural_t>()) as u32;
        self.info("task_info(TASK_VM_INFO)", TASK_VM_INFO, count)
    }

    /// Older kernels fill only the start of a flavor's struct; the rest
    /// stays zero.
    fn info<T: Default>(&self, call: &'static str, flavor: u32, count: u32) -> Result<T, Failed> {
        let mut info = T::default();
        let mut count = count;
        // SAFETY: `info` has room for `count` naturals.
        let code = unsafe {
            task_info(
                self.port.name(),
                flavor,
                (&mut info as *mut T).cast(),
                &mut count,
            )
        };
        check(call, code)?;
        Ok(info)
    }
}

impl Memory for Task {
    fn read(&self, address: u64, into: &mut [u8]) -> io::Result<()> {
        Task::read(self, address, into).map_err(io::Error::other)
    }
}

/// Memory of another process, mapped into uhr's space.
#[derive(Debug)]
pub(crate) struct Mapped {
    address: u64,
    size: u64,
    offset: usize,
    len: usize,
}

impl Deref for Mapped {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        // SAFETY: mach_vm_read mapped `size` bytes at `address`, which hold
        // `offset + len`, until this is dropped.
        unsafe { slice::from_raw_parts((self.address as *const u8).add(self.offset), self.len) }
    }
}

impl Drop for Mapped {
    fn drop(&mut self) {
        // SAFETY: the mapping is uhr's, and nothing borrows it any more.
        unsafe { mach_vm_deallocate(mach_task_self(), self.address, self.size) };
    }
}

// SAFETY: the mapping is private to uhr and never written.
unsafe impl Send for Mapped {}

pub(crate) fn page_size() -> u64 {
    // SAFETY: sysconf has no preconditions.
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 }
}

/// What thread_info says of a thread.
#[derive(Debug, Clone)]
pub(crate) struct ThreadInfo {
    pub user_ns: u64,
    pub system_ns: u64,
    pub run_state: i32,
    pub name: String,
}

pub(crate) fn thread_info(thread: &Port) -> Result<ThreadInfo, Failed> {
    let extended = extended_info(thread)?;
    let name: Vec<u8> = extended
        .pth_name
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    Ok(ThreadInfo {
        user_ns: extended.pth_user_time,
        system_ns: extended.pth_system_time,
        run_state: extended.pth_run_state,
        name: String::from_utf8_lossy(&name).into_owned(),
    })
}

/// The kernel's id for the thread, unique since boot.
pub(crate) fn thread_id(thread: &Port) -> Result<u64, Failed> {
    let mut identifier = MaybeUninit::<libc::thread_identifier_info>::zeroed();
    let mut count = libc::THREAD_IDENTIFIER_INFO_COUNT;
    // SAFETY: `identifier` has room for `count` integers.
    let code = unsafe {
        libc::thread_info(
            thread.name(),
            libc::THREAD_IDENTIFIER_INFO as u32,
            identifier.as_mut_ptr().cast(),
            &mut count,
        )
    };
    check("thread_info(THREAD_IDENTIFIER_INFO)", code)?;
    // SAFETY: zeroed is valid, and the kernel filled it.
    Ok(unsafe { identifier.assume_init() }.thread_id)
}

/// A thread's CPU time so far, in user and in kernel mode, in
/// nanoseconds, which the kernel counts in microseconds.
pub(crate) fn thread_cpu_ns(thread: &Port) -> Result<(u64, u64), Failed> {
    let extended = extended_info(thread)?;
    Ok((extended.pth_user_time, extended.pth_system_time))
}

fn extended_info(thread: &Port) -> Result<libc::thread_extended_info, Failed> {
    let mut extended = MaybeUninit::<libc::thread_extended_info>::zeroed();
    let mut count = libc::THREAD_EXTENDED_INFO_COUNT;
    // SAFETY: `extended` has room for `count` integers.
    let code = unsafe {
        libc::thread_info(
            thread.name(),
            libc::THREAD_EXTENDED_INFO as u32,
            extended.as_mut_ptr().cast(),
            &mut count,
        )
    };
    check("thread_info(THREAD_EXTENDED_INFO)", code)?;
    // SAFETY: zeroed is valid, and the kernel filled it.
    Ok(unsafe { extended.assume_init() })
}

/// The thread this runs on.
pub(crate) fn thread_self() -> Port {
    // SAFETY: mach_thread_self has no preconditions, and gives a right that
    // the port frees.
    Port::new(unsafe { mach2::mach_init::mach_thread_self() })
}

/// A thread held still, let go when dropped.
pub(crate) struct Suspended<'a>(&'a Port);

pub(crate) fn suspend(thread: &Port) -> Result<Suspended<'_>, Failed> {
    // SAFETY: the port is a thread's.
    check("thread_suspend", unsafe { thread_suspend(thread.name()) })?;
    Ok(Suspended(thread))
}

impl Drop for Suspended<'_> {
    fn drop(&mut self) {
        // SAFETY: uhr suspended it once, so it resumes it once.
        unsafe { thread_resume(self.0.name()) };
    }
}

/// What unwinding needs of a thread's registers.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Registers {
    pub pc: u64,
    pub sp: u64,
    pub fp: u64,
    /// The link register, which holds a leaf function's return address.
    #[cfg(target_arch = "aarch64")]
    pub lr: u64,
}

impl Suspended<'_> {
    #[cfg(target_arch = "aarch64")]
    pub(crate) fn registers(&self) -> Result<Registers, Failed> {
        let mut state = arm_thread_state64_t::new();
        let mut count = arm_thread_state64_t::count();
        // SAFETY: `state` has room for `count` integers.
        let code = unsafe {
            thread_get_state(
                self.0.name(),
                ARM_THREAD_STATE64,
                (&mut state as *mut arm_thread_state64_t).cast(),
                &mut count,
            )
        };
        check("thread_get_state", code)?;
        Ok(Registers {
            pc: state.__pc,
            sp: state.__sp,
            fp: state.__fp,
            lr: state.__lr,
        })
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) fn registers(&self) -> Result<Registers, Failed> {
        let mut state = x86_thread_state64_t::new();
        let mut count = x86_thread_state64_t::count();
        // SAFETY: `state` has room for `count` integers.
        let code = unsafe {
            thread_get_state(
                self.0.name(),
                x86_THREAD_STATE64,
                (&mut state as *mut x86_thread_state64_t).cast(),
                &mut count,
            )
        };
        check("thread_get_state", code)?;
        Ok(Registers {
            pc: state.__rip,
            sp: state.__rsp,
            fp: state.__rbp,
        })
    }
}

/// What the kernel saved of how a thread last entered it, as
/// `arm_exception_state64_t` has it.
#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Default)]
struct ExceptionState {
    far: u64,
    esr: u32,
    _exception: u32,
}

#[cfg(target_arch = "aarch64")]
impl ExceptionState {
    /// An instruction or data abort from user mode. The kernel clears the
    /// address for an interrupt, as the one that stops a thread running its
    /// own code, whose syndrome is left from an earlier exception.
    fn page_fault(&self) -> bool {
        matches!(self.esr >> 26, 0x20 | 0x24) && self.far != 0
    }
}

/// What the kernel saved of how a thread last entered it, as
/// `x86_exception_state64_t` has it.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Default)]
struct ExceptionState {
    trapno: u16,
    _cpu: u16,
    _err: u32,
    _faultvaddr: u64,
}

#[cfg(target_arch = "x86_64")]
impl ExceptionState {
    /// The kernel saves the trap number at every entry.
    fn page_fault(&self) -> bool {
        const T_PAGE_FAULT: u16 = 14;
        self.trapno == T_PAGE_FAULT
    }
}

impl Suspended<'_> {
    /// Whether the thread is in a page fault, which the kernel handles
    /// before it lets the thread stop, at the instruction that faulted.
    pub(crate) fn in_page_fault(&self) -> Result<bool, Failed> {
        #[cfg(target_arch = "aarch64")]
        let flavor = ARM_EXCEPTION_STATE64;
        #[cfg(target_arch = "x86_64")]
        let flavor = x86_EXCEPTION_STATE64;
        let mut state = ExceptionState::default();
        let mut count = (mem::size_of::<ExceptionState>() / mem::size_of::<natural_t>())
            as mach_msg_type_number_t;
        // SAFETY: `state` has room for `count` integers.
        let code = unsafe {
            thread_get_state(
                self.0.name(),
                flavor,
                (&mut state as *mut ExceptionState).cast(),
                &mut count,
            )
        };
        check("thread_get_state", code)?;
        Ok(state.page_fault())
    }
}

/// CLOCK_MONOTONIC, which recordings are timed on. Async-signal-safe.
pub fn monotonic_ns() -> u64 {
    clock_ns(libc::CLOCK_MONOTONIC) as u64
}

fn clock_ns(clock: libc::clockid_t) -> i64 {
    let mut now = MaybeUninit::uninit();
    // SAFETY: `now` is valid to write.
    unsafe { libc::clock_gettime(clock, now.as_mut_ptr()) };
    // SAFETY: clock_gettime fills it for a clock that exists.
    let now = unsafe { now.assume_init() };
    now.tv_sec * 1_000_000_000 + now.tv_nsec
}

pub(crate) fn realtime_ns() -> i64 {
    clock_ns(libc::CLOCK_REALTIME)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, mpsc};
    use std::thread;
    use std::time::Duration;

    use super::*;

    /// How many of 400 polls of a thread that runs `work` until told to stop
    /// find it in a page fault.
    fn in_page_fault(work: fn(&AtomicBool)) -> usize {
        let stop = Arc::new(AtomicBool::new(false));
        let (sender, port) = mpsc::channel();
        let worker = thread::spawn({
            let stop = Arc::clone(&stop);
            move || {
                sender.send(thread_self()).unwrap();
                work(&stop);
            }
        });
        let port = port.recv().unwrap();
        thread::sleep(Duration::from_millis(20));
        let found = (0..400)
            .filter(|_| {
                thread::sleep(Duration::from_micros(200));
                suspend(&port).unwrap().in_page_fault().unwrap()
            })
            .count();
        stop.store(true, Ordering::Relaxed);
        worker.join().unwrap();
        found
    }

    fn touch_new_pages(stop: &AtomicBool) {
        // SAFETY: sysconf has no preconditions.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let len = 64 << 20;
        while !stop.load(Ordering::Relaxed) {
            // SAFETY: an anonymous mapping of uhr's own, which it writes in
            // and then unmaps.
            unsafe {
                let start = libc::mmap(
                    ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_ANON | libc::MAP_PRIVATE,
                    -1,
                    0,
                );
                assert_ne!(start, libc::MAP_FAILED);
                for offset in (0..len).step_by(page) {
                    ptr::write_volatile(start.cast::<u8>().add(offset), 1);
                }
                libc::munmap(start, len);
            }
        }
    }

    fn compute(stop: &AtomicBool) {
        let mut sum = 0u64;
        while !stop.load(Ordering::Relaxed) {
            sum = std::hint::black_box(sum.wrapping_add(1));
        }
    }

    #[test]
    fn knows_a_thread_in_a_page_fault() {
        let touching = in_page_fault(touch_new_pages);
        assert!(touching > 400 / 3, "{touching} of 400 polls in a fault");
        // Its last fault was long ago.
        assert_eq!(in_page_fault(compute), 0);
    }
}
