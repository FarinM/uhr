use crate::functions::Functions;
use crate::recording::{Origin, Recording};

/// Where a stack stands with syscalls, read from the kernel functions on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum InSyscall<'a> {
    Named(&'a str),
    /// In a syscall whose own function is not on the stack, as on its way
    /// back to user space.
    Unnamed,
    /// In user code, or in kernel code entered another way: a fault or an
    /// interrupt from user space, or the start of a thread.
    Outside,
    /// The stack does not show how the kernel was entered: its kernel
    /// functions have no names, it may have been cut short, or the
    /// architecture's entries are not known.
    Unknown,
}

/// What a kernel function tells about the syscall it runs in.
#[derive(Clone, Copy)]
enum Mark<'a> {
    Syscall(&'a str),
    SyscallPath,
    /// Where kernel code starts other than for a syscall.
    Entry,
    Other,
}

/// The syscall each stack is in. `None` for a stack without kernel
/// functions, which is outside syscalls only where the CPU was in user
/// mode: a virtual machine's guest code, for one, runs inside a syscall
/// with no frames in the host's kernel.
pub(crate) fn of_stacks<'a>(
    recording: &Recording,
    functions: &'a Functions,
) -> Vec<Option<InSyscall<'a>>> {
    let marks: Vec<Option<Mark>> = (0..functions.len() as u32)
        .map(|id| {
            let function = functions.get(id);
            (function.origin == Origin::Kernel)
                .then(|| function.name.as_deref().map_or(Mark::Other, mark))
        })
        .collect();
    // x86 enters the kernel the same way for a fault or an interrupt in
    // kernel code as in user code, so an entry shows where the kernel was
    // entered only on a stack that perf's depth limit did not cut.
    let depth_limit = recording
        .manifest
        .streams
        .iter()
        .map(|s| s.coverage.max_stack_depth as usize)
        .min();
    recording
        .stacks
        .iter()
        .map(|stack| {
            let whole = depth_limit.is_some_and(|limit| stack.len() < limit);
            let (mut syscall, mut path, mut outermost) = (None, false, None);
            // Leaf first, so the last kernel function is where the kernel
            // was entered.
            for mark in functions.expand(stack).filter_map(|f| marks[f as usize]) {
                match mark {
                    Mark::Syscall(name) => syscall = Some(name),
                    Mark::SyscallPath => path = true,
                    Mark::Entry | Mark::Other => {}
                }
                outermost = Some(mark);
            }
            Some(match (syscall, outermost) {
                (Some(name), _) => InSyscall::Named(name),
                _ if path => InSyscall::Unnamed,
                (None, None) => return None,
                (None, Some(Mark::Entry)) if whole => InSyscall::Outside,
                _ => InSyscall::Unknown,
            })
        })
        .collect()
}

/// Architectures' prefixes of the functions that syscalls enter, as in
/// `__x64_sys_read`, and those of the functions these call, in case the
/// compiler left the entry out.
const SYSCALL_PREFIXES: [&str; 7] = ["x64", "x32", "ia32", "arm64", "riscv", "do", "se"];

/// Kernel functions every syscall passes on its way in or out, so a stack
/// with one is in a syscall even without the syscall's own function.
const SYSCALL_PATH: [&str; 19] = [
    // x86, and 32-bit syscalls on x86-64.
    "do_syscall_64",
    "x64_sys_call",
    "x32_sys_call",
    "ia32_sys_call",
    "do_fast_syscall_32",
    "__do_fast_syscall_32",
    "do_int80_syscall_32",
    "do_int80_emulation",
    "asm_int80_emulation",
    "entry_INT80_compat",
    "do_SYSENTER_32",
    // arm64
    "el0_svc",
    "el0_svc_compat",
    "do_el0_svc",
    "do_el0_svc_compat",
    "el0_svc_common",
    "invoke_syscall",
    // riscv
    "do_trap_ecall_u",
    // The common way out, which is also how a new thread returns from
    // clone.
    "syscall_exit_to_user_mode",
];

/// Where the kernel starts running other than for a syscall: x86's
/// exception and interrupt entries, and arm64's from user space.
const ENTRY_PREFIXES: [&str; 4] = ["asm_exc_", "asm_sysvec_", "asm_xenpv_exc_", "el0t_"];

const ENTRIES: [&str; 5] = [
    "asm_common_interrupt",
    "asm_spurious_interrupt",
    // riscv's for every trap.
    "handle_exception",
    // Where new threads start.
    "ret_from_fork",
    "ret_from_fork_asm",
];

fn mark(name: &str) -> Mark<'_> {
    // Copies the compiler made, as in `el0_svc_common.constprop.0`.
    let name = name.split('.').next().unwrap_or(name);
    if let Some(syscall) = syscall(name) {
        Mark::Syscall(syscall)
    } else if SYSCALL_PATH.contains(&name)
        // x86's entry code, as in `entry_SYSCALL_64_after_hwframe`.
        || name.starts_with("entry_SYS")
    {
        Mark::SyscallPath
    } else if ENTRY_PREFIXES.iter().any(|p| name.starts_with(p)) || ENTRIES.contains(&name) {
        Mark::Entry
    } else {
        Mark::Other
    }
}

/// The syscall a function of the kernel's syscall macros is for: `read`
/// for `__x64_sys_read` or `__ia32_compat_sys_read`.
fn syscall(name: &str) -> Option<&str> {
    let (prefix, rest) = name.strip_prefix("__")?.split_once('_')?;
    if !SYSCALL_PREFIXES.contains(&prefix) {
        return None;
    }
    let rest = rest.strip_prefix("compat_").unwrap_or(rest);
    rest.strip_prefix("sys_")
        .filter(|syscall| !syscall.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn syscall_of(name: &str) -> Option<&str> {
        match mark(name) {
            Mark::Syscall(syscall) => Some(syscall),
            _ => None,
        }
    }

    #[test]
    fn names_syscalls_by_their_functions() {
        assert_eq!(syscall_of("__x64_sys_read"), Some("read"));
        assert_eq!(syscall_of("__ia32_compat_sys_ioctl"), Some("ioctl"));
        assert_eq!(
            syscall_of("__arm64_sys_clock_nanosleep"),
            Some("clock_nanosleep")
        );
        assert_eq!(syscall_of("__do_sys_clone3.isra.0"), Some("clone3"));
        assert_eq!(syscall_of("__x64_sys_"), None);
        // Padding before the function, and kernel functions that are not
        // syscalls.
        assert_eq!(syscall_of("__pfx___x64_sys_read"), None);
        assert_eq!(syscall_of("do_sys_openat2"), None);
        assert_eq!(syscall_of("sys_fillrect"), None);
        assert_eq!(syscall_of("ksys_read"), None);
    }

    #[test]
    fn knows_the_ways_into_the_kernel() {
        for name in [
            "entry_SYSCALL_64_after_hwframe",
            "entry_SYSENTER_compat_after_hwframe",
            "do_syscall_64",
            "syscall_exit_to_user_mode",
            "el0_svc_common.constprop.0",
            "invoke_syscall",
        ] {
            assert!(matches!(mark(name), Mark::SyscallPath), "{name}");
        }
        for name in [
            "asm_exc_page_fault",
            "asm_sysvec_apic_timer_interrupt",
            "el0t_64_sync",
            "ret_from_fork_asm",
        ] {
            assert!(matches!(mark(name), Mark::Entry), "{name}");
        }
        for name in [
            "irqentry_exit_to_user_mode",
            "asm_load_gs_index",
            "ksys_read",
        ] {
            assert!(matches!(mark(name), Mark::Other), "{name}");
        }
    }
}
