use std::collections::BTreeMap;

use serde::Serialize;

use crate::filter::Filter;
use crate::functions::Functions;
use crate::recording::{Origin, Recording, Signal, SyscallCalls};

/// Where a stack stands with syscalls, read from the kernel functions on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum InSyscall<'a> {
    Named(&'a str),
    /// In uhr's own eBPF programs, which run as syscalls enter and leave
    /// the kernel. Their stacks don't show which syscall.
    OwnPrograms,
    /// In a syscall whose own function is not on the stack, as on its way
    /// back to user space.
    Unnamed,
    /// In user code, or in kernel code entered another way: a fault or an
    /// interrupt from user space, or the start of a thread.
    Outside,
    /// The stack does not show how the kernel was entered: its kernel
    /// functions have no names, it may have been cut short, or uhr does not
    /// know the kernel's entries.
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
/// with no frames in the host's kernel. Only Linux's kernel functions are
/// known.
pub(crate) fn of_stacks<'a>(
    recording: &Recording,
    functions: &'a Functions,
) -> Vec<Option<InSyscall<'a>>> {
    let linux = recording.manifest.platform.os == "linux";
    let marks: Vec<Option<Mark>> = (0..functions.len() as u32)
        .map(|id| {
            let function = functions.get(id);
            (function.origin == Origin::Kernel).then(|| match function.name.as_deref() {
                Some(name) if linux => mark(name),
                _ => Mark::Other,
            })
        })
        .collect();
    // x86 enters the kernel the same way for a fault or an interrupt in
    // kernel code as in user code, so an entry shows where the kernel was
    // entered only on a stack that perf's depth limit did not cut.
    let depth_limit = recording
        .manifest
        .streams
        .iter()
        .filter_map(|s| s.coverage.stacks.as_ref())
        .map(|s| s.max_stack_depth as usize)
        .min();
    let own_programs = recording.in_own_programs();
    recording
        .stacks
        .iter()
        .enumerate()
        .map(|(id, stack)| {
            if own_programs.as_ref().is_some_and(|own| own[id]) {
                return Some(InSyscall::OwnPrograms);
            }
            // Interpreter frames come from the interpreter's memory, not the
            // walk the limit cuts.
            let native = stack
                .iter()
                .filter(|&&frame| recording.frames[frame as usize].origin != Origin::Interpreted)
                .count();
            let whole = depth_limit.is_some_and(|limit| native < limit);
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
    let function = rest
        .strip_prefix("sys_")
        .filter(|syscall| !syscall.is_empty())?;
    Some(table_name(function))
}

/// The syscall tables' name for a syscall whose function has another, as
/// `fstat` for `newfstat`, so both name it as the counted calls do.
fn table_name(function: &str) -> &str {
    match function {
        "newstat" => "stat",
        "newfstat" => "fstat",
        "newlstat" => "lstat",
        "newuname" => "uname",
        "umount" => "umount2",
        _ => function,
    }
}

/// What uhr's eBPF programs counted of each syscall, for the processes and
/// threads `filter` keeps. `None` without them, or for a filter they can't
/// take: they count each thread's calls over the whole capture, not by
/// time, mode or stack.
pub(crate) fn counted(recording: &Recording, filter: &Filter) -> Option<BTreeMap<String, Counted>> {
    let streamed = recording
        .manifest
        .streams
        .iter()
        .any(|s| s.signals.contains(&Signal::SyscallCalls));
    let whole_threads = filter.thread_names.is_empty()
        && filter.modes.is_empty()
        && filter.under.is_empty()
        && filter.from_ns.is_none()
        && filter.to_ns.is_none();
    if !streamed || !whole_threads {
        return None;
    }
    let mut counted: BTreeMap<String, Counted> = BTreeMap::new();
    for calls in &recording.syscall_calls {
        let name = calls_name(calls);
        let kept = (filter.pids.is_empty() || filter.pids.contains(&calls.pid))
            && (filter.tids.is_empty() || filter.tids.contains(&calls.tid))
            && (filter.syscalls.is_empty() || filter.syscalls.contains(&name));
        if kept {
            counted.entry(name).or_default().add(calls);
        }
    }
    for counted in counted.values_mut() {
        counted.median = counted.percentile(50);
        counted.p99 = counted.percentile(99);
    }
    Some(counted)
}

/// The name of a syscall that was counted, or its number for one the
/// table has no name for, as `#439`.
pub(crate) fn calls_name(calls: &SyscallCalls) -> String {
    calls
        .name
        .clone()
        .unwrap_or_else(|| format!("#{}", calls.number))
}

/// The calls of one syscall that uhr's eBPF programs counted.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Counted {
    /// Calls that returned during the capture.
    pub calls: u64,
    /// Their time from entry to exit, on CPU or not.
    pub time_ns: u64,
    /// The range of times the median call, and the 99th percentile one,
    /// fall in. `None` without returned calls.
    pub median: Option<Latency>,
    pub p99: Option<Latency>,
    /// Threads still in the syscall when the capture ended, and the time
    /// they had spent in it then.
    pub unfinished: u64,
    pub unfinished_ns: u64,
    #[serde(skip)]
    latency: Vec<u64>,
}

/// A range of call times: one of the counted latency buckets.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Latency {
    pub at_least_ns: u64,
    /// `None` for the last bucket, which has no end.
    pub below_ns: Option<u64>,
}

impl Counted {
    fn add(&mut self, calls: &SyscallCalls) {
        self.calls += calls.calls;
        self.time_ns += calls.time_ns;
        if let Some(ns) = calls.unfinished_ns {
            self.unfinished += 1;
            self.unfinished_ns += ns;
        }
        if self.latency.len() < calls.latency.len() {
            self.latency.resize(calls.latency.len(), 0);
        }
        for (sum, n) in self.latency.iter_mut().zip(&calls.latency) {
            *sum += n;
        }
    }

    fn percentile(&self, percent: u64) -> Option<Latency> {
        // The call at least `percent` percent of the calls are no longer
        // than.
        let rank = (self.calls * percent).div_ceil(100).max(1);
        let mut below = 0;
        let last = self.latency.len().checked_sub(1)?;
        let bucket = self.latency.iter().position(|&n| {
            below += n;
            below >= rank
        })?;
        Some(Latency {
            at_least_ns: if bucket == 0 { 0 } else { 1 << bucket },
            below_ns: (bucket < last).then(|| 1 << (bucket + 1)),
        })
    }
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
        // As the syscall tables name it.
        assert_eq!(syscall_of("__x64_sys_newfstat"), Some("fstat"));
        assert_eq!(syscall_of("__x64_sys_"), None);
        // Padding before the function, and kernel functions that are not
        // syscalls.
        assert_eq!(syscall_of("__pfx___x64_sys_read"), None);
        assert_eq!(syscall_of("do_sys_openat2"), None);
        assert_eq!(syscall_of("sys_fillrect"), None);
        assert_eq!(syscall_of("ksys_read"), None);
    }

    #[test]
    fn finds_the_latency_of_a_percentile() {
        let mut counted = Counted::default();
        counted.add(&SyscallCalls {
            pid: 1,
            tid: 1,
            number: 0,
            name: Some("read".into()),
            calls: 100,
            time_ns: 0,
            latency: vec![1, 0, 0, 97, 2],
            unfinished_ns: None,
        });
        let range = |at_least_ns, below_ns| {
            Some(Latency {
                at_least_ns,
                below_ns,
            })
        };
        assert_eq!(counted.percentile(50), range(8, Some(16)));
        assert_eq!(counted.percentile(99), range(16, None));
        assert_eq!(counted.percentile(1), range(0, Some(2)));
        assert_eq!(Counted::default().percentile(50), None);
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
