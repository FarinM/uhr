//! End to end: needs perf, a C compiler and root through sudo without a
//! password, for uhr's eBPF programs. `uhr doctor` shows what is missing.
#![cfg(target_os = "linux")]

mod common;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::Duration;

use uhr_core::recording::{OffCPUInterval, Origin, Recording, Signal, ThreadState, Waker};

use common::{compile, scratch, uhr, uhr_as_root};

/// Each test's eBPF programs see every wakeup on the machine, so they take
/// turns.
static EBPF: Mutex<()> = Mutex::new(());

fn one_at_a_time() -> MutexGuard<'static, ()> {
    EBPF.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Records `waits` as root with `flags`. `None` where uhr can't be root.
fn record_waits(name: &str, flags: &[&str]) -> Option<(PathBuf, Recording)> {
    let dir = scratch(name);
    let program = dir.join("waits");
    compile("waits", &program, "-O2");
    let recording = dir.join("rec");
    let mut args = vec!["record", "-o", recording.to_str().unwrap()];
    args.extend(flags);
    args.extend(["--", program.to_str().unwrap()]);
    uhr_as_root(&args, &recording)?;
    let read = Recording::read(&recording).unwrap();
    Some((recording, read))
}

/// The time off CPU of the overview of `recording`.
fn off_cpu(recording: &Path) -> serde_json::Value {
    let args = ["overview", recording.to_str().unwrap(), "--json"];
    let overview: serde_json::Value = serde_json::from_slice(&uhr(&args).stdout).unwrap();
    overview["off_cpu"].clone()
}

/// Each thread's last name.
fn names(recording: &Recording) -> HashMap<u32, &str> {
    let names = recording.thread_names.iter();
    names.map(|n| (n.tid, n.name.as_str())).collect()
}

fn of<'a>(recording: &'a Recording, thread: &str) -> Vec<&'a OffCPUInterval> {
    let names = names(recording);
    let intervals = recording.off_cpu.iter();
    intervals.filter(|i| names[&i.tid] == thread).collect()
}

/// The kernel functions of a stack, leaf first.
fn kernel_functions(recording: &Recording, stack: u32) -> Vec<&str> {
    let frames = recording.stacks[stack as usize].iter();
    let frames = frames.map(|&f| &recording.frames[f as usize]);
    frames
        .filter(|f| f.origin == Origin::Kernel)
        .filter_map(|f| {
            let address = f.address - u64::from(f.return_address);
            let mut symbols = recording.kernel_symbols.iter();
            let symbol = symbols.find(|s| s.start <= address && address < s.end)?;
            Some(symbol.name.as_str())
        })
        .collect()
}

#[test]
fn sees_what_woke_each_waiting_thread() {
    let _turn = one_at_a_time();
    let Some((path, recording)) = record_waits("wakeups", &[]) else {
        eprintln!("skipped: needs root through sudo without a password");
        return;
    };
    let ebpf = &recording.manifest.streams;
    let ebpf = ebpf.iter().find(|s| s.id == "ebpf").unwrap();
    assert!(ebpf.signals.contains(&Signal::Wakeups), "{ebpf:?}");
    let named = recording.manifest.kernel_symbols == uhr_core::recording::KernelSymbols::Saved;

    // locker waits for the lock all the time holder computes, until holder
    // lets go of it.
    let lock = of(&recording, "locker");
    let lock = lock.iter().max_by_key(|i| i.end_ns - i.start_ns).unwrap();
    let wakeup = lock.wakeup.as_ref().unwrap();
    match &wakeup.waker {
        Waker::Thread { name, .. } => assert_eq!(name, "holder"),
        waker => panic!("{waker:?}"),
    }
    assert!((lock.start_ns..=lock.end_ns).contains(&wakeup.time_ns));
    if named {
        let stack = kernel_functions(&recording, wakeup.stack.unwrap());
        assert_eq!(stack.first(), Some(&"try_to_wake_up"), "{stack:?}");
        assert!(stack.contains(&"futex_wake"), "{stack:?}");
    }

    // napper's timer wakes it, in an interrupt.
    let naps = of(&recording, "napper");
    let blocked = naps.iter().filter(|i| i.state == ThreadState::Blocked);
    let mut woken = 0;
    for nap in blocked.filter(|i| i.end_ns - i.start_ns > 5_000_000) {
        let wakeup = nap.wakeup.as_ref().unwrap();
        assert_eq!(wakeup.waker, Waker::Interrupt);
        if named {
            let stack = kernel_functions(&recording, wakeup.stack.unwrap());
            assert!(stack.contains(&"hrtimer_wakeup"), "{stack:?}");
        }
        woken += 1;
    }
    assert!(woken >= 10, "{naps:?}");

    // Preempted threads need no wakeup.
    for spinner in ["spin_a", "spin_b"] {
        let runnable = of(&recording, spinner);
        let runnable = runnable.iter().filter(|i| i.state == ThreadState::Runnable);
        assert!(runnable.clone().count() > 0);
        assert!(runnable.into_iter().all(|i| i.wakeup.is_none()));
    }

    // Once woken, threads waited for a CPU.
    let time = off_cpu(&path);
    let woken = time["wakeup_latency_ns"].as_u64().unwrap();
    let runnable = time["runnable_ns"].as_u64().unwrap();
    assert!(0 < woken && woken < runnable, "{time}");
}

#[test]
fn finds_who_let_go_of_the_lock_a_thread_waited_for() {
    let _turn = one_at_a_time();
    let Some((path, recording)) = record_waits("waker_query", &[]) else {
        eprintln!("skipped: needs root through sudo without a password");
        return;
    };
    let query = |group_by| -> serde_json::Value {
        let args = [
            "query",
            path.to_str().unwrap(),
            "--group-by",
            group_by,
            "--metric",
            "off-cpu",
            "--under",
            "wait_for_lock",
            "--json",
        ];
        serde_json::from_slice(&uhr(&args).stdout).unwrap()
    };
    let share = |row: &serde_json::Value, field| row[field].as_f64().unwrap();

    let wakers = query("waker");
    let top = &wakers["rows"][0];
    assert_eq!(top["waker_name"], "holder", "{wakers}");
    assert!(share(top, "share") > 0.9, "{wakers}");

    let functions = query("waker-function");
    let rows = functions["rows"].as_array().unwrap();
    let total = |name: &str| {
        let row = rows.iter().find(|r| r["function"] == name);
        let row = row.unwrap_or_else(|| panic!("no {name}: {functions}"));
        share(row, "total_share")
    };
    assert!(total("holder") > 0.9, "{functions}");
    if recording.manifest.kernel_symbols == uhr_core::recording::KernelSymbols::Saved {
        assert!(total("futex_wake") > 0.9, "{functions}");
    }
}

/// Records `program`, run on `cpus` with `arg`, by attaching to it as root
/// for a second, with its process id. `None` where uhr can't be root.
fn record_attached(name: &str, program: &str, cpus: &str, arg: &str) -> Option<(u32, Recording)> {
    let dir = scratch(name);
    let binary = dir.join(program);
    compile(program, &binary, "-O2");
    let Ok(mut target) = Command::new("taskset")
        .args(["-c", cpus])
        .arg(&binary)
        .arg(arg)
        .stdout(Stdio::null())
        .spawn()
    else {
        eprintln!("skipped: needs taskset");
        return None;
    };
    thread::sleep(Duration::from_millis(100));
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    let pid = target.id().to_string();
    let args = ["record", "-o", rec, "--pid", &pid, "--duration", "1s"];
    let recorded = uhr_as_root(&args, &recording);
    target.kill().unwrap();
    target.wait().unwrap();
    if recorded.is_none() {
        eprintln!("skipped: needs root through sudo without a password");
        return None;
    }
    Some((target.id(), Recording::read(&recording).unwrap()))
}

#[test]
fn an_interrupt_wakes_a_thread_rather_than_the_one_it_interrupts() {
    let _turn = one_at_a_time();
    // On one CPU, the timer that wakes the sleeping main thread interrupts
    // the computing one.
    let Some((main, recording)) = record_attached("wakeups_interrupted", "naps", "0", "20") else {
        return;
    };
    let woken: Vec<_> = recording
        .off_cpu
        .iter()
        .filter(|i| i.tid == main)
        .filter_map(|i| i.wakeup.as_ref())
        .collect();
    assert!(woken.len() >= 20, "{woken:?}");
    assert!(
        woken.iter().all(|w| w.waker == Waker::Interrupt),
        "{woken:?}"
    );
}

#[test]
fn sees_threads_woken_on_their_way_off_the_cpu() {
    let _turn = one_at_a_time();
    // With more threads than CPUs after a lock held only briefly, its holder
    // often lets go of it as a waiter is still going to sleep.
    let Some((_, recording)) = record_attached("wakeups_contended", "locks", "0-3", "16") else {
        return;
    };
    let blocked = recording.off_cpu.iter();
    let blocked: Vec<_> = blocked
        .filter(|i| i.state == ThreadState::Blocked)
        .collect();
    assert!(blocked.len() > 1_000, "{}", blocked.len());
    // perf starts before uhr's programs and stops after them.
    let woken = || blocked.iter().filter_map(|i| i.wakeup.as_ref());
    let first = woken().map(|w| w.time_ns).min().unwrap();
    let last = woken().map(|w| w.time_ns).max().unwrap();
    let watched = blocked
        .iter()
        .filter(|i| (first..last).contains(&i.start_ns));
    let unwoken = watched.filter(|i| i.wakeup.is_none()).count() as u64;
    let streams = recording.manifest.streams.iter();
    let lost: u64 = streams.map(|s| s.coverage.lost_events).sum();
    assert!(
        unwoken <= lost + blocked.len() as u64 / 1_000,
        "{unwoken} of {} waits had no wakeup, with {lost} events lost",
        blocked.len()
    );
}

#[test]
fn a_softirq_wakes_a_thread_rather_than_the_one_it_ran_on() {
    let _turn = one_at_a_time();
    // Its sender delivers each packet itself, in a softirq run as its send
    // enables them.
    let Some((sender, recording)) = record_attached("wakeups_softirq", "udp", "0-3", "") else {
        return;
    };
    let received = recording.off_cpu.iter().filter(|i| i.tid != sender);
    let woken: Vec<_> = received.filter_map(|i| i.wakeup.as_ref()).collect();
    assert!(woken.len() >= 100, "{}", woken.len());
    if recording.manifest.kernel_symbols != uhr_core::recording::KernelSymbols::Saved {
        return;
    }
    let in_softirq = |stack: &[&str]| {
        let last = stack.last().copied();
        last == Some("handle_softirqs") || last == Some("__do_softirq")
    };
    let mut softirqs = 0;
    for wakeup in woken.iter().filter(|w| w.waker == Waker::Interrupt) {
        let stack = kernel_functions(&recording, wakeup.stack.unwrap());
        softirqs += u32::from(in_softirq(&stack));
        assert!(!stack.iter().any(|f| f.contains("sendto")), "{stack:?}");
    }
    assert!(softirqs >= 100, "{softirqs}");
}

#[test]
fn another_probe_leaves_wakers_stacks_as_they_are() {
    let _turn = one_at_a_time();
    // With a second probe, the kernel gets to each through one more function.
    let probe = Command::new("sudo")
        .args(["-n", "perf", "stat", "-a", "-e", "sched:sched_waking"])
        .args(["--", "sleep", "5"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut probe) = probe else {
        eprintln!("skipped: needs sudo");
        return;
    };
    thread::sleep(Duration::from_secs(1));
    let recorded = record_waits("wakeups_other_probe", &[]);
    let probed = probe.wait().unwrap().success();
    let (Some((_, recording)), true) = (recorded, probed) else {
        eprintln!("skipped: needs root through sudo without a password, and perf's tracepoints");
        return;
    };
    if recording.manifest.kernel_symbols != uhr_core::recording::KernelSymbols::Saved {
        return;
    }
    let woken = recording.off_cpu.iter();
    let woken: Vec<_> = woken.filter_map(|i| i.wakeup.as_ref()).collect();
    assert!(!woken.is_empty());
    for wakeup in woken {
        let stack = kernel_functions(&recording, wakeup.stack.unwrap());
        assert_eq!(stack.first(), Some(&"try_to_wake_up"), "{stack:?}");
    }
}

#[test]
fn sees_no_wakeups_when_asked_not_to() {
    let _turn = one_at_a_time();
    let Some((path, recording)) = record_waits("no_wakeups", &["--no-wakeups"]) else {
        eprintln!("skipped: needs root through sudo without a password");
        return;
    };
    let streams = recording.manifest.streams.iter();
    assert!(
        streams
            .clone()
            .all(|s| !s.signals.contains(&Signal::Wakeups))
    );
    let missing = streams.flat_map(|s| &s.missing_signals);
    let missing = missing.chain(&recording.manifest.missing_signals);
    assert!(missing.into_iter().all(|m| m.signal != Signal::Wakeups));
    assert!(!recording.off_cpu.is_empty());
    assert!(recording.off_cpu.iter().all(|i| i.wakeup.is_none()));
    assert!(off_cpu(&path)["wakeup_latency_ns"].is_null());
}

#[test]
fn says_why_it_saw_no_wakeups_without_root() {
    let dir = scratch("wakeups_unprivileged");
    let program = dir.join("waits");
    compile("waits", &program, "-O2");
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    uhr(&["record", "-o", rec, "--", program.to_str().unwrap()]);
    let recording = Recording::read(&recording).unwrap();
    let streams = recording.manifest.streams.iter();
    if streams
        .clone()
        .any(|s| s.signals.contains(&Signal::Wakeups))
    {
        eprintln!("skipped: uhr may load its eBPF programs without root here");
        return;
    }
    let missing = streams.flat_map(|s| &s.missing_signals);
    let mut missing = missing.chain(&recording.manifest.missing_signals);
    let wakeups = missing.find(|m| m.signal == Signal::Wakeups).unwrap();
    assert!(!wakeups.reason.is_empty());
}
