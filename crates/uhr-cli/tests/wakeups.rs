//! End to end: needs perf, a C compiler and root through sudo without a
//! password, for uhr's eBPF programs. `uhr doctor` shows what is missing.
#![cfg(target_os = "linux")]

mod common;

use std::collections::HashMap;
use std::path::Path;
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
fn record_waits(name: &str, flags: &[&str]) -> Option<Recording> {
    let dir = scratch(name);
    let program = dir.join("waits");
    compile("waits", &program, "-O2");
    let recording = dir.join("rec");
    let mut args = vec!["record", "-o", recording.to_str().unwrap()];
    args.extend(flags);
    args.extend(["--", program.to_str().unwrap()]);
    uhr_as_root(&args, &recording)?;
    Some(Recording::read(&recording).unwrap())
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
    let Some(recording) = record_waits("wakeups", &[]) else {
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
}

#[test]
fn an_interrupt_wakes_a_thread_rather_than_the_one_it_interrupts() {
    let _turn = one_at_a_time();
    let dir = scratch("wakeups_interrupted");
    let program = dir.join("naps");
    compile("naps", &program, "-O2");
    // On one CPU, the timer that wakes the sleeping main thread interrupts
    // the computing one.
    let Ok(mut target) = Command::new("taskset")
        .args(["-c", "0"])
        .arg(&program)
        .arg("20")
        .stdout(Stdio::null())
        .spawn()
    else {
        eprintln!("skipped: needs taskset");
        return;
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
        return;
    }
    let recording = Recording::read(Path::new(rec)).unwrap();
    let main = target.id();
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
fn sees_no_wakeups_when_asked_not_to() {
    let _turn = one_at_a_time();
    let Some(recording) = record_waits("no_wakeups", &["--no-wakeups"]) else {
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
