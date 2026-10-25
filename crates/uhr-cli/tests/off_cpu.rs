//! End to end: needs perf and a C compiler. Off-CPU stacks also need kernel
//! sampling, and their kernel names /proc/kallsyms to show the kernel's
//! addresses; where those are missing, these tests check what is left.
//! `uhr doctor` shows what is missing.

mod common;

use std::fs;
use std::path::Path;
use std::process::Command;

use serde_json::Value;

use common::{UHR, compile, scratch, uhr};

fn json(args: &[&str]) -> Value {
    let mut args = args.to_vec();
    args.push("--json");
    serde_json::from_slice(&uhr(&args).stdout).unwrap()
}

fn record(name: &str, flags: &[&str]) -> String {
    let dir = scratch(name);
    let program = dir.join("waits");
    compile("waits", &program, "-O2");
    let recording = dir.join("rec");
    let mut args = vec!["record", "-o", recording.to_str().unwrap()];
    args.extend(flags);
    args.extend(["--", program.to_str().unwrap()]);
    uhr(&args);
    recording.to_str().unwrap().to_owned()
}

fn manifest(recording: &str) -> Value {
    serde_json::from_slice(&fs::read(Path::new(recording).join("manifest.json")).unwrap()).unwrap()
}

fn thread<'a>(overview: &'a Value, name: &str) -> &'a Value {
    overview["threads"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["names"].as_array().unwrap().last().unwrap() == name)
        .unwrap_or_else(|| panic!("no thread {name} in {overview}"))
}

fn number(value: &Value) -> f64 {
    value
        .as_f64()
        .unwrap_or_else(|| panic!("{value} is not a number"))
}

fn off_cpu(recording: &str, filter: &[&str]) -> Value {
    let mut args = vec![
        "query",
        recording,
        "--group-by",
        "function",
        "--metric",
        "off-cpu",
        "--top",
        "100",
    ];
    args.extend(filter);
    json(&args)
}

fn row<'a>(result: &'a Value, function: &str, origin: &str) -> &'a Value {
    result["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["function"] == function && r["origin"] == origin)
        .unwrap_or_else(|| panic!("no {origin} row {function} in {result}"))
}

fn find<'a>(nodes: &'a Value, function: &str) -> Option<&'a Value> {
    nodes.as_array()?.iter().find_map(|node| {
        if node["function"] == function {
            Some(node)
        } else {
            find(&node["children"], function)
        }
    })
}

#[test]
fn tells_computing_from_waiting_and_why() {
    let recording = record("off_cpu", &[]);
    let manifest = manifest(&recording);
    let stream = &manifest["streams"][0];
    assert_eq!(stream["collector"]["context_switches"], true);
    let signals = stream["signals"].as_array().unwrap();
    assert!(signals.contains(&"off_cpu_time".into()), "{stream}");

    let overview = json(&["overview", &recording]);
    for thread in overview["threads"].as_array().unwrap() {
        let accounted = number(&thread["on_cpu_share"])
            + number(&thread["runnable_share"])
            + number(&thread["blocked_share"]);
        assert!((0.85..=1.1).contains(&accounted), "{thread}");
    }
    let holder = thread(&overview, "holder");
    assert!(number(&holder["blocked_share"]) < 0.05, "{holder}");
    for name in ["spin_a", "spin_b"] {
        let spinner = thread(&overview, name);
        assert!(number(&spinner["runnable_share"]) > 0.25, "{spinner}");
    }
    for name in ["locker", "napper"] {
        let waiter = thread(&overview, name);
        assert!(number(&waiter["blocked_share"]) > 0.9, "{waiter}");
    }

    let wall = json(&[
        "query",
        &recording,
        "--group-by",
        "function",
        "--metric",
        "wall",
    ]);
    let alive: f64 = overview["threads"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| number(&t["alive_ns"]))
        .sum();
    let accounted = number(&wall["time_ns"]) / alive;
    assert!((0.85..=1.05).contains(&accounted), "{accounted}");

    if !signals.contains(&"off_cpu_stacks".into()) {
        let all = off_cpu(&recording, &[]);
        assert_eq!(all["coverage"]["no_stack_share"], 1.0, "{all}");
        return;
    }

    let napper = off_cpu(&recording, &["--thread", "napper"]);
    let nap = row(&napper, "nap", "binary");
    assert!(number(&nap["total_share"]) > 0.95, "{nap}");

    // The lock is held for as long as holder lives.
    let locked = off_cpu(&recording, &["--under", "wait_for_lock"]);
    let held = number(&locked["time_ns"]) / number(&holder["alive_ns"]);
    assert!((0.9..=1.05).contains(&held), "{held}");

    if manifest["kernel_symbols"]["status"] != "saved" {
        return;
    }
    let sleep = row(&napper, "do_nanosleep", "kernel");
    assert!(number(&sleep["total_share"]) > 0.95, "{sleep}");
    let paths = json(&[
        "call-paths",
        &recording,
        "--function",
        "wait_for_lock",
        "--metric",
        "off-cpu",
        "--depth",
        "16",
    ]);
    let futex = find(&paths["callees"], "futex_wait_queue").expect("the lock waits in a futex");
    assert_eq!(futex["origin"], "kernel");
    assert!(
        number(&futex["time_ns"]) > 0.95 * number(&paths["total_ns"]),
        "{futex}"
    );

    let syscall_share = |thread: &str, syscall: &str| {
        let result = json(&[
            "query",
            &recording,
            "--group-by",
            "syscall",
            "--metric",
            "off-cpu",
            "--thread",
            thread,
        ]);
        result["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["syscall"] == syscall)
            .map_or(0.0, |r| number(&r["share"]))
    };
    let napping = syscall_share("napper", "clock_nanosleep");
    assert!(napping > 0.95, "napper is {napping} in clock_nanosleep");
    let locking = syscall_share("locker", "futex");
    assert!(locking > 0.95, "locker is {locking} in futex");
    let in_futex = off_cpu(
        &recording,
        &["--under", "wait_for_lock", "--syscall", "futex"],
    );
    let share = number(&in_futex["time_ns"]) / number(&locked["time_ns"]);
    assert!(share > 0.95, "{share} of the lock wait is in futex");
}

#[test]
fn records_no_context_switches_when_told_not_to() {
    let recording = record("no_off_cpu", &["--no-off-cpu"]);
    assert_eq!(
        manifest(&recording)["streams"][0]["collector"]["context_switches"],
        false
    );
    let overview = json(&["overview", &recording]);
    assert!(overview["off_cpu"].is_null(), "{overview}");
    assert!(
        overview["coverage"]["unknown"]
            .as_array()
            .unwrap()
            .iter()
            .any(|u| u.as_str().unwrap().starts_with("why threads were off CPU")),
        "{overview}"
    );

    let output = Command::new(UHR)
        .args([
            "query",
            &recording,
            "--group-by",
            "function",
            "--metric",
            "off-cpu",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("context switches were not recorded"),
        "{stderr}"
    );
}
