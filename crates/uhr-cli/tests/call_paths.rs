//! End to end: needs perf and a C compiler. `uhr doctor` shows what is
//! missing.
#![cfg(target_os = "linux")]

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use common::{compile, scratch, uhr};

fn record(name: &str) -> PathBuf {
    let dir = scratch(name);
    let program = dir.join("paths");
    compile("paths", &program, "-O2");
    let recording = dir.join("rec");
    uhr(&[
        "record",
        "-o",
        recording.to_str().unwrap(),
        "--",
        program.to_str().unwrap(),
        "100",
    ]);
    recording
}

/// User mode only: a timer interrupt or page fault in a function adds
/// kernel frames below it, and these tests are about the C call structure.
fn call_paths(recording: &Path, function: &str) -> Value {
    let output = uhr(&[
        "call-paths",
        recording.to_str().unwrap(),
        "--function",
        function,
        "--mode",
        "user",
        "--json",
    ]);
    serde_json::from_slice(&output.stdout).unwrap()
}

fn node<'a>(nodes: &'a Value, function: &str) -> &'a Value {
    nodes
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["function"] == function)
        .unwrap_or_else(|| panic!("no {function} in {nodes:#}"))
}

#[test]
fn finds_which_callers_make_a_function_expensive() {
    let recording = record("call_paths_callers");
    let spin = call_paths(&recording, "spin");
    assert!(spin["total_share"].as_f64().unwrap() > 0.95, "{spin:#}");

    let a = node(&spin["callers"], "from_a");
    let b = node(&spin["callers"], "from_b");
    let a_share = a["share"].as_f64().unwrap();
    let b_share = b["share"].as_f64().unwrap();
    assert!((0.7..=0.8).contains(&a_share), "from_a has {a_share}");
    assert!((0.2..=0.3).contains(&b_share), "from_b has {b_share}");
    for caller in [a, b] {
        let main = node(&caller["children"], "main");
        assert_eq!(main["value"], caller["value"]);
    }
    // spin's only callee runs for nanoseconds and is rarely sampled.
    assert!(
        spin["callees"]
            .as_array()
            .unwrap()
            .iter()
            .all(|n| n["function"] == "keep"),
        "{:#}",
        spin["callees"]
    );

    // The id from query selects the same function.
    let output = uhr(&[
        "query",
        recording.to_str().unwrap(),
        "--group-by",
        "function",
        "--mode",
        "user",
        "--json",
    ]);
    let query: Value = serde_json::from_slice(&output.stdout).unwrap();
    let row = node(&query["rows"], "spin");
    let by_id = call_paths(&recording, row["id"].as_str().unwrap());
    assert_eq!(by_id["total"], spin["total"]);
    assert_eq!(by_id["total"], row["total"]);
}

#[test]
fn follows_callees_down_to_where_the_time_is_spent() {
    let recording = record("call_paths_callees");
    let main = call_paths(&recording, "main");
    for caller in ["from_a", "from_b"] {
        let caller = node(&main["callees"], caller);
        let spin = node(&caller["children"], "spin");
        let leaf = spin["self"].as_f64().unwrap();
        assert!(
            leaf > 0.99 * caller["value"].as_f64().unwrap(),
            "{caller:#}"
        );
    }

    let output = Command::new(common::UHR)
        .args([
            "call-paths",
            recording.to_str().unwrap(),
            "--function",
            "nothing",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no function in the recorded stacks"));
}
