//! End to end: needs perf, and Python 3.12 or later or Node. The test of a
//! runtime that is missing checks nothing.

mod common;

use std::path::Path;
use std::process::Command;

use serde_json::Value;

use common::{scratch, uhr};

const PROGRAMS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test-programs");

fn json(args: &[&str]) -> Value {
    let mut args = args.to_vec();
    args.push("--json");
    serde_json::from_slice(&uhr(&args).stdout).unwrap()
}

fn succeeds(command: &[&str]) -> bool {
    Command::new(command[0])
        .args(&command[1..])
        .output()
        .is_ok_and(|output| output.status.success())
}

fn has_python_perf_support() -> bool {
    let check = "import sys; sys.exit(sys.version_info < (3, 12))";
    succeeds(&["python3", "-c", check])
}

fn record(dir: &Path, flags: &[&str], command: &[&str]) -> String {
    let recording = dir.join("rec");
    let recording = recording.to_str().unwrap();
    let mut args = vec!["record", "-o", recording];
    args.extend(flags);
    args.push("--");
    args.extend(command);
    uhr(&args);
    recording.to_owned()
}

fn functions(recording: &str) -> Vec<Value> {
    let result = json(&[
        "query",
        recording,
        "--group-by",
        "function",
        "--top",
        "1000",
    ]);
    result["rows"].as_array().unwrap().clone()
}

fn jit<'a>(rows: &'a [Value], function: &str) -> &'a Value {
    rows.iter()
        .find(|r| r["origin"] == "jit" && r["function"] == function)
        .unwrap_or_else(|| panic!("no JIT function {function}"))
}

fn share(row: &Value, which: &str) -> f64 {
    row[which].as_f64().unwrap()
}

/// The perf maps of the recorded processes are gone.
fn maps_removed(recording: &str) {
    let overview = json(&["overview", recording]);
    for process in overview["processes"].as_array().unwrap() {
        let map = format!("/tmp/perf-{}.map", process["pid"]);
        assert!(!Path::new(&map).exists(), "{map} was left behind");
    }
}

#[test]
fn names_python_functions_and_counts_the_interpreter_for_them() {
    if !has_python_perf_support() {
        eprintln!("skipped: needs Python 3.12 or later");
        return;
    }
    let dir = scratch("python_functions");
    let program = format!("{PROGRAMS}/jit.py");
    let recording = record(&dir, &[], &["python3", &program, "50"]);
    maps_removed(&recording);

    let rows = functions(&recording);
    let hot = jit(&rows, "hot");
    assert_eq!(hot["module"], "[python]", "{hot}");
    let file = hot["file"].as_str().unwrap();
    assert!(file.ends_with("test-programs/jit.py"), "{hot}");
    assert_eq!(hot["id"], format!("jit+python:hot:{file}"));
    // The interpreter's time counts for the Python function it runs.
    let (hot, warm) = (
        share(hot, "self_share"),
        share(jit(&rows, "warm"), "self_share"),
    );
    let split = hot / (hot + warm);
    assert!(hot + warm > 0.7, "hot {hot}, warm {warm}");
    assert!((0.65..0.92).contains(&split), "hot gets {split} of the two");
    assert!(share(jit(&rows, "work"), "total_share") > 0.9);

    let under = json(&[
        "query",
        &recording,
        "--group-by",
        "function",
        "--under",
        "work",
    ]);
    let all = json(&["query", &recording, "--group-by", "function"]);
    let ratio = share(&under, "time_ns") / share(&all, "time_ns");
    assert!(ratio > 0.9, "only {ratio} of the time is under work");
}

#[test]
fn names_javascript_functions() {
    if !succeeds(&["node", "--version"]) {
        eprintln!("skipped: needs Node");
        return;
    }
    let dir = scratch("javascript_functions");
    let program = format!("{PROGRAMS}/jit.js");
    let recording = record(&dir, &[], &["node", &program, "50"]);
    maps_removed(&recording);

    let rows = functions(&recording);
    let work = jit(&rows, "work");
    assert_eq!(work["module"], "[node]", "{work}");
    assert!(share(work, "total_share") > 0.8, "{work}");
    // V8 can compile hot and warm into work, so their time is work's.
    let program_time: f64 = rows
        .iter()
        .filter(|r| {
            r["origin"] == "jit"
                && r["file"]
                    .as_str()
                    .is_some_and(|f| f.ends_with("test-programs/jit.js"))
        })
        .map(|r| share(r, "self_share"))
        .sum();
    assert!(program_time > 0.7, "only {program_time} in jit.js");
}

#[test]
fn leaves_runtimes_alone_when_told_to() {
    if !has_python_perf_support() {
        eprintln!("skipped: needs Python 3.12 or later");
        return;
    }
    let dir = scratch("no_runtime_support");
    let program = format!("{PROGRAMS}/jit.py");
    let recording = record(
        &dir,
        &["--no-runtime-support"],
        &["python3", &program, "10"],
    );
    let manifest: Value = serde_json::from_slice(
        &std::fs::read(Path::new(&recording).join("manifest.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(manifest["target"]["runtime_support"], serde_json::json!([]));
    assert!(functions(&recording).iter().all(|r| r["origin"] != "jit"));
}
