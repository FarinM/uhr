//! End to end: needs perf and a C compiler. `uhr doctor` shows what is
//! missing.
#![cfg(target_os = "linux")]

mod common;

use std::path::Path;

use serde_json::Value;

use common::{compile, scratch, uhr};

fn json(command: &str, recording: &Path, args: &[&str]) -> Value {
    let mut all = vec![command, recording.to_str().unwrap(), "--json"];
    all.extend(args);
    serde_json::from_slice(&uhr(&all).stdout).unwrap()
}

#[test]
fn splits_one_recording_by_the_function_that_led_to_the_time() {
    let dir = scratch("stack_filter");
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

    let query = |args: &[&str]| {
        let mut all = vec!["--group-by", "function"];
        all.extend(args);
        json("query", &recording, &all)
    };
    let cpu_ns = |result: &Value| result["time_ns"].as_f64().unwrap();
    let all = query(&[]);
    let a = query(&["--under", "from_a"]);
    let b = query(&["--under", "from_b"]);
    let a_share = cpu_ns(&a) / cpu_ns(&all);
    assert!((0.7..=0.8).contains(&a_share), "from_a has {a_share}");
    // Only main's own loop, startup and exit are under neither.
    let both = cpu_ns(&a) + cpu_ns(&b);
    assert!(both <= cpu_ns(&all) && both > 0.95 * cpu_ns(&all));
    let either = query(&["--under", "from_a", "--under", "from_b"]);
    assert_eq!(cpu_ns(&either), both);

    // The other tools take the same samples.
    let overview = json("overview", &recording, &["--under", "from_b"]);
    assert_eq!(overview["samples"], b["samples"]);
    let paths = json(
        "call-paths",
        &recording,
        &["--function", "spin", "--under", "from_a"],
    );
    assert_eq!(paths["samples"], a["samples"]);
    let callers: Vec<_> = paths["callers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["function"].as_str().unwrap())
        .collect();
    assert_eq!(callers, ["from_a"]);
}
