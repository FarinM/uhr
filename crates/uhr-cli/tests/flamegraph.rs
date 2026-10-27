//! End to end: needs perf and a C compiler. `uhr doctor` shows what is
//! missing.
#![cfg(target_os = "linux")]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use common::{UHR, compile, scratch, uhr};

/// A recording of main calling spin through from_a for 75% of the time
/// and from_b for 25%, and where to write its graph.
fn record(name: &str) -> (PathBuf, PathBuf) {
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
    (recording, dir.join("graph"))
}

/// User mode only: a timer interrupt or page fault in a function adds
/// kernel frames above it, and these tests are about the C call structure.
fn flamegraph(recording: &Path, output: &Path, flags: &[&str]) -> Value {
    let mut args = vec![
        "flamegraph",
        recording.to_str().unwrap(),
        "-o",
        output.to_str().unwrap(),
        "--mode",
        "user",
        "--json",
    ];
    args.extend(flags);
    serde_json::from_slice(&uhr(&args).stdout).unwrap()
}

#[test]
fn draws_where_the_time_went() {
    let (recording, output) = record("flamegraph_svg");
    let graph = flamegraph(&recording, &output, &[]);
    assert!(graph["graphed_share"].as_f64().unwrap() > 0.99, "{graph:#}");
    let svg = fs::read_to_string(&output).unwrap();
    assert!(svg.starts_with("<?xml"), "{}", &svg[..200]);
    for function in ["main", "from_a", "from_b", "spin"] {
        assert!(svg.contains(function), "no {function}");
    }
    assert!(svg.contains("CPU time: "), "the title names the metric");
}

#[test]
fn folds_the_stacks_from_a_function() {
    let (recording, output) = record("flamegraph_folded");
    let graph = flamegraph(&recording, &output, &["--folded", "--root", "main"]);
    assert_eq!(graph["root"]["function"], "main");
    let folded = fs::read_to_string(&output).unwrap();
    let mut total = 0;
    let under = |caller: &str| -> u64 {
        folded
            .lines()
            .filter(|line| line.starts_with(&format!("main;{caller};spin")))
            .map(|line| line.rsplit_once(' ').unwrap().1.parse::<u64>().unwrap())
            .sum()
    };
    let (a, b) = (under("from_a"), under("from_b"));
    for line in folded.lines() {
        assert!(line.starts_with("main"), "{line}");
        total += line.rsplit_once(' ').unwrap().1.parse::<u64>().unwrap();
    }
    assert_eq!(total, graph["graphed_ns"].as_u64().unwrap());
    let share = a as f64 / (a + b) as f64;
    assert!((0.7..0.8).contains(&share), "from_a has {share}");
}

#[test]
fn says_when_nothing_is_left_to_draw() {
    let (recording, output) = record("flamegraph_empty");
    let failed = Command::new(UHR)
        .args(["flamegraph", recording.to_str().unwrap()])
        .args(["-o", output.to_str().unwrap(), "--pid", "1"])
        .output()
        .unwrap();
    assert!(!failed.status.success());
    let stderr = String::from_utf8_lossy(&failed.stderr);
    assert!(stderr.contains("nothing to draw"), "{stderr}");
    assert!(!output.exists());
}
