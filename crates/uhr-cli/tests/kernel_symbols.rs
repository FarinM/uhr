//! End to end: needs perf and a C compiler. Kernel names also need
//! /proc/kallsyms to show the kernel's addresses; where it hides them,
//! these tests check that results say why. `uhr doctor` shows what is
//! missing.

mod common;

use std::fs;
use std::path::Path;

use serde_json::Value;

use common::{compile, scratch, uhr};

fn json(args: &[&str]) -> Value {
    let mut args = args.to_vec();
    args.push("--json");
    serde_json::from_slice(&uhr(&args).stdout).unwrap()
}

/// The kernel hides every address or none.
fn kallsyms_shows_addresses() -> bool {
    fs::read_to_string("/proc/kallsyms")
        .unwrap()
        .lines()
        .find(|l| matches!(l.split_whitespace().nth(1), Some("t" | "T")))
        .is_some_and(|l| !l.starts_with("0000000000000000"))
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
fn names_the_kernel_code_under_a_syscall() {
    let dir = scratch("kernel_symbols");
    let program = dir.join("syscalls");
    compile("syscalls", &program, "-O2");
    let recording = dir.join("rec");
    let recording = recording.to_str().unwrap();
    uhr(&[
        "record",
        "-o",
        recording,
        "--",
        program.to_str().unwrap(),
        "200000",
    ]);
    let manifest: Value =
        serde_json::from_slice(&fs::read(Path::new(recording).join("manifest.json")).unwrap())
            .unwrap();
    let query = json(&[
        "query",
        recording,
        "--group-by",
        "function",
        "--mode",
        "kernel",
        "--top",
        "100",
    ]);
    let coverage = &query["coverage"];

    if !kallsyms_shows_addresses() {
        assert_eq!(manifest["kernel_symbols"]["status"], "unavailable");
        let problems = coverage["symbol_problems"].as_array().unwrap();
        assert!(
            problems
                .iter()
                .any(|p| p["path"] == "[kernel]" && p["status"] == "unavailable"),
            "{coverage}"
        );
        return;
    }

    assert_eq!(manifest["kernel_symbols"]["status"], "saved");
    assert!(
        coverage["named_share"].as_f64().unwrap() > 0.99,
        "{coverage}"
    );
    let rows = query["rows"].as_array().unwrap();
    let vfs_read = rows
        .iter()
        .find(|r| r["function"] == "vfs_read")
        .expect("read() runs vfs_read");
    assert!(
        vfs_read["total_share"].as_f64().unwrap() > 0.8,
        "{vfs_read}"
    );
    assert_eq!(vfs_read["module"], "[kernel]");
    let build_id = vfs_read["build_id"]
        .as_str()
        .expect("the kernel's build-id");
    let start = vfs_read["function_address"].as_u64().unwrap();
    assert_eq!(vfs_read["id"], format!("{build_id}+0x{start:x}"));

    // One stack runs from the program's read_zero down into the kernel's.
    let read_zero = rows
        .iter()
        .find(|r| r["function"] == "read_zero" && r["origin"] == "binary")
        .unwrap();
    let paths = json(&[
        "call-paths",
        recording,
        "--function",
        read_zero["id"].as_str().unwrap(),
        "--depth",
        "12",
    ]);
    let callee = find(&paths["callees"], "vfs_read").expect("vfs_read under read_zero");
    assert_eq!(callee["origin"], "kernel");
    assert!(callee["share"].as_f64().unwrap() > 0.8, "{callee}");
}
