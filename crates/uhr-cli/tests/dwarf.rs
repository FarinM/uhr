//! End to end: needs perf, built with zstd, and a C compiler. `uhr doctor`
//! shows what is missing.
#![cfg(target_os = "linux")]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use common::{
    compile, compile_rust, compile_with_flags, compile_without_frame_pointers, scratch, uhr,
};

fn record(dir: &Path, program: &Path, extra: &[&str], args: &[&str]) -> PathBuf {
    let recording = dir.join("rec");
    let mut all = vec![
        "record",
        "-o",
        recording.to_str().unwrap(),
        "--unwind",
        "dwarf",
    ];
    all.extend(extra);
    all.push("--");
    all.push(program.to_str().unwrap());
    all.extend(args);
    uhr(&all);
    recording
}

fn manifest(recording: &Path) -> Value {
    serde_json::from_slice(&fs::read(recording.join("manifest.json")).unwrap()).unwrap()
}

/// User mode only: a timer interrupt in a function adds kernel frames
/// below it, and these tests are about the C call structure.
fn callers(recording: &Path, function: &str) -> Vec<(String, f64)> {
    let output = uhr(&[
        "call-paths",
        recording.to_str().unwrap(),
        "--function",
        function,
        "--mode",
        "user",
        "--json",
    ]);
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    result["callers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| {
            (
                n["function"].as_str().unwrap_or("<unnamed>").to_owned(),
                n["share"].as_f64().unwrap(),
            )
        })
        .collect()
}

#[test]
fn finds_the_caller_of_a_function_without_a_frame() {
    // GCC sets up no frame in hot(), so frame-pointer stacks skip main.
    let dir = scratch("dwarf_frameless_leaf");
    let program = dir.join("cpu_bound");
    compile("cpu_bound", &program, "-O2");
    let recording = record(&dir, &program, &[], &["30"]);
    let callers = callers(&recording, "hot");
    assert_eq!(callers[0].0, "main", "{callers:?}");
    assert!(callers[0].1 > 0.7, "{callers:?}");
}

#[test]
fn unwinds_binaries_built_without_frame_pointers() {
    let dir = scratch("dwarf_no_frame_pointers");
    let program = dir.join("paths");
    compile_without_frame_pointers("paths", &program, "-O2");
    let recording = record(&dir, &program, &[], &["100"]);

    let stream = &manifest(&recording)["streams"][0];
    let stacks = &stream["coverage"]["stacks"];
    assert_eq!(stacks["unwinding"], "dwarf");
    assert_eq!(stacks["stack_copy_bytes"], 32768);
    assert_eq!(stacks["stacks_cut_at_stack_copy"], 0);

    let callers = callers(&recording, "spin");
    let share = |name: &str| {
        callers
            .iter()
            .find(|(caller, _)| caller == name)
            .unwrap_or_else(|| panic!("no {name} in {callers:?}"))
            .1
    };
    assert!((0.7..=0.8).contains(&share("from_a")), "{callers:?}");
    assert!((0.2..=0.3).contains(&share("from_b")), "{callers:?}");
}

#[test]
fn unwinds_rust_binaries() {
    let dir = scratch("dwarf_rust");
    let program = dir.join("stack_frames");
    compile_rust("stack_frames", &program);
    let recording = record(&dir, &program, &[], &["10"]);
    let callers = callers(&recording, "stack_frames::burn");
    assert_eq!(callers.len(), 1, "{callers:?}");
    assert_eq!(callers[0].0, "stack_frames::caller");
    assert!(callers[0].1 > 0.95, "{callers:?}");
}

#[test]
fn uses_debug_frame_where_eh_frame_has_no_rules() {
    // Only the startup code gets .eh_frame; the program's own rules are in
    // a compressed .debug_frame.
    let dir = scratch("dwarf_debug_frame");
    let program = dir.join("paths");
    compile_with_flags(
        "paths",
        &program,
        &[
            "-O2",
            "-g",
            "-gz=zlib",
            "-fomit-frame-pointer",
            "-fno-asynchronous-unwind-tables",
            "-fno-unwind-tables",
        ],
    );
    let recording = record(&dir, &program, &[], &["100"]);
    let callers = callers(&recording, "spin");
    let share = |name: &str| {
        callers
            .iter()
            .find(|(caller, _)| caller == name)
            .unwrap_or_else(|| panic!("no {name} in {callers:?}"))
            .1
    };
    assert!((0.7..=0.8).contains(&share("from_a")), "{callers:?}");
    assert!((0.2..=0.3).contains(&share("from_b")), "{callers:?}");
}

#[test]
fn counts_the_stacks_cut_at_the_stack_copy() {
    let dir = scratch("dwarf_small_stack_copy");
    let program = dir.join("paths");
    compile_without_frame_pointers("paths", &program, "-O2");
    let recording = record(&dir, &program, &["--stack-size", "64"], &["30"]);
    let coverage = &manifest(&recording)["streams"][0]["coverage"]["stacks"];
    let stacks =
        coverage["samples"].as_f64().unwrap() + coverage["off_cpu_intervals"].as_f64().unwrap();
    let cut = coverage["stacks_cut_at_stack_copy"].as_f64().unwrap();
    assert!(cut > 0.9 * stacks, "{coverage}");
    // What fits in the copy is still there.
    assert_eq!(callers(&recording, "spin").len(), 2);
}

#[test]
fn does_not_unwind_32_bit_code_whose_file_is_gone() {
    let dir = scratch("dwarf_32_bit");
    let program = dir.join("i386");
    compile_with_flags("i386", &program, &["-m32", "-static", "-nostdlib", "-O2"]);
    let recording = record(&dir, &program, &[], &[]);
    assert!(!program.exists(), "the program deletes itself");
    let coverage = &manifest(&recording)["streams"][0]["coverage"]["stacks"];
    let samples = coverage["samples"].as_u64().unwrap();
    assert!(samples > 0, "{coverage}");
    let stacks = samples + coverage["off_cpu_intervals"].as_u64().unwrap();
    assert_eq!(coverage["stacks_not_unwound"], stacks, "{coverage}");
    assert_eq!(coverage["stacks_cut_at_stack_copy"], 0, "{coverage}");
}

#[test]
fn a_stack_size_needs_dwarf_unwinding() {
    let dir = scratch("dwarf_stack_size_without_dwarf");
    let output = Command::new(common::UHR)
        .arg("record")
        .arg("-o")
        .arg(dir.join("rec"))
        .args(["--stack-size", "4096", "--", "true"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--unwind dwarf"));
}
