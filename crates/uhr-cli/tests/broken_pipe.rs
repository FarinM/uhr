//! Agents pipe output into `head` and the like, which stop reading early.
//! The tests use a pipe whose read end is already closed: a closed fd would
//! not do, because Rust reopens closed stdio on /dev/null at startup.
#![cfg(target_os = "linux")]

mod common;

use std::fs;
use std::process::{Command, Output, Stdio};

use serde_json::Value;

fn closed_pipe() -> Stdio {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    writer.into()
}

fn uhr(args: &[&str], stdout: Stdio, stderr: Stdio) -> Output {
    Command::new(common::UHR)
        .args(args)
        .stdout(stdout)
        .stderr(stderr)
        .output()
        .unwrap()
}

#[test]
fn doctor_keeps_its_exit_code_when_stdout_is_closed() {
    for args in [&["doctor"][..], &["doctor", "--json"]] {
        let normal = uhr(args, Stdio::null(), Stdio::null());
        let closed = uhr(args, closed_pipe(), Stdio::piped());
        assert_eq!(
            closed.status.code(),
            normal.status.code(),
            "{args:?}: {}",
            String::from_utf8_lossy(&closed.stderr)
        );
    }
}

#[test]
fn record_finishes_when_stderr_is_closed() {
    let dir = common::scratch("record_with_closed_stderr");
    let program = dir.join("cpu_bound");
    common::compile("cpu_bound", &program, "-O2");
    let recording = dir.join("rec");
    // The target has uhr's stderr, as it would without uhr, so writing to
    // it kills the target. uhr and perf still finish the recording.
    let target = format!("'{}' 20; echo done >&2", program.display());
    let output = uhr(
        &[
            "record",
            "-o",
            recording.to_str().unwrap(),
            "--",
            "sh",
            "-c",
            &target,
        ],
        Stdio::null(),
        closed_pipe(),
    );
    assert!(
        output.status.success(),
        "uhr record exited with {}",
        output.status
    );

    let manifest: Value =
        serde_json::from_slice(&fs::read(recording.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["target"]["exit"]["signal"], 13);
    assert!(
        manifest["streams"][0]["coverage"]["stacks"]["samples"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(recording.join("symbols.parquet").exists());
}

#[test]
fn query_succeeds_when_stdout_is_closed() {
    let dir = common::scratch("query_with_closed_stdout");
    let program = dir.join("cpu_bound");
    common::compile("cpu_bound", &program, "-O2");
    let recording = dir.join("rec");
    let recording = recording.to_str().unwrap();
    let record = uhr(
        &[
            "record",
            "-o",
            recording,
            "--",
            program.to_str().unwrap(),
            "20",
        ],
        Stdio::null(),
        Stdio::null(),
    );
    assert!(record.status.success());

    for json in [false, true] {
        let mut args = vec!["query", recording, "--group-by", "function"];
        if json {
            args.push("--json");
        }
        let output = uhr(&args, closed_pipe(), Stdio::piped());
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn errors_exit_cleanly_when_stderr_is_closed() {
    let output = uhr(
        &["query", "/nonexistent", "--group-by", "function"],
        Stdio::null(),
        closed_pipe(),
    );
    assert_eq!(output.status.code(), Some(1));
}
