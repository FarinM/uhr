//! Agents pipe output into `head` and the like, which stop reading early.
//! The tests use a pipe whose read end is already closed: a closed fd would
//! not do, because Rust reopens closed stdio on /dev/null at startup.

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
    common::compile(&program, "-O2");
    let recording = dir.join("rec");
    // The target writes to stderr itself, so this fails on any host, not
    // only on those where perf prints a warning.
    let target = format!("echo started >&2; exec '{}' 20", program.display());
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
    assert_eq!(manifest["target"]["exit"]["code"], 0);
    assert!(
        manifest["streams"][0]["coverage"]["samples"]
            .as_u64()
            .unwrap()
            > 0
    );
}
