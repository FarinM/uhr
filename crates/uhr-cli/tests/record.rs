//! End to end: needs perf and a C compiler. `uhr doctor` shows what is
//! missing.

mod common;

use std::fs;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

fn manifest(recording: &Path) -> Value {
    serde_json::from_slice(&fs::read(recording.join("manifest.json")).unwrap()).unwrap()
}

fn record(recording: &Path, extra: &[&str], target: &[&str]) -> Output {
    Command::new(common::UHR)
        .arg("record")
        .arg("-o")
        .arg(recording)
        .args(extra)
        .arg("--")
        .args(target)
        .stdout(Stdio::null())
        .output()
        .unwrap()
}

#[test]
fn records_the_frequency_perf_actually_used() {
    let dir = common::scratch("records_the_actual_frequency");
    let program = dir.join("cpu_bound");
    common::compile(&program, "-O2");
    let recording = dir.join("rec");
    // Far above any kernel's sampling limit, so perf has to lower it.
    let output = record(
        &recording,
        &["-F", "10000000"],
        &[program.to_str().unwrap(), "5"],
    );
    assert!(output.status.success());

    let collector = &manifest(&recording)["streams"][0]["collector"];
    assert_eq!(collector["requested_frequency_hz"], 10_000_000);
    assert!(collector["frequency_hz"].as_u64().unwrap() < 10_000_000);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("perf lowered the sampling frequency")
    );
}

#[test]
fn an_interrupt_makes_the_exit_status_unknown() {
    let dir = common::scratch("interrupt_makes_exit_unknown");
    let program = dir.join("cpu_bound");
    common::compile(&program, "-O2");
    let recording = dir.join("rec");
    let mut uhr = Command::new(common::UHR)
        .arg("record")
        .arg("-o")
        .arg(&recording)
        .arg("--")
        .arg(&program)
        .arg("100000")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .unwrap();
    thread::sleep(Duration::from_secs(1));
    // Like Ctrl-C at a terminal: the whole process group gets SIGINT.
    let group = format!("-{}", uhr.id());
    let kill = Command::new("kill")
        .args(["-INT", "--", &group])
        .status()
        .unwrap();
    assert!(kill.success());
    assert!(uhr.wait().unwrap().success());

    let manifest = manifest(&recording);
    assert!(
        manifest["target"]["exit"]["unknown"].is_string(),
        "{}",
        manifest["target"]
    );
    assert!(
        manifest["streams"][0]["coverage"]["samples"]
            .as_u64()
            .unwrap()
            > 0
    );
}

struct RecordingProcess(Child);

impl RecordingProcess {
    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "recording did not finish");
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for RecordingProcess {
    fn drop(&mut self) {
        // A failing assertion must not leave the intentionally endless target running.
        let _ = Command::new("kill")
            .args(["-KILL", "--", &format!("-{}", self.0.id())])
            .stderr(Stdio::null())
            .status();
        let _ = self.0.wait();
    }
}

/// Whether perf's child, which is uhr's grandchild, has exec'd `name`.
fn target_runs(uhr: u32, name: &str) -> bool {
    let children = |pid: u32| -> Vec<u32> {
        fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))
            .unwrap_or_default()
            .split_whitespace()
            .map(|pid| pid.parse().unwrap())
            .collect()
    };
    children(uhr).into_iter().flat_map(children).any(|pid| {
        fs::read_to_string(format!("/proc/{pid}/comm")).is_ok_and(|comm| comm.trim() == name)
    })
}

#[test]
fn an_interrupt_ends_the_capture_even_while_the_target_sleeps() {
    let dir = common::scratch("interrupt_ends_the_capture");
    let recording = dir.join("rec");
    // Ignored signals stay ignored across exec, so sleep outlives the
    // interrupt and no exit event marks the end of the capture.
    let mut uhr = RecordingProcess(
        Command::new(common::UHR)
            .arg("record")
            .arg("-o")
            .arg(&recording)
            .arg("--no-symbolize")
            .args(["--", "sh", "-c", "trap '' INT; exec sleep 30"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    // The capture starts when the target execs.
    while !target_runs(uhr.0.id(), "sleep") {
        assert!(
            uhr.0.try_wait().unwrap().is_none(),
            "recording exited early"
        );
        assert!(Instant::now() < deadline, "target did not start");
        thread::sleep(Duration::from_millis(10));
    }
    thread::sleep(Duration::from_millis(500));
    let group = format!("-{}", uhr.0.id());
    assert!(
        Command::new("kill")
            .args(["-INT", "--", &group])
            .status()
            .unwrap()
            .success()
    );
    assert!(uhr.wait().success());

    let manifest = manifest(&recording);
    let start = manifest["start_ns"].as_u64().unwrap();
    let end = manifest["end_ns"].as_u64().unwrap();
    assert!(
        end - start >= 500_000_000,
        "the capture lasted only {} ns",
        end - start
    );
}

#[test]
fn a_signal_sent_only_to_perf_is_not_the_targets_exit_status() {
    let dir = common::scratch("perf_signal_makes_exit_unknown");
    let source = dir.join("target.c");
    let program = dir.join("target");
    let ready = dir.join("ready");
    let exited = dir.join("exited");
    fs::write(
        &source,
        r#"
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

static int exit_file;
static void finish(int signal) {
    (void)signal;
    write(exit_file, "exit 0", 6);
    _exit(0);
}

int main(int argc, char **argv) {
    (void)argc;
    exit_file = open(argv[2], O_CREAT | O_WRONLY, 0600);
    if (exit_file < 0 || signal(SIGTERM, finish) == SIG_ERR) return 1;
    int ready = open(argv[1], O_CREAT | O_WRONLY, 0600);
    if (ready < 0) return 1;
    close(ready);
    for (;;) pause();
}
"#,
    )
    .unwrap();
    assert!(
        Command::new("cc")
            .arg(&source)
            .arg("-o")
            .arg(&program)
            .status()
            .unwrap()
            .success()
    );
    let recording = dir.join("rec");
    let mut uhr = RecordingProcess(
        Command::new(common::UHR)
            .arg("record")
            .arg("-o")
            .arg(&recording)
            .arg("--no-symbolize")
            .arg("--")
            .arg(&program)
            .arg(&ready)
            .arg(&exited)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready.exists() {
        assert!(
            uhr.0.try_wait().unwrap().is_none(),
            "recording exited early"
        );
        assert!(Instant::now() < deadline, "target did not start");
        thread::sleep(Duration::from_millis(10));
    }
    let pid = uhr.0.id();
    let children = fs::read_to_string(format!("/proc/{pid}/task/{pid}/children")).unwrap();
    let children: Vec<_> = children.split_whitespace().collect();
    assert_eq!(children.len(), 1, "expected only the perf subprocess");
    assert!(
        Command::new("kill")
            .args(["-INT", "--", children[0]])
            .status()
            .unwrap()
            .success()
    );
    assert!(uhr.wait().success());
    assert_eq!(fs::read_to_string(exited).unwrap(), "exit 0");
    let exit = &manifest(&recording)["target"]["exit"];
    assert!(exit["unknown"].is_string(), "{exit}");
}

#[test]
fn preserves_the_targets_numeric_exit_code() {
    let dir = common::scratch("preserves_target_exit_code");
    for code in [0, 23] {
        let recording = dir.join(format!("rec-{code}"));
        let output = record(
            &recording,
            &["--no-symbolize"],
            &["sh", "-c", &format!("exit {code}")],
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(manifest(&recording)["target"]["exit"]["code"], code);
    }
}

#[test]
fn refuses_a_staging_directory_left_behind() {
    let dir = common::scratch("refuses_leftover_staging");
    fs::create_dir(dir.join("rec.partial")).unwrap();
    let output = record(&dir.join("rec"), &[], &["true"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("rec.partial exists"));
}
