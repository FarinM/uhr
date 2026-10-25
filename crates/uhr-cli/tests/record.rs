//! End to end: needs perf and a C compiler. `uhr doctor` shows what is
//! missing.
#![cfg(target_os = "linux")]

mod common;

use std::fs;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
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
    common::compile("cpu_bound", &program, "-O2");
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
fn an_interrupt_records_how_the_target_ended() {
    let dir = common::scratch("interrupt_records_exit");
    let program = dir.join("cpu_bound");
    common::compile("cpu_bound", &program, "-O2");
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
    assert_eq!(
        manifest["target"]["exit"]["signal"], 2,
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

/// uhr's child running `name`, once it has exec'd it. Any of uhr's threads
/// can be its parent.
fn child_running(uhr: u32, name: &str) -> Option<u32> {
    let mut children = Vec::new();
    for task in fs::read_dir(format!("/proc/{uhr}/task")).ok()?.flatten() {
        let list = fs::read_to_string(task.path().join("children")).unwrap_or_default();
        children.extend(
            list.split_whitespace()
                .map(|pid| pid.parse::<u32>().unwrap()),
        );
    }
    children.into_iter().find(|pid| {
        fs::read_to_string(format!("/proc/{pid}/comm")).is_ok_and(|comm| comm.trim() == name)
    })
}

fn interrupt_group(uhr: u32) {
    assert!(
        Command::new("kill")
            .args(["-INT", "--", &format!("-{uhr}")])
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn an_interrupt_ends_the_capture_and_a_second_kills_the_target() {
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
    while child_running(uhr.0.id(), "sleep").is_none() {
        assert!(
            uhr.0.try_wait().unwrap().is_none(),
            "recording exited early"
        );
        assert!(Instant::now() < deadline, "target did not start");
        thread::sleep(Duration::from_millis(10));
    }
    thread::sleep(Duration::from_millis(500));
    interrupt_group(uhr.0.id());
    // uhr waits for the target, which ignores the interrupt.
    thread::sleep(Duration::from_millis(500));
    assert!(uhr.0.try_wait().unwrap().is_none(), "uhr did not wait");
    assert!(!recording.exists());
    interrupt_group(uhr.0.id());
    assert!(uhr.wait().success());

    let manifest = manifest(&recording);
    let start = manifest["start_ns"].as_u64().unwrap();
    let end = manifest["end_ns"].as_u64().unwrap();
    assert!(
        (500_000_000..900_000_000).contains(&(end - start)),
        "the capture lasted {} ns, not until the first interrupt",
        end - start
    );
    assert_eq!(manifest["target"]["exit"]["signal"], 9);
}

/// Exits 0 on SIGTERM, writing "exit 0" to its second argument first. Its
/// first argument is created once it waits.
const EXITS_ON_SIGTERM: &str = r#"
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
"#;

/// Counts its SIGINTs, and once it has one, waits long enough for another
/// to arrive, then writes the count to its second argument and exits 0. Its
/// first argument is created once it waits.
const COUNTS_SIGINTS: &str = r#"
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t interrupts;
static void count(int signal) { (void)signal; interrupts++; }

int main(int argc, char **argv) {
    (void)argc;
    struct sigaction action = {0};
    action.sa_handler = count;
    if (sigaction(SIGINT, &action, NULL) != 0) return 1;
    int ready = open(argv[1], O_CREAT | O_WRONLY, 0600);
    if (ready < 0) return 1;
    close(ready);
    while (!interrupts) pause();
    struct timespec left = {0, 300000000};
    while (nanosleep(&left, &left) != 0) {}
    FILE *out = fopen(argv[2], "w");
    if (!out) return 1;
    fprintf(out, "%d", (int)interrupts);
    return fclose(out) != 0;
}
"#;

fn build(dir: &Path, name: &str, source: &str) -> PathBuf {
    let path = dir.join(format!("{name}.c"));
    fs::write(&path, source).unwrap();
    let program = dir.join(name);
    assert!(
        Command::new("cc")
            .arg(&path)
            .arg("-o")
            .arg(&program)
            .status()
            .unwrap()
            .success()
    );
    program
}

fn wait_for(path: &Path, uhr: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(uhr.try_wait().unwrap().is_none(), "recording exited early");
        assert!(Instant::now() < deadline, "target did not start");
        thread::sleep(Duration::from_millis(10));
    }
}

/// Records a target that exits 0 on SIGTERM, once it waits. Returns where
/// it writes when it exits.
fn record_until_sigterm(dir: &Path, recording: &Path) -> (RecordingProcess, PathBuf) {
    let program = build(dir, "target", EXITS_ON_SIGTERM);
    let (ready, exited) = (dir.join("ready"), dir.join("exited"));
    let mut uhr = RecordingProcess(
        Command::new(common::UHR)
            .arg("record")
            .arg("-o")
            .arg(recording)
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
    wait_for(&ready, &mut uhr.0);
    (uhr, exited)
}

fn signal(pid: u32, signal: &str) {
    assert!(
        Command::new("kill")
            .args([signal, &pid.to_string()])
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn when_perf_stops_first_the_target_is_asked_to_stop() {
    let dir = common::scratch("perf_stops_first");
    let recording = dir.join("rec");
    let (mut uhr, exited) = record_until_sigterm(&dir, &recording);
    let perf = child_running(uhr.0.id(), "perf").expect("perf runs");
    signal(perf, "-INT");
    assert!(uhr.wait().success());
    // The target got SIGTERM, and exited 0 from its handler.
    assert_eq!(fs::read_to_string(exited).unwrap(), "exit 0");
    assert_eq!(manifest(&recording)["target"]["exit"]["code"], 0);
}

#[test]
fn a_signal_sent_to_uhr_alone_reaches_the_target() {
    let dir = common::scratch("signal_to_uhr_reaches_target");
    let recording = dir.join("rec");
    let (mut uhr, exited) = record_until_sigterm(&dir, &recording);
    signal(uhr.0.id(), "-TERM");
    assert!(uhr.wait().success());
    assert_eq!(fs::read_to_string(exited).unwrap(), "exit 0");
    assert_eq!(manifest(&recording)["target"]["exit"]["code"], 0);
}

#[test]
fn ctrl_c_at_a_terminal_reaches_the_target_once() {
    if Command::new("script").arg("--version").output().is_err() {
        eprintln!("skipped: script, which gives uhr a terminal, is not installed");
        return;
    }
    let dir = common::scratch("ctrl_c_reaches_target_once");
    let program = build(&dir, "counter", COUNTS_SIGINTS);
    let (recording, ready, count) = (dir.join("rec"), dir.join("ready"), dir.join("count"));
    let record = format!(
        "exec '{}' record -o '{}' --no-symbolize -- '{}' '{}' '{}'",
        common::UHR,
        recording.display(),
        program.display(),
        ready.display(),
        count.display()
    );
    // script runs uhr on a terminal of its own, and passes its input on.
    let mut terminal = RecordingProcess(
        Command::new("script")
            .args(["-qec", &record, "/dev/null"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap(),
    );
    wait_for(&ready, &mut terminal.0);
    let mut input = terminal.0.stdin.take().unwrap();
    input.write_all(b"\x03").unwrap();
    input.flush().unwrap();
    assert!(terminal.wait().success());
    drop(input);
    assert_eq!(fs::read_to_string(count).unwrap(), "1");
    assert_eq!(manifest(&recording)["target"]["exit"]["code"], 0);
}

#[test]
fn records_the_signal_that_killed_the_target() {
    let dir = common::scratch("records_killing_signal");
    let recording = dir.join("rec");
    let output = record(
        &recording,
        &["--no-symbolize"],
        &["sh", "-c", "kill -TERM $$"],
    );
    assert!(output.status.success());
    assert_eq!(manifest(&recording)["target"]["exit"]["signal"], 15);
}

#[test]
fn the_recording_starts_at_the_targets_exec() {
    let dir = common::scratch("starts_at_exec");
    let program = dir.join("cpu_bound");
    common::compile("cpu_bound", &program, "-O2");
    let recording = dir.join("rec");
    let output = record(&recording, &[], &[program.to_str().unwrap(), "5"]);
    assert!(output.status.success());
    let overview = common::uhr(&["overview", recording.to_str().unwrap(), "--json"]);
    let overview: Value = serde_json::from_slice(&overview.stdout).unwrap();
    // Held, the process still ran uhr, under uhr's name.
    let threads = overview["threads"].as_array().unwrap();
    assert_eq!(threads.len(), 1, "{threads:?}");
    assert_eq!(threads[0]["names"], serde_json::json!(["cpu_bound"]));
}

/// A process uhr did not start.
struct Bystander(Child);

impl Drop for Bystander {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn attaching_records_for_the_duration_and_leaves_the_process_alone() {
    let dir = common::scratch("attach_for_a_duration");
    let program = dir.join("cpu_bound");
    common::compile("cpu_bound", &program, "-O2");
    let mut running = Bystander(
        Command::new(&program)
            .arg("100000")
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let recording = dir.join("rec");
    let pid = running.0.id().to_string();
    let output = Command::new(common::UHR)
        .arg("record")
        .arg("-o")
        .arg(&recording)
        .args(["--no-symbolize", "--pid", &pid, "--duration", "1s"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(running.0.try_wait().unwrap().is_none(), "the process ended");

    let manifest = manifest(&recording);
    assert_eq!(manifest["target"]["launched"], false);
    assert!(
        manifest["target"]["exit"].is_null(),
        "{}",
        manifest["target"]
    );
    let seconds = (manifest["end_ns"].as_u64().unwrap() - manifest["start_ns"].as_u64().unwrap())
        as f64
        / 1e9;
    assert!((0.9..1.5).contains(&seconds), "captured {seconds} s");
    assert!(
        manifest["streams"][0]["coverage"]["samples"]
            .as_u64()
            .unwrap()
            > 0
    );
}

/// uhr attached to `pid`, once it records.
fn attach(recording: &Path, log: &Path, pid: u32) -> RecordingProcess {
    let mut uhr = RecordingProcess(
        Command::new(common::UHR)
            .arg("record")
            .arg("-o")
            .arg(recording)
            .args(["--no-symbolize", "--pid", &pid.to_string()])
            .stderr(fs::File::create(log).unwrap())
            .process_group(0)
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !fs::read_to_string(log)
        .unwrap()
        .contains("attached, recording")
    {
        assert!(
            uhr.0.try_wait().unwrap().is_none(),
            "recording exited early"
        );
        assert!(Instant::now() < deadline, "the capture did not start");
        thread::sleep(Duration::from_millis(10));
    }
    uhr
}

#[test]
fn an_interrupt_ends_an_attached_capture_without_signalling_the_process() {
    let dir = common::scratch("interrupt_attached_capture");
    // SIGINT would end sleep.
    let mut running = Bystander(Command::new("sleep").arg("30").spawn().unwrap());
    let (recording, log) = (dir.join("rec"), dir.join("uhr.log"));
    let mut uhr = attach(&recording, &log, running.0.id());
    signal(uhr.0.id(), "-INT");
    let status = uhr.wait();
    assert!(
        status.success(),
        "{status}: {}",
        fs::read_to_string(&log).unwrap()
    );
    assert!(
        running.0.try_wait().unwrap().is_none(),
        "the process got the interrupt"
    );
    assert!(manifest(&recording)["target"]["exit"].is_null());
}

#[test]
fn an_attached_process_still_runs_when_perf_stops_first() {
    let dir = common::scratch("perf_stops_under_attached_process");
    let mut running = Bystander(Command::new("sleep").arg("30").spawn().unwrap());
    let (recording, log) = (dir.join("rec"), dir.join("uhr.log"));
    let mut uhr = attach(&recording, &log, running.0.id());
    let perf = child_running(uhr.0.id(), "perf").expect("perf runs");
    signal(perf, "-INT");
    assert!(uhr.wait().success());
    assert!(running.0.try_wait().unwrap().is_none());
    assert!(
        manifest(&recording)["target"]["exit"].is_null(),
        "{}",
        manifest(&recording)["target"]
    );
}

#[test]
fn a_target_that_asks_for_a_parent_death_signal_keeps_running() {
    let tools = ["taskset", "setpriv"];
    if tools
        .iter()
        .any(|tool| Command::new(tool).arg("--version").output().is_err())
    {
        eprintln!("skipped: needs taskset and setpriv");
        return;
    }
    let dir = common::scratch("parent_death_signal");
    let recording = dir.join("rec");
    // On one CPU, the target asks for the signal before the thread that
    // started it would have exited, had it not lived on.
    let output = Command::new("taskset")
        .args(["-c", "0", common::UHR, "record", "--no-symbolize", "-o"])
        .arg(&recording)
        .args(["--", "setpriv", "--pdeathsig", "TERM", "sleep", "0.1"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(manifest(&recording)["target"]["exit"]["code"], 0);
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
