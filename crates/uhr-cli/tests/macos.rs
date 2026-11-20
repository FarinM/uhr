//! End to end on macOS, with uhr's own sampler: needs a C compiler. `uhr
//! doctor` shows what is missing.
#![cfg(target_os = "macos")]

mod common;

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::Value;

use common::{UHR, compile, compile_with_debug_info, scratch, uhr, uhr_as_root};

fn json(args: &[&str]) -> Value {
    let mut args = args.to_vec();
    args.push("--json");
    serde_json::from_slice(&uhr(&args).stdout).unwrap()
}

fn record(recording: &Path, command: &[&str]) {
    let mut args = vec!["record", "-o", recording.to_str().unwrap(), "--"];
    args.extend(command);
    uhr(&args);
}

fn rows(result: &Value) -> &[Value] {
    result["rows"].as_array().unwrap()
}

fn row<'a>(result: &'a Value, function: &str) -> &'a Value {
    rows(result)
        .iter()
        .find(|r| r["function"] == function)
        .unwrap_or_else(|| panic!("no row for {function} in {result:#}"))
}

fn share(result: &Value, function: &str, kind: &str) -> f64 {
    row(result, function)[kind].as_f64().unwrap()
}

fn manifest(recording: &Path) -> Value {
    serde_json::from_slice(&fs::read(recording.join("manifest.json")).unwrap()).unwrap()
}

#[test]
fn finds_the_hot_function_with_its_share() {
    let dir = scratch("macos_finds_the_hot_function");
    let program = dir.join("cpu_bound");
    compile_with_debug_info("cpu_bound", &program, "-O2");
    let recording = dir.join("rec");
    record(&recording, &[program.to_str().unwrap()]);
    let path = recording.to_str().unwrap();

    let result = json(&["query", path, "--group-by", "function", "--top", "100"]);
    assert_eq!(rows(&result)[0]["function"], "hot");
    assert_eq!(rows(&result)[1]["function"], "warm");
    let hot = share(&result, "hot", "self_share");
    let warm = share(&result, "warm", "self_share");
    assert!((0.75..=0.85).contains(&hot), "hot has {hot}");
    assert!((0.15..=0.25).contains(&warm), "warm has {warm}");
    // Every stack reaches dyld's start, which calls main, and is named from
    // the names the recording saved of the system's code.
    assert!(share(&result, "start", "total_share") > 0.95);
    assert!(share(&result, "main", "total_share") > 0.95);
    let named = result["coverage"]["named_share"].as_f64().unwrap();
    assert!(
        named > 0.95,
        "only {named} of the time is in named functions"
    );

    // Lines come from the dSYM the compiler made beside the program.
    let lines = json(&["query", path, "--group-by", "line"]);
    let hot_line = rows(&lines)
        .iter()
        .find(|r| r["function"] == "hot")
        .unwrap();
    assert!(
        hot_line["file"]
            .as_str()
            .is_some_and(|f| f.ends_with("cpu_bound.c")),
        "{hot_line:#}"
    );

    let manifest = manifest(&recording);
    assert_eq!(manifest["platform"]["os"], "macos");
    let stream = &manifest["streams"][0];
    assert_eq!(stream["collector"]["name"], "mach");
    assert_eq!(stream["coverage"]["stacks"]["unwinding"], "unwind_tables");
    let missing: Vec<&str> = stream["missing_signals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["signal"].as_str().unwrap())
        .collect();
    assert!(missing.contains(&"kernel_stacks"), "{missing:?}");
    assert_eq!(manifest["target"]["exit"]["code"], 0);
}

#[test]
fn a_blocked_threads_time_off_cpu_is_under_its_wait() {
    let dir = scratch("macos_a_blocked_thread");
    let program = dir.join("nap_and_join");
    compile("nap_and_join", &program, "-O2");
    let recording = dir.join("rec");
    record(&recording, &[program.to_str().unwrap()]);
    let path = recording.to_str().unwrap();

    let main = ["--thread", "nap_and_join"];
    let mut args = vec![
        "query",
        path,
        "--group-by",
        "function",
        "--metric",
        "off-cpu",
    ];
    args.extend(main);
    let result = json(&args);
    // It sleeps about 0.3 s, then waits as long for the thread it joins.
    let nap = share(&result, "nap", "total_share");
    let join = share(&result, "join", "total_share");
    assert!((0.4..=0.6).contains(&nap), "nap has {nap}");
    assert!((0.4..=0.6).contains(&join), "join has {join}");

    let mut args = vec![
        "query",
        path,
        "--group-by",
        "syscall",
        "--metric",
        "off-cpu",
    ];
    args.extend(main);
    let syscalls = json(&args);
    let slept = rows(&syscalls)
        .iter()
        .find(|r| r["syscall"] == "semwait_signal")
        .unwrap_or_else(|| panic!("no semwait_signal in {syscalls:#}"));
    assert!(slept["share"].as_f64().unwrap() > 0.4, "{slept:#}");

    // The thread it joins has the process's name too, as it gave itself
    // none, but started during the capture.
    let overview = json(&["overview", path]);
    let thread = overview["threads"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["start_ns"].is_null())
        .unwrap();
    let blocked = thread["blocked_share"].as_f64().unwrap();
    assert!(blocked > 0.8, "the main thread was blocked for {blocked}");
}

#[test]
fn follows_a_child_through_its_fork_and_its_exec() {
    let dir = scratch("macos_follows_a_child");
    let program = dir.join("spawns");
    compile("spawns", &program, "-O2");
    let recording = dir.join("rec");
    record(&recording, &[program.to_str().unwrap()]);
    let path = recording.to_str().unwrap();

    let result = json(&["query", path, "--group-by", "function"]);
    for function in ["before_exec", "after_exec"] {
        let share = share(&result, function, "self_share");
        assert!((0.4..=0.6).contains(&share), "{function} has {share}");
    }
    // The parent, and the child before and after its exec.
    let overview = json(&["overview", path]);
    let processes = overview["processes"].as_array().unwrap();
    assert_eq!(processes.len(), 3, "{processes:#?}");
}

#[test]
fn refuses_a_program_the_system_protects() {
    let dir = scratch("macos_refuses_a_protected_program");
    let recording = dir.join("rec");
    let output = Command::new(UHR)
        .args([
            "record",
            "-o",
            recording.to_str().unwrap(),
            "--",
            "/bin/sleep",
            "0",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("System Integrity Protection"), "{stderr}");
    assert!(!recording.exists());
}

#[test]
fn attaches_to_a_running_program() {
    let dir = scratch("macos_attaches");
    let program = dir.join("cpu_bound");
    compile("cpu_bound", &program, "-O2");
    let mut target = Command::new(&program)
        .arg("100000")
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let pid = target.id().to_string();
    let recording = dir.join("rec");
    let args = [
        "record",
        "-o",
        recording.to_str().unwrap(),
        "--pid",
        &pid,
        "--duration",
        "1s",
    ];
    // SAFETY: geteuid has no preconditions.
    let root = unsafe { libc::geteuid() } == 0;
    let attached = if root {
        uhr(&args);
        Some(())
    } else {
        let output = Command::new(UHR).args(args).output().unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("sudo"), "{stderr}");
        uhr_as_root(&args, &recording)
    };
    let _ = target.kill();
    let _ = target.wait();
    if attached.is_none() {
        eprintln!("sudo needs a password, so attaching was not tested");
        return;
    }
    let result = json(&[
        "query",
        recording.to_str().unwrap(),
        "--group-by",
        "function",
    ]);
    assert_eq!(rows(&result)[0]["function"], "hot");
    let manifest = manifest(&recording);
    assert_eq!(manifest["target"]["launched"], false);
    assert!(manifest["target"]["runtime_support"].is_null());
    // Still running when the duration ended.
    assert!(manifest["target"]["exit"].is_null());
}
