//! End to end on macOS, with uhr's own sampler: needs a C compiler, and
//! for the frames of runtimes, Python 3.11 or later, Node 20 to 24 and
//! Bun 1.4.3 outside the directories System Integrity Protection protects,
//! as Homebrew installs them. The test of a runtime that is missing checks
//! nothing. `uhr doctor` shows what is missing.
#![cfg(target_os = "macos")]

mod common;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use serde_json::Value;

use common::{UHR, compile, compile_with_debug_info, scratch, uhr, uhr_as_root};

const PROGRAMS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test-programs");

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

/// `program` found in `PATH`, outside the directories whose programs
/// System Integrity Protection keeps uhr's library out of.
fn find(program: &str) -> Option<PathBuf> {
    let protected = [
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/libexec",
        "/System",
    ];
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .filter(|dir| !protected.iter().any(|p| dir.starts_with(p)))
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

/// A `python3` whose frames uhr reads.
fn python() -> Option<PathBuf> {
    let python = ["python3.14", "python3.13", "python3.12", "python3.11"]
        .into_iter()
        .find_map(find);
    if python.is_none() {
        eprintln!("skipped: needs Python 3.11 or later");
    }
    python
}

/// A `node` whose V8 uhr reads the frames of.
fn node() -> Option<PathBuf> {
    let node = find("node").filter(|node| {
        let output = Command::new(node)
            .args(["-p", "process.versions.v8"])
            .output();
        let major = output.ok().and_then(|output| {
            let version = String::from_utf8(output.stdout).ok()?;
            version.split('.').next()?.trim().parse::<u32>().ok()
        });
        major.is_some_and(|v8| (11..=13).contains(&v8))
    });
    if node.is_none() {
        eprintln!("skipped: needs Node 20 to 24");
    }
    node
}

/// A `bun` whose frames uhr reads: the release whose offsets it knows, of
/// which uhr knows the build for arm64.
fn bun() -> Option<PathBuf> {
    let bun = find("bun").filter(|bun| {
        let output = Command::new(bun).arg("--revision").output();
        cfg!(target_arch = "aarch64")
            && output.is_ok_and(|output| output.stdout.starts_with(b"1.4.3+c6da4a4d3"))
    });
    if bun.is_none() {
        eprintln!("skipped: needs Bun 1.4.3 for arm64");
    }
    bun
}

/// What the stream says of the interpreters whose frames it read.
fn interpreters(recording: &Path) -> Vec<Value> {
    let manifest = manifest(recording);
    manifest["streams"][0]["coverage"]["stacks"]["interpreters"]
        .as_array()
        .unwrap()
        .clone()
}

fn functions(recording: &str) -> Value {
    json(&[
        "query",
        recording,
        "--group-by",
        "function",
        "--top",
        "1000",
    ])
}

fn runtime_function<'a>(result: &'a Value, runtime: &str, name: &str) -> &'a Value {
    rows(result)
        .iter()
        .find(|r| r["module"] == format!("[{runtime}]") && r["function"] == name)
        .unwrap_or_else(|| panic!("no {runtime} function {name} in {result:#}"))
}

/// That `program` of `runtime` spent its time as jit.py does: hot() does
/// four times the work of warm(), all under work().
fn has_the_split_of(recording: &str, runtime: &str, program: &str) {
    let result = functions(recording);
    let function = |name| runtime_function(&result, runtime, name);
    let hot = function("hot");
    let file = hot["file"].as_str().unwrap();
    assert!(file.ends_with(&format!("test-programs/{program}")), "{hot}");
    let share = |row: &Value, which: &str| row[which].as_f64().unwrap();
    let (hot, warm, work) = (function("hot"), function("warm"), function("work"));
    let (hot_self, warm_self) = (share(hot, "self_share"), share(warm, "self_share"));
    let split = hot_self / (hot_self + warm_self);
    assert!(
        hot_self + warm_self > 0.7,
        "hot {hot_self}, warm {warm_self}"
    );
    assert!((0.7..0.9).contains(&split), "hot gets {split} of the two");
    let under = share(hot, "total_share") + share(warm, "total_share");
    assert!(share(work, "total_share") >= under - 0.01, "{work}");
}

/// That every walk of `runtime`'s frames read them, and all but a share
/// `unread` of their code. A process that starts frees code, and V8's
/// garbage collector moves it, before uhr reads it.
fn read_the_frames(recording: &Path, runtime: &str, unread: f64) {
    let walked = interpreters(recording);
    let walks = walked
        .iter()
        .find(|w| w["runtime"] == runtime)
        .unwrap_or_else(|| panic!("no walks of {runtime} in {walked:?}"));
    let frames = walks["frames"].as_u64().unwrap();
    assert!(frames > 0, "{walks}");
    assert_eq!(walks["failed"], 0, "{walks}");
    let missed = walks["unread_frames"].as_u64().unwrap();
    assert!(missed as f64 <= unread * frames as f64, "{walks}");
}

#[test]
fn reads_the_frames_of_python() {
    let Some(python) = python() else {
        return;
    };
    let dir = scratch("macos_python");
    let recording = dir.join("rec");
    let program = format!("{PROGRAMS}/jit.py");
    record(&recording, &[python.to_str().unwrap(), &program, "50"]);
    has_the_split_of(recording.to_str().unwrap(), "python", "jit.py");
    read_the_frames(&recording, "python", 0.01);
}

/// Whether a node of a call-paths tree, or one under it, is the Python
/// function `name`.
fn has_python(nodes: &Value, name: &str) -> bool {
    nodes.as_array().unwrap().iter().any(|node| {
        (node["origin"] == "interpreted" && node["function"] == name)
            || has_python(&node["children"], name)
    })
}

#[test]
fn puts_python_frames_around_the_native_code_they_call() {
    let Some(python) = python() else {
        return;
    };
    let dir = scratch("macos_python_callback");
    let recording = dir.join("rec");
    let program = format!("{PROGRAMS}/callback.py");
    record(&recording, &[python.to_str().unwrap(), &program, "60"]);
    let path = recording.to_str().unwrap();
    // sort() calls qsort(), which calls compare(). Of libc's functions
    // named so, the one that does.
    let result = functions(path);
    let qsort = rows(&result)
        .iter()
        .filter(|r| r["function"].as_str().is_some_and(|f| f.contains("qsort")))
        .max_by(|a, b| {
            let total = |row: &Value| row["total_share"].as_f64().unwrap();
            total(a).total_cmp(&total(b))
        })
        .unwrap_or_else(|| panic!("no qsort in {result:#}"));
    let paths = json(&[
        "call-paths",
        path,
        "--function",
        qsort["id"].as_str().unwrap(),
        "--mode",
        "user",
        "--depth",
        "20",
        "--top",
        "20",
    ]);
    assert!(has_python(&paths["callers"], "sort"), "{paths}");
    assert!(!has_python(&paths["callers"], "compare"), "{paths}");
    assert!(has_python(&paths["callees"], "compare"), "{paths}");
}

#[test]
fn reads_python_frames_when_attached() {
    let Some(python) = python() else {
        return;
    };
    let dir = scratch("macos_python_attached");
    let program = format!("{PROGRAMS}/jit.py");
    let mut target = Command::new(&python)
        .args([&program, "300"])
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    thread::sleep(Duration::from_millis(300));
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
    let attached = if unsafe { libc::geteuid() } == 0 {
        uhr(&args);
        Some(())
    } else {
        uhr_as_root(&args, &recording)
    };
    let _ = target.kill();
    let _ = target.wait();
    if attached.is_none() {
        eprintln!("skipped: needs root through sudo without a password");
        return;
    }
    let path = recording.to_str().unwrap();
    let result = functions(path);
    for name in ["hot", "warm", "work"] {
        runtime_function(&result, "python", name);
    }
    read_the_frames(&recording, "python", 0.0);
}

#[test]
fn reads_the_frames_of_node() {
    let Some(node) = node() else {
        return;
    };
    let dir = scratch("macos_node");
    let recording = dir.join("rec");
    let program = format!("{PROGRAMS}/jit.js");
    record(&recording, &[node.to_str().unwrap(), &program, "50"]);
    has_the_split_of(recording.to_str().unwrap(), "node", "jit.js");
    read_the_frames(&recording, "node", 0.01);
}

#[test]
fn reads_the_frames_of_bun() {
    let Some(bun) = bun() else {
        return;
    };
    let dir = scratch("macos_bun");
    let recording = dir.join("rec");
    let program = format!("{PROGRAMS}/jit.js");
    record(&recording, &[bun.to_str().unwrap(), &program, "100"]);
    has_the_split_of(recording.to_str().unwrap(), "bun", "jit.js");
    read_the_frames(&recording, "bun", 0.01);
}

/// That the functions of await.js that waited for inner() have the time it
/// worked for, once resumed, with none of them on the stack.
fn has_the_functions_that_waited(runtime: &Path, name: &str) {
    let dir = scratch(&format!("macos_{name}_await"));
    let recording = dir.join("rec");
    let program = format!("{PROGRAMS}/await.js");
    record(&recording, &[runtime.to_str().unwrap(), &program, "60"]);
    let result = functions(recording.to_str().unwrap());
    let total = |function: &str| {
        runtime_function(&result, name, function)["total_share"]
            .as_f64()
            .unwrap()
    };
    let work = total("work");
    assert!(work > 0.5, "{work}");
    for function in ["inner", "middle", "outer", "main"] {
        let waited = total(function);
        assert!(waited >= work - 0.05, "{function}: {waited} of {work}");
    }
}

#[test]
fn names_the_functions_that_wait_for_one() {
    if let Some(node) = node() {
        has_the_functions_that_waited(&node, "node");
    }
    if let Some(bun) = bun() {
        has_the_functions_that_waited(&bun, "bun");
    }
}
