//! End to end: uhr's eBPF programs reading the frames of CPython, V8,
//! JavaScriptCore, CRuby and PHP. Needs root through sudo without a password,
//! perf, a C compiler, and Python 3.11 or later, Node 20 or later, Bun 1.4.3,
//! Ruby 3.2 or PHP 8.3, and skips without sudo. The test of a runtime that is
//! missing checks nothing.
#![cfg(target_os = "linux")]

mod common;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use serde_json::Value;

use common::{compile, scratch, uhr, uhr_as_root};

const PROGRAMS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test-programs");

fn json(args: &[&str]) -> Value {
    let mut args = args.to_vec();
    args.push("--json");
    serde_json::from_slice(&uhr(&args).stdout).unwrap()
}

/// `program` found in `PATH`.
fn find(program: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

/// Records `command` as root, `None` where sudo asks for a password or uhr
/// was built without its eBPF programs. Without perf maps, so the names can
/// only come from the interpreter's frames.
fn record(dir: &Path, flags: &[&str], command: &[&str]) -> Option<String> {
    record_as_root(dir, flags, command, false)
}

fn record_as_root(dir: &Path, flags: &[&str], command: &[&str], maps: bool) -> Option<String> {
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    let mut args = vec!["record", "-o", rec];
    args.extend(flags);
    if !command.is_empty() {
        if !maps {
            args.push("--no-runtime-support");
        }
        args.push("--");
        args.extend(command);
    }
    if uhr_as_root(&args, &recording).is_none() {
        eprintln!("skipped: needs root through sudo without a password");
        return None;
    }
    if interpreters(rec).is_none() {
        eprintln!("skipped: uhr was built without its eBPF programs");
        return None;
    }
    Some(rec.to_owned())
}

/// What the eBPF stream says of the interpreters it read, `None` if they
/// did not sample.
fn interpreters(recording: &str) -> Option<Vec<Value>> {
    let manifest: Value =
        serde_json::from_slice(&fs::read(Path::new(recording).join("manifest.json")).unwrap())
            .unwrap();
    let streams = manifest["streams"].as_array().unwrap();
    let ebpf = streams
        .iter()
        .find(|s| s["id"] == "ebpf" && !s["collector"]["sampling"].is_null())?;
    Some(
        ebpf["coverage"]["stacks"]["interpreters"]
            .as_array()
            .unwrap()
            .clone(),
    )
}

fn functions(recording: &str) -> Vec<Value> {
    let result = json(&[
        "query",
        recording,
        "--group-by",
        "function",
        "--top",
        "1000",
    ]);
    result["rows"].as_array().unwrap().clone()
}

/// The row of the Python function `name`, read from the interpreter's
/// frames or named in a perf map, which are one function.
fn python_function<'a>(rows: &'a [Value], name: &str) -> &'a Value {
    runtime_function(rows, "python", name)
}

fn runtime_function<'a>(rows: &'a [Value], runtime: &str, name: &str) -> &'a Value {
    rows.iter()
        .find(|r| r["module"] == format!("[{runtime}]") && r["function"] == name)
        .unwrap_or_else(|| panic!("no {runtime} function {name}"))
}

fn share(row: &Value, which: &str) -> f64 {
    row[which].as_f64().unwrap()
}

/// The program's known split: hot() does four times the work of warm(),
/// all under work().
fn has_the_split_of_jit_py(recording: &str) {
    has_the_split_of_hot_and_warm(recording);
    let rows = functions(recording);
    assert!(share(python_function(&rows, "work"), "total_share") > 0.85);
}

fn has_the_split_of_hot_and_warm(recording: &str) {
    has_the_split_of(recording, "python", "jit.py");
}

/// That `program` of `runtime` spent its time as jit.py does.
fn has_the_split_of(recording: &str, runtime: &str, program: &str) {
    let rows = functions(recording);
    let hot = runtime_function(&rows, runtime, "hot");
    let file = hot["file"].as_str().unwrap();
    assert!(file.ends_with(&format!("test-programs/{program}")), "{hot}");
    // Python's functions group by name alone, and Bun's say no lines.
    // Others group by where they start too, the line hot() is declared at.
    let id = hot["id"].as_str().unwrap();
    let start = id
        .strip_prefix(&format!("jit+{runtime}:hot"))
        .and_then(|id| id.strip_suffix(&format!(":{file}")))
        .unwrap_or_else(|| panic!("{hot}"));
    let line = match (runtime, program) {
        ("python" | "bun", _) => "",
        (_, "jit.rb") => "@7",
        _ => "@8",
    };
    assert!(
        start == line || start.starts_with(&format!("{line}%3A")) && !line.is_empty(),
        "{hot}"
    );
    let (hot, warm) = (
        share(hot, "self_share"),
        share(runtime_function(&rows, runtime, "warm"), "self_share"),
    );
    let split = hot / (hot + warm);
    assert!(hot + warm > 0.7, "hot {hot}, warm {warm}");
    assert!((0.7..0.9).contains(&split), "hot gets {split} of the two");
}

#[test]
fn reads_the_frames_of_each_python() {
    let pythons: Vec<_> = ["python3.11", "python3.12", "python3.13", "python3.14"]
        .into_iter()
        .filter_map(|name| Some((name, find(name)?)))
        .collect();
    if pythons.is_empty() {
        eprintln!("skipped: needs Python 3.11 or later");
        return;
    }
    let program = format!("{PROGRAMS}/jit.py");
    for (name, python) in pythons {
        let dir = scratch(&format!("interpreters_{name}"));
        let command = [python.to_str().unwrap(), &program, "50"];
        let Some(recording) = record(&dir, &[], &command) else {
            return;
        };
        has_the_split_of_jit_py(&recording);
        let found = interpreters(&recording).unwrap();
        let [found] = &found[..] else {
            panic!("{name}: {found:?}");
        };
        let version = found["version"].as_str().unwrap();
        assert!(
            version.starts_with(&name["python".len()..]),
            "{name}: {found}"
        );
        // Code a module ran on import is freed once the import is done,
        // which can be before uhr reads it.
        let (frames, unread) = (found["frames"].as_u64(), found["unread_frames"].as_u64());
        assert!(unread.unwrap() * 50 <= frames.unwrap(), "{name}: {found}");
        assert_eq!(found["failed"], 0, "{name}: {found}");

        // The loop of hot() is its lines 13 and 14.
        let lines = json(&["query", &recording, "--group-by", "line", "--top", "1000"]);
        let hot_lines: Vec<u64> = lines["rows"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["origin"] == "interpreted" && r["function"] == "hot")
            .filter(|r| share(r, "self_share") > 0.05)
            .map(|r| r["line"]["line"].as_u64().unwrap())
            .collect();
        assert!(
            !hot_lines.is_empty() && hot_lines.iter().all(|l| (13..=14).contains(l)),
            "{name}: {hot_lines:?}"
        );

        // work's generator calls hot, out of sum(), which the generator's
        // native frames run in.
        let paths = call_paths(&recording, &id_of(&recording, "hot"));
        let outer = |node: &Value| {
            let name = node["function"].as_str().unwrap_or_default();
            name == "builtin_sum" || name.contains("gen_iternext") || name == "work"
        };
        assert!(!has(&paths["callees"], &outer), "{name}: {paths}");
    }
}

#[test]
fn reads_python_frames_when_attached() {
    let Some(python) = find("python3.12").or_else(|| find("python3")) else {
        eprintln!("skipped: needs Python");
        return;
    };
    let dir = scratch("interpreters_attached");
    let program = format!("{PROGRAMS}/jit.py");
    let mut target = Command::new(&python)
        .args([&program, "300"])
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    // Running the program's own code by then.
    thread::sleep(Duration::from_millis(300));
    let pid = target.id().to_string();
    let recording = record(&dir, &["--pid", &pid, "--duration", "1s"], &[]);
    let _ = target.kill();
    let _ = target.wait();
    let Some(recording) = recording else {
        return;
    };
    has_the_split_of_jit_py(&recording);
}

#[test]
fn reads_the_frames_of_the_pythons_a_target_starts() {
    let Some(python) = find("python3.12").or_else(|| find("python3")) else {
        eprintln!("skipped: needs Python");
        return;
    };
    let dir = scratch("interpreters_started");
    let program = format!("{PROGRAMS}/jit.py");
    let start =
        format!("import subprocess, sys; subprocess.run([sys.executable, {program:?}, '50'])");
    let command = [python.to_str().unwrap(), "-c", &start];
    let Some(recording) = record(&dir, &[], &command) else {
        return;
    };
    has_the_split_of_jit_py(&recording);
    let found = interpreters(&recording).unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0]["processes"], 2, "{found:?}");
}

/// A Python 3.13 with a shared library to embed, as uv's builds have: where
/// its headers are, the library's directory and its version.
fn shared_python() -> Option<(String, String, String)> {
    let python = find("python3.13")?;
    let config = |name: &str| {
        let query = format!("import sysconfig; print(sysconfig.get_config_var({name:?}))");
        let output = Command::new(&python).args(["-c", &query]).output().unwrap();
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    };
    let (include, libdir, version) = (config("INCLUDEPY"), config("LIBDIR"), config("LDVERSION"));
    let library = Path::new(&libdir).join(format!("libpython{version}.so"));
    library.exists().then_some((include, libdir, version))
}

#[test]
fn reads_the_frames_of_python_a_program_embeds() {
    let Some((include, libdir, version)) = shared_python() else {
        eprintln!("skipped: needs Python 3.13 with a shared library");
        return;
    };
    let dir = scratch("interpreters_embedded");
    let program = dir.join("embed");
    let status = Command::new("cc")
        .args(["-O2", "-fno-omit-frame-pointer", "-I", &include, "-o"])
        .arg(&program)
        .arg(format!("{PROGRAMS}/embed.c"))
        .args([format!("-L{libdir}"), format!("-lpython{version}")])
        .arg(format!("-Wl,-rpath,{libdir}"))
        .status()
        .unwrap();
    assert!(status.success(), "cc failed");
    let Some(recording) = record(&dir, &[], &[program.to_str().unwrap()]) else {
        return;
    };
    let rows = functions(&recording);
    let spin = python_function(&rows, "spin");
    assert!(share(spin, "self_share") > 0.6, "{spin}");
    let found = interpreters(&recording).unwrap();
    assert!(
        found[0]["version"].as_str().unwrap().starts_with("3.13"),
        "{found:?}"
    );
}

#[test]
fn reads_the_frames_of_python_a_program_loads_later() {
    let Some((_, libdir, version)) = shared_python() else {
        eprintln!("skipped: needs Python 3.13 with a shared library");
        return;
    };
    let dir = scratch("interpreters_loaded_later");
    let program = dir.join("dlopen_python");
    compile("dlopen_python", &program, "-O2");
    let library = format!("{libdir}/libpython{version}.so");
    let Some(recording) = record(&dir, &[], &[program.to_str().unwrap(), &library]) else {
        return;
    };
    // It loads Python once uhr has looked for it, and runs it for about
    // half the time.
    let rows = functions(&recording);
    let spin = python_function(&rows, "spin");
    assert!(share(spin, "self_share") > 0.25, "{spin}");
}

/// Whether a node of a call-paths tree, or one under it, is the Python
/// function `name`.
fn has_python(nodes: &Value, name: &str) -> bool {
    has(nodes, &|node| {
        node["origin"] == "interpreted" && node["function"] == name
    })
}

fn has(nodes: &Value, wanted: &dyn Fn(&Value) -> bool) -> bool {
    let nodes = nodes.as_array().unwrap();
    nodes
        .iter()
        .any(|node| wanted(node) || has(&node["children"], wanted))
}

fn call_paths(recording: &str, function: &str) -> Value {
    json(&[
        "call-paths",
        recording,
        "--function",
        function,
        "--mode",
        "user",
        "--depth",
        "30",
        "--top",
        "20",
    ])
}

/// The id of the Python function `name`.
fn id_of(recording: &str, name: &str) -> String {
    let rows = functions(recording);
    python_function(&rows, name)["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn puts_python_frames_around_the_native_code_they_call() {
    let Some(python) = find("python3.12").or_else(|| find("python3")) else {
        eprintln!("skipped: needs Python");
        return;
    };
    let program = format!("{PROGRAMS}/callback.py");
    for unwind in ["fp", "dwarf"] {
        let dir = scratch(&format!("interpreters_callback_{unwind}"));
        let command = [python.to_str().unwrap(), &program, "60"];
        let Some(recording) = record(&dir, &["--unwind", unwind], &command) else {
            return;
        };
        // sort() calls qsort(), which calls compare(). Of libc's functions
        // named so, the one that does: another can have a sample of its own.
        let rows = functions(&recording);
        let qsort = rows
            .iter()
            .filter(|r| r["function"].as_str().is_some_and(|f| f.contains("qsort")))
            .max_by(|a, b| share(a, "total_share").total_cmp(&share(b, "total_share")))
            .unwrap_or_else(|| panic!("{unwind}: no qsort"));
        let id = qsort["id"].as_str().unwrap();
        let paths = json(&[
            "call-paths",
            &recording,
            "--function",
            id,
            "--mode",
            "user",
            "--depth",
            "20",
            "--top",
            "20",
        ]);
        assert!(has_python(&paths["callers"], "sort"), "{unwind}: {paths}");
        assert!(
            !has_python(&paths["callers"], "compare"),
            "{unwind}: {paths}"
        );
        assert!(
            has_python(&paths["callees"], "compare"),
            "{unwind}: {paths}"
        );
    }
}

#[test]
fn names_the_python_functions_that_wait() {
    let Some(python) = find("python3.12") else {
        eprintln!("skipped: needs Python 3.12");
        return;
    };
    let dir = scratch("interpreters_off_cpu");
    let program = "import time\ndef sleeping():\n    time.sleep(0.75)\nsleeping()\n";
    let command = [python.to_str().unwrap(), "-c", program];
    let Some(recording) = record_as_root(&dir, &[], &command, true) else {
        return;
    };
    let result = json(&[
        "query",
        &recording,
        "--metric",
        "off-cpu",
        "--group-by",
        "function",
        "--top",
        "1000",
    ]);
    let rows = result["rows"].as_array().unwrap();
    let sleeping = rows.iter().find(|r| r["function"] == "sleeping");
    let waited = sleeping.map_or(0, |r| r["total_ns"].as_u64().unwrap());
    assert!(waited > 700_000_000, "{result}");
}

#[test]
fn counts_a_call_a_perf_map_names_once() {
    let Some(python) = find("python3.12") else {
        eprintln!("skipped: needs Python 3.12");
        return;
    };
    let dir = scratch("interpreters_perf_maps");
    let program = format!("{PROGRAMS}/jit.py");
    let command = [python.to_str().unwrap(), &program, "50"];
    let Some(recording) = record_as_root(&dir, &[], &command, true) else {
        return;
    };
    has_the_split_of_jit_py(&recording);
    for name in ["hot", "warm", "work"] {
        let id = id_of(&recording, name);
        let paths = call_paths(&recording, &id);
        let again = |node: &Value| node["id"].as_str() == Some(&id);
        assert!(!has(&paths["callees"], &again), "{name}: {paths}");
    }
}

#[test]
fn reads_the_frames_of_a_thread_beside_another_interpreter() {
    let Some(python) = find("python3.12") else {
        eprintln!("skipped: needs Python 3.12");
        return;
    };
    let dir = scratch("interpreters_subinterpreter");
    let program = format!(
        "import _xxsubinterpreters, runpy, sys\n\
         idle = _xxsubinterpreters.create()\n\
         sys.argv = ['jit.py', '50']\n\
         runpy.run_path({:?}, run_name='__main__')\n",
        format!("{PROGRAMS}/jit.py")
    );
    let command = [python.to_str().unwrap(), "-c", &program];
    let Some(recording) = record(&dir, &[], &command) else {
        return;
    };
    has_the_split_of_jit_py(&recording);
}

#[test]
fn reads_the_frames_of_python_in_another_pid_namespace() {
    let (Some(python), Some(unshare)) = (find("python3.12"), find("unshare")) else {
        eprintln!("skipped: needs Python 3.12 and unshare");
        return;
    };
    let dir = scratch("interpreters_pid_namespace");
    let program = format!("{PROGRAMS}/jit.py");
    let command = [
        unshare.to_str().unwrap(),
        "--pid",
        "--fork",
        python.to_str().unwrap(),
        &program,
        "50",
    ];
    let Some(recording) = record(&dir, &[], &command) else {
        return;
    };
    has_the_split_of_jit_py(&recording);
}

#[test]
fn reads_the_frames_of_python_execed_from_one_it_cannot_read() {
    let (Some(old), Some(python)) = (find("python3.10"), find("python3.12")) else {
        eprintln!("skipped: needs Python 3.10 and 3.12");
        return;
    };
    let dir = scratch("interpreters_exec");
    let program = format!("{PROGRAMS}/jit.py");
    let exec = format!(
        "import os\nos.execv({python:?}, [{python:?}, {program:?}, '50'])\n",
        python = python.to_str().unwrap()
    );
    let command = [old.to_str().unwrap(), "-c", &exec];
    let Some(recording) = record(&dir, &[], &command) else {
        return;
    };
    has_the_split_of_jit_py(&recording);
}

#[test]
fn reads_the_frames_of_threads_past_the_search() {
    let Some(python) = find("python3.12") else {
        eprintln!("skipped: needs Python 3.12");
        return;
    };
    let dir = scratch("interpreters_many_threads");
    // The main thread's state is the oldest, at the end of the list, past
    // the 256 the programs search.
    let program = format!(
        "import runpy, sys, threading\n\
         stop = threading.Event()\n\
         waiting = [threading.Thread(target=stop.wait) for _ in range(300)]\n\
         [t.start() for t in waiting]\n\
         sys.argv = ['jit.py', '80']\n\
         runpy.run_path({:?}, run_name='__main__')\n\
         stop.set()\n",
        format!("{PROGRAMS}/jit.py")
    );
    let command = [python.to_str().unwrap(), "-c", &program];
    let Some(recording) = record(&dir, &[], &command) else {
        return;
    };
    // Starting the threads takes time too.
    has_the_split_of_hot_and_warm(&recording);
    let found = interpreters(&recording).unwrap();
    let count = |what: &str| found[0][what].as_u64().unwrap();
    assert!(count("unsearched") * 50 < count("samples"), "{found:?}");
}

#[test]
fn puts_python_frames_past_the_most_walked_inside_the_stack() {
    let Some(python) = find("python3.12") else {
        eprintln!("skipped: needs Python 3.12");
        return;
    };
    let dir = scratch("interpreters_deep");
    let program = format!("{PROGRAMS}/callback.py");
    // sort() calls itself past the 127 frames walked, then qsort calls
    // compare().
    let command = [python.to_str().unwrap(), &program, "60", "150"];
    let Some(recording) = record(&dir, &[], &command) else {
        return;
    };
    let rows = functions(&recording);
    let start = rows.iter().find(|r| {
        r["function"]
            .as_str()
            .is_some_and(|f| f.contains("libc_start_call_main"))
    });
    let start = start.expect("no __libc_start_call_main")["id"]
        .as_str()
        .unwrap();
    let paths = call_paths(&recording, start);
    let python = |node: &Value| node["origin"] == "interpreted";
    assert!(!has(&paths["callers"], &python), "{paths}");
    let compare = call_paths(&recording, &id_of(&recording, "compare"));
    assert!(has_python(&compare["callers"], "sort"), "{compare}");
}

#[test]
fn counts_each_program_a_process_runs_apart() {
    let (Some(old), Some(new)) = (find("python3.12"), find("python3.14")) else {
        eprintln!("skipped: needs Python 3.12 and 3.14");
        return;
    };
    let dir = scratch("interpreters_programs");
    let program = format!("{PROGRAMS}/jit.py");
    let exec = format!(
        "import os\nos.execv({new:?}, [{new:?}, {program:?}, '100'])\n",
        new = new.to_str().unwrap()
    );
    let command = [old.to_str().unwrap(), "-c", &exec];
    let Some(recording) = record(&dir, &[], &command) else {
        return;
    };
    has_the_split_of_jit_py(&recording);
    let found = interpreters(&recording).unwrap();
    let of = |version: &str| {
        found
            .iter()
            .find(|i| i["version"].as_str().unwrap().starts_with(version))
            .map(|i| i["samples"].as_u64().unwrap())
    };
    // 3.12 only starts up before its exec.
    let (old, new) = (of("3.12").unwrap_or(0), of("3.14").unwrap());
    assert!(old < 50 && new > 300, "{found:?}");
}

/// The major version of the V8 `node` runs.
fn v8_major(node: &Path) -> Option<u32> {
    let output = Command::new(node)
        .args(["-p", "process.versions.v8"])
        .output()
        .ok()?;
    let version = String::from_utf8(output.stdout).ok()?;
    version.split('.').next()?.trim().parse().ok()
}

/// A `node` whose V8 uhr reads the frames of.
fn node() -> Option<PathBuf> {
    let node = find("node").filter(|node| v8_major(node).is_some_and(|v8| (11..=13).contains(&v8)));
    if node.is_none() {
        eprintln!("skipped: needs Node 20 or later");
    }
    node
}

/// That jit.js spent its time as it does, with every walked sample under
/// work().
fn has_the_split_of_jit_js(recording: &str) {
    has_the_split_of(recording, "node", "jit.js");
    let rows = functions(recording);
    let (hot, warm, work) = (
        runtime_function(&rows, "node", "hot"),
        runtime_function(&rows, "node", "warm"),
        runtime_function(&rows, "node", "work"),
    );
    let under = share(hot, "total_share") + share(warm, "total_share");
    assert!(share(work, "total_share") >= under - 0.01, "{work}");
}

#[test]
fn reads_v8_frames_when_attached() {
    let Some(node) = node() else {
        return;
    };
    let dir = scratch("interpreters_v8_attached");
    let program = format!("{PROGRAMS}/jit.js");
    let mut target = Command::new(&node)
        .args([&program, "300"])
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    thread::sleep(Duration::from_millis(300));
    let pid = target.id().to_string();
    let recording = record(&dir, &["--pid", &pid, "--duration", "1s"], &[]);
    let _ = target.kill();
    let _ = target.wait();
    let Some(recording) = recording else {
        return;
    };
    has_the_split_of_jit_js(&recording);
    let walked = interpreters(&recording).unwrap();
    let v8 = walked.iter().find(|w| w["runtime"] == "node").unwrap();
    assert_eq!(v8["unread_frames"], 0, "{v8}");
}

#[test]
fn counts_a_v8_call_a_perf_map_names_once() {
    let Some(node) = node() else {
        return;
    };
    let dir = scratch("interpreters_v8_perf_maps");
    let program = format!("{PROGRAMS}/jit.js");
    let command = [node.to_str().unwrap(), &program, "60"];
    let Some(recording) = record_as_root(&dir, &[], &command, true) else {
        return;
    };
    has_the_split_of_jit_js(&recording);
    for name in ["hot", "warm", "work"] {
        let rows = functions(&recording);
        let id = runtime_function(&rows, "node", name)["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let paths = call_paths(&recording, &id);
        let again = |node: &Value| node["id"].as_str() == Some(&id);
        assert!(!has(&paths["callees"], &again), "{name}: {paths}");
    }
}

/// A `ruby` whose frames uhr reads.
fn ruby() -> Option<PathBuf> {
    let ruby = find("ruby").filter(|ruby| {
        let output = Command::new(ruby)
            .args(["-e", "print RUBY_VERSION"])
            .output();
        output.is_ok_and(|output| output.stdout.starts_with(b"3.2."))
    });
    if ruby.is_none() {
        eprintln!("skipped: needs Ruby 3.2");
    }
    ruby
}

/// That jit.rb spent its time as it does, under work(), and on the lines
/// of hot()'s loop.
fn has_the_split_of_jit_rb(recording: &str) {
    has_the_split_of(recording, "ruby", "jit.rb");
    let rows = functions(recording);
    let work = runtime_function(&rows, "ruby", "work");
    assert!(share(work, "total_share") > 0.85, "{work}");
    let lines = json(&["query", recording, "--group-by", "line", "--top", "100"]);
    let lines = lines["rows"].as_array().unwrap();
    let hot: Vec<u64> = lines
        .iter()
        .filter(|r| r["function"] == "hot" && share(r, "self_share") > 0.05)
        .map(|r| r["line"]["line"].as_u64().unwrap())
        .collect();
    assert!(
        !hot.is_empty() && hot.iter().all(|line| (10..=12).contains(line)),
        "{hot:?}"
    );
}

#[test]
fn reads_ruby_frames() {
    let Some(ruby) = ruby() else {
        return;
    };
    let dir = scratch("interpreters_ruby");
    let program = format!("{PROGRAMS}/jit.rb");
    let command = [ruby.to_str().unwrap(), &program, "80"];
    let Some(recording) = record(&dir, &[], &command) else {
        return;
    };
    has_the_split_of_jit_rb(&recording);
}

#[test]
fn reads_ruby_frames_when_attached() {
    let Some(ruby) = ruby() else {
        return;
    };
    let dir = scratch("interpreters_ruby_attached");
    let program = format!("{PROGRAMS}/jit.rb");
    let mut target = Command::new(&ruby)
        .args([&program, "300"])
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    thread::sleep(Duration::from_millis(300));
    let pid = target.id().to_string();
    let recording = record(&dir, &["--pid", &pid, "--duration", "1s"], &[]);
    let _ = target.kill();
    let _ = target.wait();
    let Some(recording) = recording else {
        return;
    };
    has_the_split_of_jit_rb(&recording);
    // A leaf that sets up no frame loses its caller, the eval loop, to the
    // walk of frame pointers, so that where its frames went is a guess.
    let walked = interpreters(&recording).unwrap();
    let ruby = walked.iter().find(|w| w["runtime"] == "ruby").unwrap();
    let unmatched = ruby["unmatched"].as_f64().unwrap() / ruby["samples"].as_f64().unwrap();
    assert!(unmatched < 0.2, "{ruby}");
}

/// A `php` whose frames uhr reads.
fn php() -> Option<PathBuf> {
    let php = find("php").filter(|php| {
        let output = Command::new(php).args(["-r", "echo PHP_VERSION;"]).output();
        output.is_ok_and(|output| output.stdout.starts_with(b"8.3."))
    });
    if php.is_none() {
        eprintln!("skipped: needs PHP 8.3");
    }
    php
}

#[test]
fn reads_php_frames() {
    let Some(php) = php() else {
        return;
    };
    let dir = scratch("interpreters_php");
    let program = format!("{PROGRAMS}/jit.php");
    let command = [php.to_str().unwrap(), &program, "80"];
    let Some(recording) = record(&dir, &[], &command) else {
        return;
    };
    has_the_split_of(&recording, "php", "jit.php");
    let rows = functions(&recording);
    let work = runtime_function(&rows, "php", "work");
    assert!(share(work, "total_share") > 0.85, "{work}");
    let main = runtime_function(&rows, "php", "{main}");
    assert!(share(main, "total_share") > 0.85, "{main}");
    calls_from_known_lines(&recording, "hot", "work", 27);
}

/// That `function`, innermost, has no line, as the runtime saves where its
/// innermost frame is only when it calls, and that `caller` calls it from
/// `line`.
fn calls_from_known_lines(recording: &str, function: &str, caller: &str, line: u64) {
    let lines = json(&["query", recording, "--group-by", "line", "--top", "1000"]);
    let lines = lines["rows"].as_array().unwrap();
    let innermost: Vec<&Value> = lines
        .iter()
        .filter(|r| r["function"] == function && share(r, "self_share") > 0.05)
        .collect();
    assert!(!innermost.is_empty(), "{lines:?}");
    assert!(
        innermost.iter().all(|r| r["line"].is_null()),
        "{innermost:?}"
    );
    let calls = lines
        .iter()
        .find(|r| r["function"] == caller && r["line"]["line"] == line)
        .unwrap_or_else(|| panic!("{lines:?}"));
    assert!(share(calls, "total_share") > 0.5, "{calls}");
}

/// A `bun` whose frames uhr reads: the release whose offsets it knows.
fn bun() -> Option<PathBuf> {
    let bun = find("bun").filter(|bun| {
        let output = Command::new(bun).arg("--revision").output();
        output.is_ok_and(|output| output.stdout.starts_with(b"1.4.3+c6da4a4d3"))
    });
    if bun.is_none() {
        eprintln!("skipped: needs Bun 1.4.3");
    }
    bun
}

#[test]
fn reads_bun_frames() {
    let Some(bun) = bun() else {
        return;
    };
    let dir = scratch("interpreters_bun");
    let program = format!("{PROGRAMS}/jit.js");
    let command = [bun.to_str().unwrap(), &program, "100"];
    let Some(recording) = record(&dir, &[], &command) else {
        return;
    };
    has_the_split_of(&recording, "bun", "jit.js");
    let rows = functions(&recording);
    let hot = share(runtime_function(&rows, "bun", "hot"), "total_share");
    let warm = share(runtime_function(&rows, "bun", "warm"), "total_share");
    let work = runtime_function(&rows, "bun", "work");
    assert!(share(work, "total_share") >= hot + warm - 0.01, "{work}");
}
