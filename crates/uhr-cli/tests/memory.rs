//! End to end: needs perf and a C compiler. `uhr doctor` shows what is
//! missing.
#![cfg(target_os = "linux")]

mod common;

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use serde_json::Value;

use common::{compile, kernel_names_memory, scratch, uhr};

const MIB: u64 = 1 << 20;

fn overview(recording: &str) -> Value {
    serde_json::from_slice(&uhr(&["overview", recording, "--json"]).stdout).unwrap()
}

fn rows(overview: &Value) -> &Vec<Value> {
    overview["memory"]["processes"]
        .as_array()
        .unwrap_or_else(|| panic!("no memory in {overview}"))
}

fn number(value: &Value) -> u64 {
    value
        .as_u64()
        .unwrap_or_else(|| panic!("{value} is not an unsigned number"))
}

#[test]
fn reads_how_much_a_program_and_its_child_grow() {
    let dir = scratch("memory_grows");
    let program = dir.join("grow");
    compile("grow", &program, "-O2");
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    let program = program.to_str().unwrap();
    uhr(&[
        "record",
        "--no-symbolize",
        "-o",
        rec,
        "--",
        program,
        "128",
        "64",
    ]);

    let overview = overview(rec);
    assert_eq!(overview["memory"]["interval_ns"], 100_000_000);
    let rows = rows(&overview);
    assert_eq!(rows.len(), 2, "{rows:?}");
    let (parent, child) = (&rows[0], &rows[1]);
    // Read from right after its exec, until it starts to exit.
    assert!(
        number(&parent["first"]["rss_anon_bytes"]) < 16 * MIB,
        "{parent}"
    );
    assert!(
        number(&parent["last"]["rss_anon_bytes"]) >= 128 * MIB,
        "{parent}"
    );
    assert!(
        number(&parent["last"]["peak_rss_bytes"]) >= 128 * MIB,
        "{parent}"
    );
    assert!(number(&parent["readings"]) >= 5, "{parent}");
    assert!(
        number(&child["max"]["rss_anon_bytes"]) >= 64 * MIB,
        "{child}"
    );
    assert_eq!(child["name"], parent["name"]);
}

#[test]
fn reads_the_memory_of_a_process_it_attaches_to() {
    let dir = scratch("memory_attached");
    let program = dir.join("grow");
    compile("grow", &program, "-O2");
    let mut running = Command::new(&program)
        .args(["64", "0", "10000"])
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    // Long enough to have grown.
    thread::sleep(Duration::from_millis(500));
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    let pid = running.id().to_string();
    let recorded = Command::new(common::UHR)
        .args(["record", "--no-symbolize", "-o", rec, "--pid", &pid])
        .args(["--duration", "500ms"])
        .output()
        .unwrap();
    running.kill().unwrap();
    running.wait().unwrap();
    assert!(
        recorded.status.success(),
        "{}",
        String::from_utf8_lossy(&recorded.stderr)
    );

    let overview = overview(rec);
    let rows = rows(&overview);
    assert_eq!(rows.len(), 1, "{rows:?}");
    let process = &rows[0];
    assert_eq!(process["pid"], running.id());
    assert!(
        number(&process["first"]["rss_anon_bytes"]) >= 64 * MIB,
        "{process}"
    );
    // One at the start, every 100 ms, and one when the capture ends.
    assert!(number(&process["readings"]) >= 5, "{process}");
}

#[test]
fn reads_no_memory_when_told_not_to() {
    let dir = scratch("memory_off");
    let program = dir.join("grow");
    compile("grow", &program, "-O2");
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    let program = program.to_str().unwrap();
    uhr(&[
        "record",
        "--no-symbolize",
        "--no-memory",
        "-o",
        rec,
        "--",
        program,
        "8",
        "0",
        "0",
    ]);

    let overview = overview(rec);
    assert!(overview["memory"].is_null(), "{}", overview["memory"]);
    let unknown = overview["coverage"]["unknown"].as_array().unwrap();
    assert!(
        unknown.iter().any(|u| u == "memory use: it was not read"),
        "{unknown:?}"
    );
}

#[test]
fn follows_the_processes_it_starts_but_not_their_threads() {
    let dir = scratch("memory_threads");
    let program = dir.join("threads");
    compile("threads", &program, "-O2");
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    // The shell has to start it, as it runs more after it.
    let script = format!("{} 40; true", program.to_str().unwrap());
    uhr(&[
        "record",
        "--no-symbolize",
        "-o",
        rec,
        "--",
        "sh",
        "-c",
        &script,
    ]);

    let overview = overview(rec);
    let mut names: Vec<&str> = rows(&overview)
        .iter()
        .map(|row| row["name"].as_str().unwrap_or("<unnamed>"))
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["sh", "threads"], "{}", overview["memory"]);
}

#[test]
fn reads_a_process_whose_main_thread_ended() {
    let dir = scratch("memory_leader_exits");
    let program = dir.join("leader_exits");
    compile("leader_exits", &program, "-O2");
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    uhr(&[
        "record",
        "--no-symbolize",
        "-o",
        rec,
        "--",
        program.to_str().unwrap(),
        "128",
    ]);

    let overview = overview(rec);
    let rows = rows(&overview);
    assert_eq!(rows.len(), 1, "{rows:?}");
    let process = &rows[0];
    assert!(
        number(&process["last"]["rss_anon_bytes"]) >= 128 * MIB,
        "{process}"
    );
    // It lives about 0.6 s.
    assert!(number(&process["readings"]) >= 5, "{process}");
}

#[test]
fn an_attached_capture_keeps_threads_off_cpu_for_all_their_time() {
    let dir = scratch("memory_attached_window");
    let mut sleeping = Command::new("sleep").arg("10").spawn().unwrap();
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    let pid = sleeping.id().to_string();
    let recorded = Command::new(common::UHR)
        .args(["record", "--no-symbolize", "-o", rec, "--pid", &pid])
        .args(["--duration", "300ms"])
        .output()
        .unwrap();
    sleeping.kill().unwrap();
    sleeping.wait().unwrap();
    assert!(
        recorded.status.success(),
        "{}",
        String::from_utf8_lossy(&recorded.stderr)
    );

    // The memory readings are part of the capture, which it was off CPU
    // for all of.
    let overview = overview(rec);
    let thread = &overview["threads"][0];
    let off_cpu = &thread["off_cpu"];
    let off_ns = ["runnable_ns", "blocked_ns", "unknown_state_ns"]
        .iter()
        .map(|state| number(&off_cpu[state]))
        .sum::<u64>();
    assert_eq!(off_ns, number(&thread["alive_ns"]), "{thread}");
    assert!(number(&overview["memory"]["processes"][0]["readings"]) >= 3);
}

#[test]
fn reads_a_process_whose_name_is_not_utf8() {
    let dir = scratch("memory_name_not_utf8");
    // The kernel cuts a name at 15 bytes, here within its last character.
    let name = OsStr::from_bytes(b"zz\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9");
    let program = dir.join(name);
    compile("grow", &program, "-O2");
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    let recorded = Command::new(common::UHR)
        .args(["record", "--no-symbolize", "-o", rec, "--"])
        .arg(&program)
        .args(["32", "0"])
        .output()
        .unwrap();
    assert!(
        recorded.status.success(),
        "{}",
        String::from_utf8_lossy(&recorded.stderr)
    );

    let overview = overview(rec);
    let rows = rows(&overview);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(
        number(&rows[0]["last"]["rss_anon_bytes"]) >= 32 * MIB,
        "{}",
        rows[0]
    );
}

#[test]
fn keeps_reading_a_process_after_another_thread_execs() {
    let dir = scratch("memory_exec_from_thread");
    let (launcher, program) = (dir.join("exec_from_thread"), dir.join("grow"));
    compile("exec_from_thread", &launcher, "-O2");
    compile("grow", &program, "-O2");
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    let (launcher, program) = (launcher.to_str().unwrap(), program.to_str().unwrap());
    uhr(&[
        "record",
        "--no-symbolize",
        "-o",
        rec,
        "--",
        launcher,
        program,
        "64",
        "0",
    ]);

    // The thread that ran grow took the process's ids, and its start.
    let overview = overview(rec);
    let grown = rows(&overview)
        .iter()
        .map(|row| number(&row["max"]["rss_anon_bytes"]))
        .max();
    assert!(grown >= Some(64 * MIB), "{}", overview["memory"]);
}

#[test]
fn says_how_much_of_each_kind_of_region_is_resident() {
    let dir = scratch("memory_by_kind");
    let program = dir.join("grow");
    compile("grow", &program, "-O2");
    let program = program.to_str().unwrap();
    // Blocks of 8 MiB, which malloc maps on its own, and of 4 KiB, which
    // it takes from the heap, kept a while.
    for (block, kind) in [("8192", "anonymous"), ("4", "heap")] {
        let recording = dir.join(format!("rec-{block}"));
        let rec = recording.to_str().unwrap();
        uhr(&[
            "record",
            "--no-symbolize",
            "-o",
            rec,
            "--",
            program,
            "64",
            "0",
            "1000",
            block,
        ]);
        let overview = overview(rec);
        let process = &rows(&overview)[0];
        let kinds = process["regions"]["kinds"].as_array().unwrap();
        let resident = kinds
            .iter()
            .find(|k| k["kind"] == kind)
            .map_or(0, |k| number(&k["rss_bytes"]));
        assert!(resident >= 60 * MIB, "{}", process["regions"]);
    }
}

#[test]
fn says_how_much_is_resident_under_each_name_a_process_gave_its_memory() {
    if !kernel_names_memory() {
        eprintln!("skipped: needs Linux 5.17 or later, built with CONFIG_ANON_VMA_NAME");
        return;
    }
    let dir = scratch("memory_by_name");
    let program = dir.join("named");
    compile("named", &program, "-O2");
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    uhr(&[
        "record",
        "--no-symbolize",
        "-o",
        rec,
        "--",
        program.to_str().unwrap(),
        "32",
        "300",
    ]);
    let overview = overview(rec);
    let process = &rows(&overview)[0];
    let kinds = process["regions"]["kinds"].as_array().unwrap();
    // Without the number its name ends in.
    let named = kinds
        .iter()
        .find(|k| k["name"] == "[anon:uhr test]")
        .unwrap_or_else(|| panic!("{}", process["regions"]));
    assert_eq!(named["kind"], "anonymous");
    assert!(number(&named["rss_bytes"]) >= 32 * MIB, "{named}");
}
