//! End to end: needs perf and a C compiler, and for uhr's eBPF programs
//! root through sudo without a password. `uhr doctor` shows what is
//! missing.
#![cfg(target_os = "linux")]

mod common;

use std::fs;
use std::path::Path;
use std::process::Command;

use serde_json::Value;

use common::{UHR, compile, scratch, uhr, uhr_as_root};

const PROGRAMS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test-programs");

/// The pages `grow 64` touches: 64 MiB in pages of this host's size.
fn pages() -> f64 {
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    (64 << 20) as f64 / page as f64
}

fn json(args: &[&str]) -> Value {
    let mut args = args.to_vec();
    args.push("--json");
    serde_json::from_slice(&uhr(&args).stdout).unwrap()
}

fn manifest(recording: &str) -> Value {
    serde_json::from_slice(&fs::read(Path::new(recording).join("manifest.json")).unwrap()).unwrap()
}

fn stream<'a>(manifest: &'a Value, id: &str) -> &'a Value {
    let streams = manifest["streams"].as_array().unwrap();
    streams
        .iter()
        .find(|s| s["id"] == id)
        .unwrap_or_else(|| panic!("no stream {id} in {manifest}"))
}

fn faults_by_function(recording: &str) -> Value {
    json(&[
        "query",
        recording,
        "--metric",
        "page-faults",
        "--group-by",
        "function",
        "--top",
        "1000",
    ])
}

fn row(result: &Value, matches: impl Fn(&Value) -> bool) -> &Value {
    let rows = result["rows"].as_array().unwrap();
    rows.iter()
        .find(|row| matches(row))
        .unwrap_or_else(|| panic!("no such row in {rows:?}"))
}

/// Where the kernel maps 2 MiB at a fault, the faults don't count pages.
fn huge_pages_always() -> bool {
    fs::read_to_string("/sys/kernel/mm/transparent_hugepage/enabled")
        .is_ok_and(|setting| setting.contains("[always]"))
}

/// Checks a recording of `grow 64 0 0`: its faults are in `touch`, which
/// first writes the memory it grows by.
fn check_grown(recording: &str, collector: &str) {
    let manifest = manifest(recording);
    let sampled = &stream(&manifest, collector)["collector"]["page_faults"];
    // With frame pointers.
    assert_eq!(sampled["period"], 64, "{sampled}");
    let result = faults_by_function(recording);
    assert_eq!(result["unit"], "faults");
    let faults = result["value"].as_f64().unwrap();
    let pages = pages();
    if !huge_pages_always() {
        assert!(
            (0.9 * pages..1.5 * pages).contains(&faults),
            "{faults} faults for {pages} pages"
        );
    }
    // GCC names a copy it makes for the arguments, as `touch.constprop.0`.
    let touch = row(&result, |row| {
        let function = row["function"].as_str().unwrap_or_default();
        function == "touch" || function.starts_with("touch.")
    });
    assert!(touch["self_share"].as_f64().unwrap() > 0.8, "{touch}");
}

#[test]
fn samples_where_a_program_first_touches_memory() {
    let dir = scratch("page_faults_perf");
    let program = dir.join("grow");
    compile("grow", &program, "-O2");
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    let program = program.to_str().unwrap();
    uhr(&[
        "record",
        "--sampler",
        "perf",
        "-o",
        rec,
        "--",
        program,
        "64",
        "0",
        "0",
    ]);
    check_grown(rec, "perf");

    let svg = dir.join("faults.svg");
    let svg_path = svg.to_str().unwrap();
    uhr(&["flamegraph", rec, "--metric", "page-faults", "-o", svg_path]);
    let svg = fs::read_to_string(svg).unwrap();
    assert!(svg.contains("Page faults: "), "no title");
    assert!(svg.contains(" faults, "), "no amounts of faults");
}

#[test]
fn samples_page_faults_with_its_ebpf_programs() {
    let dir = scratch("page_faults_ebpf");
    let program = dir.join("grow");
    compile("grow", &program, "-O2");
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    let program = program.to_str().unwrap();
    let args = [
        "record",
        "--sampler",
        "ebpf",
        "-o",
        rec,
        "--",
        program,
        "64",
        "0",
        "0",
    ];
    if uhr_as_root(&args, &recording).is_none() {
        eprintln!("skipped: needs root through sudo without a password");
        return;
    }
    check_grown(rec, "ebpf");
}

#[test]
fn names_the_python_functions_that_first_touch_memory() {
    let dir = scratch("page_faults_python");
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    let script = format!("{PROGRAMS}/alloc.py");
    // Without perf maps, so the names come from the interpreter's frames.
    let args = [
        "record",
        "--sampler",
        "ebpf",
        "--no-runtime-support",
        "-o",
        rec,
        "--",
        "python3",
        &script,
    ];
    if uhr_as_root(&args, &recording).is_none() {
        eprintln!("skipped: needs root through sudo without a password");
        return;
    }
    let result = faults_by_function(rec);
    let build = row(&result, |row| {
        row["module"] == "[python]" && row["function"] == "build"
    });
    assert!(build["total_share"].as_f64().unwrap() > 0.8, "{build}");
}

#[test]
fn samples_no_page_faults_when_told_not_to() {
    let dir = scratch("page_faults_off");
    let program = dir.join("grow");
    compile("grow", &program, "-O2");
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    let program = program.to_str().unwrap();
    let flags = ["record", "--no-page-faults", "--no-symbolize", "-o", rec];
    uhr(&[&flags[..], &["--", program, "8", "0", "0"]].concat());
    let manifest = manifest(rec);
    let signals: Vec<&Value> = manifest["streams"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|s| s["signals"].as_array().unwrap())
        .collect();
    assert!(!signals.iter().any(|s| *s == "page_faults"), "{signals:?}");

    let query = Command::new(UHR)
        .args([
            "query",
            rec,
            "--metric",
            "page-faults",
            "--group-by",
            "function",
        ])
        .output()
        .unwrap();
    assert!(!query.status.success());
    let stderr = String::from_utf8_lossy(&query.stderr);
    assert!(stderr.contains("--no-page-faults"), "{stderr}");
}

fn faults_by_region(recording: &str) -> Value {
    json(&[
        "query",
        recording,
        "--metric",
        "page-faults",
        "--group-by",
        "region",
    ])
}

/// The share of a recording's page faults in regions of `kind`.
fn share_in(result: &Value, kind: &str) -> f64 {
    let rows = result["rows"].as_array().unwrap();
    rows.iter()
        .filter(|row| row["kind"] == kind)
        .map(|row| row["share"].as_f64().unwrap())
        .sum()
}

#[test]
fn tells_the_regions_a_program_grew_apart() {
    let dir = scratch("page_faults_regions");
    let program = dir.join("grow");
    compile("grow", &program, "-O2");
    let program = program.to_str().unwrap();
    // Blocks of 8 MiB, which malloc maps on its own, and of 4 KiB, which
    // it takes from the heap.
    for (block, kind) in [("8192", "anonymous"), ("4", "heap")] {
        let recording = dir.join(format!("rec-{block}"));
        let rec = recording.to_str().unwrap();
        uhr(&["record", "-o", rec, "--", program, "32", "0", "0", block]);
        let result = faults_by_region(rec);
        let share = share_in(&result, kind);
        assert!(share > 0.9, "{}", result["rows"]);

        let under = json(&[
            "query",
            rec,
            "--metric",
            "page-faults",
            "--region",
            kind,
            "--group-by",
            "function",
        ]);
        let kept = under["value"].as_f64().unwrap() / result["value"].as_f64().unwrap();
        assert!((kept - share).abs() < 1e-9, "{kept} kept of {share}");
        // malloc itself first touches each page of the heap it grows, as it
        // writes where the next block starts.
        if kind == "anonymous" {
            let touch = row(&under, |row| {
                let function = row["function"].as_str().unwrap_or_default();
                function == "touch" || function.starts_with("touch.")
            });
            assert!(touch["self_share"].as_f64().unwrap() > 0.8, "{touch}");
        }
    }
}

#[test]
fn says_only_page_faults_were_in_regions() {
    let dir = scratch("page_faults_regions_of_time");
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
        "8",
        "0",
        "0",
    ]);
    for args in [
        &["--group-by", "region"][..],
        &["--group-by", "function", "--region", "heap"][..],
    ] {
        let query = Command::new(UHR)
            .args(["query", rec])
            .args(args)
            .output()
            .unwrap();
        assert!(!query.status.success(), "{args:?}");
        let stderr = String::from_utf8_lossy(&query.stderr);
        assert!(stderr.contains("--metric page-faults"), "{stderr}");
    }
}
