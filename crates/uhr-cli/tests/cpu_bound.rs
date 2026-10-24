//! End to end: needs perf and a C compiler. `uhr doctor` shows what is
//! missing.

mod common;

use std::path::Path;
use std::process::Command;

use serde_json::Value;

use common::{compile, scratch, uhr};

fn query(recording: &Path) -> Value {
    let output = uhr(&[
        "query",
        recording.to_str().unwrap(),
        "--group-by",
        "function",
        "--top",
        "100",
        "--json",
    ]);
    serde_json::from_slice(&output.stdout).unwrap()
}

fn row<'a>(result: &'a Value, function: &str) -> Option<&'a Value> {
    result["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["function"] == function)
}

fn share(result: &Value, function: &str, kind: &str) -> f64 {
    let row = row(result, function).unwrap_or_else(|| panic!("no row for {function}"));
    row[kind].as_f64().unwrap()
}

#[test]
fn finds_the_hot_function_with_its_share() {
    let dir = scratch("finds_the_hot_function");
    let program = dir.join("cpu_bound");
    compile("cpu_bound", &program, "-O2");
    let recording = dir.join("rec");
    uhr(&[
        "record",
        "-o",
        recording.to_str().unwrap(),
        "--",
        program.to_str().unwrap(),
    ]);

    let result = query(&recording);
    assert_eq!(result["rows"][0]["function"], "hot");
    assert_eq!(result["rows"][1]["function"], "warm");
    let hot = share(&result, "hot", "self_share");
    let warm = share(&result, "warm", "self_share");
    assert!((0.75..=0.85).contains(&hot), "hot has {hot}");
    assert!((0.15..=0.25).contains(&warm), "warm has {warm}");

    // Every stack reaches _start, through libc.
    assert!(share(&result, "_start", "total_share") > 0.95);
    assert!(share(&result, "__libc_start_call_main", "total_share") > 0.95);

    let named = result["coverage"]["named_share"].as_f64().unwrap();
    assert!(
        named > 0.95,
        "only {named} of the time is in named functions"
    );
    assert_eq!(result["coverage"]["lost_events"], 0);
}

#[test]
fn resolves_symbols_after_recording_and_rejects_rebuilt_binaries() {
    let dir = scratch("resolves_symbols_later");
    let program = dir.join("cpu_bound");
    compile("cpu_bound", &program, "-O2");
    let recording = dir.join("rec");
    let recording = recording.to_str().unwrap();
    uhr(&[
        "record",
        "-o",
        recording,
        "--no-symbolize",
        "--",
        program.to_str().unwrap(),
        "20",
    ]);

    let result = query(Path::new(recording));
    assert_eq!(result["coverage"]["symbolized"], false);
    assert!(row(&result, "hot").is_none());

    uhr(&["symbolize", recording]);
    let result = query(Path::new(recording));
    assert_eq!(result["coverage"]["symbolized"], true);
    assert!(row(&result, "hot").is_some());

    // A different build at the same path has a different build-id.
    compile("cpu_bound", &program, "-O1");
    uhr(&["symbolize", recording]);
    let result = query(Path::new(recording));
    assert!(row(&result, "hot").is_none());
    let problems = result["coverage"]["symbol_problems"].as_array().unwrap();
    assert!(
        problems
            .iter()
            .any(|p| p["status"] == "build_id_mismatch" && p["path"] == program.to_str().unwrap()),
        "{problems:?}"
    );
}

#[test]
fn placeholder_names_do_not_count_as_named() {
    let dir = scratch("placeholder_names");
    let program = dir.join("stripped");
    compile("cpu_bound", &program, "-O2");
    let status = Command::new("strip").arg(&program).status().unwrap();
    assert!(status.success());
    let recording = dir.join("rec");
    uhr(&[
        "record",
        "-o",
        recording.to_str().unwrap(),
        "--",
        program.to_str().unwrap(),
        "20",
    ]);

    let result = query(&recording);
    let top = &result["rows"][0];
    assert!(top["function"].is_null(), "{top}");
    assert!(
        top["placeholder"].as_str().unwrap().starts_with("fun_"),
        "{top}"
    );
    let named = result["coverage"]["named_share"].as_f64().unwrap();
    assert!(named < 0.05, "{named} of the time counts as named");
}
