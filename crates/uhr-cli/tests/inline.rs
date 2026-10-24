//! End to end: needs perf and a C compiler. `uhr doctor` shows what is
//! missing.

mod common;

use std::path::{Path, PathBuf};

use serde_json::Value;

use common::{compile, compile_with_debug_info, scratch, uhr};

fn record(name: &str, debug_info: bool) -> PathBuf {
    let dir = scratch(name);
    let program = dir.join("inline");
    if debug_info {
        compile_with_debug_info("inline", &program, "-O2");
    } else {
        compile("inline", &program, "-O2");
    }
    let recording = dir.join("rec");
    uhr(&[
        "record",
        "-o",
        recording.to_str().unwrap(),
        "--",
        program.to_str().unwrap(),
        "100",
    ]);
    recording
}

fn json(command: &str, recording: &Path, args: &[&str]) -> Value {
    let mut all = vec![command, recording.to_str().unwrap(), "--json"];
    all.extend(args);
    serde_json::from_slice(&uhr(&all).stdout).unwrap()
}

fn row<'a>(rows: &'a Value, function: &str) -> &'a Value {
    rows.as_array()
        .unwrap()
        .iter()
        .find(|r| r["function"] == function)
        .unwrap_or_else(|| panic!("no {function} in {rows:#}"))
}

fn share(value: &Value, field: &str) -> f64 {
    value[field].as_f64().unwrap()
}

#[test]
fn credits_inlined_code_to_the_inlined_function() {
    let recording = record("inline_expanded", true);
    let query = json("query", &recording, &["--group-by", "function"]);
    let mix = row(&query["rows"], "mix");
    assert_eq!(mix["inlined"], true);
    assert!(share(mix, "self_share") > 0.95, "{mix}");
    let from_a = row(&query["rows"], "from_a");
    assert!(share(from_a, "self_share") < 0.05, "{from_a}");
    assert!(
        (0.7..=0.8).contains(&share(from_a, "total_share")),
        "{from_a}"
    );
    assert_eq!(
        query["coverage"]["without_debug_info"],
        Value::Array(Vec::new())
    );

    // Its id selects it, and its callers are the functions it was inlined into.
    let paths = json(
        "call-paths",
        &recording,
        &["--function", mix["id"].as_str().unwrap()],
    );
    let a = share(row(&paths["callers"], "from_a"), "share");
    let b = share(row(&paths["callers"], "from_b"), "share");
    assert!((0.7..=0.8).contains(&a), "from_a has {a}");
    assert!((0.2..=0.3).contains(&b), "from_b has {b}");
}

#[test]
fn finds_the_source_lines_that_take_the_time() {
    let recording = record("inline_lines", true);
    let lines = json(
        "query",
        &recording,
        &["--group-by", "line", "--under", "mix", "--mode", "user"],
    );
    let rows = lines["rows"].as_array().unwrap();
    let in_mix: f64 = rows
        .iter()
        .filter(|r| r["function"] == "mix")
        .map(|r| {
            assert!(r["line"]["file"].as_str().unwrap().ends_with("inline.c"));
            share(r, "self_share")
        })
        .sum();
    assert!(in_mix > 0.95, "{rows:#?}");
    // Each caller's row is the line of its call.
    let from_a = row(&lines["rows"], "from_a");
    assert!(from_a["line"]["line"].as_u64().is_some(), "{from_a}");
}

#[test]
fn says_when_inlined_calls_cannot_be_expanded() {
    let recording = record("inline_without_debug_info", false);
    let query = json("query", &recording, &["--group-by", "function"]);
    let from_a = row(&query["rows"], "from_a");
    assert!(share(from_a, "self_share") > 0.7, "{from_a}");
    let program = recording.with_file_name("inline");
    assert!(
        query["coverage"]["without_debug_info"]
            .as_array()
            .unwrap()
            .iter()
            .any(|path| path == program.to_str().unwrap()),
        "{:#}",
        query["coverage"]
    );
}

#[test]
fn keeps_inlined_functions_apart_by_declaration() {
    let dir = scratch("inline_names");
    let program = dir.join("inline_names");
    compile_with_debug_info("inline_names", &program, "-O2");
    let recording = dir.join("rec");
    uhr(&[
        "record",
        "-o",
        recording.to_str().unwrap(),
        "--",
        program.to_str().unwrap(),
        "60",
    ]);

    let query = json("query", &recording, &["--group-by", "function"]);
    let rows = query["rows"].as_array().unwrap();
    for name in ["helper", "_helper"] {
        let named: Vec<_> = rows.iter().filter(|r| r["function"] == name).collect();
        assert_eq!(named.len(), 1, "{name}: {named:#?}");
        let self_share = share(named[0], "self_share");
        assert!((0.4..=0.6).contains(&self_share), "{name}: {self_share}");
        // The name picks out one function, so --under takes it.
        json(
            "query",
            &recording,
            &["--group-by", "function", "--under", name],
        );
    }

    // helper's code comes from two files, but it is one function.
    let lines = json(
        "query",
        &recording,
        &["--group-by", "line", "--under", "helper", "--mode", "user"],
    );
    let files: std::collections::BTreeSet<_> = lines["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["function"] == "helper")
        .map(|r| {
            r["line"]["file"]
                .as_str()
                .unwrap()
                .rsplit('/')
                .next()
                .unwrap()
        })
        .collect();
    assert_eq!(files, ["generated.inc", "inline_names.c"].into());
}
