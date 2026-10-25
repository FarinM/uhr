//! End to end: needs perf and a C compiler. `uhr doctor` shows what is
//! missing.

mod common;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde_json::Value;

use common::{compile, scratch, uhr};

/// What a thread of the test program measured of itself.
struct Measured {
    cpu_ns: f64,
    wall_ns: f64,
}

/// Returns the recording, and what each thread measured, by name.
fn record(name: &str) -> (PathBuf, HashMap<String, Measured>) {
    let dir = scratch(name);
    let program = dir.join("threads");
    compile("threads", &program, "-O2");
    let recording = dir.join("rec");
    let output = uhr(&[
        "record",
        "-o",
        recording.to_str().unwrap(),
        "--",
        program.to_str().unwrap(),
        "100",
    ]);
    let measured = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            match fields[..] {
                ["thread", name, "cpu_ns", cpu, "wall_ns", wall] => Some((
                    name.to_owned(),
                    Measured {
                        cpu_ns: cpu.parse().unwrap(),
                        wall_ns: wall.parse().unwrap(),
                    },
                )),
                _ => None,
            }
        })
        .collect();
    (recording, measured)
}

fn json(args: &[&str]) -> Value {
    let mut args = args.to_vec();
    args.push("--json");
    serde_json::from_slice(&uhr(&args).stdout).unwrap()
}

fn overview(recording: &Path) -> Value {
    json(&["overview", recording.to_str().unwrap()])
}

fn thread<'a>(overview: &'a Value, name: &str) -> &'a Value {
    overview["threads"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["names"].as_array().unwrap().last().unwrap() == name)
        .unwrap_or_else(|| panic!("no thread named {name}: {}", overview["threads"]))
}

fn query(recording: &Path, filter: &[&str]) -> Value {
    let mut args = vec![
        "query",
        recording.to_str().unwrap(),
        "--group-by",
        "function",
        "--top",
        "100",
    ];
    args.extend(filter);
    json(&args)
}

fn top_function(result: &Value) -> &str {
    result["rows"][0]["function"]
        .as_str()
        .unwrap_or_else(|| panic!("no named function on top: {result:#}"))
}

#[test]
fn overview_tells_computing_threads_from_waiting_ones() {
    let (recording, measured) = record("threads_overview");
    let result = overview(&recording);

    let process = &result["processes"][0];
    assert_eq!(process["name"], "threads");
    assert_eq!(process["threads"], 4);
    assert_eq!(result["threads_omitted"], 0);
    let rows: u64 = result["threads"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["cpu_ns"].as_u64().unwrap())
        .sum();
    assert_eq!(rows, result["cpu_ns"].as_u64().unwrap());

    let heavy = thread(&result, "heavy");
    let light = thread(&result, "light");
    let ratio = heavy["cpu_ns"].as_f64().unwrap() / light["cpu_ns"].as_f64().unwrap();
    assert!(
        (1.6..=2.4).contains(&ratio),
        "heavy has {ratio} times light's CPU time"
    );

    let sleeper = thread(&result, "sleeper");
    let main = thread(&result, "threads");
    for waiting in [sleeper, main] {
        let share = waiting["on_cpu_share"].as_f64().unwrap();
        assert!(share < 0.05, "{waiting}");
    }
    // The sleeper waits until heavy is done.
    assert!(sleeper["alive_ns"].as_f64().unwrap() > 0.9 * heavy["alive_ns"].as_f64().unwrap());

    // How long the threads waited depends on what else the machine runs,
    // so compare with what they measured of themselves.
    assert_eq!(measured.len(), 4);
    for (name, own) in &measured {
        let row = thread(&result, name);
        let sampled = row["cpu_ns"].as_f64().unwrap();
        assert!(
            (sampled - own.cpu_ns).abs() <= 0.05 * own.cpu_ns + 5e6,
            "{name}: sampled {sampled} ns of CPU time, measured {}",
            own.cpu_ns
        );
        let share = row["on_cpu_share"].as_f64().unwrap();
        let own_share = own.cpu_ns / own.wall_ns;
        assert!(
            (share - own_share).abs() <= 0.05,
            "{name}: on CPU for {share} of its life, measured {own_share}"
        );
    }
}

#[test]
fn filters_samples_by_thread_and_time() {
    let (recording, _) = record("threads_filters");

    let heavy = query(&recording, &["--thread", "heavy"]);
    assert_eq!(top_function(&heavy), "heavy_work");
    assert!(heavy["rows"][0]["self_share"].as_f64().unwrap() > 0.95);
    let light = query(&recording, &["--thread", "l*"]);
    assert_eq!(top_function(&light), "light_work");

    let result = overview(&recording);
    let tid = thread(&result, "heavy")["tid"].to_string();
    let by_tid = query(&recording, &["--tid", &tid]);
    assert!(by_tid["time_ns"].as_u64() >= heavy["time_ns"].as_u64());

    // A time range splits the samples without losing any or counting any
    // twice. Which thread finishes first depends on the scheduler, so the
    // split is checked by totals, not by which functions are left.
    let light_end = thread(&result, "light")["end_ns"].as_u64().unwrap();
    let split = format!("{}ns", light_end + 1);
    let cpu_ns = |filter: &[&str]| query(&recording, filter)["time_ns"].as_u64().unwrap();
    assert_eq!(
        cpu_ns(&["--to", &split]) + cpu_ns(&["--from", &split]),
        cpu_ns(&[])
    );
    assert_eq!(
        cpu_ns(&["--thread", "light", "--to", &split]),
        cpu_ns(&["--thread", "light"])
    );
    let after_light = json(&[
        "overview",
        recording.to_str().unwrap(),
        "--from",
        &split,
        "--thread",
        "light",
    ]);
    assert_eq!(after_light["samples"], 0);
    assert_eq!(after_light["threads"], Value::Array(Vec::new()));
}
