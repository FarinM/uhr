//! End to end: needs perf and a C compiler. `uhr doctor` shows what is
//! missing.

mod common;

use serde_json::Value;

use common::{compile, scratch, uhr};

fn json(args: &[&str]) -> Value {
    let mut args = args.to_vec();
    args.push("--json");
    serde_json::from_slice(&uhr(&args).stdout).unwrap()
}

#[test]
fn the_time_is_in_the_kernel_on_behalf_of_read_zero() {
    let dir = scratch("syscalls_kernel_time");
    let program = dir.join("syscalls");
    compile("syscalls", &program, "-O2");
    let recording = dir.join("rec");
    let recording = recording.to_str().unwrap();
    let output = uhr(&[
        "record",
        "-o",
        recording,
        "--",
        program.to_str().unwrap(),
        "200000",
    ]);
    // What the kernel measured of the program, as the program printed it.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let own: Vec<f64> = stdout
        .lines()
        .find_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            match fields[..] {
                [
                    "process",
                    "user_ns",
                    user,
                    "kernel_ns",
                    kernel,
                    "wall_ns",
                    wall,
                ] => Some([user, kernel, wall].map(|n| n.parse().unwrap()).to_vec()),
                _ => None,
            }
        })
        .unwrap_or_else(|| panic!("no measurement in {stdout:?}"));
    let (own_user, own_kernel, own_wall) = (own[0], own[1], own[2]);

    let overview = json(&["overview", recording]);
    if overview["kernel_cpu_ns"].is_null() {
        // perf could not sample the kernel here. The overview has to say
        // so instead of calling the program idle.
        let missing = overview["coverage"]["missing_signals"].as_array().unwrap();
        assert!(
            missing.iter().any(|m| m["signal"] == "kernel_cpu_samples"),
            "{missing:?}"
        );
        let unknown = overview["coverage"]["unknown"].as_array().unwrap();
        assert!(
            unknown
                .iter()
                .any(|u| u.as_str().unwrap().starts_with("CPU time in the kernel")),
            "{unknown:?}"
        );
        return;
    }

    let cpu = overview["cpu_ns"].as_f64().unwrap();
    let kernel = overview["kernel_cpu_ns"].as_f64().unwrap() / cpu;
    assert!(
        kernel > 0.8,
        "only {kernel} of the CPU time is in the kernel"
    );
    let own_cpu = own_user + own_kernel;
    assert!(
        (cpu - own_cpu).abs() <= 0.05 * own_cpu + 5e6,
        "sampled {cpu} ns of CPU time, measured {own_cpu}"
    );
    let own_kernel_share = own_kernel / own_cpu;
    assert!(
        (kernel - own_kernel_share).abs() <= 0.1,
        "{kernel} of the CPU time in the kernel, measured {own_kernel_share}"
    );
    let share = overview["threads"][0]["on_cpu_share"].as_f64().unwrap();
    let own_share = own_cpu / own_wall;
    assert!(
        (share - own_share).abs() <= 0.05,
        "on CPU for {share} of its life, measured {own_share}"
    );

    let query = json(&[
        "query",
        recording,
        "--group-by",
        "function",
        "--mode",
        "kernel",
        "--top",
        "100",
    ]);
    // The kernel has a read_zero of its own, which reads /dev/zero.
    let read_zero = query["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["function"] == "read_zero" && r["origin"] == "binary")
        .expect("read_zero is on the kernel stacks");
    assert!(
        read_zero["total_share"].as_f64().unwrap() > 0.95,
        "{read_zero}"
    );
    assert!(
        query["rows"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["origin"] == "kernel" || r["self_cpu_ns"] == 0),
        "only kernel code runs in kernel mode"
    );
}
