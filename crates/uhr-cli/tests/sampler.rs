//! End to end: uhr's eBPF programs sampling in place of perf. Needs root
//! through sudo without a password, perf and a C compiler, and skips
//! without sudo.
#![cfg(target_os = "linux")]

mod common;

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use serde_json::Value;

use common::{UHR, compile, scratch, uhr, uhr_as_root};

fn json(args: &[&str]) -> Value {
    let mut args = args.to_vec();
    args.push("--json");
    serde_json::from_slice(&uhr(&args).stdout).unwrap()
}

/// The recording's streams, or `None` if uhr was built without its eBPF
/// programs. As root, they sample otherwise.
fn sampled_by_ebpf(recording: &Path) -> Option<Vec<Value>> {
    let manifest: Value =
        serde_json::from_slice(&fs::read(recording.join("manifest.json")).unwrap()).unwrap();
    let streams = manifest["streams"].as_array().unwrap().clone();
    let sampled = streams
        .iter()
        .any(|s| s["id"] == "ebpf" && !s["collector"]["sampling"].is_null());
    if sampled {
        return Some(streams);
    }
    let missing = manifest["missing_signals"].to_string();
    assert!(missing.contains("built without"), "{manifest}");
    eprintln!("skipped: uhr was built without its eBPF programs");
    None
}

fn self_share(result: &Value, function: &str) -> f64 {
    result["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["function"] == function)
        .map_or(0.0, |r| r["self_share"].as_f64().unwrap())
}

#[test]
fn samples_with_its_ebpf_programs_where_it_may() {
    let dir = scratch("sampler_cpu_bound");
    let program = dir.join("cpu_bound");
    compile("cpu_bound", &program, "-O2");
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    let args = ["record", "-o", rec, "--", program.to_str().unwrap(), "100"];
    if uhr_as_root(&args, &recording).is_none() {
        eprintln!("skipped: needs root through sudo without a password");
        return;
    }
    let Some(streams) = sampled_by_ebpf(&recording) else {
        return;
    };
    let ebpf = streams.iter().find(|s| s["id"] == "ebpf").unwrap();
    assert_eq!(ebpf["collector"]["sampling"]["frequency_hz"], 999);
    let signals = ebpf["signals"].as_array().unwrap();
    for signal in ["user_cpu_samples", "kernel_cpu_samples", "user_stacks"] {
        assert!(signals.iter().any(|s| s == signal), "{ebpf}");
    }
    // perf only tracks the processes and their switches.
    let perf = streams.iter().find(|s| s["id"] == "perf").unwrap();
    assert!(perf["collector"]["sampling"].is_null(), "{perf}");
    assert_eq!(perf["coverage"]["stacks"]["samples"], 0);

    let result = json(&["query", rec, "--group-by", "function"]);
    assert_eq!(result["samples"], ebpf["coverage"]["stacks"]["samples"]);
    let (hot, warm) = (self_share(&result, "hot"), self_share(&result, "warm"));
    assert!((hot - 0.8).abs() < 0.05, "hot has {hot}: {result}");
    assert!((warm - 0.2).abs() < 0.05, "warm has {warm}: {result}");
}

#[test]
fn lowers_the_frequency_to_the_kernels_limit() {
    let dir = scratch("sampler_frequency");
    let program = dir.join("cpu_bound");
    compile("cpu_bound", &program, "-O2");
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    let args = [
        "record",
        "-o",
        rec,
        "-F",
        "10000000",
        "--",
        program.to_str().unwrap(),
        "5",
    ];
    if uhr_as_root(&args, &recording).is_none() {
        eprintln!("skipped: needs root through sudo without a password");
        return;
    }
    let Some(streams) = sampled_by_ebpf(&recording) else {
        return;
    };
    let ebpf = streams.iter().find(|s| s["id"] == "ebpf").unwrap();
    let sampling = &ebpf["collector"]["sampling"];
    assert_eq!(sampling["requested_frequency_hz"], 10_000_000);
    let limit: u64 = fs::read_to_string("/proc/sys/kernel/perf_event_max_sample_rate")
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(
        sampling["frequency_hz"].as_u64().unwrap() <= limit,
        "{sampling}"
    );
}

#[test]
fn samples_only_while_attached() {
    let dir = scratch("sampler_attached");
    let program = dir.join("cpu_bound");
    compile("cpu_bound", &program, "-O2");
    // Far longer than the capture.
    let mut target = Command::new(&program)
        .arg("10000")
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    thread::sleep(Duration::from_millis(200));
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    let pid = target.id().to_string();
    let args = ["record", "-o", rec, "--pid", &pid, "--duration", "500ms"];
    let recorded = uhr_as_root(&args, &recording);
    target.kill().unwrap();
    target.wait().unwrap();
    if recorded.is_none() {
        eprintln!("skipped: needs root through sudo without a password");
        return;
    }
    if sampled_by_ebpf(&recording).is_none() {
        return;
    }
    // The one thread computes all along.
    let overview = json(&["overview", rec]);
    let cpu = overview["cpu_ns"].as_f64().unwrap() / 1e9;
    assert!((0.4..0.65).contains(&cpu), "{cpu} s of CPU time in 0.5 s");
}

#[test]
fn needs_its_ebpf_programs_when_told_to_sample_with_them() {
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipped: root may load eBPF");
        return;
    }
    let dir = scratch("sampler_refused");
    let recording = dir.join("rec");
    let output = Command::new(UHR)
        .args(["record", "--sampler", "ebpf", "-o"])
        .arg(&recording)
        .args(["--", "true"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot record") && stderr.contains("eBPF"),
        "{stderr}"
    );
    assert!(!recording.exists());
}

#[test]
fn stops_sampling_when_perf_stops() {
    let sudo = |args: &[&str]| Command::new("sudo").arg("-n").args(args).output().unwrap();
    if !sudo(&["true"]).status.success() {
        eprintln!("skipped: needs root through sudo without a password");
        return;
    }
    let dir = scratch("sampler_perf_stops");
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    // Computes until told to stop, and then for a second or two.
    let script = "trap 'end=$((SECONDS + 2)); while [ $SECONDS -lt $end ]; do :; done; exit' \
                  TERM; while :; do :; done";
    let mut recorder = Command::new("sudo")
        .args(["-n", UHR, "record", "-o", rec, "--", "bash", "-c", script])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    thread::sleep(Duration::from_secs(1));
    let children = |parent: u32, name: &str| {
        let found = sudo(&["pgrep", "-P", &parent.to_string(), "-x", name]);
        String::from_utf8_lossy(&found.stdout).trim().to_owned()
    };
    let uhr_pid = children(recorder.id(), "uhr");
    let perf = children(uhr_pid.parse().unwrap(), "perf");
    assert!(
        sudo(&["kill", "-INT", &perf]).status.success(),
        "perf {perf:?}"
    );
    assert!(recorder.wait().unwrap().success());
    assert!(
        sudo(&[
            "chown",
            "-R",
            &format!("{}", unsafe { libc::getuid() }),
            rec
        ])
        .status
        .success()
    );
    if sampled_by_ebpf(&recording).is_none() {
        return;
    }
    // perf ran a second, and the target computed a second or two after.
    let overview = json(&["overview", rec]);
    let cpu = overview["cpu_ns"].as_f64().unwrap() / 1e9;
    assert!(cpu < 1.5, "{cpu} s of CPU time");
}

#[test]
fn counts_a_virtual_machines_guest_in_unknown_mode() {
    let dir = scratch("sampler_guest");
    let program = dir.join("guest");
    compile("guest", &program, "-O2");
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    let probe = Command::new("sudo")
        .args(["-n", program.to_str().unwrap(), "10"])
        .output()
        .unwrap();
    if !probe.status.success() {
        eprintln!("skipped: needs root through sudo and /dev/kvm");
        return;
    }
    let args = ["record", "-o", rec, "--", program.to_str().unwrap(), "500"];
    uhr_as_root(&args, &recording).unwrap();
    if sampled_by_ebpf(&recording).is_none() {
        return;
    }
    // Not the host's code that entered the guest, as in kernel mode.
    let overview = json(&["overview", rec]);
    let unknown = overview["unknown_mode_cpu_ns"].as_f64().unwrap();
    let share = unknown / overview["cpu_ns"].as_f64().unwrap();
    assert!(
        share > 0.9,
        "{share} of the CPU time in unknown mode: {overview}"
    );
}

#[test]
fn samples_a_command_another_thread_ran() {
    let dir = scratch("sampler_exec_from_thread");
    let (launcher, program) = (dir.join("exec_from_thread"), dir.join("cpu_bound"));
    common::compile_with_flags("exec_from_thread", &launcher, &["-O2"]);
    compile("cpu_bound", &program, "-O2");
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    let target = [launcher.to_str().unwrap(), program.to_str().unwrap(), "100"];
    let args = [&["record", "-o", rec, "--"][..], &target].concat();
    if uhr_as_root(&args, &recording).is_none() {
        eprintln!("skipped: needs root through sudo without a password");
        return;
    }
    if sampled_by_ebpf(&recording).is_none() {
        return;
    }
    // The command runs as the main thread, with its id.
    let result = json(&["query", rec, "--group-by", "function"]);
    let hot = self_share(&result, "hot");
    assert!((hot - 0.8).abs() < 0.05, "hot has {hot}: {result}");
}
