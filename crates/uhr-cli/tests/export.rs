//! Export is available on every platform and needs no recording privileges.
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde_json::Value;
use uhr_core::recording::*;

const UHR: &str = env!("CARGO_BIN_EXE_uhr");

fn recording(name: &str) -> (PathBuf, PathBuf) {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let rec = dir.join("rec");
    Recording {
        manifest: Manifest {
            format_version: FORMAT_VERSION,
            platform: Platform {
                os: "linux".into(),
                arch: "x86_64".into(),
            },
            target: Target {
                command: vec!["fixture".into()],
                launched: true,
                runtime_support: None,
                exit: None,
            },
            clock: Clock::Monotonic,
            start_ns: Some(1_000_000),
            end_ns: Some(10_000_000),
            wall_clock: None,
            streams: Vec::new(),
            missing_signals: Vec::new(),
            kernel_symbols: KernelSymbols::Saved,
        },
        threads: Vec::new(),
        thread_names: vec![ThreadName {
            pid: 1,
            tid: 2,
            time_ns: None,
            name: "worker".into(),
        }],
        mappings: Vec::new(),
        frames: vec![Frame {
            origin: Origin::Unresolved,
            address: 0x123,
            mapping: None,
            file_offset: None,
            return_address: false,
            interpreted: None,
        }],
        stacks: vec![vec![0]],
        samples: vec![
            Sample {
                time_ns: 2_000_000,
                pid: 1,
                tid: 1,
                cpu: None,
                mode: Mode::User,
                stack: 0,
                cpu_ns: 123_456,
            },
            Sample {
                time_ns: 3_000_000,
                pid: 1,
                tid: 2,
                cpu: None,
                mode: Mode::User,
                stack: 0,
                cpu_ns: 987_654,
            },
        ],
        page_faults: Vec::new(),
        off_cpu: Vec::new(),
        kernel_symbols: Vec::new(),
        jit_symbols: Vec::new(),
        interpreted_code: Vec::new(),
        syscall_calls: Vec::new(),
        memory: Vec::new(),
        regions: Vec::new(),
        region_memory: Vec::new(),
    }
    .write(&rec)
    .unwrap();
    (rec, dir.join("profile.json"))
}

#[test]
fn exports_an_existing_recording_and_reports_coverage() {
    let (rec, out) = recording("export_existing");
    let manifest = fs::read(rec.join("manifest.json")).unwrap();
    let ran = Command::new(UHR)
        .arg("export")
        .arg(&rec)
        .args(["--format", "firefox", "--json", "-o"])
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        ran.status.success(),
        "{}",
        String::from_utf8_lossy(&ran.stderr)
    );
    let report: Value = serde_json::from_slice(&ran.stdout).unwrap();
    assert_eq!(report["cpu_ns"], 1_111_110);
    assert_eq!(report["unnamed_cpu_ns"], 1_111_110);
    assert_eq!(report["threads"], 2);
    assert_eq!(report["symbols"]["symbolized"], false);
    let profile: Value = serde_json::from_slice(&fs::read(&out).unwrap()).unwrap();
    assert_eq!(profile["meta"]["preprocessedProfileVersion"], 55);
    let total: f64 = profile["threads"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|t| t["samples"]["weight"].as_array().unwrap())
        .map(|n| n.as_f64().unwrap())
        .sum();
    assert!((total - 1.11111).abs() < 1e-10);
    assert_eq!(fs::read(rec.join("manifest.json")).unwrap(), manifest);
}

#[test]
fn exports_a_selected_thread_and_time_range() {
    let (rec, out) = recording("export_filtered");
    let ran = Command::new(UHR)
        .arg("export")
        .arg(&rec)
        .args(["--thread", "work*", "--from", "2ms", "--to", "3ms", "-o"])
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        ran.status.success(),
        "{}",
        String::from_utf8_lossy(&ran.stderr)
    );
    assert!(String::from_utf8_lossy(&ran.stdout).contains("profiler.firefox.com"));
    let profile: Value = serde_json::from_slice(&fs::read(out).unwrap()).unwrap();
    assert_eq!(profile["threads"].as_array().unwrap().len(), 1);
    assert_eq!(profile["threads"][0]["name"], "worker");
    assert_eq!(profile["threads"][0]["samples"]["time"][0], 2.0);
}

#[test]
fn does_not_create_an_empty_export_or_overwrite_existing_files() {
    let (rec, out) = recording("export_errors");
    let ran = Command::new(UHR)
        .arg("export")
        .arg(&rec)
        .args(["--pid", "999", "-o"])
        .arg(&out)
        .output()
        .unwrap();
    assert!(!ran.status.success());
    assert!(String::from_utf8_lossy(&ran.stderr).contains("nothing to export"));
    assert!(!out.exists());
    let out = rec.join("manifest.json");
    let before = fs::read(&out).unwrap();
    let ran = Command::new(UHR)
        .arg("export")
        .arg(&rec)
        .arg("-o")
        .arg(&out)
        .output()
        .unwrap();
    assert!(!ran.status.success());
    assert!(String::from_utf8_lossy(&ran.stderr).contains("output must not already exist"));
    assert_eq!(fs::read(out).unwrap(), before);
}

#[test]
fn finishes_the_file_when_the_summary_reader_closes_early() {
    let (rec, out) = recording("export_closed_stdout");
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let ran = Command::new(UHR)
        .arg("export")
        .arg(&rec)
        .args(["--json", "-o"])
        .arg(&out)
        .stdout(Stdio::from(writer))
        .output()
        .unwrap();
    assert!(
        ran.status.success(),
        "{}",
        String::from_utf8_lossy(&ran.stderr)
    );
    let profile: Value = serde_json::from_slice(&fs::read(out).unwrap()).unwrap();
    assert_eq!(profile["threads"].as_array().unwrap().len(), 2);
}
