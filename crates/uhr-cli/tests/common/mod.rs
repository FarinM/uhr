// Each test file uses a different part of this module.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

pub const UHR: &str = env!("CARGO_BIN_EXE_uhr");

const PROGRAMS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test-programs");

/// Runs uhr and fails the test if it fails.
pub fn uhr(args: &[&str]) -> Output {
    let output = Command::new(UHR).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "uhr {args:?} failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

pub fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Builds `test-programs/<program>.c`.
pub fn compile(program: &str, output: &Path, optimization: &str) {
    let status = Command::new("cc")
        .args([
            optimization,
            "-pthread",
            "-fno-omit-frame-pointer",
            "-Wl,--build-id",
            "-o",
        ])
        .arg(output)
        .arg(format!("{PROGRAMS}/{program}.c"))
        .status()
        .expect("running cc");
    assert!(status.success(), "cc failed");
}
