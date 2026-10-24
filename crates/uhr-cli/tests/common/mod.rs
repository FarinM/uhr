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
    build(program, output, &[optimization]);
}

/// Builds `test-programs/<program>.c` with DWARF debug info.
pub fn compile_with_debug_info(program: &str, output: &Path, optimization: &str) {
    build(program, output, &[optimization, "-g"]);
}

/// Builds `test-programs/<program>.c` the way release builds often are.
pub fn compile_without_frame_pointers(program: &str, output: &Path, optimization: &str) {
    build(program, output, &[optimization, "-fomit-frame-pointer"]);
}

/// Builds `test-programs/<program>.c` with extra compiler flags.
pub fn compile_with_flags(program: &str, output: &Path, flags: &[&str]) {
    build(program, output, flags);
}

/// Builds `test-programs/<program>.rs` as rustc does by default: without
/// frame pointers, and on x86-64 Linux linked with lld.
pub fn compile_rust(program: &str, output: &Path) {
    let status = Command::new("rustc")
        .args(["-O", "-o"])
        .arg(output)
        .arg(format!("{PROGRAMS}/{program}.rs"))
        .status()
        .expect("running rustc");
    assert!(status.success(), "rustc failed");
}

/// `flags` come last, so they win over the defaults.
fn build(program: &str, output: &Path, flags: &[&str]) {
    let status = Command::new("cc")
        .args(["-pthread", "-fno-omit-frame-pointer", "-Wl,--build-id"])
        .args(flags)
        .arg("-o")
        .arg(output)
        .arg(format!("{PROGRAMS}/{program}.c"))
        .status()
        .expect("running cc");
    assert!(status.success(), "cc failed");
}
