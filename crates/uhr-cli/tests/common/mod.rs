use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const UHR: &str = env!("CARGO_BIN_EXE_uhr");

const SOURCE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-programs/cpu_bound.c"
);

pub fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

pub fn compile(output: &Path, optimization: &str) {
    let status = Command::new("cc")
        .args([
            optimization,
            "-fno-omit-frame-pointer",
            "-Wl,--build-id",
            "-o",
        ])
        .arg(output)
        .arg(SOURCE)
        .status()
        .expect("running cc");
    assert!(status.success(), "cc failed");
}
