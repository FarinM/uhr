//! Builds uhr's eBPF programs for the BPF target with nightly Rust and
//! bpf-linker, when they are installed. Without them uhr builds without the
//! programs, and says so when asked to use them.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }
    println!("cargo::rustc-check-cfg=cfg(uhr_ebpf)");
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR");
    let source = Path::new(&manifest_dir).join("../uhr-ebpf");
    println!("cargo::rerun-if-changed={}", source.display());
    println!("cargo::rerun-if-changed=../../Cargo.lock");
    println!("cargo::rerun-if-env-changed=PATH");
    if let Err(missing) = toolchain() {
        println!("cargo::warning=building uhr without its eBPF programs: {missing}");
        return;
    }
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("cargo sets the target's arch");
    let target_dir = out.join("ebpf");
    let status = Command::new("rustup")
        .args(["run", "nightly", "cargo", "build", "--manifest-path"])
        .arg(source.join("Cargo.toml"))
        .args([
            "--bin",
            "uhr-ebpf",
            "--release",
            "--target",
            "bpfel-unknown-none",
        ])
        .args(["-Z", "build-std=core", "--target-dir"])
        .arg(&target_dir)
        .env(
            "CARGO_ENCODED_RUSTFLAGS",
            format!("--cfg=bpf_target_arch=\"{arch}\"\x1f-Cdebuginfo=2\x1f-Clink-arg=--btf"),
        )
        // Set for this build script, they would pick the stable compiler.
        .env_remove("RUSTC")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env_remove("RUSTUP_TOOLCHAIN")
        .status()
        .expect("running cargo for the eBPF programs");
    assert!(status.success(), "building the eBPF programs failed");
    let built = target_dir.join("bpfel-unknown-none/release/uhr-ebpf");
    fs::copy(&built, out.join("uhr-ebpf")).expect("copying the eBPF programs");
    println!("cargo::rustc-cfg=uhr_ebpf");
}

/// What of the toolchain for the BPF target is missing, if anything.
fn toolchain() -> Result<(), String> {
    let on_path = |name: &str| {
        env::var_os("PATH")
            .is_some_and(|path| env::split_paths(&path).any(|dir| dir.join(name).is_file()))
    };
    if !on_path("bpf-linker") {
        return Err("bpf-linker is not on PATH".into());
    }
    let sysroot = Command::new("rustup")
        .args(["run", "nightly", "rustc", "--print", "sysroot"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .ok_or("no nightly Rust through rustup")?;
    let sysroot = String::from_utf8_lossy(&sysroot.stdout);
    if !Path::new(sysroot.trim())
        .join("lib/rustlib/src/rust/library")
        .is_dir()
    {
        return Err("nightly Rust has no rust-src".into());
    }
    Ok(())
}
