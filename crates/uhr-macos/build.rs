//! Builds the library uhr has dyld load into the programs it launches on
//! macOS, with the C compiler that builds for the target.

use std::env;
use std::path::PathBuf;

fn main() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    let source = "src/preload.c";
    println!("cargo::rerun-if-changed={source}");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"))
        .join("libuhr_preload.dylib");
    let compiler = cc::Build::new().opt_level(2).get_compiler();
    let status = compiler
        .to_command()
        .args(["-shared", "-Wall", "-Werror", "-o"])
        .arg(&out)
        .arg(source)
        .status()
        .expect("running the C compiler for the preload library");
    assert!(status.success(), "building the preload library failed");
}
