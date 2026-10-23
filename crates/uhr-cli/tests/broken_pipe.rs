//! Agents pipe output into `head` and the like, which stop reading early.
//! The tests use a pipe whose read end is already closed: a closed fd would
//! not do, because Rust reopens closed stdio on /dev/null at startup.

use std::process::{Command, Output, Stdio};

fn closed_pipe() -> Stdio {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    writer.into()
}

fn uhr(args: &[&str], stdout: Stdio, stderr: Stdio) -> Output {
    Command::new(env!("CARGO_BIN_EXE_uhr"))
        .args(args)
        .stdout(stdout)
        .stderr(stderr)
        .output()
        .unwrap()
}

#[test]
fn doctor_keeps_its_exit_code_when_stdout_is_closed() {
    for args in [&["doctor"][..], &["doctor", "--json"]] {
        let normal = uhr(args, Stdio::null(), Stdio::null());
        let closed = uhr(args, closed_pipe(), Stdio::piped());
        assert_eq!(
            closed.status.code(),
            normal.status.code(),
            "{args:?}: {}",
            String::from_utf8_lossy(&closed.stderr)
        );
    }
}
