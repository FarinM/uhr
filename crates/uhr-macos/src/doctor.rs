//! What this Mac lets uhr's sampler record, and how to fix what it lacks.

use std::env;
use std::fs;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use uhr_core::doctor::{Check, Report, Status};

use crate::launch::{self, Service};
use crate::macho;

/// How long uhr's own executable has to say hello.
const PATIENCE: Duration = Duration::from_secs(10);

pub fn check() -> Report {
    Report {
        checks: vec![
            check_launch(),
            check_attach(),
            Check {
                status: Status::Limited,
                detail: "macOS lets no process read the kernel's stacks, but through xctrace or \
                         private interfaces, so time in the kernel shows under the user stack \
                         that entered it"
                    .into(),
                fix: None,
            },
            Check {
                status: Status::Limited,
                detail: "macOS does not let uhr see when threads are woken, count syscalls, \
                         sample page faults, or read the regions of a process's memory, so \
                         recordings have none of them"
                    .into(),
                fix: None,
            },
        ],
        notes: vec![
            "dyld leaves uhr's library out of programs System Integrity Protection protects, \
             as those in /usr/bin, and out of all they run, as scripts that start with \
             `#!/usr/bin/env`, so record your own builds, or Homebrew's. It also leaves it out \
             of programs signed for the hardened runtime, as most apps are, unless they allow \
             it: sign a build again without it, with `codesign -s - -f <program>`."
                .into(),
        ],
    }
}

/// Launches uhr's own executable as a target, which needs only what any
/// launch does: dyld loading uhr's library, and the library sending its
/// task port.
fn check_launch() -> Check {
    match launch_self() {
        Ok(()) => Check {
            status: Status::Ok,
            detail: "uhr launches programs with its library, which hands it their task ports, \
                     without root"
                .into(),
            fix: None,
        },
        Err(reason) => Check {
            status: Status::Blocked,
            detail: format!("uhr could not launch a program to record: {reason}"),
            fix: None,
        },
    }
}

fn launch_self() -> Result<(), String> {
    let program = env::current_exe().map_err(|e| format!("finding uhr's executable: {e}"))?;
    let service = Service::register().map_err(|e| error_chain(&e))?;
    let environment = launch::environment(&service).map_err(|e| error_chain(&e))?;
    let mut child = Command::new(&program)
        .arg("--version")
        .envs(environment)
        .stdout(Stdio::null())
        .spawn()
        .map_err(|e| format!("starting {}: {e}", program.display()))?;
    let started = Instant::now();
    let result = loop {
        match service.receive(10) {
            Ok(Some(hello)) if hello.pid == child.id() => break Ok(()),
            Ok(_) => {}
            Err(error) => break Err(format!("receiving its task port: {error}")),
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                break Err(format!(
                    "{} exited with {status} without loading uhr's library",
                    program.display()
                ));
            }
            Ok(None) if started.elapsed() > PATIENCE => {
                break Err(format!(
                    "{} did not load uhr's library within {} s",
                    program.display(),
                    PATIENCE.as_secs()
                ));
            }
            Ok(None) => thread::sleep(Duration::from_millis(1)),
            Err(error) => break Err(format!("waiting for {}: {error}", program.display())),
        }
    };
    // An answered hello, or none, lets it run on and exit.
    if result.is_err() {
        let _ = child.kill();
    }
    let _ = child.wait();
    result
}

/// Attaching needs another process's task port, which macOS gives to root
/// and to programs signed with the debugger entitlement.
fn check_attach() -> Check {
    // SAFETY: geteuid has no preconditions.
    let root = unsafe { libc::geteuid() } == 0;
    let entitled = env::current_exe()
        .ok()
        .and_then(|path| fs::read(path).ok())
        .and_then(|bytes| macho::signing(&bytes))
        .is_some_and(|signing| signing.debugger);
    if root || entitled {
        let who = if root {
            "uhr runs as root"
        } else {
            "uhr is signed with the debugger entitlement"
        };
        return Check {
            status: Status::Ok,
            detail: format!(
                "{who}, so it can attach with --pid to processes that System Integrity \
                 Protection and the hardened runtime do not protect"
            ),
            fix: None,
        };
    }
    Check {
        status: Status::Limited,
        detail: "uhr can't attach with --pid: macOS gives another process's task port only to \
                 root, or to a program signed with the com.apple.security.cs.debugger \
                 entitlement"
            .into(),
        fix: Some("Run `sudo uhr record --pid <pid>`, or launch the program with uhr.".into()),
    }
}

fn error_chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(&format!(": {cause}"));
        source = cause.source();
    }
    text
}
