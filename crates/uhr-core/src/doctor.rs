use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::process::Command;

use linux_perf_data::{PerfFileReader, linux_perf_event_reader::AttrFlags};
use serde::Serialize;

use crate::perf::{RecordOptions, Unwind, perf_args};

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub checks: Vec<Check>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub status: Status,
    pub detail: String,
    pub fix: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    /// Recording works, but a signal will be missing.
    Limited,
    /// Recording cannot run.
    Blocked,
}

impl Report {
    pub fn blocked(&self) -> impl Iterator<Item = &Check> {
        self.checks.iter().filter(|c| c.status == Status::Blocked)
    }
}

/// What CPU sampling with perf needs on this host.
pub fn check_perf() -> Report {
    let mut checks = vec![check_perf_binary()];
    if checks[0].status != Status::Blocked {
        checks.push(check_recording());
        checks.push(check_dwarf_unwinding());
    }
    Report {
        checks,
        notes: vec![
            "By default, user stacks are unwound with frame pointers. Build with \
             -fno-omit-frame-pointer (C, C++) or -C force-frame-pointers=yes (Rust). \
             GCC still leaves them out of leaf functions that don't use the stack, \
             so stacks skip the caller of those functions. `uhr record --unwind dwarf` \
             needs no rebuild and finds those callers, at the cost of a stack copy in \
             every sample."
                .into(),
        ],
    }
}

/// What `uhr record --unwind dwarf` needs beyond frame-pointer sampling.
pub fn check_dwarf_unwinding() -> Check {
    if std::env::consts::ARCH != "x86_64" {
        return Check {
            status: Status::Limited,
            detail: "DWARF unwinding (--unwind dwarf) is only implemented for x86-64".into(),
            fix: Some("Record with frame pointers, the default.".into()),
        };
    }
    match perf_has_zstd() {
        Ok(true) => Check {
            status: Status::Ok,
            detail: "perf can compress the stack copies that --unwind dwarf records".into(),
            fix: None,
        },
        Ok(false) => Check {
            status: Status::Limited,
            detail: "perf was built without zstd, so --unwind dwarf would write every stack \
                     copy uncompressed"
                .into(),
            fix: Some("Use a perf built with zstd, or record with frame pointers.".into()),
        },
        Err(detail) => Check {
            status: Status::Limited,
            detail,
            fix: None,
        },
    }
}

fn perf_has_zstd() -> Result<bool, String> {
    let output = Command::new("perf")
        .args(["version", "--build-options"])
        .output()
        .map_err(|e| format!("cannot run perf: {e}"))?;
    let options = String::from_utf8_lossy(&output.stdout);
    Ok(options.lines().any(|line| {
        let line = line.trim_start();
        line.starts_with("zstd:") && line.contains("[ on")
    }))
}

/// Runs `perf --version`, which also catches the Debian and Ubuntu wrapper
/// that exists but has no perf build for the running kernel.
pub fn perf_version() -> Result<String, String> {
    let output = Command::new("perf")
        .arg("--version")
        .output()
        .map_err(|e| format!("cannot run perf: {e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let first = stderr
            .lines()
            .chain(stdout.lines())
            .find(|l| !l.trim().is_empty());
        return Err(format!(
            "perf --version failed ({}): {}",
            output.status,
            first.unwrap_or("no output")
        ));
    }
    let version = stdout.trim().trim_start_matches("perf version ").to_owned();
    Ok(version)
}

fn check_perf_binary() -> Check {
    match perf_version() {
        Ok(version) => Check {
            status: Status::Ok,
            detail: format!("perf {version}"),
            fix: None,
        },
        Err(detail) => Check {
            status: Status::Blocked,
            detail,
            fix: Some(
                "Install perf for the running kernel: `sudo apt install linux-tools-$(uname -r)` \
                 on Debian and Ubuntu, `sudo dnf install perf` on Fedora."
                    .into(),
            ),
        },
    }
}

/// Run the actual backend: file capabilities and container restrictions can
/// give perf different permissions from this process.
fn check_recording() -> Check {
    match probe_recording(Path::new("perf")) {
        Ok(false) => Check {
            status: Status::Ok,
            detail: "perf can record user and kernel CPU samples and stacks".into(),
            fix: None,
        },
        Ok(true) => Check {
            status: Status::Limited,
            detail: "perf can record user CPU samples and stacks; kernel CPU samples and stacks are excluded".into(),
            fix: Some("Allow kernel sampling through the perf executable's capabilities or the host's perf_event_paranoid setting.".into()),
        },
        Err(detail) => Check {
            status: Status::Blocked,
            detail,
            fix: Some("Check perf's diagnostic above. For permission errors, configure access for the perf executable; container restrictions and perf_event_paranoid can also block it.".into()),
        },
    }
}

fn probe_recording(perf: &Path) -> Result<bool, String> {
    let dir = tempfile::tempdir().map_err(|e| format!("creating perf probe directory: {e}"))?;
    let data = dir.path().join("perf.data");
    let options = RecordOptions {
        command: vec!["true".into()],
        frequency_hz: 1,
        unwind: Unwind::FramePointers,
    };
    let mut args = perf_args(&data, &options);
    // Permission errors from perf are suppressed by --quiet.
    args.retain(|arg| arg != "--quiet");
    let output = Command::new(perf)
        .args(args)
        .output()
        .map_err(|e| format!("cannot run perf recording probe: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "perf recording probe failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let file = File::open(&data).map_err(|e| format!("opening perf probe: {e}"))?;
    let reader = PerfFileReader::parse_file(BufReader::new(file))
        .map_err(|e| format!("reading perf probe: {e}"))?;
    let [event] = reader.perf_file.event_attributes() else {
        return Err("perf probe did not record the requested event".into());
    };
    Ok(event.attributes().flags.contains(AttrFlags::EXCLUDE_KERNEL))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn reports_the_backends_actual_failure() {
        let dir = tempfile::tempdir().unwrap();
        let perf = dir.path().join("perf");
        std::fs::write(
            &perf,
            "#!/bin/sh\necho 'perf_event_open blocked by container' >&2\nexit 1\n",
        )
        .unwrap();
        std::fs::set_permissions(&perf, std::fs::Permissions::from_mode(0o700)).unwrap();
        let error = probe_recording(&perf).unwrap_err();
        assert!(
            error.contains("perf_event_open blocked by container"),
            "{error}"
        );
    }
}
