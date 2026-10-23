use std::fs;
use std::process::Command;

use serde::Serialize;

const CAP_SYS_ADMIN: u32 = 21;
const CAP_PERFMON: u32 = 38;

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
    checks.extend(check_paranoid());
    Report {
        checks,
        notes: vec![
            "User stacks are unwound with frame pointers. Build with \
             -fno-omit-frame-pointer (C, C++) or -C force-frame-pointers=yes (Rust). \
             GCC still leaves them out of leaf functions that don't use the stack, \
             so stacks skip the caller of those functions."
                .into(),
        ],
    }
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

fn check_paranoid() -> Vec<Check> {
    if privileged() {
        return vec![Check {
            status: Status::Ok,
            detail: "running with root or CAP_PERFMON: user and kernel stacks can be sampled"
                .into(),
            fix: None,
        }];
    }
    let paranoid = match read_sysctl("kernel/perf_event_paranoid") {
        Ok(value) => value,
        Err(detail) => {
            return vec![Check {
                status: Status::Blocked,
                detail,
                fix: None,
            }];
        }
    };
    let persist = "Add the setting to a file in /etc/sysctl.d to keep it after a reboot.";
    if paranoid >= 3 {
        return vec![Check {
            status: Status::Blocked,
            detail: format!(
                "perf_event_paranoid is {paranoid}: this kernel blocks perf for unprivileged users"
            ),
            fix: Some(format!(
                "`sudo sysctl kernel.perf_event_paranoid=1` allows user and kernel stacks, \
                 2 allows user stacks only. {persist}"
            )),
        }];
    }
    if paranoid == 2 {
        return vec![Check {
            status: Status::Limited,
            detail: "perf_event_paranoid is 2: kernel frames will not be captured".into(),
            fix: Some(format!(
                "`sudo sysctl kernel.perf_event_paranoid=1` allows kernel stacks. {persist}"
            )),
        }];
    }
    vec![Check {
        status: Status::Ok,
        detail: format!("perf_event_paranoid is {paranoid}: user and kernel stacks can be sampled"),
        fix: None,
    }]
}

fn privileged() -> bool {
    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        return false;
    };
    let field = |name: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .map(str::trim)
            .map(str::to_owned)
    };
    let root = field("Uid:")
        .and_then(|uids| uids.split_whitespace().nth(1).map(|euid| euid == "0"))
        .unwrap_or(false);
    let capabilities = field("CapEff:")
        .and_then(|hex| u64::from_str_radix(&hex, 16).ok())
        .unwrap_or(0);
    let has = |cap: u32| capabilities & (1 << cap) != 0;
    root || has(CAP_PERFMON) || has(CAP_SYS_ADMIN)
}

fn read_sysctl(name: &str) -> Result<i32, String> {
    let path = format!("/proc/sys/{name}");
    let text = fs::read_to_string(&path).map_err(|e| format!("cannot read {path}: {e}"))?;
    text.trim()
        .parse()
        .map_err(|_| format!("{path} is not a number: {:?}", text.trim()))
}
