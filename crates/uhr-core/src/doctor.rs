//! What a host needs to record, and how to fix what it lacks. Each
//! platform's collectors check their own needs.

use serde::Serialize;

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
