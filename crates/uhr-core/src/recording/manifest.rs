use serde::{Deserialize, Serialize};

/// Readers reject other versions. Version 0 makes no compatibility promise.
pub const FORMAT_VERSION: u32 = 0;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub format_version: u32,
    pub target: Target,
    pub clock: Clock,
    /// First and last timestamp seen from any collector.
    pub start_ns: Option<u64>,
    pub end_ns: Option<u64>,
    pub streams: Vec<Stream>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Target {
    pub command: Vec<String>,
    pub launched: bool,
    /// `None` if the target was still running when the recording stopped.
    pub exit: Option<Exit>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Exit {
    Code(i32),
    Signal(i32),
    /// The status that was observed says nothing reliable about the target,
    /// for the reason given.
    Unknown(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Clock {
    #[serde(rename = "CLOCK_MONOTONIC")]
    Monotonic,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Stream {
    pub id: String,
    pub collector: Collector,
    /// What was captured, not what was requested. The gap is in `missing_signals`.
    pub signals: Vec<Signal>,
    pub missing_signals: Vec<MissingSignal>,
    pub coverage: StreamCoverage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "name", rename_all = "snake_case")]
pub enum Collector {
    Perf {
        version: String,
        event: String,
        /// What perf sampled at. perf lowers requests above the kernel's limit.
        frequency_hz: u64,
        requested_frequency_hz: u64,
        unwinding: Unwinding,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unwinding {
    FramePointers,
}

/// CPU samples are split by mode because a sampler can leave one mode out,
/// and then the time spent in it is missing, not just its frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Signal {
    #[serde(rename = "user_cpu_samples")]
    UserCPUSamples,
    #[serde(rename = "kernel_cpu_samples")]
    KernelCPUSamples,
    #[serde(rename = "user_stacks")]
    UserStacks,
    #[serde(rename = "kernel_stacks")]
    KernelStacks,
}

impl Signal {
    pub fn as_str(self) -> &'static str {
        match self {
            Signal::UserCPUSamples => "user_cpu_samples",
            Signal::KernelCPUSamples => "kernel_cpu_samples",
            Signal::UserStacks => "user_stacks",
            Signal::KernelStacks => "kernel_stacks",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissingSignal {
    pub signal: Signal,
    pub reason: String,
}

/// Counts are measured; `None` means the value is unknown, never zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamCoverage {
    pub samples: u64,
    pub lost_events: u64,
    pub throttle_events: u64,
    /// Stacks longer than this were cut by the kernel.
    pub max_stack_depth: u32,
    pub samples_at_stack_limit: u64,
    pub overhead_ns: Option<u64>,
    pub known_biases: Vec<String>,
}
