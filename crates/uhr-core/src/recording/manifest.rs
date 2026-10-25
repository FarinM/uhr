use serde::{Deserialize, Serialize};

/// Readers reject other versions. Version 0 makes no compatibility promise.
pub const FORMAT_VERSION: u32 = 0;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub format_version: u32,
    pub target: Target,
    pub clock: Clock,
    /// When the capture started and stopped: the first and last event from
    /// any collector, or the interrupt that stopped it if that came later.
    pub start_ns: Option<u64>,
    pub end_ns: Option<u64>,
    pub streams: Vec<Stream>,
    pub kernel_symbols: KernelSymbols,
}

/// Whether the names of kernel code were saved while recording, the only
/// time they can be read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum KernelSymbols {
    /// The ones kernel frames fall in, in the recording's kernel symbols.
    Saved,
    /// Kernel frames have no names, for this reason.
    Unavailable { reason: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Target {
    pub command: Vec<String>,
    pub launched: bool,
    /// The runtimes whose perf maps were on in the target's environment, so
    /// that they named the code they compiled. `None` for a process uhr
    /// attached to, whose environment it did not see.
    pub runtime_support: Option<Vec<String>>,
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
        /// Bytes of user stack copied with each sample, as perf used it.
        /// `None` without DWARF unwinding.
        stack_copy_bytes: Option<u32>,
        /// Whether perf recorded every context switch, and the stack of each
        /// thread going off CPU.
        context_switches: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unwinding {
    FramePointers,
    /// From each sample's copy of the user stack, with the unwind tables of
    /// the mapped files.
    Dwarf,
}

/// CPU samples are split by mode because a sampler can leave one mode out,
/// and then the time spent in it is missing, not just its frames. Off-CPU
/// time and its stacks are split because the stacks need kernel sampling,
/// which the times do not.
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
    /// When each thread went off CPU and came back, and whether it was
    /// preempted or blocked.
    #[serde(rename = "off_cpu_time")]
    OffCPUTime,
    /// The stack of each thread going off CPU.
    #[serde(rename = "off_cpu_stacks")]
    OffCPUStacks,
}

impl Signal {
    pub fn as_str(self) -> &'static str {
        match self {
            Signal::UserCPUSamples => "user_cpu_samples",
            Signal::KernelCPUSamples => "kernel_cpu_samples",
            Signal::UserStacks => "user_stacks",
            Signal::KernelStacks => "kernel_stacks",
            Signal::OffCPUTime => "off_cpu_time",
            Signal::OffCPUStacks => "off_cpu_stacks",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissingSignal {
    pub signal: Signal,
    pub reason: String,
}

/// Counts are measured; `None` means the value is unknown, never zero. The
/// stack counts cover every stack recorded: one per CPU sample, and one per
/// thread going off CPU.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamCoverage {
    pub samples: u64,
    /// `None` without context switches.
    pub off_cpu_intervals: Option<u64>,
    pub lost_events: u64,
    pub throttle_events: u64,
    /// Stacks longer than this were cut by the kernel.
    pub max_stack_depth: u32,
    pub stacks_at_stack_limit: u64,
    /// Stacks that went on past the end of their stack copy, so their outer
    /// callers are missing. `None` without DWARF unwinding.
    pub stacks_cut_at_stack_copy: Option<u64>,
    /// Stacks of 32-bit code, which DWARF unwinding cannot walk. They keep
    /// only the instruction they were taken at. `None` without DWARF
    /// unwinding.
    pub stacks_not_unwound: Option<u64>,
    pub overhead_ns: Option<u64>,
    pub known_biases: Vec<String>,
}
