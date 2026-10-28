use serde::{Deserialize, Serialize};

/// Readers reject other versions. Version 0 makes no compatibility promise.
pub const FORMAT_VERSION: u32 = 0;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub format_version: u32,
    pub platform: Platform,
    pub target: Target,
    pub clock: Clock,
    /// When the capture started and stopped: the first and last event from
    /// any collector, or the interrupt that stopped it if that came later.
    pub start_ns: Option<u64>,
    pub end_ns: Option<u64>,
    pub streams: Vec<Stream>,
    /// The signals of collectors that could not run, each with the reason.
    pub missing_signals: Vec<MissingSignal>,
    pub kernel_symbols: KernelSymbols,
}

/// The system the target ran on, which says how to read what was recorded,
/// such as the names of its kernel's functions. As Rust names them: `linux`
/// and `x86_64`, for one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Platform {
    pub os: String,
    pub arch: String,
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
        sampling: Option<Sampling>,
        /// How perf sampled page faults, if it did.
        page_faults: Option<FaultSampling>,
        /// Whether perf recorded every context switch, and the stack of each
        /// thread going off CPU.
        context_switches: bool,
    },
    /// uhr's own eBPF programs.
    Ebpf {
        /// Their tags, in hex. The kernel names a program's code
        /// `bpf_prog_<tag>_<name>`, so its frames can be told apart.
        programs: Vec<String>,
        sampling: Option<Sampling>,
        /// How they sampled page faults, if they did.
        page_faults: Option<FaultSampling>,
    },
    /// uhr reading the processes' files in `/proc`.
    Procfs {
        /// How often it read them.
        interval_ns: u64,
    },
}

impl Collector {
    pub fn sampling(&self) -> Option<&Sampling> {
        match self {
            Collector::Perf { sampling, .. } | Collector::Ebpf { sampling, .. } => {
                sampling.as_ref()
            }
            Collector::Procfs { .. } => None,
        }
    }
}

/// How a collector sampled CPU time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sampling {
    pub event: String,
    /// What it sampled at. perf lowers requests above the kernel's limit.
    pub frequency_hz: u64,
    pub requested_frequency_hz: u64,
}

/// How a collector sampled page faults: one in every `period`, which each
/// sample stands for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaultSampling {
    pub event: String,
    pub period: u64,
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
    /// How often each thread called each syscall, and how long the calls
    /// took.
    #[serde(rename = "syscall_calls")]
    SyscallCalls,
    /// Samples of the page faults threads took, with their stacks.
    #[serde(rename = "page_faults")]
    PageFaults,
    /// How much memory each process had resident and in swap, over time.
    #[serde(rename = "resident_memory")]
    ResidentMemory,
    /// The regions of each process's memory, as it mapped them.
    #[serde(rename = "memory_regions")]
    MemoryRegions,
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
            Signal::SyscallCalls => "syscall_calls",
            Signal::PageFaults => "page_faults",
            Signal::ResidentMemory => "resident_memory",
            Signal::MemoryRegions => "memory_regions",
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
    /// Events the collector dropped.
    pub lost_events: u64,
    /// `None` for a collector that takes no stacks.
    pub stacks: Option<StackCoverage>,
    pub overhead_ns: Option<u64>,
    pub known_biases: Vec<String>,
}

/// The stack counts cover every stack recorded: one per CPU sample, one per
/// page-fault sample, and one per thread going off CPU.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackCoverage {
    pub unwinding: Unwinding,
    /// Bytes of user stack copied with each stack, as the collector used it.
    /// `None` without DWARF unwinding.
    pub stack_copy_bytes: Option<u32>,
    pub samples: u64,
    /// `None` without page faults.
    pub page_fault_samples: Option<u64>,
    /// `None` without context switches.
    pub off_cpu_intervals: Option<u64>,
    /// `None` where the collector does not see them.
    pub throttle_events: Option<u64>,
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
    /// The interpreters whose frames the collector read, by runtime and
    /// version.
    pub interpreters: Vec<InterpreterCoverage>,
}

/// How the frames of one runtime and version were read, over the samples of
/// the processes that ran it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterpreterCoverage {
    pub runtime: String,
    pub version: String,
    pub processes: u64,
    pub samples: u64,
    /// Samples taken before uhr found the runtime, which have none of its
    /// frames.
    pub before_found: u64,
    /// Samples of threads the runtime keeps no state for, such as ones it
    /// does not run on, which have none of its frames.
    pub no_thread: u64,
    /// Samples of threads whose state the collector did not search as far
    /// as, of a process with more threads than it searches, which have none
    /// of its frames.
    pub unsearched: u64,
    /// Samples whose frames could not be read, and those whose frames went
    /// on past the most the collector reads, whose outer frames are missing.
    pub failed: u64,
    pub cut: u64,
    /// Its frames in all samples, and those whose code could not be read.
    pub frames: u64,
    pub unread_frames: u64,
    /// Samples of an interpreter that does not say where its calls start,
    /// with calls whose eval-loop frames the native stack does not show:
    /// frame-pointer stacks lose the caller of a leaf that set up no frame,
    /// often the eval loop. Where those calls' frames go is a guess, just
    /// above the native leaf.
    pub unmatched: u64,
}
