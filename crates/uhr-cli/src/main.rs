#[cfg(target_os = "linux")]
mod signals;

use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
#[cfg(target_os = "linux")]
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::LevelFilter;
use uhr_core::call_paths;
use uhr_core::doctor::Report;
#[cfg(not(target_os = "linux"))]
use uhr_core::doctor::{Check, Status};
use uhr_core::export;
use uhr_core::filter::Filter;
use uhr_core::flamegraph;
use uhr_core::metric::Metric;
use uhr_core::overview;
use uhr_core::query::{self, GroupBy, Query};
use uhr_core::recording::{Mode, RegionKind, read_manifest};
use uhr_core::symbols;
use uhr_core::text;
use uhr_core::wall_clock::{self, Time};

#[cfg(target_os = "linux")]
use signals::{Handlers, INTERRUPTS};
#[cfg(target_os = "linux")]
use uhr_linux::perf::{self, RecordOptions, Sampler, Target, Unwind};

#[derive(Parser)]
#[command(
    version,
    about = "Agent-first profiling toolkit",
    after_help = "Logs go to stderr. Set UHR_LOG to change what is logged, for example UHR_LOG=debug."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check what recording needs on this host, and how to fix what is missing
    Doctor {
        #[arg(long)]
        json: bool,
    },
    /// Record a command, or a running process, with perf and write a
    /// recording
    Record(RecordArgs),
    /// Resolve function names in a recording against the files on this machine
    Symbolize { recording: PathBuf },
    /// Export a recording for interactive exploration in Firefox Profiler
    Export {
        recording: PathBuf,
        /// Viewer format
        #[arg(long, value_enum, default_value_t = ExportFormat::Firefox)]
        format: ExportFormat,
        /// New file to write; an existing file is not overwritten
        #[arg(short, long)]
        output: PathBuf,
        /// Print the export summary and coverage as JSON
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        filter: FilterArgs,
    },
    /// Show CPU time by mode and time off CPU, by process and thread, against
    /// time alive: is it computing or waiting? And how much memory each
    /// process had
    Overview {
        recording: PathBuf,
        /// Processes and threads to print, by CPU time, and processes by
        /// memory
        #[arg(long, default_value_t = 20)]
        top: usize,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        filter: FilterArgs,
    },
    /// Group a recording's CPU time, off-CPU time or page faults and print
    /// the top rows, with coverage
    Query {
        recording: PathBuf,
        #[arg(long, value_enum)]
        group_by: GroupByArg,
        /// What to weigh stacks by
        #[arg(long, value_enum, default_value_t = MetricArg::Cpu)]
        metric: MetricArg,
        /// Rows to print
        #[arg(long, default_value_t = 20)]
        top: usize,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        filter: FilterArgs,
    },
    /// Draw a flame graph of a recording's CPU time, off-CPU time or page
    /// faults, as an SVG to open in a browser
    Flamegraph {
        recording: PathBuf,
        /// The file to write
        #[arg(short, long)]
        output: PathBuf,
        /// What to weigh stacks by
        #[arg(long, value_enum, default_value_t = MetricArg::Cpu)]
        metric: MetricArg,
        /// Start the graph at a function, by id or by a name only one function
        /// has. Stacks without it are left out
        #[arg(long, value_name = "FUNCTION")]
        root: Option<String>,
        /// Write folded stacks, one per line, as other flame graph tools read
        /// them, instead of an SVG
        #[arg(long)]
        folded: bool,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        filter: FilterArgs,
    },
    /// Show who calls a function and what it calls, with their CPU time,
    /// off-CPU time or page faults
    CallPaths {
        recording: PathBuf,
        /// A function id from `uhr query --json`, or a name only one function
        /// has
        #[arg(long)]
        function: String,
        /// What to weigh stacks by
        #[arg(long, value_enum, default_value_t = MetricArg::Cpu)]
        metric: MetricArg,
        /// Levels of callers and of callees to show
        #[arg(
            long,
            default_value_t = 3,
            value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..)
        )]
        depth: usize,
        /// Children to show per node. The rest are summed
        #[arg(long, default_value_t = 5)]
        top: usize,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        filter: FilterArgs,
    },
}

#[derive(Args)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct RecordArgs {
    /// Directory for the recording. Must not exist
    #[arg(short, long)]
    output: PathBuf,
    /// Samples per second
    #[arg(short = 'F', long, default_value_t = 999, value_parser = clap::value_parser!(u64).range(1..))]
    frequency: u64,
    /// Skip resolving function names. Run `uhr symbolize` later
    #[arg(long)]
    no_symbolize: bool,
    /// How to walk user stacks. `dwarf` needs no frame pointers and finds
    /// callers that frame pointers miss, but copies part of the stack
    /// with every sample
    #[arg(long, value_enum, default_value_t = UnwindArg::Fp)]
    unwind: UnwindArg,
    /// Bytes of user stack to copy with each sample, for `--unwind
    /// dwarf`, a multiple of 8. Deeper stacks lose their outer callers
    /// [default: 32768]
    #[arg(long, value_name = "BYTES", value_parser = parse_stack_size)]
    stack_size: Option<u32>,
    /// Don't record context switches. Saves their cost in programs that
    /// switch often, but then nothing says why threads were off CPU
    #[arg(long)]
    no_off_cpu: bool,
    /// Don't see when each thread that slept was woken, and what woke it,
    /// which takes a stack at each wakeup. uhr's eBPF programs see wakeups
    /// when they sample
    #[arg(long)]
    no_wakeups: bool,
    /// Don't set the variables that make runtimes, such as Python 3.12
    /// and later and Node, name the code they compile, and glibc the
    /// memory it maps. That costs them a little time, and without it
    /// their functions, and glibc's memory, have no names
    #[arg(long, conflicts_with = "pid")]
    no_runtime_support: bool,
    /// Don't count and time the target's syscalls. uhr does that with its
    /// eBPF programs when it may load them: as root, or with CAP_BPF and
    /// CAP_PERFMON
    #[arg(long)]
    no_syscalls: bool,
    /// Don't count or time the calls of this syscall, as one the target
    /// makes so often that counting them slows it. They still run part of
    /// the counting, and their time still shows in the stacks. Can be
    /// given more than once
    #[arg(long, value_name = "NAME", conflicts_with = "no_syscalls")]
    skip_syscall: Vec<String>,
    /// Don't read how much memory the target's processes have, which uhr
    /// does from /proc every 100 ms
    #[arg(long)]
    no_memory: bool,
    /// Don't sample the page faults the target's threads take, which show
    /// the code that first touched memory. The sampler of CPU time samples
    /// one in every 64, or fewer with stack copies
    #[arg(long)]
    no_page_faults: bool,
    /// What samples CPU time. By default uhr's eBPF programs do, when uhr
    /// may load them, and perf does otherwise
    #[arg(long, value_enum)]
    sampler: Option<SamplerArg>,
    /// Record this running process, and the threads and processes it
    /// starts, rather than a command. It is not signalled
    #[arg(long, conflicts_with = "command")]
    pid: Option<u32>,
    /// With --pid, stop after this long, such as 10s or 500ms, rather
    /// than at Ctrl-C or when the process exits
    #[arg(long, value_name = "DURATION", requires = "pid", value_parser = parse_offset)]
    duration: Option<u64>,
    /// Command to profile, after `--`
    #[arg(required_unless_present = "pid", last = true)]
    command: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum SamplerArg {
    Perf,
    /// uhr's eBPF programs, at each tick of every CPU's clock
    Ebpf,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum UnwindArg {
    /// Frame pointers
    Fp,
    /// DWARF unwind tables, from a copy of each sample's stack
    Dwarf,
}

/// Covers most C, C++ and Rust stacks, including deep async ones, at half
/// the cost of perf's maximum.
#[cfg(target_os = "linux")]
const STACK_COPY_BYTES: u32 = 32 * 1024;

#[derive(Clone, Copy, ValueEnum)]
enum GroupByArg {
    Function,
    /// Function and source line, from debug info
    Line,
    /// Binary or library, or the kernel or one of its modules: self time
    /// runs its code, total time has it anywhere on the stack
    Module,
    /// The syscall a thread was in, from the kernel functions on its stack
    Syscall,
    /// The region of memory a page fault was in, as the heap or a file, with
    /// --metric page-faults
    Region,
    /// The thread or interrupt that woke each thread that blocked, with
    /// --metric off-cpu. Filters pick the waits, not the wakers
    Waker,
    /// The functions on the stacks of those wakeups: the kernel's from
    /// try_to_wake_up, then the waking thread's
    WakerFunction,
}

#[derive(Clone, Copy, ValueEnum)]
enum MetricArg {
    /// CPU time, from CPU samples
    Cpu,
    /// Time threads spent off CPU, runnable or blocked, from context switches
    OffCpu,
    /// Both, all the time threads were alive
    Wall,
    /// Page faults, from samples of them: the code that first touched
    /// memory
    PageFaults,
}

impl From<MetricArg> for Metric {
    fn from(metric: MetricArg) -> Self {
        match metric {
            MetricArg::Cpu => Metric::OnCPU,
            MetricArg::OffCpu => Metric::OffCPU,
            MetricArg::Wall => Metric::Wall,
            MetricArg::PageFaults => Metric::PageFaults,
        }
    }
}

#[derive(Args)]
#[command(next_help_heading = "Filters (repeat a flag to allow several values)")]
struct FilterArgs {
    /// Only samples of this process
    #[arg(long = "pid", value_name = "PID")]
    pids: Vec<u32>,
    /// Only samples of this thread id
    #[arg(long = "tid", value_name = "TID")]
    tids: Vec<u32>,
    /// Only samples taken while the thread's name matched. `*` matches any
    /// characters, `?` one character
    #[arg(long = "thread", value_name = "PATTERN")]
    thread_names: Vec<String>,
    /// Only samples in this CPU mode
    #[arg(long = "mode", value_name = "MODE", value_enum)]
    modes: Vec<ModeArg>,
    /// Only samples whose stack contains this function, by id or by a name
    /// only one function has
    #[arg(long = "under", value_name = "FUNCTION")]
    under: Vec<String>,
    /// Only samples in this syscall, by name, as in read
    #[arg(long = "syscall", value_name = "NAME")]
    syscalls: Vec<String>,
    /// Only page faults in this kind of memory region; excludes CPU samples
    /// and off-CPU intervals
    #[arg(long = "region", value_name = "KIND", value_enum)]
    regions: Vec<RegionArg>,
    /// Only samples from this time on: an offset into the recording, such
    /// as 1.5s or 200ms, or a time of day with a date and a UTC offset, such
    /// as 2026-11-06T12:34:56.7Z
    #[arg(long, value_name = "TIME", value_parser = parse_time)]
    from: Option<Time>,
    /// Only samples before this time, given as for --from
    #[arg(long, value_name = "TIME", value_parser = parse_time)]
    to: Option<Time>,
}

#[derive(Clone, Copy, ValueEnum)]
enum ModeArg {
    User,
    Kernel,
    Unknown,
}

#[derive(Clone, Copy, ValueEnum)]
enum ExportFormat {
    Firefox,
}

#[derive(Clone, Copy, ValueEnum)]
enum RegionArg {
    /// Grown with brk, where malloc starts
    Heap,
    /// The main thread's
    Stack,
    /// The process's own memory that maps no file, as large allocations,
    /// garbage-collected heaps and other threads' stacks
    Anonymous,
    /// Anonymous memory that runs code, as a JIT's
    AnonymousCode,
    /// Shared with other processes
    Shared,
    /// A file's code
    Code,
    /// The rest of a file mapped
    File,
    /// Mapped by the kernel into every process
    Kernel,
}

impl From<RegionArg> for RegionKind {
    fn from(region: RegionArg) -> Self {
        match region {
            RegionArg::Heap => RegionKind::Heap,
            RegionArg::Stack => RegionKind::Stack,
            RegionArg::Anonymous => RegionKind::Anonymous,
            RegionArg::AnonymousCode => RegionKind::AnonymousCode,
            RegionArg::Shared => RegionKind::Shared,
            RegionArg::Code => RegionKind::Code,
            RegionArg::File => RegionKind::File,
            RegionArg::Kernel => RegionKind::Kernel,
        }
    }
}

impl FilterArgs {
    /// Reads the manifest of `recording` for the times of day of `--from`
    /// and `--to`.
    fn into_filter(self, recording: &Path) -> Result<Filter> {
        let (from_ns, to_ns) = match (self.from, self.to) {
            (None, None) => (None, None),
            (from, to) => wall_clock::offsets(&read_manifest(recording)?, from, to)?,
        };
        Ok(Filter {
            pids: self.pids,
            tids: self.tids,
            thread_names: self.thread_names,
            modes: self
                .modes
                .into_iter()
                .map(|mode| match mode {
                    ModeArg::User => Mode::User,
                    ModeArg::Kernel => Mode::Kernel,
                    ModeArg::Unknown => Mode::Unknown,
                })
                .collect(),
            under: self.under,
            syscalls: self.syscalls,
            regions: self.regions.into_iter().map(RegionKind::from).collect(),
            from_ns,
            to_ns,
        })
    }
}

/// An offset, or a time of day where it has the shape of one.
fn parse_time(text: &str) -> Result<Time, String> {
    if text.contains([':', 'T']) || text.get(4..5) == Some("-") {
        wall_clock::parse(text)
            .map(Time::Utc)
            .map_err(|e| e.to_string())
    } else {
        parse_offset(text).map(Time::Offset)
    }
}

/// A duration with a unit, in nanoseconds.
fn parse_offset(text: &str) -> Result<u64, String> {
    let units = [("ns", 1.0), ("us", 1e3), ("ms", 1e6), ("s", 1e9)];
    let Some((number, scale)) = units
        .iter()
        .find_map(|&(unit, scale)| text.strip_suffix(unit).map(|n| (n, scale)))
    else {
        return Err("needs a unit: ns, us, ms or s, as in 1.5s".into());
    };
    match number.parse::<f64>() {
        Ok(value) if value.is_finite() && value >= 0.0 => Ok((value * scale).round() as u64),
        _ => Err(format!("{number:?} is not a non-negative number")),
    }
}

/// In whole words, as stacks are unwound, up to perf's limit.
fn parse_stack_size(text: &str) -> Result<u32, String> {
    match text.parse::<u32>() {
        Ok(bytes) if (8..=65528).contains(&bytes) && bytes % 8 == 0 => Ok(bytes),
        _ => Err("must be a multiple of 8 from 8 to 65528".into()),
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging();
    let result = match cli.command {
        Command::Doctor { json } => run_doctor(json),
        Command::Record(args) => run_record(args),
        Command::Symbolize { recording } => run_symbolize(&recording),
        Command::Overview {
            recording,
            top,
            json,
            filter,
        } => run_overview(&recording, top, filter, json),
        Command::Query {
            recording,
            group_by,
            metric,
            top,
            filter,
            json,
        } => run_query(&recording, group_by, metric.into(), top, filter, json),
        Command::Flamegraph {
            recording,
            output,
            metric,
            root,
            folded,
            json,
            filter,
        } => run_flamegraph(
            &recording,
            &output,
            metric.into(),
            root,
            filter,
            folded,
            json,
        ),
        Command::Export {
            recording,
            output,
            format,
            json,
            filter,
        } => run_export(&recording, &output, format, filter, json),
        Command::CallPaths {
            recording,
            function,
            metric,
            depth,
            top,
            json,
            filter,
        } => run_call_paths(
            &recording,
            function,
            metric.into(),
            depth,
            top,
            filter,
            json,
        ),
    };
    result.unwrap_or_else(|error| {
        tracing::error!("{error:#}");
        ExitCode::FAILURE
    })
}

fn init_logging() {
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .with_env_var("UHR_LOG")
        .from_env_lossy();
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .with_target(false)
        .without_time()
        // Its fallback for a failed write is eprintln!, which panics when
        // stderr is a closed pipe.
        .log_internal_errors(false)
        .init();
}

/// Writes a command's result to stdout. A reader that stops early, as `head`
/// does, is not an error, so the command keeps the exit code it already has.
fn write_output(write: impl FnOnce(&mut io::StdoutLock) -> io::Result<()>) -> Result<()> {
    let mut stdout = io::stdout().lock();
    match write(&mut stdout).and_then(|()| stdout.flush()) {
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        result => result.context("writing to stdout"),
    }
}

fn run_doctor(json: bool) -> Result<ExitCode> {
    let report = host_report();
    if json {
        let text = serde_json::to_string_pretty(&report)?;
        write_output(|out| writeln!(out, "{text}"))?;
    } else {
        write_output(|out| text::write_report(out, &report))?;
    }
    Ok(if report.blocked().next().is_some() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

#[cfg(target_os = "linux")]
fn host_report() -> Report {
    uhr_linux::doctor::check()
}

#[cfg(not(target_os = "linux"))]
fn host_report() -> Report {
    Report {
        checks: vec![Check {
            status: Status::Blocked,
            detail: format!(
                "uhr records on Linux only, so far, not on {}",
                std::env::consts::OS
            ),
            fix: None,
        }],
        notes: Vec::new(),
    }
}

#[cfg(target_os = "linux")]
fn run_record(args: RecordArgs) -> Result<ExitCode> {
    let unwind = match (args.unwind, args.stack_size) {
        (UnwindArg::Fp, None) => Unwind::FramePointers,
        (UnwindArg::Fp, Some(_)) => bail!("--stack-size only applies to --unwind dwarf"),
        (UnwindArg::Dwarf, stack_size) => Unwind::Dwarf {
            stack_bytes: stack_size.unwrap_or(STACK_COPY_BYTES),
        },
    };
    let target = match args.pid {
        Some(pid) => Target::Attach {
            pid,
            duration: args.duration.map(Duration::from_nanos),
        },
        None => Target::Launch(args.command),
    };
    let skipped_syscalls = args
        .skip_syscall
        .iter()
        .map(|name| {
            name.parse()
                .map_err(|()| anyhow::anyhow!("no syscall is named {name:?} on this system"))
        })
        .collect::<Result<_>>()?;
    let options = RecordOptions {
        target,
        frequency_hz: args.frequency,
        unwind,
        off_cpu: !args.no_off_cpu,
        wakeups: !args.no_wakeups,
        runtime_support: !args.no_runtime_support,
        syscalls: !args.no_syscalls,
        skipped_syscalls,
        memory: !args.no_memory,
        page_faults: !args.no_page_faults,
        sampler: args.sampler.map(|sampler| match sampler {
            SamplerArg::Perf => Sampler::Perf,
            SamplerArg::Ebpf => Sampler::Ebpf,
        }),
    };
    let handlers = Handlers::install().context("installing the signal handlers")?;
    let recorded = perf::record(&options, &INTERRUPTS, &args.output);
    drop(handlers);
    recorded?;
    if args.no_symbolize {
        return Ok(ExitCode::SUCCESS);
    }
    run_symbolize(&args.output)
}

#[cfg(not(target_os = "linux"))]
fn run_record(_: RecordArgs) -> Result<ExitCode> {
    bail!("uhr records on Linux only, so far")
}

fn run_symbolize(recording: &Path) -> Result<ExitCode> {
    symbols::symbolize(recording)?;
    Ok(ExitCode::SUCCESS)
}

fn run_overview(recording: &Path, top: usize, filter: FilterArgs, json: bool) -> Result<ExitCode> {
    let result = overview::overview(recording, &filter.into_filter(recording)?, top)?;
    if json {
        let text = serde_json::to_string_pretty(&result)?;
        write_output(|out| writeln!(out, "{text}"))?;
    } else {
        write_output(|out| text::write_overview(out, &result))?;
    }
    Ok(ExitCode::SUCCESS)
}

fn run_call_paths(
    recording: &Path,
    function: String,
    metric: Metric,
    depth: usize,
    top: usize,
    filter: FilterArgs,
    json: bool,
) -> Result<ExitCode> {
    let query = call_paths::Query {
        function,
        depth,
        top,
        metric,
        filter: filter.into_filter(recording)?,
    };
    let result = call_paths::call_paths(recording, &query)?;
    if json {
        let text = serde_json::to_string_pretty(&result)?;
        write_output(|out| writeln!(out, "{text}"))?;
    } else {
        write_output(|out| text::write_call_paths(out, &result))?;
    }
    Ok(ExitCode::SUCCESS)
}

fn run_export(
    recording: &Path,
    output: &Path,
    format: ExportFormat,
    filter: FilterArgs,
    json: bool,
) -> Result<ExitCode> {
    let filter = filter.into_filter(recording)?;
    let profile = match format {
        ExportFormat::Firefox => export::firefox(recording, &filter)?,
    };
    let file = fs::File::create_new(output).with_context(|| {
        format!(
            "creating {} (output must not already exist)",
            output.display()
        )
    })?;
    let mut file = io::BufWriter::new(file);
    profile
        .write(&mut file)
        .and_then(|()| file.flush())
        .with_context(|| format!("writing {}", output.display()))?;
    let report = &profile.report;
    if json {
        let text = serde_json::to_string_pretty(report)?;
        write_output(|out| writeln!(out, "{text}"))?;
    } else {
        write_output(|out| text::write_export(out, report, output))?;
    }
    Ok(ExitCode::SUCCESS)
}

fn run_flamegraph(
    recording: &Path,
    output: &Path,
    metric: Metric,
    root: Option<String>,
    filter: FilterArgs,
    folded: bool,
    json: bool,
) -> Result<ExitCode> {
    let query = flamegraph::Query {
        metric,
        filter: filter.into_filter(recording)?,
        root,
    };
    let graph = flamegraph::flame_graph(recording, &query)?;
    if graph.stacks == 0 {
        bail!("no stacks passed the filter, so there is nothing to draw");
    }
    let file =
        fs::File::create(output).with_context(|| format!("creating {}", output.display()))?;
    let mut file = io::BufWriter::new(file);
    if folded {
        graph.write_folded(&mut file)
    } else {
        let what = match graph.metric {
            Metric::OnCPU => "CPU time",
            Metric::OffCPU => "Off-CPU time",
            Metric::Wall => "Thread time",
            Metric::PageFaults => "Page faults",
        };
        let title = match graph.command.is_empty() {
            true => what.to_owned(),
            false => format!("{what}: {}", graph.command.join(" ")),
        };
        let mut parts: Vec<String> = graph
            .root
            .iter()
            .map(|root| format!("from {}", text::function_name(root)))
            .collect();
        if !graph.filter.is_empty() {
            parts.push(text::describe_filter(&graph.filter));
        }
        let subtitle = (!parts.is_empty()).then(|| parts.join(", "));
        graph.write_svg(&title, subtitle.as_deref(), &mut file)
    }
    .and_then(|()| file.flush())
    .with_context(|| format!("writing {}", output.display()))?;
    if json {
        let text = serde_json::to_string_pretty(&graph)?;
        write_output(|out| writeln!(out, "{text}"))?;
    } else {
        write_output(|out| text::write_flamegraph(out, &graph, output))?;
    }
    Ok(ExitCode::SUCCESS)
}

fn run_query(
    recording: &Path,
    group_by: GroupByArg,
    metric: Metric,
    top: usize,
    filter: FilterArgs,
    json: bool,
) -> Result<ExitCode> {
    let query = Query {
        group_by: match group_by {
            GroupByArg::Function => GroupBy::Function,
            GroupByArg::Line => GroupBy::Line,
            GroupByArg::Module => GroupBy::Module,
            GroupByArg::Syscall => GroupBy::Syscall,
            GroupByArg::Region => GroupBy::Region,
            GroupByArg::Waker => GroupBy::Waker,
            GroupByArg::WakerFunction => GroupBy::WakerFunction,
        },
        metric,
        top,
        filter: filter.into_filter(recording)?,
    };
    let result = query::query(recording, &query)?;
    if json {
        let text = serde_json::to_string_pretty(&result)?;
        write_output(|out| writeln!(out, "{text}"))?;
    } else {
        write_output(|out| text::write_query(out, &result))?;
    }
    Ok(ExitCode::SUCCESS)
}
