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
use uhr_core::call_paths::{self, CallPaths, Node, Omitted};
use uhr_core::coverage::{Coverage, SymbolCoverage};
#[cfg(not(target_os = "linux"))]
use uhr_core::doctor::Check;
use uhr_core::doctor::{Report, Status};
use uhr_core::filter::Filter;
use uhr_core::flamegraph::{self, FlameGraph};
use uhr_core::functions::Function;
use uhr_core::metric::Metric;
use uhr_core::overview::{self, CPUTime, Overview};
use uhr_core::query::{
    self, FunctionRow, GroupBy, Latency, ModuleRow, Query, QueryResult, Rows, SyscallRow,
};
use uhr_core::recording::{Exit, Mode};
use uhr_core::symbols;

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
    /// Show CPU time by mode and time off CPU, by process and thread, against
    /// time alive: is it computing or waiting?
    Overview {
        recording: PathBuf,
        /// Processes and threads to print
        #[arg(long, default_value_t = 20)]
        top: usize,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        filter: FilterArgs,
    },
    /// Group a recording's CPU or off-CPU time and print the top rows, with
    /// coverage
    Query {
        recording: PathBuf,
        #[arg(long, value_enum)]
        group_by: GroupByArg,
        /// The time to weigh stacks by
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
    /// Draw a flame graph of a recording's CPU or off-CPU time, as an SVG
    /// to open in a browser
    Flamegraph {
        recording: PathBuf,
        /// The file to write
        #[arg(short, long)]
        output: PathBuf,
        /// The time to weigh stacks by
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
    /// Show who calls a function and what it calls, with their CPU or off-CPU
    /// time
    CallPaths {
        recording: PathBuf,
        /// A function id from `uhr query --json`, or a name only one function
        /// has
        #[arg(long)]
        function: String,
        /// The time to weigh stacks by
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
    /// Don't set the variables that make runtimes, such as Python 3.12
    /// and later and Node, name the code they compile. That costs them
    /// a little time, and without it their functions have no names
    #[arg(long, conflicts_with = "pid")]
    no_runtime_support: bool,
    /// Don't count and time the target's syscalls. uhr does that with its
    /// eBPF programs when it may load them: as root, or with CAP_BPF and
    /// CAP_PERFMON
    #[arg(long)]
    no_syscalls: bool,
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
}

#[derive(Clone, Copy, ValueEnum)]
enum MetricArg {
    /// CPU time, from CPU samples
    Cpu,
    /// Time threads spent off CPU, runnable or blocked, from context switches
    OffCpu,
    /// Both, all the time threads were alive
    Wall,
}

impl From<MetricArg> for Metric {
    fn from(metric: MetricArg) -> Self {
        match metric {
            MetricArg::Cpu => Metric::OnCPU,
            MetricArg::OffCpu => Metric::OffCPU,
            MetricArg::Wall => Metric::Wall,
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
    /// Only samples from this offset into the recording on, such as 1.5s or
    /// 200ms
    #[arg(long, value_name = "OFFSET", value_parser = parse_offset)]
    from: Option<u64>,
    /// Only samples before this offset into the recording
    #[arg(long, value_name = "OFFSET", value_parser = parse_offset)]
    to: Option<u64>,
}

#[derive(Clone, Copy, ValueEnum)]
enum ModeArg {
    User,
    Kernel,
    Unknown,
}

impl FilterArgs {
    fn into_filter(self) -> Result<Filter> {
        if let (Some(from), Some(to)) = (self.from, self.to)
            && from >= to
        {
            bail!("--from must be before --to");
        }
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
            from_ns: self.from,
            to_ns: self.to,
        })
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
        write_output(|out| write_report(out, &report))?;
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

fn write_report(out: &mut impl Write, report: &Report) -> io::Result<()> {
    for check in &report.checks {
        let status = match check.status {
            Status::Ok => "ok",
            Status::Limited => "limited",
            Status::Blocked => "blocked",
        };
        writeln!(out, "{status:<8} {}", check.detail)?;
        if let Some(fix) = &check.fix {
            writeln!(out, "{:<8} fix: {fix}", "")?;
        }
    }
    for note in &report.notes {
        writeln!(out, "{:<8} {note}", "note")?;
    }
    Ok(())
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
    let options = RecordOptions {
        target,
        frequency_hz: args.frequency,
        unwind,
        off_cpu: !args.no_off_cpu,
        runtime_support: !args.no_runtime_support,
        syscalls: !args.no_syscalls,
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
    let result = overview::overview(recording, &filter.into_filter()?, top)?;
    if json {
        let text = serde_json::to_string_pretty(&result)?;
        write_output(|out| writeln!(out, "{text}"))?;
    } else {
        write_output(|out| write_overview(out, &result))?;
    }
    Ok(ExitCode::SUCCESS)
}

fn write_overview(out: &mut impl Write, result: &Overview) -> io::Result<()> {
    let exit = match &result.exit {
        Some(Exit::Code(code)) => format!("exited with code {code}"),
        Some(Exit::Signal(signal)) => format!("killed by signal {signal}"),
        Some(Exit::Unknown(reason)) => format!("exit status unknown: {reason}"),
        None => "still running when the recording stopped".into(),
    };
    let command = match &result.command[..] {
        [] => "(no command line)".to_owned(),
        command => command.join(" "),
    };
    writeln!(out, "{command}, {exit}")?;
    let window = &result.window;
    write!(out, "{} recorded", seconds(result.recording_duration_ns))?;
    if !result.filter.is_empty() {
        write!(
            out,
            ", showing {} to {}, filter: {}",
            seconds(window.start_ns),
            seconds(window.end_ns),
            describe_filter(&result.filter)
        )?;
    }
    writeln!(out)?;
    let cpu = &result.cpu;
    write!(
        out,
        "{} samples, {} of CPU time",
        cpu.samples,
        seconds(cpu.cpu_ns)
    )?;
    if let Some(utilization) = result.cpu_utilization {
        write!(out, ", {utilization:.2} CPUs busy on average")?;
    }
    writeln!(out)?;
    match cpu.kernel_cpu_ns {
        Some(kernel) => writeln!(
            out,
            "  user {}, kernel {}",
            seconds(cpu.user_cpu_ns),
            seconds(kernel)
        ),
        None => writeln!(
            out,
            "  user {}, kernel not sampled",
            seconds(cpu.user_cpu_ns)
        ),
    }?;
    if cpu.unknown_mode_cpu_ns > 0 {
        writeln!(out, "  unknown mode {}", seconds(cpu.unknown_mode_cpu_ns))?;
    }
    match &result.off_cpu {
        Some(off_cpu) => {
            let unknown = match off_cpu.unknown_state_ns {
                0 => String::new(),
                ns => format!(", unknown {}", seconds(ns)),
            };
            writeln!(
                out,
                "off CPU {}, summed over threads: runnable {}, blocked {}{unknown}",
                seconds(off_cpu.runnable_ns + off_cpu.blocked_ns + off_cpu.unknown_state_ns),
                seconds(off_cpu.runnable_ns),
                seconds(off_cpu.blocked_ns)
            )
        }
        None => writeln!(out, "off CPU: not recorded"),
    }?;

    writeln!(out, "\nprocesses")?;
    writeln!(
        out,
        "{:>9} {:>7} {:>6} {:>8} {:>9}  name",
        "cpu", "kernel", "cpus", "threads", "pid"
    )?;
    for process in &result.processes {
        writeln!(
            out,
            "{:>9} {:>7} {:>6} {:>8} {:>9}  {}",
            seconds(process.cpu.cpu_ns),
            kernel_share(&process.cpu),
            process
                .cpu_utilization
                .map_or("-".into(), |u| format!("{u:.2}")),
            process.threads,
            process.pid,
            process.name.as_deref().unwrap_or("<unnamed>"),
        )?;
    }
    if result.processes_omitted > 0 {
        writeln!(
            out,
            "({} more processes, raise --top to see them)",
            result.processes_omitted
        )?;
    }

    writeln!(out, "\nthreads")?;
    // Off CPU since before an attached capture, runnable or blocked.
    let unknown = result
        .threads
        .iter()
        .any(|t| t.unknown_state_share.is_some_and(|s| s > 0.0));
    let unknown_column = |cell: String| {
        if unknown {
            format!(" {cell:>7}")
        } else {
            String::new()
        }
    };
    let percent = |share: Option<f64>| share.map_or("-".into(), |s| format!("{:.1}%", s * 100.0));
    writeln!(
        out,
        "{:>9} {:>7} {:>7} {:>8} {:>7}{} {:>9} {:>9}  name",
        "cpu",
        "kernel",
        "on cpu",
        "runnable",
        "blocked",
        unknown_column("unknown".into()),
        "alive",
        "tid"
    )?;
    for thread in &result.threads {
        writeln!(
            out,
            "{:>9} {:>7} {:>7} {:>8} {:>7}{} {:>9} {:>9}  {}",
            seconds(thread.cpu.cpu_ns),
            kernel_share(&thread.cpu),
            percent(thread.on_cpu_share),
            percent(thread.runnable_share),
            percent(thread.blocked_share),
            unknown_column(percent(thread.unknown_state_share)),
            seconds(thread.alive_ns),
            thread.tid,
            thread.names.last().map_or("<unnamed>", String::as_str),
        )?;
    }
    if result.threads_omitted > 0 {
        writeln!(
            out,
            "({} more threads, raise --top to see them)",
            result.threads_omitted
        )?;
    }

    writeln!(out, "\ncoverage")?;
    write_coverage(out, &result.coverage)
}

/// The share of a row's CPU time spent in the kernel.
fn kernel_share(cpu: &CPUTime) -> String {
    match cpu.kernel_cpu_ns {
        None => "?".into(),
        Some(_) if cpu.cpu_ns == 0 => "-".into(),
        Some(kernel) => format!("{:.1}%", kernel as f64 / cpu.cpu_ns as f64 * 100.0),
    }
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
        filter: filter.into_filter()?,
    };
    let result = call_paths::call_paths(recording, &query)?;
    if json {
        let text = serde_json::to_string_pretty(&result)?;
        write_output(|out| writeln!(out, "{text}"))?;
    } else {
        write_output(|out| write_call_paths(out, &result))?;
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
        filter: filter.into_filter()?,
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
        };
        let title = match graph.command.is_empty() {
            true => what.to_owned(),
            false => format!("{what}: {}", graph.command.join(" ")),
        };
        let mut parts: Vec<String> = graph
            .root
            .iter()
            .map(|root| format!("from {}", function_name(root)))
            .collect();
        if !graph.filter.is_empty() {
            parts.push(describe_filter(&graph.filter));
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
        write_output(|out| write_flamegraph(out, &graph, output))?;
    }
    Ok(ExitCode::SUCCESS)
}

fn write_flamegraph(out: &mut impl Write, graph: &FlameGraph, output: &Path) -> io::Result<()> {
    writeln!(
        out,
        "wrote {}: {}, {:.1}% of it in {} stacks",
        output.display(),
        describe_time(
            graph.metric,
            graph.samples,
            graph.off_cpu_intervals,
            graph.time_ns
        ),
        graph.graphed_share * 100.0,
        graph.stacks
    )?;
    if let Some(root) = &graph.root {
        writeln!(out, "from {}  {}", function_name(root), module_name(root))?;
    }
    if !graph.filter.is_empty() {
        writeln!(out, "filter: {}", describe_filter(&graph.filter))?;
    }
    let coverage = &graph.coverage;
    writeln!(out, "\ncoverage")?;
    if let Some(share) = coverage.named_share {
        writeln!(
            out,
            "  graphed time with every frame named: {:.1}%",
            share * 100.0
        )?;
    }
    for (origin, share) in &coverage.unnamed_by_origin {
        writeln!(out, "  unnamed {}: {:.1}%", origin.as_str(), share * 100.0)?;
    }
    write_no_stack(out, coverage.no_stack_share)?;
    write_symbol_coverage(out, &coverage.symbols)?;
    write_coverage(out, &coverage.recording)
}

fn write_call_paths(out: &mut impl Write, result: &CallPaths) -> io::Result<()> {
    let percent = |ns: u64| {
        if result.time_ns == 0 {
            0.0
        } else {
            ns as f64 / result.time_ns as f64 * 100.0
        }
    };
    writeln!(
        out,
        "{}  {}",
        function_name(&result.function),
        module_name(&result.function)
    )?;
    writeln!(
        out,
        "{}. On the stack for {:.1}% of it, its own for {:.1}%",
        describe_time(
            result.metric,
            result.samples,
            result.off_cpu_intervals,
            result.time_ns
        ),
        result.total_share * 100.0,
        result.self_share * 100.0
    )?;
    if !result.filter.is_empty() {
        writeln!(out, "filter: {}", describe_filter(&result.filter))?;
    }

    writeln!(out, "\ncallers")?;
    write_nodes(out, &result.callers, &result.callers_omitted, 0, &percent)?;
    if result.no_caller_ns > 0 {
        writeln!(
            out,
            "{:>6.1}%  (no caller: where the thread started, or the stack was cut short)",
            percent(result.no_caller_ns)
        )?;
    }
    writeln!(out, "\ncallees")?;
    write_nodes(out, &result.callees, &result.callees_omitted, 0, &percent)?;

    let coverage = &result.coverage;
    writeln!(out, "\ncoverage")?;
    match coverage.named_share {
        Some(share) => writeln!(
            out,
            "  function time with every frame named, within the depth: {:.1}%",
            share * 100.0
        ),
        None => writeln!(out, "  named frames: unknown, no time in the function"),
    }?;
    for (origin, share) in &coverage.unnamed_by_origin {
        writeln!(out, "  unnamed {}: {:.1}%", origin.as_str(), share * 100.0)?;
    }
    write_no_stack(out, coverage.no_stack_share)?;
    write_symbol_coverage(out, &coverage.symbols)?;
    write_coverage(out, &coverage.recording)
}

fn write_nodes(
    out: &mut impl Write,
    nodes: &[Node],
    omitted: &Omitted,
    level: usize,
    percent: &dyn Fn(u64) -> f64,
) -> io::Result<()> {
    let indent = "  ".repeat(level);
    if level == 0 && nodes.is_empty() && omitted.nodes == 0 {
        writeln!(out, "  none")?;
    }
    for node in nodes {
        let leaf = match node.self_ns {
            Some(ns) if ns > 0 => format!("  (leaf {:.1}%)", percent(ns)),
            _ => String::new(),
        };
        writeln!(
            out,
            "{:>6.1}%  {indent}{}  {}{leaf}",
            percent(node.time_ns),
            function_name(&node.function),
            module_name(&node.function)
        )?;
        write_nodes(out, &node.children, &node.omitted, level + 1, percent)?;
    }
    if omitted.nodes > 0 {
        writeln!(
            out,
            "{:>6.1}%  {indent}({} more)",
            percent(omitted.time_ns),
            omitted.nodes
        )?;
    }
    Ok(())
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
        },
        metric,
        top,
        filter: filter.into_filter()?,
    };
    let result = query::query(recording, &query)?;
    if json {
        let text = serde_json::to_string_pretty(&result)?;
        write_output(|out| writeln!(out, "{text}"))?;
    } else {
        write_output(|out| write_query(out, &result))?;
    }
    Ok(ExitCode::SUCCESS)
}

fn write_query(out: &mut impl Write, result: &QueryResult) -> io::Result<()> {
    let by = match result.group_by {
        GroupBy::Function => "function",
        GroupBy::Line => "line",
        GroupBy::Module => "module",
        GroupBy::Syscall => "syscall",
    };
    writeln!(
        out,
        "{}, by {by}\n",
        describe_time(
            result.metric,
            result.samples,
            result.off_cpu_intervals,
            result.time_ns
        )
    )?;
    if !result.filter.is_empty() {
        writeln!(out, "filter: {}\n", describe_filter(&result.filter))?;
    }
    match &result.rows {
        Rows::Functions(rows) => write_function_rows(out, result.group_by == GroupBy::Line, rows)?,
        Rows::Modules(rows) => write_module_rows(out, rows)?,
        Rows::Syscalls(rows) => write_syscall_rows(out, rows)?,
    }
    if result.rows_omitted > 0 {
        writeln!(
            out,
            "({} more rows, raise --top to see them)",
            result.rows_omitted
        )?;
    }

    let coverage = &result.coverage;
    writeln!(out, "\ncoverage")?;
    match coverage.named_share {
        Some(share) => writeln!(out, "  time with a named leaf frame: {:.1}%", share * 100.0),
        None => writeln!(out, "  time with a named leaf frame: unknown, no time"),
    }?;
    for (origin, share) in &coverage.unnamed_by_origin {
        writeln!(out, "  unnamed {}: {:.1}%", origin.as_str(), share * 100.0)?;
    }
    write_no_stack(out, coverage.no_stack_share)?;
    if let Some(share) = coverage.own_programs_share {
        writeln!(out, "  time in uhr's eBPF programs: {:.1}%", share * 100.0)?;
    }
    write_symbol_coverage(out, &coverage.symbols)?;
    write_coverage(out, &coverage.recording)
}

fn write_function_rows(
    out: &mut impl Write,
    by_line: bool,
    rows: &[FunctionRow],
) -> io::Result<()> {
    let by = if by_line { "line" } else { "function" };
    writeln!(out, "{:>7} {:>7}  {by}", "self", "total")?;
    for row in rows {
        let line = match (by_line, &row.line) {
            (false, _) => String::new(),
            (true, Some(line)) => {
                let file = line.file.rsplit('/').next().unwrap_or(&line.file);
                format!("  {file}:{}", line.line)
            }
            (true, None) => "  (no line)".into(),
        };
        writeln!(
            out,
            "{:>6.1}% {:>6.1}%  {}{line}  {}",
            row.self_share * 100.0,
            row.total_share * 100.0,
            function_name(&row.function),
            module_name(&row.function),
        )?;
    }
    Ok(())
}

fn write_module_rows(out: &mut impl Write, rows: &[ModuleRow]) -> io::Result<()> {
    writeln!(out, "{:>7} {:>7}  module", "self", "total")?;
    for row in rows {
        writeln!(
            out,
            "{:>6.1}% {:>6.1}%  {}",
            row.self_share * 100.0,
            row.total_share * 100.0,
            row.module.as_deref().unwrap_or(row.origin.as_str()),
        )?;
    }
    Ok(())
}

fn write_syscall_rows(out: &mut impl Write, rows: &[SyscallRow]) -> io::Result<()> {
    let counted = rows.iter().any(|row| row.calls.is_some());
    if counted {
        writeln!(
            out,
            "{:>7} {:>9} {:>10} {:>9} {:>9}  syscall",
            "time", "calls", "in calls", "median", "p99"
        )?;
    } else {
        writeln!(out, "{:>7}  syscall", "time")?;
    }
    for row in rows {
        let syscall = match (row.in_syscall, &row.syscall) {
            _ if row.own_programs => "(uhr's eBPF programs)",
            (_, Some(name)) => name,
            (Some(true), None) => "(in a syscall, unknown which)",
            (Some(false), None) => "(not in a syscall)",
            (None, None) => "(unknown)",
        };
        write!(out, "{:>6.1}%", row.share * 100.0)?;
        match &row.calls {
            Some(calls) => {
                let mut called = calls.calls.to_string();
                if calls.unfinished > 0 {
                    called = format!("{called}+{}", calls.unfinished);
                }
                write!(
                    out,
                    " {called:>9} {:>10} {:>9} {:>9}",
                    duration(calls.time_ns + calls.unfinished_ns),
                    calls.median.map(latency).unwrap_or_default(),
                    calls.p99.map(latency).unwrap_or_default(),
                )?;
            }
            None if counted => write!(out, " {:>9} {:>10} {:>9} {:>9}", "", "", "", "")?,
            None => {}
        }
        writeln!(out, "  {syscall}")?;
    }
    if rows
        .iter()
        .any(|row| row.calls.as_ref().is_some_and(|c| c.unfinished > 0))
    {
        writeln!(
            out,
            "(+n: calls still running when the capture ended, in the time)"
        )?;
    }
    Ok(())
}

/// The range a call time is in, by its end: `<2.0us`, or `>=34.4s` for the
/// last one, which has none.
fn latency(latency: Latency) -> String {
    match latency.below_ns {
        Some(below) => format!("<{}", duration(below)),
        None => format!(">={}", duration(latency.at_least_ns)),
    }
}

fn duration(ns: u64) -> String {
    let ns = ns as f64;
    match ns {
        _ if ns < 1e3 => format!("{ns:.0}ns"),
        _ if ns < 1e6 => format!("{:.1}us", ns / 1e3),
        _ if ns < 1e9 => format!("{:.1}ms", ns / 1e6),
        _ => format!("{:.1}s", ns / 1e9),
    }
}

fn describe_time(metric: Metric, samples: u64, intervals: u64, time_ns: u64) -> String {
    let seconds = time_ns as f64 / 1e9;
    match metric {
        Metric::OnCPU => format!("{samples} samples, {seconds:.2} s of CPU time"),
        Metric::OffCPU => format!("{intervals} off-CPU intervals, {seconds:.2} s off CPU"),
        Metric::Wall => format!(
            "{samples} samples and {intervals} off-CPU intervals, {seconds:.2} s of thread time"
        ),
    }
}

fn write_no_stack(out: &mut impl Write, share: f64) -> io::Result<()> {
    if share > 0.0 {
        writeln!(out, "  off-CPU time without a stack: {:.1}%", share * 100.0)?;
    }
    Ok(())
}

fn write_symbol_coverage(out: &mut impl Write, coverage: &SymbolCoverage) -> io::Result<()> {
    if !coverage.symbolized {
        writeln!(out, "  not symbolized: run `uhr symbolize`")?;
    }
    for path in &coverage.without_debug_info {
        writeln!(out, "  no debug info, inlined calls not expanded: {path}")?;
    }
    for source in &coverage.symbol_problems {
        let detail = source.detail.as_deref().map(|d| format!(": {d}"));
        writeln!(
            out,
            "  symbols {} {}{}",
            source.status.as_str(),
            source.path,
            detail.unwrap_or_default()
        )?;
    }
    Ok(())
}

fn write_coverage(out: &mut impl Write, coverage: &Coverage) -> io::Result<()> {
    writeln!(out, "  lost events: {}", coverage.lost_events)?;
    if let Some(throttled) = coverage.throttle_events {
        writeln!(out, "  throttle events: {throttled}")?;
    }
    writeln!(
        out,
        "  stacks at the depth limit: {}",
        coverage.stacks_at_stack_limit
    )?;
    if let Some(cut) = coverage.stacks_cut_at_stack_copy {
        writeln!(out, "  stacks cut at the stack copy: {cut}")?;
    }
    if let Some(skipped) = coverage.stacks_not_unwound.filter(|&n| n > 0) {
        writeln!(out, "  stacks of 32-bit code, not unwound: {skipped}")?;
    }
    for missing in &coverage.missing_signals {
        writeln!(
            out,
            "  missing {}: {}",
            missing.signal.as_str(),
            missing.reason
        )?;
    }
    for (stream, ns) in &coverage.overhead_ns {
        writeln!(
            out,
            "  profiler overhead of stream {stream}: {} of CPU time",
            seconds(*ns)
        )?;
    }
    for unknown in &coverage.unknown {
        writeln!(out, "  unknown: {unknown}")?;
    }
    for bias in &coverage.known_biases {
        writeln!(out, "  bias: {bias}")?;
    }
    Ok(())
}

fn describe_filter(filter: &Filter) -> String {
    let mut parts = Vec::new();
    parts.extend(filter.pids.iter().map(|pid| format!("pid {pid}")));
    parts.extend(filter.tids.iter().map(|tid| format!("tid {tid}")));
    parts.extend(
        filter
            .thread_names
            .iter()
            .map(|name| format!("thread {name}")),
    );
    parts.extend(
        filter
            .modes
            .iter()
            .map(|mode| format!("mode {}", mode.as_str())),
    );
    parts.extend(
        filter
            .under
            .iter()
            .map(|function| format!("under {function}")),
    );
    parts.extend(
        filter
            .syscalls
            .iter()
            .map(|syscall| format!("syscall {syscall}")),
    );
    if let Some(from) = filter.from_ns {
        parts.push(format!("from {}", seconds(from)));
    }
    if let Some(to) = filter.to_ns {
        parts.push(format!("to {}", seconds(to)));
    }
    parts.join(", ")
}

fn seconds(ns: u64) -> String {
    format!("{:.3}s", ns as f64 / 1e9)
}

fn function_name(function: &Function) -> String {
    let name = match (&function.name, &function.placeholder) {
        (Some(function), _) => function.clone(),
        (None, Some(placeholder)) => format!("{placeholder} (no symbol)"),
        (None, None) => "<unnamed>".into(),
    };
    match function.function_address {
        Some(address) => format!("{name} @0x{address:x}"),
        None if function.inlined => format!("{name} (inlined)"),
        None => name,
    }
}

fn module_name(function: &Function) -> &str {
    match &function.module {
        Some(path) => path.rsplit('/').next().unwrap_or(path),
        None => function.origin.as_str(),
    }
}
