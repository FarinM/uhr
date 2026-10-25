use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::LevelFilter;
use uhr_core::call_paths::{self, CallPaths, Node, Omitted};
use uhr_core::coverage::{Coverage, SymbolCoverage};
use uhr_core::doctor::{self, Report, Status};
use uhr_core::filter::Filter;
use uhr_core::functions::Function;
use uhr_core::metric::Metric;
use uhr_core::overview::{self, CPUTime, Overview};
use uhr_core::perf::{self, RecordOptions, Unwind};
use uhr_core::query::{self, GroupBy, Query, QueryResult};
use uhr_core::recording::{Exit, Mode};
use uhr_core::symbols;

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
    /// Run a command under perf and write a recording
    Record {
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
        /// dwarf`. Deeper stacks lose their outer callers [default: 32768]
        #[arg(long, value_name = "BYTES", value_parser = clap::value_parser!(u32).range(8..=65528))]
        stack_size: Option<u32>,
        /// Don't record context switches. Saves their cost in programs that
        /// switch often, but then nothing says why threads were off CPU
        #[arg(long)]
        no_off_cpu: bool,
        /// Command to profile, after `--`
        #[arg(required = true, last = true)]
        command: Vec<String>,
    },
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

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum UnwindArg {
    /// Frame pointers
    Fp,
    /// DWARF unwind tables, from a copy of each sample's stack
    Dwarf,
}

/// Covers most C, C++ and Rust stacks, including deep async ones, at half
/// the cost of perf's maximum.
const STACK_COPY_BYTES: u32 = 32 * 1024;

#[derive(Clone, Copy, ValueEnum)]
enum GroupByArg {
    Function,
    /// Function and source line, from debug info
    Line,
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

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging();
    let result = match cli.command {
        Command::Doctor { json } => run_doctor(json),
        Command::Record {
            output,
            frequency,
            no_symbolize,
            unwind,
            stack_size,
            no_off_cpu,
            command,
        } => run_record(
            output,
            frequency,
            no_symbolize,
            unwind,
            stack_size,
            !no_off_cpu,
            command,
        ),
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
    let report = doctor::check_perf();
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

fn run_record(
    output: PathBuf,
    frequency_hz: u64,
    no_symbolize: bool,
    unwind: UnwindArg,
    stack_size: Option<u32>,
    off_cpu: bool,
    command: Vec<String>,
) -> Result<ExitCode> {
    let unwind = match (unwind, stack_size) {
        (UnwindArg::Fp, None) => Unwind::FramePointers,
        (UnwindArg::Fp, Some(_)) => bail!("--stack-size only applies to --unwind dwarf"),
        (UnwindArg::Dwarf, stack_size) => Unwind::Dwarf {
            stack_bytes: stack_size.unwrap_or(STACK_COPY_BYTES),
        },
    };
    let options = RecordOptions {
        command,
        frequency_hz,
        unwind,
        off_cpu,
    };
    perf::record(&options, &output)?;
    if no_symbolize {
        return Ok(ExitCode::SUCCESS);
    }
    run_symbolize(&output)
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
    writeln!(out, "{}, {exit}", result.command.join(" "))?;
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
        Some(off_cpu) => writeln!(
            out,
            "off CPU {}, summed over threads: runnable {}, blocked {}",
            seconds(off_cpu.runnable_ns + off_cpu.blocked_ns),
            seconds(off_cpu.runnable_ns),
            seconds(off_cpu.blocked_ns)
        ),
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
    writeln!(
        out,
        "{:>9} {:>7} {:>7} {:>8} {:>7} {:>9} {:>9}  name",
        "cpu", "kernel", "on cpu", "runnable", "blocked", "alive", "tid"
    )?;
    let percent = |share: Option<f64>| share.map_or("-".into(), |s| format!("{:.1}%", s * 100.0));
    for thread in &result.threads {
        writeln!(
            out,
            "{:>9} {:>7} {:>7} {:>8} {:>7} {:>9} {:>9}  {}",
            seconds(thread.cpu.cpu_ns),
            kernel_share(&thread.cpu),
            percent(thread.on_cpu_share),
            percent(thread.runnable_share),
            percent(thread.blocked_share),
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
        "{}. On the stack for {:.1}% of it, the leaf for {:.1}%",
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
    writeln!(out, "{:>7} {:>7}  {by}", "self", "total")?;
    for row in &result.rows {
        let line = match (&result.group_by, &row.line) {
            (GroupBy::Function, _) => String::new(),
            (GroupBy::Line, Some(line)) => {
                let file = line.file.rsplit('/').next().unwrap_or(&line.file);
                format!("  {file}:{}", line.line)
            }
            (GroupBy::Line, None) => "  (no line)".into(),
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
        Some(share) => writeln!(out, "  self time in named functions: {:.1}%", share * 100.0),
        None => writeln!(out, "  self time in named functions: unknown, no time"),
    }?;
    for (origin, share) in &coverage.unnamed_by_origin {
        writeln!(out, "  unnamed {}: {:.1}%", origin.as_str(), share * 100.0)?;
    }
    write_no_stack(out, coverage.no_stack_share)?;
    write_symbol_coverage(out, &coverage.symbols)?;
    write_coverage(out, &coverage.recording)
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
    writeln!(out, "  throttle events: {}", coverage.throttle_events)?;
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
