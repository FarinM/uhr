use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::LevelFilter;
use uhr_core::coverage::Coverage;
use uhr_core::doctor::{self, Report, Status};
use uhr_core::perf::{self, RecordOptions};
use uhr_core::query::{self, GroupBy, Query, QueryResult, Row};
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
        /// Command to profile, after `--`
        #[arg(required = true, last = true)]
        command: Vec<String>,
    },
    /// Resolve function names in a recording against the files on this machine
    Symbolize { recording: PathBuf },
    /// Group a recording's CPU time and print the top rows, with coverage
    Query {
        recording: PathBuf,
        #[arg(long, value_enum)]
        group_by: GroupByArg,
        /// Rows to print
        #[arg(long, default_value_t = 20)]
        top: usize,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum GroupByArg {
    Function,
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
            command,
        } => run_record(output, frequency, no_symbolize, command),
        Command::Symbolize { recording } => run_symbolize(&recording),
        Command::Query {
            recording,
            group_by,
            top,
            json,
        } => run_query(&recording, group_by, top, json),
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
    command: Vec<String>,
) -> Result<ExitCode> {
    let options = RecordOptions {
        command,
        frequency_hz,
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

fn run_query(recording: &Path, group_by: GroupByArg, top: usize, json: bool) -> Result<ExitCode> {
    let query = Query {
        group_by: match group_by {
            GroupByArg::Function => GroupBy::Function,
        },
        top,
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
    writeln!(
        out,
        "{} samples, {:.2} s of CPU time, by function\n",
        result.samples,
        result.cpu_ns as f64 / 1e9
    )?;
    writeln!(out, "{:>7} {:>7}  function", "self", "total")?;
    for row in &result.rows {
        writeln!(
            out,
            "{:>6.1}% {:>6.1}%  {}  {}",
            row.self_share * 100.0,
            row.total_share * 100.0,
            function_name(row),
            module_name(row),
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
        None => writeln!(out, "  self time in named functions: unknown, no samples"),
    }?;
    for (origin, share) in &coverage.unnamed_by_origin {
        writeln!(out, "  unnamed {}: {:.1}%", origin.as_str(), share * 100.0)?;
    }
    if !coverage.symbolized {
        writeln!(out, "  not symbolized: run `uhr symbolize`")?;
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
    write_coverage(out, &coverage.recording)
}

fn write_coverage(out: &mut impl Write, coverage: &Coverage) -> io::Result<()> {
    writeln!(out, "  lost events: {}", coverage.lost_events)?;
    writeln!(out, "  throttle events: {}", coverage.throttle_events)?;
    writeln!(
        out,
        "  samples with stacks at the depth limit: {}",
        coverage.samples_at_stack_limit
    )?;
    for missing in &coverage.missing_signals {
        writeln!(out, "  missing {:?}: {}", missing.signal, missing.reason)?;
    }
    for unknown in &coverage.unknown {
        writeln!(out, "  unknown: {unknown}")?;
    }
    for bias in &coverage.known_biases {
        writeln!(out, "  bias: {bias}")?;
    }
    Ok(())
}

fn function_name(row: &Row) -> String {
    let name = match (&row.function, &row.placeholder) {
        (Some(function), _) => function.clone(),
        (None, Some(placeholder)) => format!("{placeholder} (no symbol)"),
        (None, None) => "<unnamed>".into(),
    };
    match row.function_address {
        Some(address) => format!("{name} @0x{address:x}"),
        None => name,
    }
}

fn module_name(row: &Row) -> &str {
    match &row.module {
        Some(path) => path.rsplit('/').next().unwrap_or(path),
        None => row.origin.as_str(),
    }
}
