use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::LevelFilter;
use uhr_core::doctor::{self, Report, Status};
use uhr_core::perf::{self, RecordOptions};
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
