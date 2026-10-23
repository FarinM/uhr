use std::io::IsTerminal;

use clap::Parser;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::LevelFilter;

#[derive(Parser)]
#[command(
    version,
    about = "Agent-first profiling toolkit",
    after_help = "Logs go to stderr. Set UHR_LOG to change what is logged, for example UHR_LOG=debug."
)]
struct Cli {}

fn main() {
    Cli::parse();
    init_logging();
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
