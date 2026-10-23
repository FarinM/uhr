use clap::Parser;

#[derive(Parser)]
#[command(version, about = "Agent-first profiling toolkit")]
struct Cli {}

fn main() {
    Cli::parse();
}
