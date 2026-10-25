# Agent guide

Read this first. It covers what the project is, where it stands and how to
work here. The design itself lives in `docs/`.

## What this is

An agent-first profiling toolkit. An agent, or a person on the CLI, points it
at almost any program -- a C++ or Rust binary, Python, Node, a JIT-compiled
runtime, kernel or eBPF code -- and finds out where time and memory go, from
"is it computing or waiting?" down to single instructions.

It does not replace existing profilers. It runs them (perf, eBPF, py-spy,
async-profiler, the V8 profiler, ...), converts their output into one model,
and lets an agent ask questions over that model through MCP and a CLI.

## Where things stand

Early implementation. The first milestone (see `README.md`) is in progress,
and the code covers only part of the design.

- Start with `docs/vision.md` (the goals), then `docs/model.md` (the core
  abstractions). `README.md` maps the rest.
- The docs deliberately do not fix the implementation. **Must** marks a
  requirement the design depends on, **candidate** marks one possible
  approach, and tool and field names are sketches. `docs/format.md` is the
  exception: it documents the recording format as built.
- Choices the docs leave open are decided by the maintainers. Bring options
  and trade-offs, and prototype if it helps, but don't settle one silently.
  When a decision is made, update the docs it affects.
- Keep later options open: more signals, runtimes and platforms, and other
  ways to read the data, such as direct SQL. If a choice would block one, say
  so before making it.

## Building and testing

- `cargo build`, `cargo fmt --check`, `cargo clippy --all-targets` and
  `cargo test`. `cargo check --workspace --all-targets --target
  x86_64-pc-windows-gnu` checks that what is not for Linux builds elsewhere;
  its C dependencies need a MinGW compiler.
- The end-to-end tests in `crates/uhr-cli/tests` run perf and a C compiler on
  the host. `uhr doctor` shows what is missing.
- `uhr-core` holds the model, the recording format, symbol resolution and
  queries, and builds on every platform: nothing in it depends on Linux, so a
  recording can be read anywhere. `uhr-linux` records on Linux: perf,
  launching and attaching, kernel symbols and the Linux `doctor` checks.
  Elsewhere it is empty. `uhr-cli` is the `uhr` binary. Put new tools in the
  core, so the CLI and a later MCP server share them, and code for one
  platform in that platform's crate.
- Core returns typed errors, one `thiserror` enum per module, so callers can
  tell failures apart. Only the CLI uses `anyhow`, to print them.
- Diagnostics go through `tracing` to stderr. Command results go to stdout
  through `write_output`, never `println!`, which panics when a reader such
  as `head` stops early.

## Working agreements

- If a change makes a doc wrong, fix the doc in the same commit.
- Comments explain why, not what, and stay short. Don't leave comments behind
  for removed or moved code.
- Fix problems at the root cause. If a fix has gaps or can cause a regression,
  say so.
