# Uhr -- agentic profiling

An agent-first profiling toolkit. Point an agent at almost any program --
native, JIT-compiled, interpreted, kernel or eBPF code -- and let it find where
time and memory go, from the process level down to single instructions.

It does not replace existing profilers. It runs them (perf, eBPF, py-spy,
async-profiler, the V8 profiler, ...), converts their output into one model,
and exposes questions over that model through MCP and a CLI.

## Status

Design stage. Nothing is implemented. The docs describe intent, the
abstractions the design depends on, and candidate approaches. The core will be
written in Rust.

The first milestone targets Linux, where perf_event and eBPF give the full
depth: per-thread user and kernel time; perf sampling with kernel and user
stacks; native symbol resolution; `overview`, `query` and `call_paths`; one
CPU-bound and one syscall-heavy test program.

## Docs

- [Vision](docs/vision.md): problem, goals, non-goals.
- [Model](docs/model.md): core abstractions -- recordings, observations,
  dimensions, levels, coverage, storage.
- [Collection](docs/collection.md): collectors, code origin resolution,
  platforms, privileges.
- [Agent interface](docs/agent-interface.md): tools, result behavior,
  measurement rigor.

## Conventions in these docs

- **Must** marks a requirement the design depends on.
- **Candidate** marks one possible approach. Alternatives are welcome.
- Tool names, field names and tables of tools are sketches to show shape, not
  final APIs.
