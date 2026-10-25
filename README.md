# Uhr -- agentic profiling

An agent-first profiling toolkit. Point an agent at almost any program --
native, JIT-compiled, interpreted, kernel or eBPF code -- and let it find where
time and memory go, from the process level down to single instructions.

It does not replace existing profilers. It runs them (perf, eBPF, py-spy,
async-profiler, the V8 profiler, ...), converts their output into one model,
and exposes questions over that model through MCP and a CLI.

## Status

Early implementation. The first milestone is in progress, and the code covers
only part of the design. The docs describe intent, the abstractions the design
depends on, and candidate approaches. The core is written in Rust.

The first milestone targets Linux, where perf_event and eBPF give the full
depth: per-thread user and kernel time; perf sampling with kernel and user
stacks; native symbol resolution; `overview`, `query` and `call_paths`; one
CPU-bound and one syscall-heavy test program.

## Try it

Linux only for now, with perf installed. Build with `cargo build`, then:

```sh
uhr doctor                                 # what this host is missing, and the fix
uhr record -o rec -- ./my-program args     # record CPU samples and context switches,
                                           # and resolve names
uhr overview rec                           # computing or waiting? CPU time by mode
                                           # and time off CPU, runnable or blocked,
                                           # by process and thread, against time alive
uhr query rec --group-by function          # top functions, with coverage
uhr query rec --group-by function --json   # the same, for agents
uhr query rec --group-by module            # which binaries, libraries and
                                           # kernel modules the time is in
uhr query rec --group-by syscall --metric off-cpu
                                           # which syscalls threads waited in
uhr query rec --group-by function --metric off-cpu --syscall futex
                                           # and the code that waited in one
uhr query rec --group-by function --thread 'worker-*' --mode kernel --from 1s
                                           # only some samples
uhr query rec --group-by function --metric off-cpu
                                           # where threads waited, off CPU
uhr call-paths rec --function memcpy       # who calls it, and what it calls
uhr query rec --group-by function --under run_bench
                                           # only time spent under one function
uhr query rec --group-by line --under parse_json
                                           # which source lines, from debug info
```

Full stacks need frame pointers, and `uhr doctor` lists the build flags. Or
record with `--unwind dwarf`, which needs no rebuild and finds the callers
frame pointers miss, at the cost of a stack copy in every sample. Kernel
functions get names only if the kernel shows uhr its addresses while
recording; `uhr doctor` says how to allow that.

## Docs

- [Vision](docs/vision.md): problem, goals, non-goals.
- [Model](docs/model.md): core abstractions -- recordings, observations,
  dimensions, levels, coverage, storage.
- [Format](docs/format.md): the on-disk schema of a recording.
- [Collection](docs/collection.md): collectors, code origin resolution,
  platforms, privileges.
- [Agent interface](docs/agent-interface.md): tools, result behavior,
  measurement rigor.

## Conventions in these docs

- **Must** marks a requirement the design depends on.
- **Candidate** marks one possible approach. Alternatives are welcome.
- Tool names, field names and tables of tools are sketches to show shape, not
  final APIs.
