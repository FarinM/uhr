# Uhr -- agentic profiling

An agent-first profiling toolkit. Point an agent at almost any program --
native, JIT-compiled, interpreted, kernel or eBPF code -- and let it find where
time and memory go, from the process level down to single instructions.

It does not replace existing profilers. It runs them (perf, eBPF, py-spy,
async-profiler, the V8 profiler, ...), converts their output into one model,
and exposes questions over that model through MCP and a CLI.

## Status

Early, and Linux only. Recording needs Linux and perf; a recording can be read
anywhere. The [docs](#docs) describe the whole design, which the code only
partly covers.

uhr records CPU samples with user and kernel stacks, and time off CPU, per
process and thread, of a program it starts or one already running. It names
the code Python 3.12+ and Node compile from their perf maps. It samples with
one of two samplers:

- **perf**, without root, or with `--sampler perf`.
- **uhr's eBPF sampler**, as root (or with CAP_BPF and CAP_PERFMON). It also
  counts and times syscalls, and reads the frames of CPython 3.11 to 3.14,
  Node 20 to 24, Bun 1.4.3, Ruby 3.2, PHP 8.3, Lua 5.4 and Java's interpreter
  ([limits](docs/collection.md#runtimes)).

## How the eBPF sampler works

About a thousand times a second on each CPU (999 by default, set with `-F`),
the kernel pauses the running thread and runs uhr's sampler, which takes about
half a microsecond. It copies the thread's kernel and user stacks, and if the
thread runs an interpreter, it also reads the interpreter's own frames from the
process's memory: which function each one runs, and where in it. uhr looks up
the names of those functions afterwards.

The sampler itself knows no runtime. When uhr finds an interpreter in a
process, it describes to the sampler, in numbers, where that runtime keeps its
frames and what to copy of each. So a new runtime needs a description, not new
kernel code, and it works on programs already running, with no flags or
restarts.

## Try it

Build with `cargo build`, then:

```sh
uhr doctor                                         # what this host is missing

uhr record -o rec -- ./my-program args             # record a program
uhr record -o rec --pid 4312 --duration 10s        # or attach to one
sudo uhr record -o rec -- python3 app.py           # with the eBPF sampler

uhr overview rec                                   # computing or waiting?
uhr query rec --group-by function                  # top functions
uhr query rec --group-by line --under parse_json   # hot lines under a function
uhr query rec --group-by syscall --metric off-cpu  # syscalls threads waited in
uhr call-paths rec --function memcpy               # callers and callees
```

Add `--json` to any but `record` for output an agent can read. See
`uhr query --help` for the other groupings and the filters by process, thread,
mode and time.

Full stacks need frame pointers. `uhr doctor` lists the build flags, or record
with `--unwind dwarf`, which needs no rebuild but copies the stack in every
sample.

## Docs

- [Vision](docs/vision.md): problem, goals, non-goals.
- [Model](docs/model.md): recordings, observations, dimensions, levels,
  coverage, storage.
- [Format](docs/format.md): the on-disk schema of a recording.
- [Collection](docs/collection.md): collectors, runtimes, code origin
  resolution, platforms, privileges.
- [Agent interface](docs/agent-interface.md): tools, result behavior,
  measurement rigor.

In the docs, **must** marks a requirement the design depends on, and
**candidate** one possible approach, with alternatives welcome. Tool and field
names are sketches of the shape, not final APIs.
