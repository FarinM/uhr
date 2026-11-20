# Uhr -- agentic profiling

An agent-first profiling toolkit. Point an agent at almost any program --
native, JIT-compiled, interpreted, kernel or eBPF code -- and let it find where
time and memory go, from the process level down to single instructions.

It does not replace existing profilers. It runs them (perf, eBPF, py-spy,
async-profiler, the V8 profiler, ...), converts their output into one model,
and exposes questions over that model through MCP and a CLI.

## Status

Early, on Linux and macOS. Recording needs Linux and perf, or macOS; a
recording can be read anywhere. The [docs](#docs) describe the whole design,
which the code only partly covers.

uhr records CPU samples with user and kernel stacks, and time off CPU, per
process and thread, how much memory each process has resident over time,
and samples of page faults with their stacks, which show the code that
first touched memory, of a program it starts or one already running. It
names
the code Python 3.12+ and Node compile from their perf maps. It samples with
one of two samplers:

- **perf**, without root, or with `--sampler perf`.
- **uhr's eBPF sampler**, as root (or with CAP_BPF and CAP_PERFMON). It also
  counts and times syscalls, sees what woke each thread that waited, and
  reads the frames of CPython 3.11 to 3.14,
  Node 20 to 24, Bun 1.4.3, Ruby 3.2, PHP 8.3, Lua 5.4 and Java's interpreter
  ([limits](docs/collection.md#runtimes)), with the async functions of Node
  and Bun that wait for the one that runs as its callers.

On macOS uhr samples with a sampler of its own, without root for a program
it starts, and records CPU time in user and kernel mode with user stacks,
time off CPU with the stacks threads waited at, and each process's memory.
It reads the frames of CPython, Node and Bun 1.4.3's build for arm64 as the
eBPF sampler does, checked with CPython 3.13 and Node 24, but not yet those
of the other runtimes.
macOS shows no process the kernel's stacks, so time in the kernel is under
the user code that entered it, and there are no wakeups, syscall counts or
page faults. dyld leaves uhr's library out of programs the system protects,
as those in `/usr/bin`, and hardened ones ([limits](docs/collection.md#uhrs-sampler-on-macos)).

## How the macOS sampler works

About a thousand times a second, uhr reads each thread's CPU time and state. A
thread that ran since the last time, or can run now, it holds still for about
16 microseconds and walks its stack with the unwind tables of the images in
its process, and if it runs Python or JavaScript, their frames from the
process's memory. The CPU time since the last poll goes to that stack. A
thread that waits costs one call, and its time off CPU goes to the stack it
waits at. uhr gets each process's task port from a small library it has dyld
load into the program and every process that program starts, which sends the
port to uhr before the program's own code runs.

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

uhr overview rec                                   # computing or waiting? how big?
uhr query rec --group-by function                  # top functions
uhr query rec --group-by line --under parse_json   # hot lines under a function
uhr query rec --group-by syscall --metric off-cpu  # syscalls threads waited in
uhr query rec --group-by waker --metric off-cpu --under lock_slow  # who ended those waits
uhr query rec --group-by function --from 2026-11-06T12:34:56Z  # from a time in a log
uhr query rec --group-by function --metric page-faults  # code that grew memory
uhr query rec --group-by region --metric page-faults    # heap, files, or mappings?
uhr call-paths rec --function memcpy               # callers and callees
uhr flamegraph rec -o cpu.svg                      # a flame graph to open
uhr export rec --format firefox -o profile.json     # explore in Firefox Profiler
```

Add `--json` to any but `record` for output an agent can read. See
`uhr query --help` for the other groupings and the filters by process, thread,
mode and time.

An agent can also read a recording over MCP: `uhr mcp` serves `overview`,
`query` and `call_paths` on stdin and stdout. Register it with the agent's
client, as with `claude mcp add uhr -- uhr mcp`. See the [agent
interface](docs/agent-interface.md#mcp-server).

Open the exported file at [Firefox Profiler](https://profiler.firefox.com/)
to select threads, narrow the time range, and explore call trees, flame graphs,
waits and memory. Export accepts the same filters as queries. `--json` prints
the export summary; `-o` names a new profile file and never overwrites an
existing file. See [viewer exports](docs/export.md) for coverage and limits.

Full stacks need frame pointers. `uhr doctor` lists the build flags, or record
with `--unwind dwarf`, which needs no rebuild but copies the stack in every
sample. On macOS, stacks are walked with each image's unwind tables, and
`--sampler`, `--unwind dwarf`, `--stack-size` and `--skip-syscall` are for
Linux only. Attaching with `--pid` needs `sudo` there.

## Docs

- [Vision](docs/vision.md): problem, goals, non-goals.
- [Model](docs/model.md): recordings, observations, dimensions, levels,
  coverage, storage.
- [Format](docs/format.md): the on-disk schema of a recording.
- [Viewer exports](docs/export.md): Firefox Profiler and what it can show.
- [Collection](docs/collection.md): collectors, runtimes, code origin
  resolution, platforms, privileges.
- [Agent interface](docs/agent-interface.md): tools, result behavior,
  measurement rigor.

In the docs, **must** marks a requirement the design depends on, and
**candidate** one possible approach, with alternatives welcome. Tool and field
names are sketches of the shape, not final APIs.

## License

[MIT](LICENSE), except that `crates/uhr-ebpf`, which holds the eBPF programs,
is under your choice of MIT or [GPL-2.0](crates/uhr-ebpf/LICENSE-GPL2). The
kernel only lets GPL-compatible programs use the helpers they need.
