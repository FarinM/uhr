# Recording format

The on-disk form of the [model](model.md). This is version 0: it can change
in any commit, and readers reject other versions. Compatibility starts at
version 1.

A recording is a directory:

| File | Contents |
|---|---|
| `manifest.json` | Format version, target, clock and streams. Written last |
| `threads.parquet` | Every thread seen, with its lifetime |
| `thread_names.parquet` | Name history per thread |
| `mappings.parquet` | Executable memory mappings, for resolving addresses |
| `frames.parquet` | Unique frames, before symbol resolution |
| `stacks.parquet` | Unique stacks as lists of frames |
| `samples.parquet` | CPU samples |
| `off_cpu.parquet` | Times threads spent off CPU, with why and where |
| `kernel_symbols.parquet` | The kernel functions kernel frames fall in, read while recording |
| `jit_symbols.parquet` | The code runtimes compiled that frames fall in, named in the runtimes' perf maps while recording |
| `symbols.parquet` | Function name per frame, after symbol resolution |
| `symbol_sources.parquet` | Files the names came from, and why some frames have none |
| `inline_frames.parquet` | Inlined calls and source lines per frame, from debug info |

A directory without `manifest.json` is a recording that did not finish. The
three symbol files are the only ones that change: resolving symbols again
replaces them.

## Conventions

- Times are nanoseconds on the clock named in the manifest.
- Ids count up from 0 in row order, so an id is also a row number.
- Null never stands for zero. Each nullable column says what null means.
- Only standard Parquet types: unsigned integers, UTF-8 strings, booleans and
  lists of `uint32`. Pages are zstd-compressed.

## manifest.json

| Field | Meaning |
|---|---|
| `format_version` | `0` |
| `platform.os`, `platform.arch` | The system the target ran on, as Rust names them, such as `linux` and `x86_64`. It says how to read what was recorded: uhr finds syscalls only in stacks recorded on Linux, from its kernel's function names |
| `target.command` | Command and arguments. Empty for an attached process without a command line, such as a kernel thread |
| `target.launched` | True if the recording started the target, false if it attached |
| `target.runtime_support` | The runtimes whose perf maps were on in the target's environment, so that they named the code they compiled: `python`, `node`. Null for a process uhr attached to, whose environment it did not see |
| `target.exit` | `{"code": n}`, `{"signal": n}`, `{"unknown": reason}` when uhr could not see the status, as for a process it attached to, or null if it was still running |
| `clock` | `CLOCK_MONOTONIC` |
| `start_ns`, `end_ns` | When the capture started and stopped: the first and last event, or when perf began sampling a process uhr attached to if that came earlier, and when uhr stopped the recording if that came later, at an interrupt or the end of `--duration`. Null if nothing was recorded |
| `streams` | One per collector that ran |
| `kernel_symbols` | `{"status": "saved"}` if the kernel's symbols were read while recording, or `{"status": "unavailable", "reason": ...}` if not, and then kernel frames have no names |

Each stream has:

| Field | Meaning |
|---|---|
| `id` | Unique within the recording |
| `collector` | `name` plus the collector's version and settings. For perf: `version`, `event`, `frequency_hz` (what perf sampled at), `requested_frequency_hz`, `unwinding` (`frame_pointers` or `dwarf`), `stack_copy_bytes` (user stack copied with each sample as perf used it, null without `dwarf`), `context_switches` (whether perf recorded every context switch) |
| `signals` | What was captured: `user_cpu_samples`, `kernel_cpu_samples`, `user_stacks`, `kernel_stacks`, `off_cpu_time` (when threads went off CPU and came back, and whether they were preempted), `off_cpu_stacks` (where they went off CPU) |
| `missing_signals` | Signals requested but not captured, each with a `reason`. Without `kernel_cpu_samples`, CPU time spent in the kernel is not in the samples at all, not merely unnamed. Threads go off CPU in the kernel, so without kernel sampling `off_cpu_stacks` is missing too |
| `coverage.lost_events` | Events the kernel dropped |
| `coverage.stacks` | For a collector that takes stacks, the counts below. Null for one that takes none |
| `coverage.stacks.samples` | Samples written |
| `coverage.stacks.off_cpu_intervals` | Off-CPU intervals written. Null without `context_switches` |
| `coverage.stacks.throttle_events` | Times the kernel throttled sampling |
| `coverage.stacks.max_stack_depth` | Stacks deeper than this were cut |
| `coverage.stacks.stacks_at_stack_limit` | Stacks that reached that depth. This and the next two count every stack: one per sample and one per switch out |
| `coverage.stacks.stacks_cut_at_stack_copy` | Stacks that went on past the end of their stack copy, so their outer callers are missing. Null without `dwarf` |
| `coverage.stacks.stacks_not_unwound` | Stacks of 32-bit code, which `dwarf` unwinding cannot walk. They keep only the instruction they were taken at. Null without `dwarf` |
| `coverage.overhead_ns` | Profiler overhead. Null until it is measured |
| `coverage.known_biases` | Biases of this collector, in words |

## Tables

`threads`, one row per thread lifetime. The kernel reuses ids, so `pid` and
`tid` can repeat; `start_ns` tells the rows apart.

| Column | Type | Meaning |
|---|---|---|
| `pid`, `tid` | uint32 | |
| `parent_pid`, `parent_tid` | uint32, nullable | The thread that created it. Null if it started before the recording |
| `start_ns` | uint64, nullable | Null if the thread started before the recording |
| `end_ns` | uint64, nullable | Null if the thread outlived the recording, or its exit was not seen |

`thread_names`:

| Column | Type | Meaning |
|---|---|---|
| `pid`, `tid` | uint32 | |
| `time_ns` | uint64, nullable | When the name was set. Null if before the recording |
| `name` | string | |

`mappings`:

| Column | Type | Meaning |
|---|---|---|
| `mapping_id` | uint32 | |
| `pid` | uint32, nullable | Null for kernel mappings. A forked process shares its parent's mappings of files, but has its own copy of other memory its frames fall in, such as a JIT's, which each process fills in its own way |
| `start`, `end` | uint64 | Address range, end exclusive. Kernel mappings end where the next one starts: perf gives a module the start of its code and its total size, but its data can lie elsewhere |
| `file_offset` | uint64 | File offset of `start` |
| `path` | string | File path, or a name such as `[vdso]` or `//anon`. `[kernel]` for the kernel, and the module name in brackets for a kernel module, as in `[ext4]` |
| `build_id` | string, nullable | Hex. Null if the kernel could not read it |
| `time_ns` | uint64, nullable | When it was mapped. Null if before the recording |

`frames`:

| Column | Type | Meaning |
|---|---|---|
| `frame_id` | uint32 | |
| `origin` | string | `binary`, `kernel`, `jit` or `unresolved`. See [frames](model.md#frames). `jit` is code a runtime compiled in anonymous memory, which its perf map names |
| `address` | uint64 | Address in the process, or in the kernel |
| `mapping_id` | uint32, nullable | Region containing the address. Null if none is known |
| `file_offset` | uint64, nullable | Offset in the mapped file. Null without a file mapping |
| `return_address` | bool | True if the address is a return address, which points one instruction past the call |

`stacks`:

| Column | Type | Meaning |
|---|---|---|
| `stack_id` | uint32 | |
| `frame_ids` | list of uint32 | Leaf first |

`samples`:

| Column | Type | Meaning |
|---|---|---|
| `time_ns` | uint64 | |
| `pid`, `tid` | uint32 | |
| `cpu` | uint32, nullable | Null if not recorded |
| `mode` | string | `user`, `kernel` or `unknown` (hypervisor, guest) |
| `stack_id` | uint32 | |
| `cpu_ns` | uint64 | CPU time this sample stands for |

`off_cpu`, one row per time a thread was switched out, sorted by
`start_ns`. A thread still off CPU when the capture ends stays off until
then. One already off CPU when an attached capture starts is off from then
until it first runs, or all along if it never does. A new thread's wait for
its first run is not included, nor is a time off CPU whose switch back in
the kernel dropped, since when it ended is unknown.

| Column | Type | Meaning |
|---|---|---|
| `start_ns`, `end_ns` | uint64 | When it was switched out and back in |
| `pid`, `tid` | uint32 | |
| `state` | string | `runnable` if it was preempted and waited for a CPU, `blocked` if it gave up the CPU to wait, for a lock, I/O, a timer or another thread. Only switches are recorded, not wakeups, so the time a woken thread then waits for a CPU counts as `blocked`. `unknown` if it was off CPU already when an attached capture started, so its switch out was not seen |
| `stack_id` | uint32, nullable | The stack it was switched out at. Null if the stack was not recorded: without kernel sampling, when the kernel dropped it, or when the switch out came before the capture |

`kernel_symbols`, sorted by `start`, with ranges that don't overlap. The
kernel moves to a random address on every boot, and modules come and go, so
`/proc/kallsyms` is read right after recording and the functions kernel
frames fall in are kept. A module can list stale names at addresses another
module now holds, so a frame in a mapping takes its function from the
mapping's module only. A frame outside every mapping, such as in a BPF
program, takes it from the modules without a mapping. Of a module's names at
one address, the one perf shows is kept, and the markers that ARM and RISC-V
put between code and data are skipped, as the kernel's own lookups skip
them.

| Column | Type | Meaning |
|---|---|---|
| `start`, `end` | uint64 | Address range, end exclusive. A function ends where the next one of its module starts, or where its mapping ends. Outside every mapping, it ends where the next such function or the next mapping starts |
| `name` | string | |
| `module` | string, nullable | The module, as in `ext4`, or `bpf` for a BPF program. Null for the kernel itself |

`jit_symbols`, sorted by `pid` and `start`, with ranges that don't overlap
in a process. A runtime that compiles code as it runs, such as Python 3.12
and later or Node, can name it in a perf map, `/tmp/perf-<pid>.map`, which
uhr reads right after recording and keeps the code frames fall in from. A
map written before its process started belongs to an earlier process with
the pid, and is left out. Where code took the place of older code, the
newer name holds, so samples of the older code there get the newer name.

| Column | Type | Meaning |
|---|---|---|
| `pid` | uint32 | The process the code ran in |
| `start`, `end` | uint64 | Address range, end exclusive |
| `name` | string | As the runtime wrote it, as in `py::inner:/app/spin.py` or `JS:*parse /app/x.js:42:7` |

## Symbols

Written by `uhr symbolize`, which `uhr record` runs unless told not to. Names
are matched to files by build-id, and come from the binary or from a separate
debug file found by build-id or debug link. Kernel frames are named from
`kernel_symbols`, and JIT frames from `jit_symbols`, which the recording
saved.

Each file is copied to a private temporary snapshot before reading its identity
or symbols. Subsequent reads use that snapshot while debug-file lookup retains
the original path. Snapshots are released after resolving each binary. This
uses temporary disk space and copy I/O proportional to that binary and its debug
files, without requiring their entire contents to stay in RAM. An in-place
write detected during copying fails resolution for that file.

Function queries group by build-id, or by module path for a file without one,
and relative function start. So distinct functions sharing a name stay
separate, while remappings of a function and copies of its binary at other
paths combine. JSON rows expose `build_id` and `function_address`; the
readable output includes the address beside the name. Kernel code outside
every mapping has no start to count from. A BPF program groups by the tag
and name in its kernel symbol, `bpf_prog_<tag>_<name>`, and has the id
`bpf+<tag>_<name>`: the tag hashes its instructions, so loading the program
again keeps the id. Other such code, like BPF trampolines, groups by its
kernel symbol and has no id.

Code a runtime compiled moves from run to run, so it groups by what the
runtime called it. One of the program's functions, from a name uhr can read,
groups by its runtime, file and name across processes, and has the id
`jit+<runtime>:<name>:<file>`, as in `jit+python:inner:/app/spin.py`. The
name has `%`, `:` and `@` escaped as `%25`, `%3A` and `%40`, so no two
functions share an id. An anonymous one has `@` and where it starts, escaped
the same way, in place of the name, as in `jit+node:@12%3A7:/app/x.js`. Its
module is its runtime in brackets, as in `[python]` or `[node]`, and its
file is the source file. Other code, such as V8's builtins, groups by its
name in the map, with the id `jit+<runtime>+<name>`, as in
`jit+node+Builtin:ArrayPrototypePush`, or `jit:<name>` for a runtime uhr
does not know. V8 inlines functions into
the code it optimizes, and its map cannot say so, so their time counts for
the function they were inlined into.

Queries expand each frame's inlined calls from `inline_frames`, so time in
inlined code counts for the inlined function. An inlined function has no
address: it groups by build-id (or path), name and declaration (file and
line), across every function it was inlined into. The declaration stays the
same where the code itself reports other files, as code from macros or
`#line` directives does. A copy of it that was called rather than
inlined is a separate function. Code without debug info cannot be expanded,
and results list the files that have none.

Grouped by line, a row is a function and a line from `inline_frames`. Self
time goes to the innermost line, and total time to every line on the stack,
which for a caller is the line of the call. Code without line info keeps its
time in a row with no line.

`symbols`:

| Column | Type | Meaning |
|---|---|---|
| `frame_id` | uint32 | One row per frame |
| `function_address` | uint32, nullable | Function start relative to the binary's image base, including functions with placeholder labels. For kernel code, relative to the start of the kernel's or the module's mapping. Null when no function boundary was resolved |
| `function` | string, nullable | Null if no name was found. The frame's source says why |
| `placeholder` | string, nullable | A label wholesym made up from the address when the code has no symbol, such as `fun_1200` in a stripped binary. It tells functions apart, but is not a name. Null when `function` is set |

Real names are identified from DWARF or the symbol tables of the binary and
verified debug artifacts, including MiniDebugInfo. A genuine name that resembles
a placeholder still counts as named; rejected debug candidates supply no names.

`symbol_sources`, one row per file. A frame's source is the row whose `path`
and `build_id` match the frame's mapping. Kernel frames share one row with
path `[kernel]`, and JIT frames one with path `[jit]`.

| Column | Type | Meaning |
|---|---|---|
| `path` | string | |
| `build_id` | string, nullable | As recorded. Null if the kernel could not read it |
| `status` | string | See below |
| `detail` | string, nullable | For example how many frames got a name, or the error |

| Status | Meaning |
|---|---|
| `resolved` | The file's build-id matches the recording |
| `unverified` | Resolved, but there was no recorded build-id to check |
| `missing_file` | The file is gone |
| `build_id_mismatch` | The file changed since recording. No names are taken from it |
| `unsupported` | `[vdso]` and other code that is not read from a file |
| `failed` | Reading the file failed |
| `unavailable` | The names could not be read while recording, the only time they could be. The kernel's, when the manifest's `kernel_symbols` is unavailable |

`inline_frames`, one row per frame and function at the frame's address, from
debug info. A frame inside inlined code has a row for each inlined call and
one for the function the machine code belongs to; a frame without debug info
has none. uhr reads it from the DWARF with addr2line, and demangles names by
their source language, so ELF names keep their leading underscores. Symbols
resolved before this table existed have to be resolved again.

| Column | Type | Meaning |
|---|---|---|
| `frame_id` | uint32 | Rows of a frame are together |
| `depth` | uint32 | 0 for the innermost inlined call, counting up to the function the machine code belongs to |
| `function` | string, nullable | Null if the debug info has no name |
| `file` | string, nullable | Source file, as written in the debug info. Null if unknown |
| `line` | uint32, nullable | Line in `file`. For a caller's frame, the line of the call. Null if unknown |
| `decl_file` | string, nullable | Source file the function is declared in. Null if the debug info does not say |
| `decl_line` | uint32, nullable | Line of the declaration in `decl_file`. Null if unknown |
