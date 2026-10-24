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
| `symbols.parquet` | Function name per frame, after symbol resolution |
| `symbol_sources.parquet` | Files the names came from, and why some frames have none |

A directory without `manifest.json` is a recording that did not finish. The
two symbol files are the only ones that change: resolving symbols again
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
| `target.command` | Command and arguments |
| `target.launched` | True if the recording started the target, false if it attached |
| `target.exit` | `{"code": n}`, `{"signal": n}`, `{"unknown": reason}` when the observed status can't be trusted, or null if it was still running. The perf collector reports signal exits as unknown: perf can re-raise its own signal rather than the target's |
| `clock` | `CLOCK_MONOTONIC` |
| `start_ns`, `end_ns` | First and last timestamp seen. Null if nothing was recorded |
| `streams` | One per collector that ran |

Each stream has:

| Field | Meaning |
|---|---|
| `id` | Unique within the recording |
| `collector` | `name` plus the collector's version and settings. For perf: `version`, `event`, `frequency_hz` (what perf sampled at), `requested_frequency_hz`, `unwinding` |
| `signals` | What was captured: `user_cpu_samples`, `kernel_cpu_samples`, `user_stacks`, `kernel_stacks` |
| `missing_signals` | Signals requested but not captured, each with a `reason`. Without `kernel_cpu_samples`, CPU time spent in the kernel is not in the samples at all, not merely unnamed |
| `coverage.samples` | Samples written |
| `coverage.lost_events` | Events the kernel dropped |
| `coverage.throttle_events` | Times the kernel throttled sampling |
| `coverage.max_stack_depth` | Stacks deeper than this were cut |
| `coverage.samples_at_stack_limit` | Samples whose stack reached that depth |
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
| `pid` | uint32, nullable | Null for kernel mappings |
| `start`, `end` | uint64 | Address range, end exclusive |
| `file_offset` | uint64 | File offset of `start` |
| `path` | string | File path, or a name such as `[vdso]` or `//anon` |
| `build_id` | string, nullable | Hex. Null if the kernel could not read it |
| `time_ns` | uint64, nullable | When it was mapped. Null if before the recording |

`frames`:

| Column | Type | Meaning |
|---|---|---|
| `frame_id` | uint32 | |
| `origin` | string | `binary`, `kernel` or `unresolved`. See [frames](model.md#frames) |
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

## Symbols

Written by `uhr symbolize`, which `uhr record` runs unless told not to. Names
are matched to files by build-id, and come from the binary or from a separate
debug file found by build-id or debug link.

Each file is copied to a private temporary snapshot before reading its identity
or symbols. Subsequent reads use that snapshot while debug-file lookup retains
the original path. Snapshots are released after resolving each binary. This
uses temporary disk space and copy I/O proportional to that binary and its debug
files, without requiring their entire contents to stay in RAM. An in-place
write detected during copying fails resolution for that file.

Function queries group by module path, build-id and relative function start,
so distinct functions sharing a name stay separate and remappings of the same
function still combine. JSON rows expose `build_id` and `function_address`;
the readable output includes the address beside the name.

Inline call chains are not yet expanded. Query coverage explicitly reports
that self time is attributed to the enclosing machine function. Supporting
inline function identity requires additional information from the symbol engine.

`symbols`:

| Column | Type | Meaning |
|---|---|---|
| `frame_id` | uint32 | One row per frame |
| `function_address` | uint32, nullable | Function start relative to the binary's image base, including functions with placeholder labels. Null when no function boundary was resolved |
| `function` | string, nullable | Null if no name was found. The frame's source says why |
| `placeholder` | string, nullable | A label wholesym made up from the address when the code has no symbol, such as `fun_1200` in a stripped binary. It tells functions apart, but is not a name. Null when `function` is set |

Real names are identified from DWARF or the symbol tables of the binary and
verified debug artifacts, including MiniDebugInfo. A genuine name that resembles
a placeholder still counts as named; rejected debug candidates supply no names.

`symbol_sources`, one row per file. A frame's source is the row whose `path`
and `build_id` match the frame's mapping. Kernel frames share one row with
path `[kernel]`.

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
| `unsupported` | Kernel, `[vdso]` and other code that is not read from a file |
| `failed` | Reading the file failed |
