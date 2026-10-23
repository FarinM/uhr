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

A directory without `manifest.json` is a recording that did not finish.

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
| `target.exit` | `{"code": n}`, `{"signal": n}`, `{"unknown": reason}` when the observed status can't be trusted, or null if it was still running |
| `clock` | `CLOCK_MONOTONIC` |
| `start_ns`, `end_ns` | First and last timestamp seen. Null if nothing was recorded |
| `streams` | One per collector that ran |

Each stream has:

| Field | Meaning |
|---|---|
| `id` | Unique within the recording |
| `collector` | `name` plus the collector's version and settings. For perf: `version`, `event`, `frequency_hz` (what perf sampled at), `requested_frequency_hz`, `unwinding` |
| `signals` | What was captured: `cpu_samples`, `user_stacks`, `kernel_stacks` |
| `missing_signals` | Signals requested but not captured, each with a `reason` |
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
