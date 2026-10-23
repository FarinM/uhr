# Model

Everything else depends on this. Collectors write into the model, and every
agent-facing tool reads only from it. Adding a runtime or signal should mean
writing a collector, not new analysis tools. Field names here are
illustrative; the concepts are the requirement.

## Recording

A recording is one profiling session of one target. It contains:

- **Target**: what was profiled (command, PID, container, remote host, browser
  page, existing production data) and whether it was launched or attached.
- **Streams**: one per collector that ran. Each stream states its collector,
  version, settings (rate, filters), the signals it captured, and its own
  coverage.
- **Shared clock**: all observations sit on one monotonic timeline. Collectors
  with their own clocks are aligned by a measured offset.
- **Process and thread table**: every process and thread seen, with lifetime
  and name history.
- **Mapping table**: the memory mappings and code regions seen, so addresses
  can be resolved after recording.

A finished recording must be immutable. Analysis never changes it; derived
results reference it.

## Observations

Four shapes cover everything known so far:

| Shape | Meaning | Examples |
|---|---|---|
| Sample | A weighted point in time | CPU sample, allocation sample, hardware counter overflow |
| Interval | A span with a start and end | thread blocked on a futex, a syscall, GC pause, JIT compile, app span |
| Counter | A value over time | RSS, heap size, thread count, CPU frequency |
| Aggregate | Totals over a time window, for events too frequent to record one by one | count, total time and latency histogram per thread and syscall, per window |

An aggregate holds its keys (for example thread, syscall, stack), its time
window, a count, a total and a latency histogram. It has no per-event
timestamps. Aggregates answer group-by queries and show as a coarse timeline,
one value per window. They cannot say what overlapped what, and latency
percentiles are only as precise as the histogram buckets. Results built on
aggregates must say so.

## Dimensions

Every observation carries the dimensions that apply to it. Shared dimensions
are what make cross-level queries possible.

| Dimension | Values | Notes |
|---|---|---|
| time | timestamp, duration | on the shared clock |
| process, thread | pid, tid | links to the thread table for names and roles |
| cpu | core id | optional |
| mode | user, kernel | for on-CPU samples |
| thread state | running, runnable, blocked (io, lock, sleep, page fault, other) | for intervals and off-CPU samples |
| syscall | number and name | when the thread is inside a syscall |
| stack | ordered frames, kernel to user | interned, see frames |
| values | cpu_ns, wall_ns, alloc_bytes, live_bytes, counter events, ... | one observation can carry several |
| context | GC phase, JIT tier, app span or request id | optional, from runtimes or app instrumentation |

### Frames

A frame must record its **origin**, not only a name:

| Origin | Example |
|---|---|
| binary | function in an ELF, Mach-O or PE file or shared library |
| kernel | kernel or kernel module function |
| bpf_prog | JIT-compiled eBPF program |
| jit | JIT-compiled code, with runtime and tier (baseline, optimized) when known |
| interpreted | interpreter-level frame (Python, Ruby, bytecode VMs) |
| unresolved | an address that could not be named, with the region it falls in |

Each frame also has the address, function, module, file:line when known, and
whether it was inlined. Unresolved frames must be kept, never dropped, so
coverage can be computed.

A mixed stack is one stack: kernel, native and runtime frames in call order.
How runtime frames get merged with native ones depends on the collector. See
[collection](collection.md).

## Levels are projections

High-level and low-level views are not separate data. They are groupings and
filters over the same observations.

Time:

| Level | Question | Group by |
|---|---|---|
| 0 process/thread | Computing or waiting? | mode, thread state |
| 1 kernel | Which syscalls, faults, interrupts? | syscall, fault type, kernel function |
| 2 runtime/module | Interpreter, JIT, native library, GC or kernel? | origin, module, JIT tier, GC phase |
| 3 function | Which code? | function, call path |
| 4 line | Which line? | file:line |
| 5 instruction | Compute-bound or memory-bound? | address and hardware counters |

Memory:

| Level | Question | Data |
|---|---|---|
| 0 resident | How big, what kind, over time? | RSS by category: heap, anonymous, file-backed, thread stacks, code and JIT cache |
| 1 allocator/runtime | Native or GC heap, and how much is overhead? | allocator and runtime heap stats |
| 2 allocation site | Which code allocates? | allocation samples with stacks |
| 3 object/type | What keeps it alive? | heap snapshots: types, retained size, retainer paths |

An agent must be able to move between levels by changing grouping and filters
on the same recording, without recording again. For example: mode, then
syscall, then the user-space function making the syscall, then a timeline of
the affected threads.

## Memory has three numbers

The model must keep these separate, and tools must never blend them:

- **Allocated**: bytes allocated over a period (churn). Drives GC and
  allocator CPU cost.
- **Live**: bytes in use at a point in time. Leaks show up here.
- **Resident**: what the OS holds in RAM for the process.

Resident minus live is overhead: fragmentation, allocator caches, GC headroom,
thread stacks, code. Memory levels 0 and 1 should explain that gap by
category. Allocation samples record the allocating thread.

Memory and time link up. Page faults are attributed to stacks, and time in
`malloc`, `free` and GC shows up in the time levels.

## Threads

- Identity: tid, name history (kernel name, pthread name, runtime thread name),
  and role when known (main, GC, JIT compiler, pool worker, I/O).
- Every query can filter or group by a thread or a thread group (name pattern,
  role).
- Blocked intervals record why the thread blocked and, when available, which
  thread woke it. That lets lock contention be shown as a holder and its
  waiters.

## Coverage

Every recording, stream and query result must carry coverage. At minimum:

- share of time or samples attributed vs unresolved, by origin
- truncated stacks
- dropped or lost events
- signals requested but not captured (platform, permissions)
- threads not covered
- measured profiler overhead
- known biases of the collectors used

Missing coverage is "unknown", never zero. A result whose coverage cannot be
computed must say so.

## Storage

A recording is a directory of Parquet files in our own schema, plus a JSON
manifest that records the schema version. It is written once and never
changed. Symbols resolved later are added as extra files.

The tools read recordings through our own query code in Rust, with no database
engine. Agents use the tools, which take plain arguments such as group by,
filters, time range and top N, not a query language.

Direct SQL over a recording must stay possible later, for agents and people:

- Use only standard Parquet types. No opaque columns such as serialized
  structs: every field must be readable as is by DuckDB, DataFusion, Polars and
  similar tools.
- Document and version the schema.
- Keep the tools' query code behind one internal layer, so a SQL engine can be
  added beside it without changing the format. DataFusion is the pure-Rust
  candidate.

Other formats (pprof, Perfetto, Firefox Profiler, speedscope, flame graphs) are
for import and export only. None of them holds everything this model needs.
