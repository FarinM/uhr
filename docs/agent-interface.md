# Agent interface

The same operations are exposed over MCP and a CLI. Tool names and
parameters below are a sketch to show the shape. The requirements are the
behaviors.

## Principles

- Answer questions, never dump raw profiles. Recordings stay on disk. Results
  are compact and carry IDs to drill down. A function's id is its build-id,
  or its path when there is none, and its start address. Starts come from
  symbols or the binary's unwind tables, so the id stays the same in every
  result and after symbols are resolved again. An inlined function has no
  start: its id is its build-id or path and a hash of its name and the file
  and line it is declared at. Other code without a known start has no id: kernel code, a
  recording not yet symbolized, and the range a stripped binary's
  `EntryPoint` placeholder covers.
- Prefer a few tools composed through filters and grouping over many
  single-purpose tools.
- Every result carries coverage. See [model](model.md#coverage).
- Results are structured (JSON with a published schema) with a short readable
  form.
- Large results are paged, and truncation is always reported.
- Times in results and filters are nanosecond offsets from the recording
  start, which `overview` gives once as a clock value. Raw clock values are
  large numbers that are easy to get wrong.

## Sketch of the tool surface

| Tool | Purpose |
|---|---|
| `record` | Launch or attach, choose signals, threads and duration. Returns a recording ID and the overview |
| `overview` | Time and memory level 0 plus coverage. The first call of any investigation |
| `query` | Group and filter observations at any level: metric, group_by, filters, time range, top N |
| `call_paths` | Callers and callees of a selected node |
| `annotate` | Per-line and per-instruction cost of one function, with hardware counters when captured |
| `timeline` | Thread state intervals with reasons, for selected threads and a time range. Aggregated signals show one value per window |
| `compare` | The same query on two recordings, with significance |
| `benchmark` | Repeated runs of a command with statistics |
| `sql` | Later: direct SQL over a recording's Parquet files. See [storage](model.md#storage) |
| `export` | Write Perfetto, Firefox Profiler or speedscope files for human review |
| `doctor` | What the requested signals need on this target and host |

`call_paths` takes a function by its id, or by a name only one function
has, and returns two trees from it outward: its callers and its callees. Both
stop at a depth limit and keep the top children of each node, and they report
the time of what they cut. Where a function recurses, each sample counts from
its outermost call, so the callers show where the function is entered.

A function picked the same way also works as a filter: `under` keeps the
samples whose stack contains it. One recording can then be split by the code
that led to the time, such as one benchmark of several in a run.

Moving across levels on one recording:

```
query(group_by=mode)                                    kernel 45%, user 55%
query(filter={mode: kernel}, group_by=syscall)          futex 31%, read 9%
query(filter={syscall: futex}, group_by=user_function)  Pool.acquire 28%
timeline(threads="pool-*", filter={syscall: futex})     14 threads waiting on one lock
```

## Measurement rigor

The agent's main loop is measure, change, measure. The tools must make noise
visible.

- `benchmark` runs warmups and repetitions and reports the median with a
  confidence interval, plus noise signals (high variance, thermal throttling,
  frequency changes).
- `compare` returns a verdict (faster, slower, no significant difference) with
  effect size, interval and run counts. It must not report a difference inside
  the noise as an improvement.
- Profiling overhead is measured and reported. Instrumenting profilers distort
  heavily, and sampling profilers have known biases.

## Agent skill

Ship instructions that teach a method, not a list of tools:

1. Benchmark a baseline.
2. Call `overview`: is it computing or waiting?
3. Choose signals from the answer. CPU-bound: stack sampling. Waiting: off-CPU,
   syscalls, locks. Growing memory: allocations and heap snapshots.
4. Zoom with `query` and `call_paths`. Check coverage before trusting a result.
5. Change one thing, run `compare`, and keep the change only if the difference
   is significant.

## Humans review the evidence

Every recording can be exported to a standard viewer, so a person can check
what the agent claims.
