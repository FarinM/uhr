# Agent interface

The same operations are exposed over MCP and a CLI. Tool names and
parameters below are a sketch to show the shape. The requirements are the
behaviors.

## Principles

- Answer questions, never dump raw profiles. Recordings stay on disk. Results
  are compact and carry IDs to drill down.
- Prefer a few tools composed through filters and grouping over many
  single-purpose tools.
- Every result carries coverage. See [model](model.md#coverage).
- Results are structured (JSON with a published schema) with a short readable
  form.
- Large results are paged, and truncation is always reported.
- Times in results and filters are nanosecond offsets from the recording
  start. Raw clock values are large numbers that are easy to get wrong.

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
