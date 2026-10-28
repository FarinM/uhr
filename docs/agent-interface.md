# Agent interface

The same operations are exposed over MCP and a CLI. Tool names and
parameters below are a sketch to show the shape. The requirements are the
behaviors.

## Principles

- Answer questions, never dump raw profiles. Recordings stay on disk. Results
  are compact and carry IDs to drill down. A function's id is its build-id,
  or its path when there is none, and its start address. Starts come from
  symbols or the binary's unwind tables, so the id stays the same in every
  result and after symbols are resolved again. A kernel function's start
  counts from the kernel's or its module's mapping, so its id stays the same
  across boots, which move the kernel. An inlined function has no start: its
  id is its build-id or path and a hash of its name and the file and line it
  is declared at. A BPF program's id is `bpf+` and the tag and name of its
  kernel symbol: the tag hashes its instructions, so the id stays the same
  when the program is loaded again. Code a runtime compiled or interpreted
  has its runtime, name, file and, where known, where it starts, as in
  `jit+node:parse@42%3A3:/app/x.js` or `jit+python:inner:/app/spin.py`. Other code
  without a known start has no id: other kernel code outside every mapping, such as BPF trampolines, a
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
| `record` | Launch or attach, choose signals or collectors, threads and duration. Returns a recording ID, which collectors ran and why, and the overview |
| `overview` | Time and memory level 0 plus coverage. The first call of any investigation |
| `query` | Group and filter observations at any level: metric, group_by, filters, time range, top N |
| `call_paths` | Callers and callees of a selected node |
| `flamegraph` | Draw the stacks that pass a filter as a flame graph, for a person to open, from the start of each thread or from one function |
| `annotate` | Per-line and per-instruction cost of one function, with hardware counters when captured |
| `timeline` | Thread state intervals with reasons, for selected threads and a time range. Aggregated signals show one value per window |
| `sql` | Later: direct SQL over a recording's Parquet files. See [storage](model.md#storage) |
| `export` | Write Perfetto, Firefox Profiler or speedscope files for human review |
| `doctor` | For a target on this host: what each collector would capture, what blocks the rest and how to fix it, and which ones `record` would use |

`overview` gives each process's memory from its readings in the window: the
first, the last and the one with the most resident, each with its split into
the process's own memory, files and shared memory, its swap, and the most it
had resident as the kernel tracked it, between readings too. Memory is read
per process, so only filters by process and time apply to it, and a filter
by thread, mode, stack or syscall leaves it out, as the result says.

`call_paths` takes a function by its id, or by a name only one function
has, and returns two trees from it outward: its callers and its callees. Both
stop at a depth limit and keep the top children of each node, and they report
the time of what they cut. Where a function recurses, each sample counts from
its outermost call, so the callers show where the function is entered.

`flamegraph` takes the metric and filters `query` takes, and a function to
start at, picked as `call_paths` picks one, from its outermost call. It writes
an interactive SVG, or the folded stacks other flame graph tools read, and
returns how much of the time it shows, with coverage. Each function is a
block as wide as its time, on top of its caller: red to yellow for native
code, blue for the kernel, green for a runtime's code, aqua for inlined calls
and grey for code without a name. Functions of one name say where they are
from, by the first of their file and start, module, file or id that tells
them apart, as `(anonymous) (app.js:12:7)`, and any label still shared after
that gets the function's id, so no two functions share a block. A `;` or
control character in a label is written as `\u` and four hex digits, as
recordings write what is no character, so that it neither ends a frame of
the folded stacks nor breaks the SVG.

`query` groups by function, source line, module or syscall. A module is a
binary or library, by build-id or by path without one, or the kernel or one
of its modules. Its self time is time running its code, and its total time is
time with it anywhere on the stack, which for the libc that starts most
threads is nearly all of it.

A stack's syscall is read from the kernel functions on it: the one the
syscall entered, such as `__x64_sys_read` for `read`. That needs no tracing,
but gives the time in each syscall, not how often it was called or how long
each call took. Where uhr's eBPF programs ran, each syscall's row also has
its `calls`: how many returned, their time, the ranges the median and the
99th percentile call fall in, and the calls still running at the end. They
count whole threads over the whole capture, so a filter by time, mode,
stack or thread name leaves them out. Where only the code every syscall
passes through is on the stack, as on the way back to user space, where
threads are often preempted, the time is in a syscall, but which one is
unknown. Time in uhr's own eBPF programs, which run as syscalls enter and
leave the kernel, is a row of its own. User code, faults and interrupts from
user space, and the start of a thread are not in a syscall.
Where the stack does not show how the kernel was entered, that is unknown:
its kernel functions have no names, or it reached the depth limit, which can
cut a fault or interrupt off from the syscall it happened in, since x86
enters the kernel the same way for one in a syscall as for one in user code.
Time without kernel functions on the stack is unknown too unless the CPU was
in user mode, as a virtual machine's guest code runs inside a syscall of the
host, and so is off-CPU time without a stack. The kernel functions known are
those of x86-64, arm64 and riscv, so on other architectures all kernel time is
unknown.

`query` and `call_paths` weigh stacks by a metric: CPU time from the CPU
samples, time off CPU from the context switches, or both, which is the
time threads were alive. A thread goes off CPU in the scheduler, so off-CPU
stacks all end in it and their self time says little; their total time
shows what the threads waited in.

A function picked the same way also works as a filter: `under` keeps the
samples whose stack contains it. One recording can then be split by the code
that led to the time, such as one benchmark of several in a run. A
`syscall` filter keeps the samples and off-CPU intervals in a syscall of that
name, so grouping them by function shows the code that made it.

Moving across levels on one recording:

```
query(group_by=mode)                                    kernel 45%, user 55%
query(filter={mode: kernel}, group_by=syscall)          futex 31%, read 9%
query(filter={syscall: futex}, group_by=user_function)  Pool.acquire 28%
timeline(threads="pool-*", filter={syscall: futex})     14 threads waiting on one lock
```

## Code on runtimes

Python, Node, Bun and Lua programs are profiled with the same commands as
native ones, and each function in a result says which language it is written
in.

When uhr could not record a program's own frames, the result says so. A
Python program recorded without a collector that sees Python frames gets "0%
of the time in Python functions" and how to fix that, not the interpreter's
own functions, such as `_PyEval_EvalFrameDefault`, presented as the answer.

Python 3.12 and later and Node name their functions for uhr. Stacks still
show the runtime's own functions, such as `_PyEval_EvalFrameDefault` or V8's
builtins, but their time counts as the self time of the innermost of the
program's functions they ran for, so the program's functions come first in a
query by function or module. Native code the program calls, such as libc or
an extension, and the kernel keep their own self time. Whether the
runtime's own functions are hidden from stacks is not decided.

## Measurement rigor

Profiling overhead is measured and reported. Instrumenting profilers distort
heavily, and sampling profilers have known biases.

## Agent skill

Ship instructions that teach a method, not a list of tools:

1. Call `overview`: is it computing or waiting?
2. Choose signals from the answer. CPU-bound: stack sampling. Waiting: off-CPU,
   syscalls, locks. Growing memory: allocations and heap snapshots.
3. Zoom with `query` and `call_paths`. Check coverage before trusting a result.
4. Change one thing, record again and run the same queries.

## Humans review the evidence

Every recording can be exported to a standard viewer, so a person can check
what the agent claims.
