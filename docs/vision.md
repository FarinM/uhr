# Vision

## Problem

Agents can already run `perf`, `py-spy` or a browser trace from a shell. They
are bad at the steps around it:

- **Picking the right signal.** Many "slow" programs are waiting, not
  computing, and a CPU profile hides that.
- **Reading the output.** Raw profiles are tens to hundreds of MB. Agents need
  ranked, compact answers they can drill into.
- **Telling real improvements from noise.** One before/after run proves
  nothing on a noisy machine.
- **Knowing when a profile is wrong.** Missing symbols, unresolved JIT code,
  truncated stacks and profiler bias produce confident, wrong conclusions.

Existing tools each cover a slice: one language, one platform, one signal, or
production data only. Nothing joins CPU, kernel, syscall, thread and memory
views across runtimes into one thing an agent can query.

## Goals

1. **Any code.** Attribute time to native binaries, kernel code, eBPF
   programs, JIT-compiled code and interpreted code, including mixed stacks
   (Python calling into a Rust extension, Node calling into a native addon).
2. **Any level.** The same recording answers process-level questions (user vs
   kernel time, computing vs waiting), instruction-level questions, and
   everything in between (syscalls, runtime/module, function, line).
3. **Memory as well as time.** Resident size by category, allocator and GC
   overhead, allocation sites, and what keeps objects alive.
4. **Threads everywhere.** Every view can be filtered or grouped by thread.
5. **Agent-first.** Small tool surface, compact results, drill-down by ID,
   honest coverage in every answer. The same workflows are available from a
   CLI.
6. **Sound measurement.** Comparisons report significance, not single-run
   deltas.
7. **Humans can check.** Every recording exports to a standard viewer.

## Non-goals for now

- Writing a new sampler where a mature one exists.
- Running a continuous production profiling fleet. Reading existing production
  data may come later.
- Automatic optimization. The tool finds and measures; the agent or human
  changes the code.
- A GUI. Export to existing viewers instead.

## What makes it more than a wrapper

- Every signal lands in one model with shared dimensions, so "levels" are
  groupings over the same data, not separate tools. See [model](model.md).
- Results always state what was not observed.
- The first question is "computing or waiting?", not "which function is hot?".
- Comparisons have statistics built in.
