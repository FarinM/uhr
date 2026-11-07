# Viewer exports

Firefox Profiler is the first interactive viewer supported by the core
exporter. An export is a derived file; the recording remains the source for
queries and future exports.

## Firefox Profiler

The exporter writes processed profile JSON, version 55, which Firefox
Profiler upgrades on import. The wire schema is isolated in
`uhr-core/src/export/firefox.rs`. It is written directly because
`fxprof-processed-profile` 0.8.1 accepts only integer sample weights and does
not expose source locations for resolved frames. Fractional weights and
source lines must survive export.

CPU samples keep their timestamps, relative to the recording's start, and
use `tracing-ms` weights equal to their recorded `cpu_ns` divided by one
million. These are estimates of CPU cost, not measured call durations.
`threadCPUDelta` is omitted: the recorded sample weights are not measurements
of a thread's CPU consumption between successive timestamps.

Threads are separate tracks, including separate lifetimes of reused thread
IDs. A thread's label lists the names it had during its lifetime. Processes
are separated by the main thread's lifetime where that was recorded. Unknown
lifetimes use the observed process/thread IDs.

Stacks use uhr's resolved functions, with inline frames expanded and native,
kernel, JIT, interpreted and unresolved code categorized. Functions sharing a
name are labelled distinctly so the viewer does not merge them. Unnamed
frames remain visible. Source file and line information is included when
known; source text and disassembly are not embedded or served.

The profile is marked symbolicated so the viewer uses the exported names.
This does not claim every frame is named: the export report in the viewer's
extra information contains symbol coverage, recording coverage, filters and
limitations. If the wall clock is unknown or changed during the capture,
relative timestamps still work; the absolute epoch is a documented placeholder.

Off-CPU intervals appear as markers, clipped to the selected time range. A
known wakeup splits an interval into blocked time and runnable time. Switch-out
stacks attach to the intervals; a separate wakeup marker carries the waker's
stack and identity. Unknown stacks and wakeups are labelled as unknown.

Page faults appear as instant markers with their stacks, sampled fault weight,
CPU mode and fault address. They are not allocation samples. Addresses are
hex strings so JavaScript cannot round large addresses.

Resident-memory counters show changes from the first selected reading.
Firefox rebases memory counters; accompanying markers carry the absolute RSS,
its anonymous/file/shared breakdown, swap, and peak RSS. Memory is per process
and is omitted with filters by thread, mode, stack, syscall or memory region.

Syscall aggregates and per-region resident-memory readings are not exported;
the export report lists these omissions when those signals were recorded.
The recording retains them for uhr's queries. No per-call events are inferred
from aggregates.

The format definitions and importer are maintained by Firefox Profiler:

- [Processed profile format](https://github.com/firefox-devtools/profiler/blob/main/docs-developer/processed-profile-format.md)
- [Format upgrades](https://github.com/firefox-devtools/profiler/blob/main/src/profile-logic/processed-profile-versioning.ts)
