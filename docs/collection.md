# Collection

How observations get into the [model](model.md). This doc lists what
collectors must do and the candidate tools for each signal. The first
milestone is in the [README](../README.md#status). The order after that is not
decided.

## Collector contract

A collector is an adapter around an existing profiler or OS facility. Each
collector must:

- declare the signals it can capture per platform, and what it needs
  (permissions, build flags, runtime flags)
- report what it actually captured, not what it was asked for
- write observations in the model's shapes and dimensions, on the shared clock
- keep unresolved addresses and the mappings needed to resolve them later
- report its own overhead and losses (dropped events, truncated stacks)
- clean up everything it started (processes, probes, temp files) and report
  when cleanup failed

Collector selection must be deterministic and reported in the result. If the
preferred collector is unavailable, the result says so. Nothing silently falls
back to a weaker collector.

## Signals

Signals are opt-in per recording. A cheap default set runs unless the caller
asks otherwise. Deeper signals are added when the question needs them.

| Signal | Answers | Linux candidates | macOS candidates | Windows candidates |
|---|---|---|---|---|
| Per-thread CPU time, user and kernel | time level 0, cheap | `/proc/<pid>/task/<tid>/stat` | thread info APIs | `GetThreadTimes` |
| Resident memory by category | memory level 0 | `smaps_rollup`, `smaps` | `task_info`, `vmmap` | working set APIs |
| On-CPU stack sampling, user and kernel | time levels 2-5 | perf, eBPF | samply, xctrace Time Profiler | ETW, samply |
| Off-CPU and thread state | time level 0, locks, I/O | eBPF on scheduler tracepoints and wakeups | xctrace System Trace | ETW context switches |
| Syscalls | time level 1 | eBPF on `raw_syscalls` tracepoints, `perf trace` | xctrace System Trace | ETW syscall events |
| Mixed native and runtime stacks | time levels 2-4 for runtimes | OpenTelemetry eBPF profiler, py-spy `--native` | runtime profilers (limited) | runtime profilers |
| Runtime CPU profiles | time levels 2-4 | async-profiler, V8 `--cpu-prof`, Go pprof, rbspy, dotnet-trace | same | same |
| Allocations | memory level 2 | heaptrack-style `LD_PRELOAD`, memray, async-profiler alloc, V8 sampling heap profiler, Go heap profile | xctrace Allocations, runtime profilers | ETW heap events, runtime profilers |
| Heap snapshots | memory level 3 | V8 heap snapshot, hprof, gcdump | same | same |
| Hardware counters | time level 5 | perf_event | xctrace CPU Counters | ETW PMC sampling |
| GPU | later | Nsight Systems, rocprof | xctrace Metal System Trace | Nsight Systems |
| Browser | later | Chrome DevTools Protocol tracing | same | same |
| Production data, read-only | later | Pyroscope, Parca, pprof endpoints | same | same |

Platform depth will differ:
- Linux gets full depth through perf_event and eBPF.
- Windows ETW covers context switches, syscalls and kernel stacks.
- macOS is the most restricted (SIP limits DTrace), so it relies on xctrace
  and the task and thread APIs.

The coverage matrix must state this per signal instead of promising parity.

## Cost control

- Aggregate in the kernel by default: counts, total time and latency
  histograms in BPF maps keyed by thread, syscall and stack. Read them out
  every window (candidate: 100 ms), so a coarse timeline still works. Stream
  individual events only when an exact timeline is requested.
- Prefer sampling for allocation tracing. Full `malloc`/`free` tracing is
  opt-in.
- Measure overhead (profiled vs unprofiled run time, eBPF program run time) and
  report it.

## Code origin resolution

This is what makes "profile anything" work. Every sample lands on an address.
Resolution decides what kind of memory the address is in and how to name it.

| Origin | Candidate resolution |
|---|---|
| Binary or library | ELF/Mach-O/PE symbols and DWARF/dSYM/PDB, matched by build-id. debuginfod when local debug info is missing |
| Kernel and modules | `kallsyms`, vmlinux BTF/DWARF |
| eBPF programs | `bpf_prog_<tag>_<name>` symbols in `kallsyms` (needs `net.core.bpf_jit_kallsyms=1`). BTF line info maps back to program source. `kernel.bpf_stats_enabled` gives per-program run time and run count |
| JIT code with a map | perf map files or jitdump: Node `--perf-basic-prof`/`--perf-prof`, Python 3.12+ `-X perf`, JVM through async-profiler, .NET `DOTNET_PerfMapEnabled=1`, Wasmtime `--profile` |
| JIT code without a map | Name the region (address range, thread, likely runtime), copy its code bytes so instruction views still work, and count it as unresolved |
| Interpreted frames | Runtime-aware collector: py-spy, rbspy, async-profiler, V8 |

Requirements:
- Resolution must be able to run after recording, from the stored mappings.
  A missing symbol file can then be supplied later without recording again.
- JIT tier and JIT compile time are recorded when the runtime exposes them.
- The profiler's own eBPF programs show up in the eBPF stats and count toward
  reported overhead.

## Unwinding and symbols

Most bad profiles come from here, not from the sampler.

- Frame pointers are fast but often missing in release builds. DWARF unwinding
  works without them at a higher cost. `doctor` must tell the user the exact
  build flags to fix this for each language.
- Inlined frames must be shown, or time gets blamed on the caller.
- In containers, binaries can have different paths inside the target's mount
  namespace. Resolve by build-id.
- Candidate building blocks: samply's crates (`framehop` for unwinding,
  `wholesym` for symbols) and `linux-perf-data` for perf.data.

## Targets

Launch a command, attach to a PID, profile a test or benchmark command, profile
a service under generated load, a container, or a remote host over ssh. Order
is not decided.

## Privileges and doctor

- Common blockers: `perf_event_paranoid`, `kptr_restrict`, CAP_PERFMON and
  CAP_BPF, container capabilities, macOS code signing for attaching, missing
  debug info and frame pointers.
- `doctor` must report exactly what is missing for the requested signals on
  this target and host, and how to fix it.
- The agent-facing server must not run as root. Privileged work (eBPF, perf)
  goes through a narrow helper with a fixed set of operations. Its shape is
  not decided.
