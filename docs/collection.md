# Collection

How observations get into the [model](model.md). This doc lists what
collectors must do and the candidate tools for each signal. The first
milestone is in the [README](../README.md#status). Since it, uhr's eBPF
programs read the frames of CPython 3.11 to 3.14, with the limits
[runtimes](#runtimes) gives. What comes next is not decided.

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

## Collector interface

Collectors sit behind one interface in the core, so adding one touches no
analysis tool. Each platform's collectors live in a crate of their own, such
as `uhr-linux`, so the core builds everywhere. A collector:

- checks a target on this host: which signals it can capture, what blocks
  the rest, and how to fix that. `doctor` shows this, and `record` plans with
  it
- prepares the launch: environment variables or flags the target needs, such
  as `PYTHONPERFSUPPORT=1`
- starts on a running process and, once stopped, writes one stream through a
  shared recording builder, which interns frames and stacks and keeps the
  thread table

Behind the interface, a collector can call a Rust crate in uhr's own process
or run an existing tool and convert its output. Either way it states whether
its samples have times. A stream without them, such as a tool's stack
totals, cannot be filtered by time or lined up with other streams, and its
coverage says so.

## Choosing collectors

`doctor` takes the target and lists, for each collector, what it would
capture and what it lacks. `record` uses a default for the target, or the
collectors or signals the caller names. Selection is deterministic, and the
recording states which collectors ran and why. A named collector that cannot
run is an error with the fix. Nothing silently falls back to a weaker
collector.

For now a recording has at most one stack sampler per process: two samplers
on one process distort each other, and py-spy, for one, pauses its target to
read it. The model does not depend on this. Observations name their stream,
frames, stacks and threads are shared across streams, and queries pick data
by signal, so merging stacks from several samplers can come later without a
format change.

## Signals

Signals are opt-in per recording. A cheap default set runs unless the caller
asks otherwise. Deeper signals are added when the question needs them.

| Signal | Answers | Linux candidates | macOS candidates | Windows candidates |
|---|---|---|---|---|
| Per-thread CPU time, user and kernel | time level 0, cheap | `/proc/<pid>/task/<tid>/stat` | thread info APIs | `GetThreadTimes` |
| Resident memory by category | memory level 0 | `smaps_rollup`, `smaps` | `task_info`, `vmmap` | working set APIs |
| On-CPU stack sampling, user and kernel | time levels 2-5 | perf, eBPF | samply, xctrace Time Profiler | ETW, samply |
| Off-CPU and thread state | time level 0, locks, I/O | perf context switches, eBPF on scheduler tracepoints and wakeups | xctrace System Trace | ETW context switches |
| Syscalls | time level 1 | eBPF on `raw_syscalls` tracepoints, `perf trace` | xctrace System Trace | ETW syscall events |
| Mixed native and runtime stacks | time levels 2-4 for runtimes | uhr's eBPF collector, perf with runtime perf maps, py-spy `--native` | runtime profilers (limited) | runtime profilers |
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

### On-CPU sampling on Linux

The first collector runs the `perf` CLI and reads its perf.data file with
`linux-perf-data`, which keeps raw addresses and mappings for resolving
symbols later. Calling `perf_event_open` directly is the alternative. The CLI
keeps the first collector small, at a cost: perf must be installed, and on
Debian and Ubuntu its package must match the running kernel.

- `cpu-clock` at 999 Hz. Its sample period is in nanoseconds, so a sample's
  weight is CPU time.
- Off CPU, unless `uhr record --no-off-cpu`: the `context-switches` event
  with a period of 1 takes the stack of each thread going off CPU, and
  `--switch-events` records when it went and came back, and whether it was
  preempted, which tells runnable from blocked. Neither needs root: the
  switch records come wherever perf can record, and the stacks need kernel
  sampling, so a `perf_event_paranoid` of 2 or more leaves them out.
  Wakeups would also tell when a blocked thread became runnable and what
  woke it, but perf gets them only from the scheduler's tracepoints, which
  need root.
- The cost of context switches grows with how often the target switches. A
  pipe ping-pong between two threads, 125,000 switches a second, ran 1.6
  times as long under CPU sampling alone and 2.2 times with context
  switches, and perf wrote about 260 bytes per switch. With `--unwind
  dwarf` each switch also copies the user stack, and bursts of switches can
  overflow perf's buffer: the switch is kept, but its stack is lost and
  counted among the lost events.
- `--clockid=CLOCK_MONOTONIC` puts samples on the shared clock.
- `--buildid-mmap` has the kernel record each mapping's build-id, so symbols
  are matched to the exact file that ran.
- Frame-pointer call graphs by default. With `--unwind dwarf`, perf copies
  each sample's user stack (32 KB unless `--stack-size` says otherwise) and
  compresses it with zstd. Right after recording, while the binaries are at
  hand, uhr unwinds the copies with `framehop` from the files' unwind tables,
  and keeps only the frames. perf's dwarf mode leaves the frame-pointer chain
  out, so stacks deeper than the copy lose their outer callers; coverage
  counts them. Rules come from `.eh_frame`, and from `.debug_frame` for code
  only it describes. perf marks the registers of each sample as 32- or
  64-bit; samples of 32-bit code are not unwound, and coverage counts them.
  The recording states which unwinding it used. Frame pointers stay the
  default: with every core of a 32-core host busy, perf's writer fell behind
  compressing the stack copies and dropped 0.3% of events, where
  frame-pointer recording dropped none.
- uhr starts the target held before it runs any of its own code and
  attaches perf with `--pid`, sampling off (`--delay=-1`). Once perf says
  over its control pipe (`--control`, perf 5.10 or later) that it samples,
  uhr lets the target run, so the recording starts at its first instruction.
  Until then perf follows the target with a dummy event, and the held
  process still runs uhr's code, which the recording leaves out.
- When it launches a target, uhr sets the variables that make runtimes name
  the code they compile in perf maps, unless `uhr record
  --no-runtime-support`: `PYTHONPERFSUPPORT=1` for Python 3.12 and later,
  and `--perf-basic-prof --interpreted-frames-native-stack` in
  `NODE_OPTIONS` for Node. Every process the target starts inherits them,
  and programs that don't read them ignore them. A variable the user set is
  left alone, except that each of Node's flags is added to the options
  already there, unless they hold it or turn it off. It makes those
  runtimes a little slower. uhr reads the maps right after recording, if
  they belong to root, to the user the target started as, or to one the
  process ran as when its map appeared or still runs as. A process can
  change user first, as one `sudo -u` runs does, so uhr watches `/tmp`
  while recording. Once the recording is written, uhr removes the maps of
  the processes it launched. Node also writes V8's log,
  `isolate-0x<isolate>-<pid>-v8.log`, in its working directory, which no
  option in its environment can move. uhr removes those it finds in the
  directory the target started in, and says when a Node process left its
  log elsewhere.
- With `--pid`, uhr attaches perf the same way to a running process, and
  follows the threads and processes it starts. It never signals the
  process: the capture ends at an interrupt, at the end of `--duration`, or
  when the process and all it started exit. uhr is not its parent, so its
  exit status is unknown. A thread that was off CPU already when the capture
  started is counted off CPU from then until it first runs, in a state that
  is unknown: it may have been preempted or blocked.
- perf shares uhr's stderr. When that is a pipe or socket, uhr gives perf a
  pipe instead and copies it through, so a reader that stops early, as
  `head` does, can't kill perf with SIGPIPE. Terminals and files are passed
  straight through. The target has uhr's stderr itself, as it would without
  uhr.
- The capture ends when the target exits; processes it leaves running are
  not followed after that. A SIGINT or SIGTERM ends it too: uhr stops perf at
  once and counts the signal as the end of the capture, then waits for the
  target, so the recording has its exit status. Terminal Ctrl-C reaches the
  target itself, and uhr passes on a signal another process sent it. That
  includes one sent to uhr's whole process group, which the target then gets
  twice. A second interrupt kills the target. If perf stops first, uhr asks
  the target to stop with SIGTERM. An interrupt before the capture starts
  ends uhr without a recording, and a target to launch never runs.
- Another perf that watches the same processes, such as that of a uhr that
  uhr records, can have some of its records land in uhr's data. uhr reads
  only the records of its own perf, and logs how many others it left out.

### eBPF on Linux

The second Linux collector is uhr's own eBPF programs, written in Rust with
aya. They run at each sample in the context of the interrupted thread, so
they can walk an interpreter's frames in its memory without runtime flags,
also in processes uhr attaches to. They can also capture what perf gets only
from tracepoints, such as wakeups and syscall latency.

- On x86-64 and arm64, they sample CPU time in place of perf, at each tick
  of every CPU's clock, and take the kernel and user stacks of the target's
  threads. They walk user stacks with frame pointers, or with `--unwind
  dwarf` on x86-64 copy the user registers and stack, as perf does, for uhr
  to unwind. perf then records only the processes' mappings and threads, and
  the context switches. It samples instead with `--sampler perf`. The kernel
  runs no program at a perf event while one at a kprobe or a tracepoint runs
  on the same CPU, so the time in those, which other tools load, has no
  samples. uhr's own that run at every syscall are at raw tracepoints, which
  don't stop it, and the rest at rarer events, as a process starting or
  mapping code. A thread running a virtual machine's guest has its time in
  unknown mode and without frames, as with perf, told apart by the task flag
  the kernel's own accounting uses, which uhr finds in the kernel's BTF. The
  kernel drops the sampling event of a CPU going offline, as across a
  suspend, so they see CPUs go and come back, and uhr starts sampling each
  again once it is back.
- They walk the frames of the interpreters uhr finds in the target's
  processes, and count the times each maps a file's code, so uhr knows when
  to look for one again, see [runtimes](#runtimes).
- They count and time the target's syscalls. At each syscall's entry and
  exit they add, per thread and syscall, the call, its time and a log2
  histogram of times in the kernel, so nothing is written per call. Each
  call still runs them, which a program making millions of quick calls
  notices, and while they run every process's syscalls take the kernel's
  slower path for traced ones.
- They follow the processes the target starts until the last thread of
  each exits, and sample and count a launched target from its exec on.
  They start before perf, so that uhr falls back to perf where they can't
  load, but sample and count only from when perf records until uhr stops
  the capture.
- `uhr record` runs them when it may load eBPF, as root or with CAP_BPF and
  CAP_PERFMON. They know processes by their ids in the kernel's first PID
  namespace, so uhr also has to run there, not in a container's own.
  Otherwise perf samples, and the recording says why it has no syscall
  counts. `--no-syscalls` leaves the counting out.
- Their overhead is the target's CPU time in them, from its samples, and a
  query gives the share of its own time in them. That leaves out the
  kernel's way into them and their cost to other processes. The kernel's
  run-time stats would measure those too, but they make every traced
  syscall slower again.
- Building them needs nightly Rust with `rust-src`, and `bpf-linker`.
  Without those uhr builds without them.

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
| JIT code with a map | perf map files, read right after recording: Python 3.12+ and Node, which uhr turns on at launch. Candidates: jitdump (Node `--perf-prof`, Python 3.13+ `-X perf_jit`), JVM through async-profiler, .NET `DOTNET_PerfMapEnabled=1`, Wasmtime `--profile` |
| JIT code without a map | Name the region (address range, thread, likely runtime), copy its code bytes so instruction views still work, and count it as unresolved |
| Interpreted frames | A collector that reads the interpreter's frames, or the runtime's own profiler. See [runtimes](#runtimes) |

Requirements:
- Resolution must be able to run after recording, from the stored mappings.
  A missing symbol file can then be supplied later without recording again.
- JIT tier and JIT compile time are recorded when the runtime exposes them.
- The profiler's own eBPF programs keep their names in the samples and count
  toward reported overhead.

## Runtimes

For code on a runtime, such as Python, JavaScript or Lua, the frames that
matter are the program's, not the interpreter's. A runtime can name its code
for a native sampler, in perf map files or jitdump; a collector can read the
interpreter's frames from its memory; or the runtime's own profiler can
record them. Which way a runtime uses is decided when it is supported, and
each supported runtime gets a test program. Python 3.12 and later and Node
name their code in perf maps. uhr's eBPF programs read the frames of
CPython 3.11 to 3.14 with the GIL, in a `python3` program or a `libpython`
another program embeds it with, from offsets 3.13 and later publish and
from the headers of 3.11 and 3.12. Off-CPU stacks come from perf's context
switches, which read no frames, so only perf maps name Python's code in
them. 3.12 and later keep the frame that starts each call into the
interpreter in the call's native frame, and mark the state each thread runs
in, among those of its interpreters. 3.11 does neither. They read the
frames of V8 11 to 13, as Node 20 to 24 run them, without pointer
compression, in a `node` program or a `libnode`, from the offsets their
`v8dbg_` symbols publish and their headers for what they don't: V8 keeps them on the
native stack, each JavaScript function's frame with its `JSFunction`, whose
`SharedFunctionInfo` they read at the sample, as V8's garbage collector
moves functions. That names its functions and their files, and the line
and column each starts at, from the script's source. Lines within a
function are not read yet.
They read the frames of JavaScriptCore as Bun 1.4.3 runs it, by its build id:
Bun's releases keep no symbols, and JavaScriptCore publishes no offsets,
so they are those found in the build with symbols Bun publishes with each
release, from the code that reads them, and the build ids of other
releases are not read. Each JavaScript function's frame holds its
`CodeBlock`, whose executable names it and its script. Where the build
with symbols is kept by its build id with the system's debug info, it also
names the interpreter's code, so that its frames take the place of the
interpreter's native ones; without it they go just above them. Lines are
not read yet. They read the frames of CRuby 3.2, in a `ruby` program or a `libruby`, from
the headers of 3.2: CRuby keeps them in an array in each thread's
execution context, which the thread-local `ruby_current_ec` points to, and
says the line of each instruction, so that lines within a function are
read. Its eval loop, which says where the frames go in the native stack, is
a static function, which only the debug info of a stripped `libruby`
names, where the system keeps it by build id. Without it they go just
above the function that calls the eval loop, inside it. They read the
frames of PHP 8.3 built without thread safety, as its command line is, from
the headers of 8.3: a list from `executor_globals`, with each function's
name, class and file, and the line of each instruction. PHP's VM keeps the
instruction it runs in a register and saves it to the frame only when it
calls, so the innermost frame's line is not known. uhr detects the
runtimes in a target and records their versions. What it knows about a
runtime's frames is kept apart from how it reads memory, so other platforms
can use it too.

uhr's eBPF programs walk interpreters' frames at each CPU sample, and know
no runtime. Each runtime uhr supports is a module of `uhr-core`. One whose
frames uhr reads finds its interpreter in a process from the files it maps,
and gives the programs a description in numbers of where the frames are and
what to copy of each. The programs implement each way to find frames once,
and a runtime picks one and gives its offsets:

- In the runtime's memory, from the sampled thread's state to its innermost
  frame, then from each frame to the next by a pointer at an offset, as
  CPython keeps them, or to the next in an array, which ends where the state
  says, as CRuby keeps them. The state is at the end of a path of pointers
  from the thread pointer, for a runtime that keeps it in a thread-local, at
  a fixed address, for one that runs on one thread, as PHP built without
  thread safety, or is found by searching lists that start at a global, as
  CPython keeps one
  for each interpreter, for the entries with the thread's id in the
  process's PID namespace. A thread can have a state in several lists, and
  the one it runs in is marked so where the runtime marks it, or else is the
  first with frames. They search the first 256 states. uhr reads the rest
  from the process's memory, where samples say they did not find a thread's,
  and tells them.
- On the native stack: each frame the programs' walk of the frame pointers
  finds, at its frame pointer. This needs that walk, which they take on
  x86-64, and not `--unwind dwarf` yet.

Of each frame they copy the bytes at an offset from it, and up to two words
read at the time of the sample at an offset from a pointer the copy holds,
as for objects a garbage collector can move before uhr reads them. The
offsets come from what the runtime publishes, such as CPython's
`_Py_DebugOffsets` and V8's `v8dbg_` symbols, from debug info, or from tables
by version. A thread-local's path from the thread pointer comes from where
the C library keeps the thread-locals of each module, and the index the
dynamic linker gave the module, which it writes where the module's
relocations say.

uhr looks for a process's runtime at its first sample, and again each time
the process maps more code, as a runtime's library can be mapped after the
exec, as by `dlopen`. The programs count the times each process maps a
file's code, at the syscall's return, and each sample says the count. uhr
also looks again a while later until it finds one, for code they don't see
mapped, as where a mapping is made executable after, or the kernel has no
tracepoints for syscalls. Samples taken before have only the interpreter's
native frames, and coverage counts them. Each sample says how many times its
process had exec'd, as the kernel counts in its task, so each program a
process runs is looked at and counted apart. While the process runs, uhr
reads the code its frames run from its memory, and turns them into functions
and lines. Each time native code called into the interpreter, that call ran
a group of the frames, which go into the native stack just above the call's
run of eval-loop frames. An interpreter can keep the frame that starts each
call in the call's native frame. Then, on x86-64, the programs walk the
frame pointers themselves, rather than with the kernel's walk, keeping where
each frame ends on the stack, as uhr's unwinding of the stack copy does too,
and each group goes just above the native frame its call started in, the
eval loop's or that of the function it was inlined into. That holds where
the walk of the native stack lost frames, as it loses the caller of a leaf
that set up no frame, which is often the eval loop itself, and where it
ended early, as in code without frame pointers. On arm64 a function's frame
record can be anywhere in its frame, so where it is says nothing of where
the frame ends, and there, as for an interpreter that keeps no such frame,
groups are matched to runs from the end of the stack that stayed whole.
Coverage counts the samples where one had no run. A frame on the native
stack takes the place of the native frame that ran it, where that runs the
runtime's interpreter or code it compiled, which no file holds, and else
goes just above it: a function that sets up no frame keeps its caller's
frame pointer, so that the walk lost the caller, whose frame it is. One
whose code could not be read stays the native frame. Frames of a version
uhr does not know stay the interpreter's own, and the recording says why.

## Unwinding and symbols

Most bad profiles come from here, not from the sampler.

- Frame pointers are fast but often missing in release builds. DWARF unwinding
  works without them at a higher cost. `doctor` must tell the user the exact
  build flags to fix this for each language.
- GCC 13 leaves frame setup out of leaf functions that don't use the stack,
  even with `-fno-omit-frame-pointer -mno-omit-leaf-frame-pointer`, so
  frame-pointer stacks skip the caller of such a function. Clang 18 keeps it.
- Inlined frames must be shown, or time gets blamed on the caller.
- Kernel names come from `/proc/kallsyms`, read right after recording: the
  kernel moves to a random address on every boot and modules come and go.
  The recording keeps the functions its kernel frames fall in, so symbols
  can still be resolved again later. The kernel shows these addresses only
  to processes with CAP_SYSLOG, such as root, unless `kernel.kptr_restrict`
  is 0 and `kernel.perf_event_paranoid` at most 1; at a `kptr_restrict` of 2
  it shows them to no one. Without them kernel frames stay unnamed, and
  coverage says why.
- In containers, binaries can have different paths inside the target's mount
  namespace. Resolve by build-id.
- Building blocks: samply's crates (`framehop` for unwinding,
  `wholesym` for symbols) and `linux-perf-data` for perf.data.

## Targets

Launch a command, attach to a PID, profile a test or benchmark command, profile
a service under generated load, a container, or a remote host over ssh. Order
is not decided.

uhr launches a target itself: it starts the program stopped before any of its
own code runs, attaches each collector, then lets it go. Launching and
attaching then share one path, several collectors can watch one target, and
uhr can stop everything it started, which cancellation needs.

## Privileges and doctor

- Common blockers: `perf_event_paranoid`, `kptr_restrict`, CAP_PERFMON and
  CAP_BPF, container capabilities, macOS code signing for attaching, missing
  debug info and frame pointers.
- `doctor` must report exactly what is missing for the requested signals on
  this target and host, and how to fix it.
- The current `doctor` tests the selected perf executable by recording `true`
  at 1 Hz with the collector's flags, then reads the event attributes to learn
  whether kernel sampling was excluded. It does not infer permission from
  uhr's UID or capabilities: the perf executable can have different credentials.
  `record` runs it only when perf fails to start, to say why.
- It also checks whether `/proc/kallsyms` shows the kernel's addresses. uhr
  reads that file itself, so there its own credentials are the ones that
  count. Without them kernel frames have no names, and the fix depends on
  `kptr_restrict` and `perf_event_paranoid`: recording as root works unless
  `kptr_restrict` is 2, and every user sees them only with `kptr_restrict`
  at 0 and `perf_event_paranoid` at most 1.
- eBPF needs root, or CAP_BPF and CAP_PERFMON. For now that means running
  `uhr record` under sudo.
- The agent-facing server must not run as root. Privileged work (eBPF, perf)
  goes through a narrow helper with a fixed set of operations. Its shape is
  not decided.
