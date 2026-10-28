use std::collections::HashMap;
use std::path::Path;

use serde::Serialize;

use crate::coverage::Coverage;
use crate::filter::{self, Filter};
use crate::functions::Functions;
use crate::recording::{
    self, Collector, Exit, MemoryReading, Mode, OffCPUInterval, Recording, RegionKind, Sample,
    Signal, Thread, ThreadState,
};
use crate::symbols::Symbols;
use crate::threads::ThreadNames;

/// Time level 0: how much CPU time each process and thread used, in which
/// mode, and how long it waited off CPU, against how long it was alive. It
/// tells computing from waiting. And memory level 0: how much memory each
/// process had.
#[derive(Debug, Clone, Serialize)]
pub struct Overview {
    pub command: Vec<String>,
    /// `None` if the target was still running when the recording stopped.
    pub exit: Option<Exit>,
    pub filter: Filter,
    /// On the recording's clock. Every other time is an offset from it.
    /// `None` if nothing was recorded.
    pub recording_start_ns: Option<u64>,
    pub recording_duration_ns: u64,
    /// The part of the recording covered: all of it, or what the time
    /// filter selects.
    pub window: Window,
    #[serde(flatten)]
    pub cpu: CPUTime,
    /// CPU time over the window's wall time: 2.0 means two CPUs busy on
    /// average. `None` for an empty window.
    pub cpu_utilization: Option<f64>,
    /// Summed over threads. `None` if context switches were not recorded.
    pub off_cpu: Option<OffCPUTime>,
    /// Sorted by CPU time.
    pub processes: Vec<ProcessRow>,
    /// Rows cut by `top`.
    pub processes_omitted: usize,
    /// One row per thread lifetime, sorted by CPU time.
    pub threads: Vec<ThreadRow>,
    /// Rows cut by `top`.
    pub threads_omitted: usize,
    /// `None` if memory was not read, or for a filter it can't take: it is
    /// read per process, so only filters by process and time apply.
    pub memory: Option<Memory>,
    pub coverage: Coverage,
}

/// How much memory each process had, from its readings in the window.
#[derive(Debug, Clone, Serialize)]
pub struct Memory {
    /// How often it was read.
    pub interval_ns: u64,
    /// Sorted by resident memory at the last reading.
    pub processes: Vec<MemoryRow>,
    /// Rows cut by `top`.
    pub processes_omitted: usize,
}

/// The readings of one process lifetime in the window.
#[derive(Debug, Clone, Serialize)]
pub struct MemoryRow {
    pub pid: u32,
    /// Its main thread's name at the last reading.
    pub name: Option<String>,
    pub readings: u64,
    pub first: MemoryUsage,
    pub last: MemoryUsage,
    /// The reading with the most resident.
    pub max: MemoryUsage,
    /// The last reading in the window of how much was resident in each
    /// kind of region, which is read less often. `None` without one.
    pub regions: Option<RegionsUsage>,
}

/// How much of a process's memory was in each kind of region when read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegionsUsage {
    pub time_ns: u64,
    /// Sorted by resident memory.
    pub kinds: Vec<KindUsage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KindUsage {
    pub kind: RegionKind,
    pub rss_bytes: u64,
    pub swap_bytes: u64,
}

/// One reading of a process's memory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemoryUsage {
    pub time_ns: u64,
    /// Resident in RAM, made of the next three: memory of the process's
    /// own, such as its heap and stacks, pages of files it mapped, and
    /// shared memory.
    pub rss_bytes: u64,
    pub rss_anon_bytes: u64,
    pub rss_file_bytes: u64,
    pub rss_shmem_bytes: u64,
    /// Its own memory the kernel moved out to swap.
    pub swap_bytes: u64,
    /// The most it had resident since it started, or last exec'd, as the
    /// kernel tracked it: between readings too, and before the capture.
    pub peak_rss_bytes: u64,
}

/// The end is exclusive when the time filter sets it, like the filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Window {
    pub start_ns: u64,
    pub end_ns: u64,
}

/// Sampled CPU time, by mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CPUTime {
    pub samples: u64,
    pub cpu_ns: u64,
    pub user_cpu_ns: u64,
    /// `None` if the kernel was not sampled. `cpu_ns` then leaves it out.
    pub kernel_cpu_ns: Option<u64>,
    /// Hypervisor, guest, or a mode the sampler did not report.
    pub unknown_mode_cpu_ns: u64,
}

/// Time a thread spent switched out, from the off-CPU intervals that passed,
/// cut to the window.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct OffCPUTime {
    pub intervals: u64,
    /// Preempted, waiting for a CPU.
    pub runnable_ns: u64,
    /// Waiting for something else: a lock, I/O, a timer or another thread.
    /// Includes the wait for a CPU after it was woken.
    pub blocked_ns: u64,
    /// Off CPU already when an attached capture started, runnable or
    /// blocked.
    pub unknown_state_ns: u64,
}

/// One process lifetime: a reused pid gets a row per lifetime. Its name,
/// times and thread count describe the process, whatever the filter. Its
/// CPU and off-CPU time is that of the samples and intervals that passed.
#[derive(Debug, Clone, Serialize)]
pub struct ProcessRow {
    pub pid: u32,
    /// The last name of its main thread in the window, or of its first
    /// thread if the main thread was not seen.
    pub name: Option<String>,
    /// When its first thread started. `None` if before the recording.
    pub start_ns: Option<u64>,
    /// When its last thread ended. `None` if a thread outlived the
    /// recording, or its exit was not seen.
    pub end_ns: Option<u64>,
    /// Thread lifetimes in the window.
    pub threads: usize,
    /// From its first thread start to its last thread end, in the window.
    pub alive_ns: u64,
    #[serde(flatten)]
    pub cpu: CPUTime,
    /// CPU time over `alive_ns`: 2.0 means two CPUs busy on average.
    pub cpu_utilization: Option<f64>,
    /// Summed over its threads. `None` if context switches were not
    /// recorded.
    pub off_cpu: Option<OffCPUTime>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreadRow {
    pub pid: u32,
    pub tid: u32,
    /// The names it had in the window, oldest first.
    pub names: Vec<String>,
    /// `None` if it started before the recording.
    pub start_ns: Option<u64>,
    /// `None` if it outlived the recording, or its exit was not seen.
    pub end_ns: Option<u64>,
    /// Time alive in the window.
    pub alive_ns: u64,
    #[serde(flatten)]
    pub cpu: CPUTime,
    /// Share of `alive_ns` spent on a CPU. The rest it was blocked,
    /// sleeping, waiting to run, or in a mode that was not sampled.
    /// Sampling error can put it slightly above 1. `None` if it was not
    /// alive in the window.
    pub on_cpu_share: Option<f64>,
    /// `None` if context switches were not recorded.
    pub off_cpu: Option<OffCPUTime>,
    /// Shares of `alive_ns` spent off CPU, runnable, blocked, and in a state
    /// unknown because it began before an attached capture. Together with
    /// `on_cpu_share` they come close to 1, short of the time perf itself
    /// took at each switch. `None` if context switches were not recorded, or
    /// it was not alive in the window.
    pub runnable_share: Option<f64>,
    pub blocked_share: Option<f64>,
    pub unknown_state_share: Option<f64>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Recording(#[from] recording::Error),
    #[error(transparent)]
    Filter(#[from] filter::Error),
}

pub fn overview(dir: &Path, filter: &Filter, top: usize) -> Result<Overview, Error> {
    let recording = Recording::read(dir)?;
    let symbols = Symbols::read(dir, &recording)?;
    run(&recording, symbols.as_ref(), filter, top)
}

/// `symbols` are only needed to pick out the functions of `filter.under`
/// and the syscalls of `filter.syscalls`.
pub fn run(
    recording: &Recording,
    symbols: Option<&Symbols>,
    filter: &Filter,
    top: usize,
) -> Result<Overview, Error> {
    // It would show no time and no memory, as though none were.
    if !filter.regions.is_empty() {
        return Err(filter::Error::RegionsOfPageFaults.into());
    }
    let manifest = &recording.manifest;
    let start = manifest.start_ns;
    let duration = start
        .zip(manifest.end_ns)
        .map_or(0, |(start, end)| end.saturating_sub(start));
    let from = filter.from_ns.unwrap_or(0);
    let window = Window {
        start_ns: from.min(duration),
        end_ns: filter
            .to_ns
            .unwrap_or(duration)
            .clamp(from.min(duration), duration),
    };
    // Absolute times, for comparing with the tables. Presence in the window
    // is half-open up to `limit`, like the time filter, but without one the
    // window keeps the end of the capture.
    let base = start.unwrap_or(0);
    let bounds = Bounds {
        from: base.saturating_add(from),
        to: base + window.end_ns,
        limit: base + filter.to_ns.unwrap_or(duration + 1).min(duration + 1),
    };

    let kernel_sampled = manifest
        .streams
        .iter()
        .any(|s| s.signals.contains(&Signal::KernelCPUSamples))
        || recording.samples.iter().any(|s| s.mode == Mode::Kernel);
    let empty = CPUTime::new(kernel_sampled);
    let switches_recorded = manifest
        .streams
        .iter()
        .any(|s| s.signals.contains(&Signal::OffCPUTime));
    let no_off_cpu = switches_recorded.then(OffCPUTime::default);

    let lifetimes = Lifetimes::new(recording);
    let names = ThreadNames::new(recording);
    let lives: Vec<Life> = lifetimes
        .threads
        .iter()
        .map(|thread| {
            let present = bounds.presence(thread);
            Life {
                names: names.during(thread.pid, thread.tid, present.0, present.1),
                present: present.0 < present.1,
                alive: bounds.clip(thread),
                process: (
                    thread.pid,
                    lifetimes.at(thread.pid, thread.pid, thread.start_ns),
                ),
            }
        })
        .collect();
    let row = |id: usize| {
        let (thread, life) = (&lifetimes.threads[id], &lives[id]);
        ThreadRow {
            pid: thread.pid,
            tid: thread.tid,
            names: life.names.iter().map(|n| n.to_string()).collect(),
            start_ns: thread.start_ns.map(|t| t.saturating_sub(base)),
            end_ns: thread.end_ns.map(|t| t.saturating_sub(base)),
            alive_ns: life.alive.1.saturating_sub(life.alive.0),
            cpu: empty.clone(),
            on_cpu_share: None,
            off_cpu: no_off_cpu.clone(),
            runnable_share: None,
            blocked_share: None,
            unknown_state_share: None,
        }
    };
    let mut threads: HashMap<usize, ThreadRow> = HashMap::new();
    for (id, (thread, life)) in lifetimes.threads.iter().zip(&lives).enumerate() {
        if life.present && filter.matches_thread(thread.pid, thread.tid, life.names.iter().copied())
        {
            threads.insert(id, row(id));
        }
    }

    let mut cpu = empty.clone();
    let functions = Functions::new(recording, symbols);
    for sample in filter.samples(recording, &functions)? {
        cpu.add(sample);
        let id = lifetimes.of(sample.pid, sample.tid, sample.time_ns);
        // Inserts the lifetime if the sample lies outside it, so the
        // sample still counts.
        threads.entry(id).or_insert_with(|| row(id)).cpu.add(sample);
    }
    let mut off_cpu = no_off_cpu.clone();
    for (interval, ns) in filter.off_cpu(recording, &functions)? {
        if let Some(total) = off_cpu.as_mut() {
            total.add(interval, ns);
        }
        let id = lifetimes.of(interval.pid, interval.tid, interval.start_ns);
        let row = threads.entry(id).or_insert_with(|| row(id));
        if let Some(time) = row.off_cpu.as_mut() {
            time.add(interval, ns);
        }
    }

    let mut processes = processes(
        &lifetimes,
        &lives,
        &threads,
        &(empty.clone(), no_off_cpu),
        base,
    );
    processes.sort_by(|a, b| {
        b.cpu
            .cpu_ns
            .cmp(&a.cpu.cpu_ns)
            .then((a.pid, a.start_ns).cmp(&(b.pid, b.start_ns)))
    });
    let processes_omitted = processes.len().saturating_sub(top);
    processes.truncate(top);
    let mut threads: Vec<ThreadRow> = threads
        .into_values()
        .map(|mut row| {
            row.on_cpu_share = ratio(row.cpu.cpu_ns, row.alive_ns);
            if let Some(time) = &row.off_cpu {
                row.runnable_share = ratio(time.runnable_ns, row.alive_ns);
                row.blocked_share = ratio(time.blocked_ns, row.alive_ns);
                row.unknown_state_share = ratio(time.unknown_state_ns, row.alive_ns);
            }
            row
        })
        .collect();
    threads.sort_by(|a, b| {
        b.cpu
            .cpu_ns
            .cmp(&a.cpu.cpu_ns)
            .then(b.alive_ns.cmp(&a.alive_ns))
            .then((a.pid, a.tid, a.start_ns).cmp(&(b.pid, b.tid, b.start_ns)))
    });
    let threads_omitted = threads.len().saturating_sub(top);
    threads.truncate(top);

    let memory = memory(recording, filter, &lifetimes, &names, base, top);
    let mut coverage = Coverage::of(recording);
    if !switches_recorded {
        coverage.unknown.push(
            "why threads were off CPU (blocked, sleeping or waiting to run): context switches \
             were not recorded"
                .into(),
        );
    }
    let memory_read = manifest
        .streams
        .iter()
        .any(|s| s.signals.contains(&Signal::ResidentMemory));
    let faults_sampled = manifest
        .streams
        .iter()
        .any(|s| s.signals.contains(&Signal::PageFaults));
    coverage.unknown.push(
        match &memory {
            Some(_) if faults_sampled => {
                "which code holds the memory: page faults show the code that first touched it, \
                 but no allocations were recorded"
            }
            Some(_) => "which code uses the memory: no allocations or page faults were recorded",
            None if !memory_read => "memory use: it was not read",
            None => {
                "memory use: it is read per process, so a filter by thread, mode, stack or syscall \
             leaves it out"
            }
        }
        .into(),
    );
    for stream in &manifest.streams {
        let Some(sampling) = stream.collector.sampling() else {
            continue;
        };
        coverage.unknown.push(format!(
            "CPU time per thread more precise than one sample period ({:.1} ms at {} Hz in \
             stream {})",
            1e3 / sampling.frequency_hz as f64,
            sampling.frequency_hz,
            stream.id
        ));
    }

    Ok(Overview {
        command: manifest.target.command.clone(),
        exit: manifest.target.exit.clone(),
        filter: filter.clone(),
        recording_start_ns: start,
        recording_duration_ns: duration,
        window,
        cpu_utilization: ratio(cpu.cpu_ns, window.end_ns - window.start_ns),
        cpu,
        off_cpu,
        processes,
        processes_omitted,
        threads,
        threads_omitted,
        memory,
        coverage,
    })
}

/// The memory of each process lifetime, from the readings `filter` keeps.
fn memory(
    recording: &Recording,
    filter: &Filter,
    lifetimes: &Lifetimes,
    names: &ThreadNames,
    base: u64,
    top: usize,
) -> Option<Memory> {
    let interval_ns = recording
        .manifest
        .streams
        .iter()
        .filter(|s| s.signals.contains(&Signal::ResidentMemory))
        .find_map(|s| match s.collector {
            Collector::Procfs { interval_ns } => Some(interval_ns),
            _ => None,
        })?;
    let mut lives: HashMap<(u32, Option<usize>), Vec<&MemoryReading>> = HashMap::new();
    for reading in filter.memory(recording)? {
        let life = lifetimes.at(reading.pid, reading.pid, Some(reading.time_ns));
        lives.entry((reading.pid, life)).or_default().push(reading);
    }
    // The last reading by kind of region of each process lifetime.
    let mut regions: HashMap<(u32, Option<usize>), RegionsUsage> = HashMap::new();
    for reading in filter.region_memory(recording)? {
        let life = lifetimes.at(reading.pid, reading.pid, Some(reading.time_ns));
        let time_ns = reading.time_ns.saturating_sub(base);
        let usage = regions.entry((reading.pid, life)).or_insert(RegionsUsage {
            time_ns,
            kinds: Vec::new(),
        });
        if usage.time_ns != time_ns {
            *usage = RegionsUsage {
                time_ns,
                kinds: Vec::new(),
            };
        }
        usage.kinds.push(KindUsage {
            kind: reading.kind,
            rss_bytes: reading.rss_bytes,
            swap_bytes: reading.swap_bytes,
        });
    }
    for usage in regions.values_mut() {
        usage
            .kinds
            .sort_by(|a, b| b.rss_bytes.cmp(&a.rss_bytes).then(a.kind.cmp(&b.kind)));
    }
    let usage = |reading: &MemoryReading| MemoryUsage {
        time_ns: reading.time_ns.saturating_sub(base),
        rss_bytes: reading.rss_bytes(),
        rss_anon_bytes: reading.rss_anon_bytes,
        rss_file_bytes: reading.rss_file_bytes,
        rss_shmem_bytes: reading.rss_shmem_bytes,
        swap_bytes: reading.swap_bytes,
        peak_rss_bytes: reading.peak_rss_bytes,
    };
    let mut processes: Vec<MemoryRow> = lives
        .into_iter()
        .map(|((pid, life), readings)| {
            // In time order, as the recording keeps them.
            let (first, last) = (readings[0], readings[readings.len() - 1]);
            let max = readings
                .iter()
                .copied()
                .rev()
                .max_by_key(|r| r.rss_bytes())
                .unwrap_or(last);
            MemoryRow {
                pid,
                name: names.at(pid, pid, last.time_ns).map(str::to_owned),
                readings: readings.len() as u64,
                first: usage(first),
                last: usage(last),
                max: usage(max),
                regions: regions.remove(&(pid, life)),
            }
        })
        .collect();
    processes.sort_by(|a, b| {
        b.last
            .rss_bytes
            .cmp(&a.last.rss_bytes)
            .then((a.pid, a.first.time_ns).cmp(&(b.pid, b.first.time_ns)))
    });
    let processes_omitted = processes.len().saturating_sub(top);
    processes.truncate(top);
    Some(Memory {
        interval_ns,
        processes,
        processes_omitted,
    })
}

impl OffCPUTime {
    fn add(&mut self, interval: &OffCPUInterval, ns: u64) {
        self.intervals += 1;
        match interval.state {
            ThreadState::Runnable => self.runnable_ns += ns,
            ThreadState::Blocked => self.blocked_ns += ns,
            ThreadState::Unknown => self.unknown_state_ns += ns,
        }
    }

    fn merge(&mut self, other: &OffCPUTime) {
        self.intervals += other.intervals;
        self.runnable_ns += other.runnable_ns;
        self.blocked_ns += other.blocked_ns;
        self.unknown_state_ns += other.unknown_state_ns;
    }
}

impl CPUTime {
    fn new(kernel_sampled: bool) -> Self {
        Self {
            samples: 0,
            cpu_ns: 0,
            user_cpu_ns: 0,
            kernel_cpu_ns: kernel_sampled.then_some(0),
            unknown_mode_cpu_ns: 0,
        }
    }

    fn add(&mut self, sample: &Sample) {
        self.samples += 1;
        self.cpu_ns += sample.cpu_ns;
        match sample.mode {
            Mode::User => self.user_cpu_ns += sample.cpu_ns,
            Mode::Kernel => *self.kernel_cpu_ns.get_or_insert(0) += sample.cpu_ns,
            Mode::Unknown => self.unknown_mode_cpu_ns += sample.cpu_ns,
        }
    }

    fn merge(&mut self, other: &CPUTime) {
        self.samples += other.samples;
        self.cpu_ns += other.cpu_ns;
        self.user_cpu_ns += other.user_cpu_ns;
        if let Some(kernel) = other.kernel_cpu_ns {
            *self.kernel_cpu_ns.get_or_insert(0) += kernel;
        }
        self.unknown_mode_cpu_ns += other.unknown_mode_cpu_ns;
    }
}

/// Every thread lifetime, including ids that only appear in samples or
/// off-CPU intervals.
struct Lifetimes {
    threads: Vec<Thread>,
    /// Lifetimes of each thread id, by start. Ones that started before the
    /// recording come first.
    by_id: HashMap<(u32, u32), Vec<usize>>,
}

impl Lifetimes {
    fn new(recording: &Recording) -> Self {
        let mut threads = recording.threads.clone();
        let mut by_id: HashMap<(u32, u32), Vec<usize>> = HashMap::new();
        for (id, thread) in threads.iter().enumerate() {
            by_id.entry((thread.pid, thread.tid)).or_default().push(id);
        }
        let seen = recording
            .samples
            .iter()
            .map(|s| (s.pid, s.tid))
            .chain(recording.off_cpu.iter().map(|i| (i.pid, i.tid)));
        for (pid, tid) in seen {
            by_id.entry((pid, tid)).or_insert_with(|| {
                threads.push(Thread {
                    pid,
                    tid,
                    parent_pid: None,
                    parent_tid: None,
                    start_ns: None,
                    end_ns: None,
                });
                vec![threads.len() - 1]
            });
        }
        for ids in by_id.values_mut() {
            ids.sort_by_key(|&id| threads[id].start_ns);
        }
        Self { threads, by_id }
    }

    /// The last lifetime of a thread id that started by `time`, where
    /// `None` is before the recording.
    fn at(&self, pid: u32, tid: u32, time: Option<u64>) -> Option<usize> {
        let ids = self.by_id.get(&(pid, tid))?;
        let started = ids.partition_point(|&id| match (self.threads[id].start_ns, time) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(start), Some(time)) => start <= time,
        });
        Some(ids[started.saturating_sub(1)])
    }

    fn of(&self, pid: u32, tid: u32, time_ns: u64) -> usize {
        self.at(pid, tid, Some(time_ns))
            .expect("every thread id seen has a lifetime")
    }
}

/// The window in absolute times.
struct Bounds {
    from: u64,
    /// Where the time alive ends.
    to: u64,
    /// Where presence ends, exclusive.
    limit: u64,
}

impl Bounds {
    /// When the thread was in the window, half-open. It counts as alive
    /// at the moment it exits.
    fn presence(&self, thread: &Thread) -> (u64, u64) {
        (
            thread
                .start_ns
                .map_or(self.from, |start| start.max(self.from)),
            thread
                .end_ns
                .map_or(self.limit, |end| end.saturating_add(1).min(self.limit)),
        )
    }

    /// The part of a lifetime inside the window, empty when the start comes
    /// after the end.
    fn clip(&self, thread: &Thread) -> (u64, u64) {
        (
            thread
                .start_ns
                .map_or(self.from, |start| start.max(self.from)),
            thread.end_ns.map_or(self.to, |end| end.min(self.to)),
        )
    }
}

/// What the window holds of one thread lifetime.
struct Life<'a> {
    /// The names it had while in the window.
    names: Vec<&'a str>,
    present: bool,
    /// Absolute times it was alive in the window.
    alive: (u64, u64),
    /// Its pid and the lifetime of that pid's main thread, if seen.
    process: (u32, Option<usize>),
}

/// One row per process lifetime that has a thread row.
fn processes(
    lifetimes: &Lifetimes,
    lives: &[Life],
    threads: &HashMap<usize, ThreadRow>,
    empty: &(CPUTime, Option<OffCPUTime>),
    base: u64,
) -> Vec<ProcessRow> {
    let mut members: HashMap<(u32, Option<usize>), Vec<usize>> = HashMap::new();
    for (id, life) in lives.iter().enumerate() {
        if life.present || threads.contains_key(&id) {
            members.entry(life.process).or_default().push(id);
        }
    }
    let mut times: HashMap<(u32, Option<usize>), (CPUTime, Option<OffCPUTime>)> = HashMap::new();
    for (&id, row) in threads {
        let (cpu, off_cpu) = times
            .entry(lives[id].process)
            .or_insert_with(|| empty.clone());
        cpu.merge(&row.cpu);
        if let (Some(total), Some(time)) = (off_cpu.as_mut(), &row.off_cpu) {
            total.merge(time);
        }
    }
    times
        .into_iter()
        .map(|((pid, main), (cpu, off_cpu))| {
            let ids = &members[&(pid, main)];
            let first = ids.iter().map(|&id| lives[id].alive.0).min().unwrap_or(0);
            let last = ids.iter().map(|&id| lives[id].alive.1).max().unwrap_or(0);
            let alive_ns = last.saturating_sub(first);
            let starts = ids.iter().map(|&id| lifetimes.threads[id].start_ns);
            let ends = ids.iter().map(|&id| lifetimes.threads[id].end_ns);
            let last_name = |id: usize| lives[id].names.last().map(|n| n.to_string());
            let name = main.and_then(last_name).or_else(|| {
                let first = ids.iter().copied().min_by_key(|&id| lives[id].alive.0)?;
                last_name(first)
            });
            ProcessRow {
                pid,
                name,
                start_ns: starts
                    .collect::<Option<Vec<u64>>>()
                    .and_then(|s| s.into_iter().min())
                    .map(|t| t.saturating_sub(base)),
                end_ns: ends
                    .collect::<Option<Vec<u64>>>()
                    .and_then(|e| e.into_iter().max())
                    .map(|t| t.saturating_sub(base)),
                threads: ids.len(),
                alive_ns,
                cpu_utilization: ratio(cpu.cpu_ns, alive_ns),
                cpu,
                off_cpu,
            }
        })
        .collect()
}

fn ratio(part: u64, whole: u64) -> Option<f64> {
    (whole > 0).then(|| part as f64 / whole as f64)
}
