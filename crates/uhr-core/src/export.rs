//! Export recordings for interactive review in Firefox Profiler.

use std::collections::{BTreeMap, HashMap};
use std::io::{self, Write};
use std::path::Path;

use serde::Serialize;
use serde_json::json;

use crate::coverage::{Coverage, SymbolCoverage};
use crate::filter::{self, Filter};
use crate::functions::{Function, Functions, Step};
use crate::recording::{self, Origin, Recording};
use crate::symbols::Symbols;
use crate::threads::ThreadNames;
use crate::wall_clock;

mod firefox;
mod observations;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Recording(#[from] recording::Error),
    #[error(transparent)]
    Filter(#[from] filter::Error),
    #[error("no observations passed the filter, so there is nothing to export")]
    Empty,
}

/// The contents and limitations of an export. Counts describe the selected
/// observations; recording and symbol coverage describe the whole recording.
#[derive(Debug, Serialize)]
pub struct Report {
    pub format: &'static str,
    pub threads: usize,
    pub samples: usize,
    pub cpu_ns: u64,
    /// CPU time whose sampled stack contains at least one unnamed frame.
    pub unnamed_cpu_ns: u64,
    #[serde(flatten)]
    pub observations: ObservationCounts,
    pub filter: Filter,
    pub symbols: SymbolCoverage,
    pub coverage: Coverage,
    pub limitations: Vec<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct ObservationCounts {
    pub off_cpu_intervals: usize,
    pub off_cpu_ns: u64,
    pub page_fault_samples: usize,
    pub memory_readings: usize,
}

pub struct FirefoxProfile {
    pub report: Report,
    profile: firefox::Profile,
}

impl FirefoxProfile {
    /// Write the profile itself, not the command's summary.
    pub fn write(&self, out: &mut impl Write) -> io::Result<()> {
        serde_json::to_writer(out, &self.profile).map_err(io::Error::from)
    }
}

pub fn firefox(dir: &Path, filter: &Filter) -> Result<FirefoxProfile, Error> {
    let recording = Recording::read(dir)?;
    let symbols = Symbols::read(dir, &recording)?;
    run(&recording, symbols.as_ref(), filter)
}

pub fn run(
    recording: &Recording,
    symbols: Option<&Symbols>,
    filter: &Filter,
) -> Result<FirefoxProfile, Error> {
    let functions = Functions::new(recording, symbols);
    let labels = labels(&functions);
    let start = recording.manifest.start_ns.unwrap_or(0);
    let mut builder = Builder::new(recording, &functions, &labels, start);
    let mut samples: Vec<_> = filter.samples(recording, &functions)?.collect();
    samples.sort_by_key(|s| s.time_ns);
    let mut cpu_ns = 0;
    let mut unnamed_cpu_ns = 0;
    let unnamed: Vec<_> = recording
        .stacks
        .iter()
        .map(|stack| {
            functions
                .expand(stack)
                .any(|f| functions.get(f).name.is_none())
        })
        .collect();
    for sample in &samples {
        let thread = builder.thread(sample.pid, sample.tid, sample.time_ns);
        let stack = builder.stack(thread, sample.stack);
        builder.threads[thread]
            .data
            .samples
            .0
            .push(firefox::Sample {
                time: relative_ms(sample.time_ns, start),
                stack,
                weight: ms(sample.cpu_ns),
            });
        cpu_ns += sample.cpu_ns;
        if unnamed[sample.stack as usize] {
            unnamed_cpu_ns += sample.cpu_ns;
        }
    }
    let (observations, counters) = builder.observations(filter)?;
    if samples.is_empty()
        && observations.off_cpu_intervals == 0
        && observations.page_fault_samples == 0
        && observations.memory_readings == 0
    {
        return Err(Error::Empty);
    }
    let mut limitations = vec![
        "CPU weights are sampled estimates, not measured durations of individual calls; per-thread CPU deltas were not recorded.".into(),
        "Source locations are included when known; source text and disassembly are not embedded.".into(),
    ];
    if !recording.syscall_calls.is_empty() {
        limitations
            .push("Syscall aggregates are not exported; use uhr query --group-by syscall.".into());
    }
    if !recording.region_memory.is_empty() {
        limitations.push("Per-region resident-memory readings are not exported.".into());
    }
    if !recording.memory.is_empty() && filter.memory(recording).is_none() {
        limitations.push("Process memory is omitted because the filter selects threads, modes, stacks, syscalls or regions.".into());
    }
    if observations.memory_readings > 0 {
        limitations.push("Firefox rebases the resident-memory graph to the minimum in the displayed range; memory markers contain absolute readings.".into());
    }
    let wall_time = match wall_clock::utc_of(&recording.manifest, 0) {
        Ok(ns) => ns as f64 / 1e6,
        Err(e) => {
            limitations.push(format!("Absolute time is unknown ({e}); the viewer's epoch is a placeholder. Relative times are preserved."));
            0.0
        }
    };
    let report = Report {
        format: "firefox",
        threads: builder.threads.len(),
        samples: samples.len(),
        cpu_ns,
        unnamed_cpu_ns,
        observations,
        filter: filter.clone(),
        symbols: SymbolCoverage::of(recording, symbols),
        coverage: Coverage::of(recording),
        limitations,
    };
    let interval = recording
        .manifest
        .streams
        .iter()
        .filter_map(|s| s.collector.sampling())
        .filter(|s| s.frequency_hz > 0)
        .map(|s| 1000.0 / s.frequency_hz as f64)
        .reduce(f64::min)
        .unwrap_or(1.0);
    let profile = firefox::Profile {
        meta: json!({
            "version": 24,
            "preprocessedProfileVersion": 55,
            "product": recording.manifest.target.command.join(" "),
            "importedFrom": "uhr",
            "interval": interval,
            "startTime": wall_time,
            "profilingStartTime": 0,
            "profilingEndTime": recording.manifest.end_ns.map(|t| relative_ms(t, start)),
            "processType": 0,
            "stackwalk": 1,
            "symbolicated": true,
            "usesOnlyOneStackType": true,
            "sourceCodeIsNotOnSearchfox": true,
            "oscpu": format!("{} {}", recording.manifest.platform.os, recording.manifest.platform.arch),
            "categories": [
                {"name": "Unknown", "color": "grey", "subcategories": ["Other"]},
                {"name": "Native", "color": "blue", "subcategories": ["Other"]},
                {"name": "Kernel", "color": "orange", "subcategories": ["Other"]},
                {"name": "JIT", "color": "purple", "subcategories": ["Other"]},
                {"name": "Interpreted", "color": "green", "subcategories": ["Other"]}
            ],
            "markerSchema": observations::schemas(),
            "extra": [{"label": "uhr export", "entries": [
                {"label": "Coverage and limitations", "format": "string", "value": serde_json::to_string_pretty(&report).expect("report contains only JSON values")}
            ]}]
        }),
        libs: builder.libs,
        counters,
        threads: builder
            .threads
            .into_iter()
            .map(|mut t| {
                t.data.markers.0.sort_by(|a, b| a.start.total_cmp(&b.start));
                t.data
            })
            .collect(),
        pages: Vec::new(),
    };
    Ok(FirefoxProfile { report, profile })
}

fn ms(ns: u64) -> f64 {
    ns as f64 / 1e6
}

fn relative_ms(time: u64, start: u64) -> f64 {
    // Subtract before conversion so a long system uptime loses no precision.
    (i128::from(time) - i128::from(start)) as f64 / 1e6
}

type ThreadKey = (u32, u32, Option<usize>, Option<usize>);

struct Builder<'a> {
    recording: &'a Recording,
    functions: &'a Functions,
    labels: &'a [String],
    start: u64,
    names: ThreadNames<'a>,
    lifetimes: BTreeMap<(u32, u32), Vec<usize>>,
    thread_ids: HashMap<ThreadKey, usize>,
    process_ends: HashMap<usize, Option<u64>>,
    tid_uses: HashMap<u32, usize>,
    threads: Vec<ThreadBuilder>,
    lib_ids: HashMap<(String, Option<String>), usize>,
    libs: Vec<firefox::Library>,
}

impl<'a> Builder<'a> {
    fn new(
        recording: &'a Recording,
        functions: &'a Functions,
        labels: &'a [String],
        start: u64,
    ) -> Self {
        let mut lifetimes: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for (i, thread) in recording.threads.iter().enumerate() {
            lifetimes
                .entry((thread.pid, thread.tid))
                .or_default()
                .push(i);
        }
        for rows in lifetimes.values_mut() {
            rows.sort_by_key(|&i| recording.threads[i].start_ns);
        }
        let mut builder = Self {
            recording,
            functions,
            labels,
            start,
            names: ThreadNames::new(recording),
            lifetimes,
            thread_ids: HashMap::new(),
            process_ends: HashMap::new(),
            tid_uses: HashMap::new(),
            threads: Vec::new(),
            lib_ids: HashMap::new(),
            libs: Vec::new(),
        };
        for thread in &recording.threads {
            *builder.tid_uses.entry(thread.tid).or_default() += 1;
            if let Some(process) = builder.process_row(thread.pid, thread.start_ns.unwrap_or(start))
            {
                builder
                    .process_ends
                    .entry(process)
                    .and_modify(|end| {
                        *end = end.zip(thread.end_ns).map(|(a, b)| a.max(b));
                    })
                    .or_insert(thread.end_ns);
            }
        }
        builder
    }

    fn process_row(&self, pid: u32, time: u64) -> Option<usize> {
        let rows = self.lifetimes.get(&(pid, pid))?;
        let end =
            rows.partition_point(|&i| self.recording.threads[i].start_ns.is_none_or(|t| t <= time));
        // The main thread may exit while workers keep the process alive.
        rows.get(end.checked_sub(1)?).copied()
    }

    fn lifetime(&self, pid: u32, tid: u32, time: u64) -> Option<usize> {
        let rows = self.lifetimes.get(&(pid, tid))?;
        let end =
            rows.partition_point(|&i| self.recording.threads[i].start_ns.is_none_or(|t| t <= time));
        let index = *rows.get(end.checked_sub(1)?)?;
        self.recording.threads[index]
            .end_ns
            .is_none_or(|t| time <= t)
            .then_some(index)
    }

    fn thread(&mut self, pid: u32, tid: u32, time: u64) -> usize {
        let row = self.lifetime(pid, tid, time);
        let leader_row = self.process_row(pid, time);
        let key = (pid, tid, row, leader_row);
        if let Some(&id) = self.thread_ids.get(&key) {
            return id;
        }
        let thread = row.map(|i| &self.recording.threads[i]);
        let leader = leader_row.map(|i| &self.recording.threads[i]);
        let from = thread.and_then(|t| t.start_ns).unwrap_or(self.start);
        let to = thread
            .and_then(|t| t.end_ns)
            .or(self.recording.manifest.end_ns)
            .unwrap_or(u64::MAX);
        let rows = self
            .lifetimes
            .get(&(pid, tid))
            .map_or(&[][..], Vec::as_slice);
        let after =
            rows.partition_point(|&i| self.recording.threads[i].start_ns.is_none_or(|t| t <= time));
        let previous_end = after
            .checked_sub(1)
            .and_then(|i| self.recording.threads[rows[i]].end_ns);
        let name_start = match thread {
            Some(thread) => thread.start_ns,
            None => previous_end.map(|t| t.saturating_add(1)),
        };
        let name_end = rows
            .get(after)
            .and_then(|&i| self.recording.threads[i].start_ns)
            .map_or(to.saturating_add(1), |next| next.min(to.saturating_add(1)));
        let name = self
            .names
            .of_lifetime(pid, tid, name_start, name_end)
            .join(" → ");
        let name = if name.is_empty() {
            format!("Thread {tid}")
        } else {
            name
        };
        let unique = |id: u32, row: Option<usize>, reused: bool| match row {
            Some(row) if reused => format!("{id}@{row}"),
            _ => id.to_string(),
        };
        let reused = |id| self.tid_uses.get(&id).is_some_and(|&n| n > 1);
        let data = firefox::Thread {
            name,
            pid: unique(pid, leader_row, reused(pid)),
            tid: match row {
                None if self.tid_uses.contains_key(&tid) || leader_row.is_some() => {
                    format!("{tid}@untracked-{}", self.threads.len())
                }
                _ => unique(tid, row, reused(tid)),
            },
            process_name: self
                .names
                .of_lifetime(
                    pid,
                    pid,
                    leader.and_then(|t| t.start_ns),
                    time.saturating_add(1),
                )
                .last()
                .map(|name| (*name).to_owned())
                .unwrap_or_else(|| format!("Process {pid}")),
            is_main_thread: pid == tid,
            process_type: "default",
            process_startup_time: relative_ms(
                leader.and_then(|t| t.start_ns).unwrap_or(self.start),
                self.start,
            ),
            process_shutdown_time: leader_row
                .and_then(|row| self.process_ends[&row])
                .map(|t| relative_ms(t, self.start)),
            register_time: relative_ms(from, self.start),
            unregister_time: thread
                .and_then(|t| t.end_ns)
                .map(|t| relative_ms(t, self.start)),
            paused_ranges: Vec::new(),
            string_array: Vec::new(),
            samples: Default::default(),
            stack_table: Default::default(),
            frame_table: Default::default(),
            func_table: Default::default(),
            resource_table: Default::default(),
            native_symbols: json!({"length": 0, "libIndex": [], "address": [], "name": [], "functionSize": []}),
            markers: Default::default(),
            show_markers_in_timeline: true,
        };
        let id = self.threads.len();
        self.threads.push(ThreadBuilder {
            data,
            ..Default::default()
        });
        self.thread_ids.insert(key, id);
        id
    }

    fn library(&mut self, function: u32) -> Option<usize> {
        let f = self.functions.get(function);
        let path = f.module.as_ref()?;
        let key = (path.clone(), f.build_id.clone());
        Some(*self.lib_ids.entry(key).or_insert_with(|| {
            let id = self.libs.len();
            self.libs.push(firefox::Library {
                name: path.rsplit('/').next().unwrap_or(path).into(),
                path: path.clone(),
                debug_path: String::new(),
                debug_name: String::new(),
                debug_id: String::new(),
                code_id: f.build_id.clone(),
                arch: self.recording.manifest.platform.arch.clone(),
            });
            id
        }))
    }

    fn stack(&mut self, thread: usize, stack: u32) -> Option<usize> {
        if let Some(&id) = self.threads[thread].stacks.get(&stack) {
            return id;
        }
        let steps: Vec<_> = self
            .functions
            .steps(&self.recording.stacks[stack as usize])
            .collect();
        let mut prefix = None;
        for step in steps.into_iter().rev() {
            let lib = self.library(step.function);
            let f = self.functions.get(step.function);
            let t = &mut self.threads[thread];
            let frame = if let Some(&id) = t.frames.get(&step) {
                id
            } else {
                let source = step
                    .line
                    .map(|l| self.functions.line(l).file.as_str())
                    .or(f.file.as_deref());
                let file = source.map(|file| t.string(file));
                let key = (step.function, file);
                let function = if let Some(&id) = t.functions.get(&key) {
                    id
                } else {
                    let name = t.string(&self.labels[step.function as usize]);
                    let place = (source == f.file.as_deref())
                        .then(|| self.functions.start(step.function))
                        .flatten();
                    let (line, column) = place
                        .as_deref()
                        .map(|s| s.split_once(':').map_or((s, None), |(l, c)| (l, Some(c))))
                        .map_or((None, None), |(l, c)| {
                            (l.parse().ok(), c.and_then(|c| c.parse().ok()))
                        });
                    let resource = match lib {
                        None => -1,
                        Some(lib) => t.resource(lib, f.module.as_deref().unwrap()) as i64,
                    };
                    let id = t.data.func_table.0.len();
                    t.data.func_table.0.push(firefox::Function {
                        name,
                        resource,
                        file,
                        line,
                        column,
                    });
                    t.functions.insert(key, id);
                    id
                };
                let id = t.data.frame_table.0.len();
                t.data.frame_table.0.push(firefox::Frame {
                    function,
                    category: category(f.origin),
                    line: step.line.map(|l| self.functions.line(l).line),
                    inlined: f.inlined,
                });
                t.frames.insert(step, id);
                id
            };
            let id = *t.prefixes.entry((prefix, frame)).or_insert_with(|| {
                let id = t.data.stack_table.0.len();
                t.data.stack_table.0.push((prefix, frame));
                id
            });
            prefix = Some(id);
        }
        self.threads[thread].stacks.insert(stack, prefix);
        prefix
    }
}

#[derive(Default)]
struct ThreadBuilder {
    data: firefox::Thread,
    strings: HashMap<String, usize>,
    functions: HashMap<(u32, Option<usize>), usize>,
    frames: HashMap<Step, usize>,
    stacks: HashMap<u32, Option<usize>>,
    prefixes: HashMap<(Option<usize>, usize), usize>,
    resources: HashMap<usize, usize>,
}

impl ThreadBuilder {
    fn string(&mut self, text: &str) -> usize {
        *self.strings.entry(text.into()).or_insert_with(|| {
            let id = self.data.string_array.len();
            self.data.string_array.push(text.into());
            id
        })
    }

    fn resource(&mut self, lib: usize, name: &str) -> usize {
        if let Some(&id) = self.resources.get(&lib) {
            return id;
        }
        let name = self.string(name);
        let id = self.data.resource_table.0.len();
        self.data.resource_table.0.push((lib, name));
        self.resources.insert(lib, id);
        id
    }
}

fn category(origin: Origin) -> usize {
    match origin {
        Origin::Unresolved => 0,
        Origin::Binary => 1,
        Origin::Kernel => 2,
        Origin::Jit => 3,
        Origin::Interpreted => 4,
    }
}

fn labels(functions: &Functions) -> Vec<String> {
    let label = |f: &Function| {
        f.name.clone().unwrap_or_else(|| {
            format!(
                "[unknown {}: {}]",
                f.origin.as_str(),
                f.placeholder
                    .as_deref()
                    .or(f.module.as_deref())
                    .unwrap_or("no mapping")
            )
        })
    };
    let mut labels: Vec<_> = (0..functions.len())
        .map(|i| label(functions.get(i as u32)))
        .collect();
    // Firefox merges functions by their visible properties when upgrading or
    // combining threads. Preserve distinct functions that share a name.
    let mut use_ids = true;
    loop {
        let mut by_label: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (i, label) in labels.iter().enumerate() {
            by_label.entry(label.clone()).or_default().push(i);
        }
        let duplicates: Vec<_> = by_label.into_values().filter(|v| v.len() > 1).collect();
        if duplicates.is_empty() {
            return labels;
        }
        for group in duplicates {
            for i in group {
                labels[i] = format!(
                    "{} [{}]",
                    labels[i],
                    (use_ids
                        .then(|| functions.get(i as u32).id.clone())
                        .flatten())
                    .unwrap_or_else(|| format!("function {i}"))
                );
            }
        }
        use_ids = false;
    }
}
