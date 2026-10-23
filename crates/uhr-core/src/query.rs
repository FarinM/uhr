use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use anyhow::Result;
use serde::Serialize;

use crate::recording::{Collector, MissingSignal, Origin, Recording, Unwinding};
use crate::symbols::{FrameName, Source, SourceStatus, Symbols};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupBy {
    Function,
}

#[derive(Debug, Clone)]
pub struct Query {
    pub group_by: GroupBy,
    pub top: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct QueryResult {
    pub group_by: GroupBy,
    pub samples: u64,
    pub cpu_ns: u64,
    /// Sorted by self time, then total time.
    pub rows: Vec<Row>,
    /// Rows cut by `top`.
    pub rows_omitted: usize,
    pub coverage: Coverage,
}

/// One function, or the unnamed code of one module.
#[derive(Debug, Clone, Serialize)]
pub struct Row {
    /// `None` for frames without a name.
    pub function: Option<String>,
    /// The label wholesym made up from the address when there is no name,
    /// such as `fun_1200`. Counted as unnamed.
    pub placeholder: Option<String>,
    /// Path of the file the code was mapped from.
    pub module: Option<String>,
    pub build_id: Option<String>,
    /// Function start relative to the binary's image base, when known.
    pub function_address: Option<u32>,
    pub origin: Origin,
    /// CPU time with this function as the leaf.
    pub self_cpu_ns: u64,
    pub self_share: f64,
    /// CPU time with this function anywhere on the stack, counted once per
    /// sample even when it recurses.
    pub total_cpu_ns: u64,
    pub total_share: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Coverage {
    /// Share of CPU time whose leaf frame has a name. Placeholders don't
    /// count. `None` without samples.
    pub named_share: Option<f64>,
    /// Share of CPU time whose leaf frame has no name, by origin.
    pub unnamed_by_origin: BTreeMap<Origin, f64>,
    pub symbolized: bool,
    /// Files whose frames got no names, or names that could not be checked.
    pub symbol_problems: Vec<Source>,
    pub lost_events: u64,
    pub throttle_events: u64,
    pub samples_at_stack_limit: u64,
    pub missing_signals: Vec<MissingSignal>,
    /// What this result cannot account for because it was not measured.
    pub unknown: Vec<String>,
    pub known_biases: Vec<String>,
}

pub fn query(dir: &Path, query: &Query) -> Result<QueryResult> {
    let recording = Recording::read(dir)?;
    let symbols = Symbols::read(dir, &recording)?;
    Ok(run(&recording, symbols.as_ref(), query))
}

pub fn run(recording: &Recording, symbols: Option<&Symbols>, query: &Query) -> QueryResult {
    match query.group_by {
        GroupBy::Function => by_function(recording, symbols, query.top),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FunctionKey {
    origin: Origin,
    module: Option<u32>,
    address: Option<u32>,
}

fn by_function(recording: &Recording, symbols: Option<&Symbols>, top: usize) -> QueryResult {
    // Mapping ids change across processes and reloads; build ids distinguish
    // different binaries that occupied the same path.
    let mut module_ids: HashMap<(&str, Option<&str>), u32> = HashMap::new();
    let mut modules: Vec<(&str, Option<&str>)> = Vec::new();
    let mut key_ids: HashMap<FunctionKey, u32> = HashMap::new();
    let mut keys: Vec<FunctionKey> = Vec::new();
    let mut names: Vec<Option<FrameName>> = Vec::new();
    let frame_keys: Vec<u32> = recording
        .frames
        .iter()
        .enumerate()
        .map(|(id, frame)| {
            let module = frame.mapping.map(|m| {
                let mapping = &recording.mappings[m as usize];
                let module = (mapping.path.as_str(), mapping.build_id.as_deref());
                *module_ids.entry(module).or_insert_with(|| {
                    modules.push(module);
                    modules.len() as u32 - 1
                })
            });
            let key = FunctionKey {
                origin: frame.origin,
                module,
                address: symbols.and_then(|s| s.function_addresses[id]),
            };
            *key_ids.entry(key).or_insert_with_key(|key| {
                keys.push(key.clone());
                names.push(symbols.and_then(|s| s.names[id].clone()));
                keys.len() as u32 - 1
            })
        })
        .collect();

    let mut stack_cpu_ns = vec![0u64; recording.stacks.len()];
    for sample in &recording.samples {
        stack_cpu_ns[sample.stack as usize] += sample.cpu_ns;
    }
    let cpu_ns: u64 = stack_cpu_ns.iter().sum();

    let mut self_ns = vec![0u64; keys.len()];
    let mut total_ns = vec![0u64; keys.len()];
    let mut seen = HashSet::new();
    for (stack, &weight) in recording.stacks.iter().zip(&stack_cpu_ns) {
        if weight == 0 {
            continue;
        }
        self_ns[frame_keys[stack[0] as usize] as usize] += weight;
        seen.clear();
        for &frame in stack {
            let key = frame_keys[frame as usize];
            if seen.insert(key) {
                total_ns[key as usize] += weight;
            }
        }
    }

    let share = |ns: u64| {
        if cpu_ns == 0 {
            0.0
        } else {
            ns as f64 / cpu_ns as f64
        }
    };
    let mut rows: Vec<Row> = keys
        .iter()
        .enumerate()
        .filter(|&(id, _)| total_ns[id] > 0)
        .map(|(id, key)| Row {
            function: names[id]
                .as_ref()
                .and_then(FrameName::symbol)
                .map(str::to_owned),
            placeholder: match &names[id] {
                Some(FrameName::Placeholder(label)) => Some(label.clone()),
                _ => None,
            },
            module: key.module.map(|m| modules[m as usize].0.to_owned()),
            build_id: key
                .module
                .and_then(|m| modules[m as usize].1.map(str::to_owned)),
            function_address: key.address,
            origin: key.origin,
            self_cpu_ns: self_ns[id],
            self_share: share(self_ns[id]),
            total_cpu_ns: total_ns[id],
            total_share: share(total_ns[id]),
        })
        .collect();
    rows.sort_by(|a, b| {
        (b.self_cpu_ns, b.total_cpu_ns)
            .cmp(&(a.self_cpu_ns, a.total_cpu_ns))
            .then_with(|| a.function.cmp(&b.function))
            .then_with(|| a.placeholder.cmp(&b.placeholder))
            .then_with(|| a.module.cmp(&b.module))
            .then_with(|| a.build_id.cmp(&b.build_id))
            .then_with(|| a.function_address.cmp(&b.function_address))
    });
    let rows_omitted = rows.len().saturating_sub(top);
    rows.truncate(top);

    let mut unnamed_by_origin = BTreeMap::new();
    let mut named_ns = 0;
    for (id, key) in keys.iter().enumerate() {
        if names[id].as_ref().and_then(FrameName::symbol).is_some() {
            named_ns += self_ns[id];
        } else if self_ns[id] > 0 {
            *unnamed_by_origin.entry(key.origin).or_insert(0) += self_ns[id];
        }
    }

    let mut coverage = stream_coverage(recording);
    coverage.named_share = (cpu_ns > 0).then(|| share(named_ns));
    coverage.unnamed_by_origin = unnamed_by_origin
        .into_iter()
        .map(|(origin, ns)| (origin, share(ns)))
        .collect();
    if let Some(symbols) = symbols {
        coverage.symbolized = true;
        coverage.unknown.push(
            "inline call chains are not expanded; self time is attributed to the enclosing machine function".into(),
        );
        coverage.symbol_problems = symbols
            .sources
            .iter()
            .filter(|s| s.status != SourceStatus::Resolved)
            .cloned()
            .collect();
    }

    QueryResult {
        group_by: GroupBy::Function,
        samples: recording.samples.len() as u64,
        cpu_ns,
        rows,
        rows_omitted,
        coverage,
    }
}

fn stream_coverage(recording: &Recording) -> Coverage {
    let mut coverage = Coverage {
        named_share: None,
        unnamed_by_origin: BTreeMap::new(),
        symbolized: false,
        symbol_problems: Vec::new(),
        lost_events: 0,
        throttle_events: 0,
        samples_at_stack_limit: 0,
        missing_signals: Vec::new(),
        unknown: Vec::new(),
        known_biases: Vec::new(),
    };
    for stream in &recording.manifest.streams {
        let c = &stream.coverage;
        coverage.lost_events += c.lost_events;
        coverage.throttle_events += c.throttle_events;
        coverage.samples_at_stack_limit += c.samples_at_stack_limit;
        coverage
            .missing_signals
            .extend(stream.missing_signals.iter().cloned());
        coverage.known_biases.extend(c.known_biases.iter().cloned());
        if c.overhead_ns.is_none() {
            coverage
                .unknown
                .push(format!("profiler overhead of stream {}", stream.id));
        }
        let Collector::Perf { unwinding, .. } = &stream.collector;
        if *unwinding == Unwinding::FramePointers {
            coverage.unknown.push(format!(
                "stacks of stream {} cut short where frame pointers are missing",
                stream.id
            ));
        }
    }
    coverage
}
