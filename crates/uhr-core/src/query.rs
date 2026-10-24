use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use serde::Serialize;

use crate::coverage::{Coverage, SymbolCoverage};
use crate::filter::Filter;
use crate::functions::{Function, Functions};
use crate::recording::{self, Origin, Recording};
use crate::symbols::Symbols;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupBy {
    Function,
}

#[derive(Debug, Clone)]
pub struct Query {
    pub group_by: GroupBy,
    pub top: usize,
    pub filter: Filter,
}

#[derive(Debug, Clone, Serialize)]
pub struct QueryResult {
    pub group_by: GroupBy,
    pub filter: Filter,
    /// Samples that passed the filter.
    pub samples: u64,
    pub cpu_ns: u64,
    /// Sorted by self time, then total time.
    pub rows: Vec<Row>,
    /// Rows cut by `top`.
    pub rows_omitted: usize,
    pub coverage: QueryCoverage,
}

#[derive(Debug, Clone, Serialize)]
pub struct Row {
    #[serde(flatten)]
    pub function: Function,
    /// CPU time with this function as the leaf.
    pub self_cpu_ns: u64,
    pub self_share: f64,
    /// CPU time with this function anywhere on the stack, counted once per
    /// sample even when it recurses.
    pub total_cpu_ns: u64,
    pub total_share: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct QueryCoverage {
    /// Share of CPU time whose leaf frame has a name. Placeholders don't
    /// count. `None` without samples.
    pub named_share: Option<f64>,
    /// Share of CPU time whose leaf frame has no name, by origin.
    pub unnamed_by_origin: BTreeMap<Origin, f64>,
    #[serde(flatten)]
    pub symbols: SymbolCoverage,
    #[serde(flatten)]
    pub recording: Coverage,
}

pub fn query(dir: &Path, query: &Query) -> Result<QueryResult, recording::Error> {
    let recording = Recording::read(dir)?;
    let symbols = Symbols::read(dir, &recording)?;
    Ok(run(&recording, symbols.as_ref(), query))
}

pub fn run(recording: &Recording, symbols: Option<&Symbols>, query: &Query) -> QueryResult {
    match query.group_by {
        GroupBy::Function => by_function(recording, symbols, query),
    }
}

fn by_function(recording: &Recording, symbols: Option<&Symbols>, query: &Query) -> QueryResult {
    let functions = Functions::new(recording, symbols);
    let mut stack_cpu_ns = vec![0u64; recording.stacks.len()];
    let mut samples = 0;
    for sample in query.filter.samples(recording) {
        stack_cpu_ns[sample.stack as usize] += sample.cpu_ns;
        samples += 1;
    }
    let cpu_ns: u64 = stack_cpu_ns.iter().sum();

    let mut self_ns = vec![0u64; functions.len()];
    let mut total_ns = vec![0u64; functions.len()];
    let mut seen = HashSet::new();
    for (stack, &weight) in recording.stacks.iter().zip(&stack_cpu_ns) {
        if weight == 0 {
            continue;
        }
        self_ns[functions.of_frame[stack[0] as usize] as usize] += weight;
        seen.clear();
        for &frame in stack {
            let function = functions.of_frame[frame as usize];
            if seen.insert(function) {
                total_ns[function as usize] += weight;
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
    let mut rows: Vec<Row> = (0..functions.len())
        .filter(|&id| total_ns[id] > 0)
        .map(|id| Row {
            function: functions.get(id as u32).clone(),
            self_cpu_ns: self_ns[id],
            self_share: share(self_ns[id]),
            total_cpu_ns: total_ns[id],
            total_share: share(total_ns[id]),
        })
        .collect();
    rows.sort_by(|a, b| {
        (b.self_cpu_ns, b.total_cpu_ns)
            .cmp(&(a.self_cpu_ns, a.total_cpu_ns))
            .then_with(|| a.function.name.cmp(&b.function.name))
            .then_with(|| a.function.placeholder.cmp(&b.function.placeholder))
            .then_with(|| a.function.module.cmp(&b.function.module))
            .then_with(|| a.function.build_id.cmp(&b.function.build_id))
            .then_with(|| {
                a.function
                    .function_address
                    .cmp(&b.function.function_address)
            })
    });
    let rows_omitted = rows.len().saturating_sub(query.top);
    rows.truncate(query.top);

    let mut unnamed_by_origin = BTreeMap::new();
    let mut named_ns = 0;
    for (id, &ns) in self_ns.iter().enumerate() {
        let function = functions.get(id as u32);
        if function.name.is_some() {
            named_ns += ns;
        } else if ns > 0 {
            *unnamed_by_origin.entry(function.origin).or_insert(0) += ns;
        }
    }

    let mut recording = Coverage::of(recording);
    let coverage = QueryCoverage {
        named_share: (cpu_ns > 0).then(|| share(named_ns)),
        unnamed_by_origin: unnamed_by_origin
            .into_iter()
            .map(|(origin, ns)| (origin, share(ns)))
            .collect(),
        symbols: SymbolCoverage::of(symbols, &mut recording),
        recording,
    };

    QueryResult {
        group_by: GroupBy::Function,
        filter: query.filter.clone(),
        samples,
        cpu_ns,
        rows,
        rows_omitted,
        coverage,
    }
}
