use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::Hash;
use std::path::Path;

use serde::Serialize;

use crate::coverage::{Coverage, SymbolCoverage};
use crate::filter::Filter;
use crate::functions::{self, Function, Functions, SourceLine};
use crate::metric::{self, Metric, stack_times};
use crate::recording::{self, Origin, Recording};
use crate::symbols::Symbols;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupBy {
    Function,
    /// Function and source line, from debug info.
    Line,
    /// Binary or library, or the kernel or one of its modules.
    Module,
}

#[derive(Debug, Clone)]
pub struct Query {
    pub group_by: GroupBy,
    pub metric: Metric,
    pub top: usize,
    pub filter: Filter,
}

#[derive(Debug, Clone, Serialize)]
pub struct QueryResult {
    pub group_by: GroupBy,
    pub metric: Metric,
    pub filter: Filter,
    /// CPU samples that passed the filter, if the metric counts them.
    pub samples: u64,
    /// Off-CPU intervals that passed the filter, if the metric counts them.
    pub off_cpu_intervals: u64,
    /// Time of the metric that passed. Shares are of this.
    pub time_ns: u64,
    pub rows: Rows,
    /// Rows cut by `top`.
    pub rows_omitted: usize,
    pub coverage: QueryCoverage,
}

/// The rows of one grouping.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum Rows {
    /// Grouped by function or line. Sorted by self time, then total time.
    Functions(Vec<FunctionRow>),
    /// Sorted by self time, then total time.
    Modules(Vec<ModuleRow>),
}

#[derive(Debug, Clone, Serialize)]
pub struct FunctionRow {
    #[serde(flatten)]
    pub function: Function,
    /// Grouped by line, the line in the function. `None` there for code
    /// without line info, and always `None` grouped by function.
    pub line: Option<SourceLine>,
    /// Time with this row as the leaf.
    pub self_ns: u64,
    pub self_share: f64,
    /// Time with this row anywhere on the stack, counted once per sample or
    /// interval even when it recurses. For a caller's line, the line of the
    /// call.
    pub total_ns: u64,
    pub total_share: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleRow {
    /// Path of the file the code was mapped from, the first one seen when
    /// copies of one binary ran from several paths. `[kernel]` for the
    /// kernel, and a kernel module's name in brackets, as in `[ext4]` or
    /// `[bpf]`. `None` for code outside every known mapping.
    pub module: Option<String>,
    pub build_id: Option<String>,
    pub origin: Origin,
    /// Time running the module's code.
    pub self_ns: u64,
    pub self_share: f64,
    /// Time with the module anywhere on the stack.
    pub total_ns: u64,
    pub total_share: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct QueryCoverage {
    /// Share of the time whose leaf frame has a name. Placeholders don't
    /// count. `None` without any time.
    pub named_share: Option<f64>,
    /// Share of the time whose leaf frame has no name, by origin.
    pub unnamed_by_origin: BTreeMap<Origin, f64>,
    /// Share of the time with no stack: off-CPU time whose stack was not
    /// recorded. It is in no row.
    pub no_stack_share: f64,
    #[serde(flatten)]
    pub symbols: SymbolCoverage,
    #[serde(flatten)]
    pub recording: Coverage,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Recording(#[from] recording::Error),
    /// The filter names a function that is not there, or not only once.
    #[error(transparent)]
    Function(#[from] functions::Error),
    #[error(transparent)]
    Metric(#[from] metric::Error),
}

pub fn query(dir: &Path, query: &Query) -> Result<QueryResult, Error> {
    let recording = Recording::read(dir)?;
    let symbols = Symbols::read(dir, &recording)?;
    run(&recording, symbols.as_ref(), query)
}

pub fn run(
    recording: &Recording,
    symbols: Option<&Symbols>,
    query: &Query,
) -> Result<QueryResult, Error> {
    query.metric.check(recording)?;
    let functions = Functions::new(recording, symbols);
    let times = stack_times(recording, &functions, &query.filter, query.metric)?;
    let time_ns = times.total_ns();

    let share = |ns: u64| {
        if time_ns == 0 {
            0.0
        } else {
            ns as f64 / time_ns as f64
        }
    };
    let mut rows = match query.group_by {
        GroupBy::Function | GroupBy::Line => Rows::Functions(function_rows(
            recording,
            &functions,
            query.group_by == GroupBy::Line,
            &times.ns,
            &share,
        )),
        GroupBy::Module => Rows::Modules(module_rows(recording, &functions, &times.ns, &share)),
    };
    let rows_omitted = rows.truncate(query.top);

    let mut unnamed_by_origin = BTreeMap::new();
    let mut named_ns = 0;
    for (stack, &weight) in recording.stacks.iter().zip(&times.ns) {
        let leaf = functions.get(functions.leaf(stack));
        if leaf.name.is_some() {
            named_ns += weight;
        } else if weight > 0 {
            *unnamed_by_origin.entry(leaf.origin).or_insert(0) += weight;
        }
    }

    let coverage = QueryCoverage {
        named_share: (time_ns > 0).then(|| share(named_ns)),
        unnamed_by_origin: unnamed_by_origin
            .into_iter()
            .map(|(origin, ns)| (origin, share(ns)))
            .collect(),
        no_stack_share: share(times.no_stack_ns),
        symbols: SymbolCoverage::of(recording, symbols),
        recording: Coverage::of(recording),
    };

    Ok(QueryResult {
        group_by: query.group_by,
        metric: query.metric,
        filter: query.filter.clone(),
        samples: times.samples,
        off_cpu_intervals: times.off_cpu_intervals,
        time_ns,
        rows,
        rows_omitted,
        coverage,
    })
}

impl Rows {
    /// Keeps the first `top` rows, and returns how many it cut.
    fn truncate(&mut self, top: usize) -> usize {
        match self {
            Rows::Functions(rows) => truncate(rows, top),
            Rows::Modules(rows) => truncate(rows, top),
        }
    }
}

fn truncate<T>(rows: &mut Vec<T>, top: usize) -> usize {
    let cut = rows.len().saturating_sub(top);
    rows.truncate(top);
    cut
}

fn function_rows(
    recording: &Recording,
    functions: &Functions,
    by_line: bool,
    stack_ns: &[u64],
    share: &impl Fn(u64) -> f64,
) -> Vec<FunctionRow> {
    let row = |function: u32, line: Option<u32>, (self_ns, total_ns): (u64, u64)| FunctionRow {
        function: functions.get(function).clone(),
        line: line.map(|line| functions.line(line).clone()),
        self_ns,
        self_share: share(self_ns),
        total_ns,
        total_share: share(total_ns),
    };
    let mut rows: Vec<FunctionRow> = if by_line {
        tally(recording, stack_ns, |stack, keys| {
            keys.extend(functions.steps(stack))
        })
        .into_iter()
        .map(|(step, times)| row(step.function, step.line, times))
        .collect()
    } else {
        tally(recording, stack_ns, |stack, keys| {
            keys.extend(functions.expand(stack))
        })
        .into_iter()
        .map(|(function, times)| row(function, None, times))
        .collect()
    };
    rows.sort_by(|a, b| {
        (b.self_ns, b.total_ns)
            .cmp(&(a.self_ns, a.total_ns))
            .then_with(|| a.function.name.cmp(&b.function.name))
            .then_with(|| a.function.placeholder.cmp(&b.function.placeholder))
            .then_with(|| a.function.module.cmp(&b.function.module))
            .then_with(|| a.function.build_id.cmp(&b.function.build_id))
            .then_with(|| {
                a.function
                    .function_address
                    .cmp(&b.function.function_address)
            })
            .then_with(|| a.function.id.cmp(&b.function.id))
            .then_with(|| {
                let place = |row: &FunctionRow| row.line.as_ref().map(|l| (l.file.clone(), l.line));
                place(a).cmp(&place(b))
            })
    });
    rows
}

/// Modules are told apart by build-id, or by path without one, as
/// functions are.
fn module_rows(
    recording: &Recording,
    functions: &Functions,
    stack_ns: &[u64],
    share: &impl Fn(u64) -> f64,
) -> Vec<ModuleRow> {
    let mut ids = HashMap::new();
    let mut modules: Vec<&Function> = Vec::new();
    let module_of: Vec<u32> = (0..functions.len() as u32)
        .map(|id| {
            let function = functions.get(id);
            let key = (
                function.origin,
                function.build_id.as_ref().or(function.module.as_ref()),
            );
            *ids.entry(key).or_insert_with(|| {
                modules.push(function);
                modules.len() as u32 - 1
            })
        })
        .collect();
    let mut rows: Vec<ModuleRow> = tally(recording, stack_ns, |stack, keys| {
        keys.extend(functions.expand(stack).map(|f| module_of[f as usize]))
    })
    .into_iter()
    .map(|(module, (self_ns, total_ns))| {
        let function = modules[module as usize];
        ModuleRow {
            module: function.module.clone(),
            build_id: function.build_id.clone(),
            origin: function.origin,
            self_ns,
            self_share: share(self_ns),
            total_ns,
            total_share: share(total_ns),
        }
    })
    .collect();
    rows.sort_by(|a, b| {
        (b.self_ns, b.total_ns)
            .cmp(&(a.self_ns, a.total_ns))
            .then_with(|| a.module.cmp(&b.module))
            .then_with(|| a.build_id.cmp(&b.build_id))
            .then_with(|| a.origin.cmp(&b.origin))
    });
    rows
}

/// Self and total time of each key. `keys` lists the keys of a stack, leaf
/// first. A stack's time counts once for each key, however often the key
/// repeats on it.
fn tally<K: Copy + Eq + Hash>(
    recording: &Recording,
    stack_ns: &[u64],
    mut keys: impl FnMut(&[u32], &mut Vec<K>),
) -> HashMap<K, (u64, u64)> {
    let mut times: HashMap<K, (u64, u64)> = HashMap::new();
    let mut stack_keys = Vec::new();
    let mut seen = HashSet::new();
    for (stack, &weight) in recording.stacks.iter().zip(stack_ns) {
        if weight == 0 {
            continue;
        }
        stack_keys.clear();
        keys(stack, &mut stack_keys);
        times.entry(stack_keys[0]).or_default().0 += weight;
        seen.clear();
        for &key in &stack_keys {
            if seen.insert(key) {
                times.entry(key).or_default().1 += weight;
            }
        }
    }
    times
}
