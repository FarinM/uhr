use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::Hash;
use std::path::Path;

use serde::Serialize;

use crate::coverage::{Coverage, SymbolCoverage};
use crate::filter::{self, Filter};
use crate::functions::{Function, Functions, SourceLine};
use crate::metric::{self, Metric, StackAmounts, Unit, stack_amounts};
use crate::recording::{self, Origin, Recording, RegionKind, Signal};
use crate::regions;
use crate::symbols::Symbols;
use crate::syscalls::{self, InSyscall};
pub use crate::syscalls::{Counted, Latency};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupBy {
    Function,
    /// Function and source line, from debug info.
    Line,
    /// Binary or library, or the kernel or one of its modules.
    Module,
    /// The syscall the thread was in, from the kernel functions on its
    /// stack.
    Syscall,
    /// The region of memory a page fault was in: its kind, and its file or
    /// name.
    Region,
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
    /// What `value` and the rows' amounts count.
    pub unit: Unit,
    pub filter: Filter,
    /// CPU samples, or page-fault samples, that passed the filter, if the
    /// metric counts them.
    pub samples: u64,
    /// Off-CPU intervals that passed the filter, if the metric counts them.
    pub off_cpu_intervals: u64,
    /// The metric's amount that passed. Shares are of this.
    pub value: u64,
    pub rows: Rows,
    /// Rows cut by `top`.
    pub rows_omitted: usize,
    pub coverage: QueryCoverage,
}

/// The rows of one grouping.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum Rows {
    /// Grouped by function or line. Sorted by self amount, then total.
    Functions(Vec<FunctionRow>),
    /// Sorted by self amount, then total.
    Modules(Vec<ModuleRow>),
    /// Sorted by amount.
    Syscalls(Vec<SyscallRow>),
    /// Sorted by amount.
    Regions(Vec<RegionRow>),
}

#[derive(Debug, Clone, Serialize)]
pub struct FunctionRow {
    #[serde(flatten)]
    pub function: Function,
    /// Grouped by line, the line in the function. `None` there for code
    /// without line info, and always `None` grouped by function.
    pub line: Option<SourceLine>,
    /// The amount with this row as the leaf. A runtime's own code, as its
    /// interpreter or builtins, run for one of the program's functions it
    /// compiled, counts for that function instead.
    #[serde(rename = "self")]
    pub self_: u64,
    pub self_share: f64,
    /// The amount with this row anywhere on the stack, counted once per
    /// sample or interval even when it recurses. For a caller's line, the
    /// line of the call.
    pub total: u64,
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
    /// The amount running the module's code, counted as for functions.
    #[serde(rename = "self")]
    pub self_: u64,
    pub self_share: f64,
    /// The amount with the module anywhere on the stack.
    pub total: u64,
    pub total_share: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyscallRow {
    /// Whether the amount was in a syscall. `None` when the stack does not
    /// show it: its kernel functions have no names, it may have been cut
    /// short, or it has none and the CPU was not in user mode, as when
    /// running a virtual machine's guest code. Off-CPU time without a stack
    /// is `None` too.
    pub in_syscall: Option<bool>,
    /// The name in the syscall's kernel function, as `read` in
    /// `__x64_sys_read`. `None` outside syscalls, and in a syscall whose
    /// function is not on the stack, as on its way back to user space.
    pub syscall: Option<String>,
    /// Time in uhr's own eBPF programs, which run as syscalls enter and
    /// leave the kernel. Their stacks don't show which syscall.
    pub own_programs: bool,
    pub value: u64,
    pub share: f64,
    /// The calls uhr's eBPF programs counted, for a named syscall. `None`
    /// without them, or with a filter by time, mode, stack or thread name:
    /// they count each thread's calls over the whole capture.
    pub calls: Option<Counted>,
}

/// The page faults in one kind of region, of one file or name.
#[derive(Debug, Clone, Serialize)]
pub struct RegionRow {
    /// `None` for faults where no region recorded was then: one moved or
    /// grown with mremap, which the kernel doesn't report, or one whose
    /// report perf lost, or none at all.
    pub kind: Option<RegionKind>,
    /// The file mapped, or the region's name, as `[anon:name]`. `None` for
    /// memory that maps no file and has no name, all of which is one row.
    pub path: Option<String>,
    pub value: u64,
    pub share: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct QueryCoverage {
    /// Share of the amount whose leaf frame has a name. Placeholders don't
    /// count. `None` without any amount.
    pub named_share: Option<f64>,
    /// Share of the amount whose leaf frame has no name, by origin.
    pub unnamed_by_origin: BTreeMap<Origin, f64>,
    /// Share of the amount with no stack: off-CPU time whose stack was not
    /// recorded. It is in no row.
    pub no_stack_share: f64,
    /// Share of the amount in uhr's own eBPF programs, which the target's
    /// threads run at their syscalls. `None` without them.
    pub own_programs_share: Option<f64>,
    #[serde(flatten)]
    pub symbols: SymbolCoverage,
    #[serde(flatten)]
    pub recording: Coverage,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Recording(#[from] recording::Error),
    #[error(transparent)]
    Filter(#[from] filter::Error),
    #[error(transparent)]
    Metric(#[from] metric::Error),
    #[error("only page faults were in regions of memory: group them with --metric page-faults")]
    RegionsOfPageFaults,
    #[error(
        "the recording has no regions of memory: perf records them when it samples page faults. \
         Record without --no-page-faults"
    )]
    NoRegions,
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
    if query.group_by == GroupBy::Region {
        if query.metric != Metric::PageFaults {
            return Err(Error::RegionsOfPageFaults);
        }
        let read = recording.manifest.streams.iter();
        if !read
            .clone()
            .any(|s| s.signals.contains(&Signal::MemoryRegions))
        {
            return Err(Error::NoRegions);
        }
    }
    let functions = Functions::new(recording, symbols);
    let amounts = stack_amounts(recording, &functions, &query.filter, query.metric)?;
    let value = amounts.total();

    let share = |amount: u64| {
        if value == 0 {
            0.0
        } else {
            amount as f64 / value as f64
        }
    };
    let mut rows = match query.group_by {
        GroupBy::Function | GroupBy::Line => Rows::Functions(function_rows(
            recording,
            &functions,
            query.group_by == GroupBy::Line,
            &amounts.by_stack,
            &share,
        )),
        GroupBy::Module => Rows::Modules(module_rows(
            recording,
            &functions,
            &amounts.by_stack,
            &share,
        )),
        GroupBy::Syscall => Rows::Syscalls(syscall_rows(
            recording,
            &functions,
            &amounts,
            syscalls::counted(recording, &query.filter),
            &share,
        )),
        GroupBy::Region => {
            Rows::Regions(region_rows(recording, &functions, &query.filter, &share)?)
        }
    };
    let rows_omitted = rows.truncate(query.top);

    let mut unnamed_by_origin = BTreeMap::new();
    let mut named = 0;
    for (stack, &weight) in recording.stacks.iter().zip(&amounts.by_stack) {
        let leaf = functions.get(functions.leaf(stack));
        if leaf.name.is_some() {
            named += weight;
        } else if weight > 0 {
            *unnamed_by_origin.entry(leaf.origin).or_insert(0) += weight;
        }
    }

    let coverage = QueryCoverage {
        named_share: (value > 0).then(|| share(named)),
        unnamed_by_origin: unnamed_by_origin
            .into_iter()
            .map(|(origin, amount)| (origin, share(amount)))
            .collect(),
        no_stack_share: share(amounts.no_stack),
        own_programs_share: recording.in_own_programs().map(|own| {
            share(
                own.iter()
                    .zip(&amounts.by_stack)
                    .filter(|&(&own, _)| own)
                    .map(|(_, &amount)| amount)
                    .sum(),
            )
        }),
        symbols: SymbolCoverage::of(recording, symbols),
        recording: Coverage::of(recording),
    };

    Ok(QueryResult {
        group_by: query.group_by,
        metric: query.metric,
        unit: query.metric.unit(),
        filter: query.filter.clone(),
        samples: amounts.samples,
        off_cpu_intervals: amounts.off_cpu_intervals,
        value,
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
            Rows::Syscalls(rows) => truncate(rows, top),
            Rows::Regions(rows) => truncate(rows, top),
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
    by_stack: &[u64],
    share: &impl Fn(u64) -> f64,
) -> Vec<FunctionRow> {
    let row = |function: u32, line: Option<u32>, (self_, total): (u64, u64)| FunctionRow {
        function: functions.get(function).clone(),
        line: line.map(|line| functions.line(line).clone()),
        self_,
        self_share: share(self_),
        total,
        total_share: share(total),
    };
    let mut rows: Vec<FunctionRow> = if by_line {
        tally(recording, by_stack, |stack, keys| {
            keys.extend(functions.steps(stack));
            let own = functions.own(stack);
            *keys
                .iter()
                .find(|step| step.function == own)
                .unwrap_or(&keys[0])
        })
        .into_iter()
        .map(|(step, amounts)| row(step.function, step.line, amounts))
        .collect()
    } else {
        tally(recording, by_stack, |stack, keys| {
            keys.extend(functions.expand(stack));
            functions.own(stack)
        })
        .into_iter()
        .map(|(function, amounts)| row(function, None, amounts))
        .collect()
    };
    rows.sort_by(|a, b| {
        (b.self_, b.total)
            .cmp(&(a.self_, a.total))
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
    by_stack: &[u64],
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
    let mut rows: Vec<ModuleRow> = tally(recording, by_stack, |stack, keys| {
        keys.extend(functions.expand(stack).map(|f| module_of[f as usize]));
        module_of[functions.own(stack) as usize]
    })
    .into_iter()
    .map(|(module, (self_, total))| {
        let function = modules[module as usize];
        ModuleRow {
            module: function.module.clone(),
            build_id: function.build_id.clone(),
            origin: function.origin,
            self_,
            self_share: share(self_),
            total,
            total_share: share(total),
        }
    })
    .collect();
    rows.sort_by(|a, b| {
        (b.self_, b.total)
            .cmp(&(a.self_, a.total))
            .then_with(|| a.module.cmp(&b.module))
            .then_with(|| a.build_id.cmp(&b.build_id))
            .then_with(|| a.origin.cmp(&b.origin))
    });
    rows
}

fn syscall_rows(
    recording: &Recording,
    functions: &Functions,
    amounts: &StackAmounts,
    mut counted: Option<BTreeMap<String, Counted>>,
    share: &impl Fn(u64) -> f64,
) -> Vec<SyscallRow> {
    let in_syscall = syscalls::of_stacks(recording, functions);
    let mut by_syscall: HashMap<InSyscall, u64> = HashMap::new();
    let mut add = |syscall, weight| {
        if weight > 0 {
            *by_syscall.entry(syscall).or_default() += weight;
        }
    };
    for (stack, &weight) in amounts.by_stack.iter().enumerate() {
        match in_syscall[stack] {
            Some(syscall) => add(syscall, weight),
            None => {
                add(InSyscall::Outside, amounts.user[stack]);
                add(InSyscall::Unknown, weight - amounts.user[stack]);
            }
        }
    }
    add(InSyscall::Unknown, amounts.no_stack);
    let mut rows: Vec<SyscallRow> = by_syscall
        .into_iter()
        .map(|(syscall, value)| {
            let own_programs = syscall == InSyscall::OwnPrograms;
            let (in_syscall, syscall) = match syscall {
                InSyscall::Named(name) => (Some(true), Some(name.to_owned())),
                InSyscall::OwnPrograms | InSyscall::Unnamed => (Some(true), None),
                InSyscall::Outside => (Some(false), None),
                InSyscall::Unknown => (None, None),
            };
            // Counted, a syscall with no calls has zero of them.
            let calls = syscall.as_ref().and_then(|name| {
                let counted = counted.as_mut()?;
                Some(counted.remove(name).unwrap_or_default())
            });
            SyscallRow {
                in_syscall,
                own_programs,
                syscall,
                value,
                share: share(value),
                calls,
            }
        })
        .collect();
    // Syscalls too quick to be in any stack.
    rows.extend(
        counted
            .into_iter()
            .flatten()
            .map(|(name, calls)| SyscallRow {
                in_syscall: Some(true),
                own_programs: false,
                syscall: Some(name),
                value: 0,
                share: 0.0,
                calls: Some(calls),
            }),
    );
    let calls = |row: &SyscallRow| row.calls.as_ref().map(|c| c.calls);
    rows.sort_by(|a, b| {
        b.value
            .cmp(&a.value)
            .then_with(|| calls(b).cmp(&calls(a)))
            .then_with(|| a.syscall.cmp(&b.syscall))
            .then_with(|| a.in_syscall.cmp(&b.in_syscall))
            .then_with(|| a.own_programs.cmp(&b.own_programs))
    });
    rows
}

/// The page faults that pass `filter`, by the kind and file of the region
/// each was in.
fn region_rows(
    recording: &Recording,
    functions: &Functions,
    filter: &Filter,
    share: &impl Fn(u64) -> f64,
) -> Result<Vec<RegionRow>, filter::Error> {
    let in_regions = regions::of_faults(recording);
    let mut faults: HashMap<(Option<RegionKind>, Option<&str>), u64> = HashMap::new();
    for (at, sample) in filter.page_faults(recording, functions)? {
        let region = in_regions[at].map(|row| &recording.regions[row as usize]);
        let key = region.map_or((None, None), |r| (Some(r.kind), r.path.as_deref()));
        *faults.entry(key).or_default() += sample.faults;
    }
    let mut rows: Vec<RegionRow> = faults
        .into_iter()
        .map(|((kind, path), value)| RegionRow {
            kind,
            path: path.map(str::to_owned),
            value,
            share: share(value),
        })
        .collect();
    rows.sort_by(|a, b| {
        b.value
            .cmp(&a.value)
            .then_with(|| a.kind.cmp(&b.kind))
            .then_with(|| a.path.cmp(&b.path))
    });
    Ok(rows)
}

/// The self and total amount of each key. `keys` lists the keys of a
/// stack, leaf first, and returns the one its self amount counts for. A
/// stack's amount counts once for each key, however often the key repeats
/// on it.
fn tally<K: Copy + Eq + Hash>(
    recording: &Recording,
    by_stack: &[u64],
    mut keys: impl FnMut(&[u32], &mut Vec<K>) -> K,
) -> HashMap<K, (u64, u64)> {
    let mut amounts: HashMap<K, (u64, u64)> = HashMap::new();
    let mut stack_keys = Vec::new();
    let mut seen = HashSet::new();
    for (stack, &weight) in recording.stacks.iter().zip(by_stack) {
        if weight == 0 {
            continue;
        }
        stack_keys.clear();
        let own = keys(stack, &mut stack_keys);
        amounts.entry(own).or_default().0 += weight;
        seen.clear();
        for &key in &stack_keys {
            if seen.insert(key) {
                amounts.entry(key).or_default().1 += weight;
            }
        }
    }
    amounts
}
