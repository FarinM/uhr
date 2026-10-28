use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use serde::Serialize;

use crate::coverage::{Coverage, SymbolCoverage};
use crate::filter::{self, Filter};
use crate::functions::{self, Function, Functions};
use crate::metric::{self, Metric, Unit, stack_amounts};
use crate::recording::{self, Origin, Recording, Unwinding};
use crate::symbols::Symbols;

#[derive(Debug, Clone)]
pub struct Query {
    /// A function id, or a name that only one function has.
    pub function: String,
    /// Levels of callers and of callees to follow.
    pub depth: usize,
    /// Children kept per node. The rest are summed.
    pub top: usize,
    pub metric: Metric,
    pub filter: Filter,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Recording(#[from] recording::Error),
    #[error(transparent)]
    Function(#[from] functions::Error),
    #[error(transparent)]
    Filter(#[from] filter::Error),
    #[error(transparent)]
    Metric(#[from] metric::Error),
}

/// Who calls a function and what it calls, as trees from the function out.
/// Where the function recurses, each stack counts from its outermost call,
/// so the callers show where it is entered and the recursion shows among
/// the callees.
#[derive(Debug, Clone, Serialize)]
pub struct CallPaths {
    pub function: Function,
    pub metric: Metric,
    /// What `value` and the other amounts count.
    pub unit: Unit,
    pub filter: Filter,
    pub depth: usize,
    /// CPU samples, or page-fault samples, that passed the filter, if the
    /// metric counts them.
    pub samples: u64,
    /// Off-CPU intervals that passed the filter, if the metric counts them.
    pub off_cpu_intervals: u64,
    /// The metric's amount that passed. Shares are of this.
    pub value: u64,
    /// The amount with the function anywhere on the stack.
    pub total: u64,
    pub total_share: f64,
    /// The amount with the function as the leaf, or running the runtime's
    /// own code for it. See `query`.
    #[serde(rename = "self")]
    pub self_: u64,
    pub self_share: f64,
    /// The amount where nothing called the function: it is where its
    /// thread started, or the stack was cut short.
    pub no_caller: u64,
    /// Its callers, each with their own callers as children.
    pub callers: Vec<Node>,
    pub callers_omitted: Omitted,
    /// Its callees, each with their own callees as children.
    pub callees: Vec<Node>,
    pub callees_omitted: Omitted,
    pub coverage: CallPathsCoverage,
}

/// One step on the paths through the function.
#[derive(Debug, Clone, Serialize)]
pub struct Node {
    #[serde(flatten)]
    pub function: Function,
    /// The amount of the function's stacks on the path to here.
    pub value: u64,
    pub share: f64,
    /// Among callees, the amount with this node as the leaf. `None` among
    /// callers.
    #[serde(rename = "self")]
    pub self_: Option<u64>,
    pub children: Vec<Node>,
    /// Children cut by `top`, or all of them at the depth limit.
    pub omitted: Omitted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Omitted {
    pub nodes: usize,
    pub value: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CallPathsCoverage {
    /// Share of the function's amount whose frames within the depth limit,
    /// on both sides, all have names. Placeholders don't count. `None`
    /// without any in the function.
    pub named_share: Option<f64>,
    /// Share of the function's amount with an unnamed frame of each origin
    /// within the depth limit. A path with unnamed frames of two origins
    /// counts for both.
    pub unnamed_by_origin: BTreeMap<Origin, f64>,
    /// Share of all the amount with no stack: off-CPU time whose stack was
    /// not recorded. It is on no path, so the function may have more.
    pub no_stack_share: f64,
    #[serde(flatten)]
    pub symbols: SymbolCoverage,
    #[serde(flatten)]
    pub recording: Coverage,
}

pub fn call_paths(dir: &Path, query: &Query) -> Result<CallPaths, Error> {
    let recording = Recording::read(dir)?;
    let symbols = Symbols::read(dir, &recording)?;
    run(&recording, symbols.as_ref(), query)
}

pub fn run(
    recording: &Recording,
    symbols: Option<&Symbols>,
    query: &Query,
) -> Result<CallPaths, Error> {
    query.metric.check(recording)?;
    let functions = Functions::new(recording, symbols);
    let target = functions.select(&query.function)?;
    let amounts = stack_amounts(recording, &functions, &query.filter, query.metric)?;
    let value = amounts.total();

    // One level past the limit, to count what the limit cuts.
    let levels = query.depth.saturating_add(1);
    let mut callers = Tree::default();
    let mut callees = Tree::default();
    let (mut total, mut self_, mut no_caller) = (0, 0, 0);
    let mut named = 0;
    let mut unnamed_amounts: BTreeMap<Origin, u64> = BTreeMap::new();
    let mut unnamed = BTreeSet::new();
    let mut path = Vec::new();
    for (stack, &weight) in recording.stacks.iter().zip(&amounts.by_stack) {
        if weight == 0 {
            continue;
        }
        path.clear();
        path.extend(functions.expand(stack));
        // Leaf first, so the outermost call is the last.
        let Some(outermost) = path.iter().rposition(|&f| f == target) else {
            continue;
        };
        total += weight;
        if functions.own(stack) == target {
            self_ += weight;
        }
        if outermost + 1 == path.len() {
            no_caller += weight;
        }
        let shown = outermost.saturating_sub(query.depth)
            ..outermost
                .saturating_add(query.depth)
                .saturating_add(1)
                .min(path.len());
        unnamed.clear();
        unnamed.extend(path[shown].iter().filter_map(|&f| {
            let function = functions.get(f);
            function.name.is_none().then_some(function.origin)
        }));
        if unnamed.is_empty() {
            named += weight;
        }
        for &origin in &unnamed {
            *unnamed_amounts.entry(origin).or_insert(0) += weight;
        }

        callers.add(path[outermost + 1..].iter().take(levels), weight, false);
        let below = path[..outermost].iter().rev();
        callees.add(below.take(levels), weight, outermost <= levels);
    }

    let share = |amount: u64| {
        if value == 0 {
            0.0
        } else {
            amount as f64 / value as f64
        }
    };
    let emit = |tree: &Tree, callees: bool| tree.emit(None, 0, query, &functions, &share, callees);
    let (callers_nodes, callers_omitted) = emit(&callers, false);
    let (callees_nodes, callees_omitted) = emit(&callees, true);

    let mut recording_coverage = Coverage::of(recording);
    let frame_pointers = recording.manifest.streams.iter().any(|stream| {
        let stacks = stream.coverage.stacks.as_ref();
        stacks.is_some_and(|stacks| stacks.unwinding == Unwinding::FramePointers)
    });
    if frame_pointers {
        recording_coverage.unknown.push(
            "callers of functions that set up no stack frame: frame-pointer stacks skip them, \
             so their time shows under the next caller up"
                .into(),
        );
    }
    Ok(CallPaths {
        function: functions.get(target).clone(),
        metric: query.metric,
        unit: query.metric.unit(),
        filter: query.filter.clone(),
        depth: query.depth,
        samples: amounts.samples,
        off_cpu_intervals: amounts.off_cpu_intervals,
        value,
        total,
        total_share: share(total),
        self_,
        self_share: share(self_),
        no_caller,
        callers: callers_nodes,
        callers_omitted,
        callees: callees_nodes,
        callees_omitted,
        coverage: CallPathsCoverage {
            named_share: ratio(named, total),
            unnamed_by_origin: unnamed_amounts
                .into_iter()
                .map(|(origin, amount)| (origin, amount as f64 / total as f64))
                .collect(),
            no_stack_share: share(amounts.no_stack),
            symbols: SymbolCoverage::of(recording, symbols),
            recording: recording_coverage,
        },
    })
}

/// Paths as a prefix tree. Node 0 is the root, the selected function.
struct Tree {
    nodes: Vec<TreeNode>,
}

struct TreeNode {
    function: u32,
    value: u64,
    /// The amount of paths that end at this node.
    ends: u64,
    children: HashMap<u32, usize>,
}

impl Default for Tree {
    fn default() -> Self {
        Self {
            nodes: vec![TreeNode {
                function: u32::MAX,
                value: 0,
                ends: 0,
                children: HashMap::new(),
            }],
        }
    }
}

impl Tree {
    /// `ends` says whether the path reaches the end of the stack, rather
    /// than being cut by the level limit.
    fn add<'a>(&mut self, path: impl Iterator<Item = &'a u32>, weight: u64, ends: bool) {
        let mut at = 0;
        for &function in path {
            let next = self.nodes.len();
            at = *self.nodes[at].children.entry(function).or_insert(next);
            if at == next {
                self.nodes.push(TreeNode {
                    function,
                    value: 0,
                    ends: 0,
                    children: HashMap::new(),
                });
            }
            self.nodes[at].value += weight;
        }
        if ends && at != 0 {
            self.nodes[at].ends += weight;
        }
    }

    /// The children of `at` (the root for `None`), at `level`, as nodes.
    fn emit(
        &self,
        at: Option<usize>,
        level: usize,
        query: &Query,
        functions: &Functions,
        share: &dyn Fn(u64) -> f64,
        callees: bool,
    ) -> (Vec<Node>, Omitted) {
        let mut children: Vec<(usize, &TreeNode)> = self.nodes[at.unwrap_or(0)]
            .children
            .values()
            .map(|&id| (id, &self.nodes[id]))
            .collect();
        children.sort_by(|(_, a), (_, b)| {
            b.value.cmp(&a.value).then_with(|| {
                let (a, b) = (functions.get(a.function), functions.get(b.function));
                (&a.name, &a.id).cmp(&(&b.name, &b.id))
            })
        });
        let keep = if level < query.depth { query.top } else { 0 };
        let omitted = Omitted {
            nodes: children.len().saturating_sub(keep),
            value: children.iter().skip(keep).map(|(_, n)| n.value).sum(),
        };
        let nodes = children
            .into_iter()
            .take(keep)
            .map(|(id, node)| {
                let (children, omitted) =
                    self.emit(Some(id), level + 1, query, functions, share, callees);
                Node {
                    function: functions.get(node.function).clone(),
                    value: node.value,
                    share: share(node.value),
                    self_: callees.then_some(node.ends),
                    children,
                    omitted,
                }
            })
            .collect();
        (nodes, omitted)
    }
}

fn ratio(part: u64, whole: u64) -> Option<f64> {
    (whole > 0).then(|| part as f64 / whole as f64)
}
