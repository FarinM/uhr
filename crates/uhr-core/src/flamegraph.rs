//! Flame graphs of a recording's stacks, for a person to read: each
//! function a block as wide as its amount of the metric, on top of its
//! caller.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{self, Write};
use std::path::Path;

use serde::Serialize;

use crate::coverage::{Coverage, SymbolCoverage};
use crate::filter::{self, Filter};
use crate::functions::{self, Function, Functions};
use crate::metric::{self, Metric, Unit, stack_amounts};
use crate::recording::{self, Origin, Recording};
use crate::symbols::Symbols;

mod svg;

#[derive(Debug, Clone)]
pub struct Query {
    pub metric: Metric,
    pub filter: Filter,
    /// A function id, or a name that only one function has, to start the
    /// graph at. Stacks without it are left out.
    pub root: Option<String>,
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

/// The stacks that passed a query, folded into a flame graph. Where the
/// graph starts at a function that recurses, each stack starts from its
/// outermost call.
#[derive(Debug, Clone, Serialize)]
pub struct FlameGraph {
    /// The target's command, as recorded.
    pub command: Vec<String>,
    pub metric: Metric,
    /// What `value` and `graphed` count.
    pub unit: Unit,
    pub filter: Filter,
    /// The function the graph starts at, if not the start of each thread.
    pub root: Option<Function>,
    /// CPU samples that passed the filter, if the metric counts them.
    pub samples: u64,
    /// Off-CPU intervals that passed the filter, if the metric counts them.
    pub off_cpu_intervals: u64,
    /// The metric's amount that passed. Shares are of this.
    pub value: u64,
    /// Of that, the amount the graph shows: all with a stack, or with the
    /// root anywhere on it.
    pub graphed: u64,
    pub graphed_share: f64,
    /// Distinct stacks in the graph.
    pub stacks: usize,
    pub coverage: FlameGraphCoverage,
    /// Each block's label and kind, by the function's index in `functions`.
    #[serde(skip)]
    blocks: Vec<Block>,
    /// Each distinct stack, root first, as indexes into `blocks`, and its
    /// amount.
    #[serde(skip)]
    paths: Vec<(Vec<u32>, u64)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FlameGraphCoverage {
    /// Share of the graphed amount whose frames all have names.
    /// Placeholders don't count. `None` with nothing graphed.
    pub named_share: Option<f64>,
    /// Share of the graphed amount with an unnamed frame of each origin. A
    /// stack with unnamed frames of two origins counts for both.
    pub unnamed_by_origin: BTreeMap<Origin, f64>,
    /// Share of all the amount with no stack: off-CPU time whose stack was
    /// not recorded. It is not in the graph.
    pub no_stack_share: f64,
    #[serde(flatten)]
    pub symbols: SymbolCoverage,
    #[serde(flatten)]
    pub recording: Coverage,
}

/// A function's block: its label, and what colors it.
#[derive(Debug, Clone)]
struct Block {
    label: String,
    kind: Kind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Native,
    Inlined,
    Kernel,
    /// Code a runtime compiled or interpreted.
    Program,
    Unnamed,
}

pub fn flame_graph(dir: &Path, query: &Query) -> Result<FlameGraph, Error> {
    let recording = Recording::read(dir)?;
    let symbols = Symbols::read(dir, &recording)?;
    run(&recording, symbols.as_ref(), query)
}

pub fn run(
    recording: &Recording,
    symbols: Option<&Symbols>,
    query: &Query,
) -> Result<FlameGraph, Error> {
    query.metric.check(recording)?;
    let functions = Functions::new(recording, symbols);
    let root = query
        .root
        .as_deref()
        .map(|root| functions.select(root))
        .transpose()?;
    let amounts = stack_amounts(recording, &functions, &query.filter, query.metric)?;
    let value = amounts.total();

    let mut folded: HashMap<Vec<u32>, u64> = HashMap::new();
    let (mut graphed, mut named) = (0, 0);
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
        let end = match root {
            Some(root) => match path.iter().rposition(|&f| f == root) {
                Some(outermost) => outermost + 1,
                None => continue,
            },
            None => path.len(),
        };
        if end == 0 {
            continue;
        }
        path.truncate(end);
        path.reverse();
        graphed += weight;
        unnamed.clear();
        unnamed.extend(path.iter().filter_map(|&f| {
            let function = functions.get(f);
            function.name.is_none().then_some(function.origin)
        }));
        if unnamed.is_empty() {
            named += weight;
        }
        for &origin in &unnamed {
            *unnamed_amounts.entry(origin).or_insert(0) += weight;
        }
        *folded.entry(path.clone()).or_insert(0) += weight;
    }

    let (blocks, paths) = blocks(&functions, folded);
    let share = |amount: u64| {
        if value == 0 {
            0.0
        } else {
            amount as f64 / value as f64
        }
    };
    Ok(FlameGraph {
        command: recording.manifest.target.command.clone(),
        metric: query.metric,
        unit: query.metric.unit(),
        filter: query.filter.clone(),
        root: root.map(|root| functions.get(root).clone()),
        samples: amounts.samples,
        off_cpu_intervals: amounts.off_cpu_intervals,
        value,
        graphed,
        graphed_share: share(graphed),
        stacks: paths.len(),
        coverage: FlameGraphCoverage {
            named_share: (graphed > 0).then(|| named as f64 / graphed as f64),
            unnamed_by_origin: unnamed_amounts
                .into_iter()
                .map(|(origin, amount)| (origin, amount as f64 / graphed as f64))
                .collect(),
            no_stack_share: share(amounts.no_stack),
            symbols: SymbolCoverage::of(recording, symbols),
            recording: Coverage::of(recording),
        },
        blocks,
        paths,
    })
}

/// The blocks of the functions on the stacks, each labeled apart from any
/// other with the same name, and the stacks in them, sorted as flame graphs
/// read them.
fn blocks(
    functions: &Functions,
    folded: HashMap<Vec<u32>, u64>,
) -> (Vec<Block>, Vec<(Vec<u32>, u64)>) {
    let mut index: HashMap<u32, u32> = HashMap::new();
    let mut used = Vec::new();
    let paths: Vec<(Vec<u32>, u64)> = folded
        .into_iter()
        .map(|(path, ns)| {
            let path = path
                .into_iter()
                .map(|function| {
                    *index.entry(function).or_insert_with(|| {
                        used.push(function);
                        used.len() as u32 - 1
                    })
                })
                .collect();
            (path, ns)
        })
        .collect();
    let mut blocks: Vec<Block> = used
        .iter()
        .map(|&function| {
            let f = functions.get(function);
            let kind = match f.origin {
                _ if f.name.is_none() => Kind::Unnamed,
                Origin::Kernel => Kind::Kernel,
                Origin::Jit | Origin::Interpreted => Kind::Program,
                _ if f.inlined => Kind::Inlined,
                _ => Kind::Native,
            };
            Block {
                label: label(f),
                kind,
            }
        })
        .collect();
    // Blocks of one label merge, so functions that share a name say where
    // they are from, by the first of these that tells them apart.
    let mut by_label: HashMap<String, Vec<usize>> = HashMap::new();
    for (at, block) in blocks.iter().enumerate() {
        by_label.entry(block.label.clone()).or_default().push(at);
    }
    for shared in by_label.into_values().filter(|at| at.len() > 1) {
        let places = (0..PLACES)
            .map(|tier| -> Option<Vec<String>> {
                shared
                    .iter()
                    .map(|&at| place(functions, used[at], tier))
                    .collect()
            })
            .find(|places| {
                places
                    .as_ref()
                    .is_some_and(|p| p.iter().collect::<BTreeSet<_>>().len() == p.len())
            })
            .flatten();
        for (n, &at) in shared.iter().enumerate() {
            let place = match &places {
                Some(places) => places[n].clone(),
                None => format!("#{}", n + 1),
            };
            // Kernel modules are in brackets already, as `[kernel]`.
            blocks[at].label = match place.starts_with('[') {
                true => format!("{} {place}", blocks[at].label),
                false => format!("{} ({place})", blocks[at].label),
            };
        }
    }
    // A label made up above can be another function's own name. Those
    // still shared say the function's id, or else a number, each longer
    // than before, until none is.
    loop {
        let mut by_label: HashMap<&str, Vec<usize>> = HashMap::new();
        for (at, block) in blocks.iter().enumerate() {
            by_label.entry(&block.label).or_default().push(at);
        }
        let shared: Vec<Vec<usize>> = by_label.into_values().filter(|at| at.len() > 1).collect();
        if shared.is_empty() {
            break;
        }
        for group in shared {
            let ids: Option<Vec<String>> = group
                .iter()
                .map(|&at| functions.get(used[at]).id.as_deref().map(clean))
                .collect();
            let ids = ids.filter(|ids| ids.iter().collect::<BTreeSet<_>>().len() == ids.len());
            for (n, &at) in group.iter().enumerate() {
                let suffix = match &ids {
                    Some(ids) => ids[n].clone(),
                    None => format!("#{}", n + 1),
                };
                blocks[at].label = format!("{} [{suffix}]", blocks[at].label);
            }
        }
    }
    let mut paths = paths;
    let line = |path: &[u32]| -> Vec<&str> {
        path.iter()
            .map(|&b| blocks[b as usize].label.as_str())
            .collect()
    };
    paths.sort_by(|(a, _), (b, _)| line(a).cmp(&line(b)));
    (blocks, paths)
}

/// What a function's block says: its name, or else the label the symbols
/// made up, its module and start, or its module or origin.
fn label(function: &Function) -> String {
    let module = function
        .module
        .as_deref()
        .map(|path| path.rsplit('/').next().unwrap_or(path));
    let label = match (&function.name, &function.placeholder, module) {
        (Some(name), _, _) => name.clone(),
        (None, Some(placeholder), _) => placeholder.clone(),
        (None, None, Some(module)) => match function.function_address {
            Some(address) => format!("{module}+{address:#x}"),
            None => format!("[{module}]"),
        },
        (None, None, None) => format!("[{}]", function.origin.as_str()),
    };
    clean(&label)
}

/// Text as a label can hold it. Folded stacks end each frame with `;` and
/// each stack with a line, so those, and other control characters, are
/// written as `\u` and four hex digits, as recordings write what is no
/// character. That keeps different text different.
fn clean(text: &str) -> String {
    let mut cleaned = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            ';' => cleaned.push_str("\\u003b"),
            c if c.is_control() => cleaned.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => cleaned.push(c),
        }
    }
    cleaned
}

/// Ways to say where a function is from, most readable first.
const PLACES: usize = 4;

/// Where a function is from, to tell it from others of its name: its file
/// and where it starts there, its module, its file, or its id.
fn place(functions: &Functions, id: u32, tier: usize) -> Option<String> {
    let function = functions.get(id);
    let base = |path: &String| clean(path.rsplit('/').next().unwrap_or(path));
    match tier {
        0 => Some(format!(
            "{}:{}",
            base(function.file.as_ref()?),
            functions.start(id)?
        )),
        1 => function.module.as_ref().map(base),
        2 => function.file.as_ref().map(base),
        _ => function.id.as_deref().map(clean),
    }
}

impl FlameGraph {
    /// Writes the stacks as folded lines, as other flame graph tools read
    /// them: the labels root first, each ended by `;`, then the amount in
    /// the graph's unit.
    pub fn write_folded(&self, out: &mut impl Write) -> io::Result<()> {
        for line in self.folded() {
            writeln!(out, "{line}")?;
        }
        Ok(())
    }

    /// Writes the graph as an SVG to open in a browser, where a click zooms
    /// into a block and search highlights the functions that match.
    pub fn write_svg(
        &self,
        title: &str,
        subtitle: Option<&str>,
        out: impl Write,
    ) -> io::Result<()> {
        let placed = svg::layout(&self.blocks, &self.paths);
        svg::write(out, &self.blocks, &placed, self.unit, title, subtitle)
    }

    fn folded(&self) -> Vec<String> {
        self.paths
            .iter()
            .map(|(path, amount)| {
                let labels: Vec<&str> = path
                    .iter()
                    .map(|&b| self.blocks[b as usize].label.as_str())
                    .collect();
                format!("{} {amount}", labels.join(";"))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_what_would_end_a_frame_or_a_stack_as_an_escape() {
        assert_eq!(clean("a;b\0c\nd e"), "a\\u003bb\\u0000c\\u000ad e");
        assert_ne!(clean("a;b"), clean("a b"));
    }
}
