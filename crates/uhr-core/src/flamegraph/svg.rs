//! Draws a flame graph as an SVG that zooms and searches on its own, in a
//! browser, and still reads where scripts don't run.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{self, Write};

use super::{Block, Kind};
use crate::functions::fnv1a;
use crate::metric::Unit;

/// Pixels: the image's width, its margin, a block's height and the gap
/// between blocks, and where the blocks start below the titles.
const IMAGE_WIDTH: f64 = 1200.0;
const MARGIN: f64 = 10.0;
const HEIGHT: f64 = 16.0;
const GAP: f64 = 1.0;
const TOP: f64 = 60.0;
const BOTTOM: f64 = 30.0;

/// The labels' font, the width of one of its characters, and the space
/// before a label in its block.
const FONT_SIZE: f64 = 12.0;
const CHAR_WIDTH: f64 = 7.2;
const PADDING: f64 = 3.0;

/// Blocks narrower than this, in pixels, are left out, as are those above
/// them.
const MIN_WIDTH: f64 = 0.1;

const SCRIPT: &str = include_str!("flamegraph.js");

/// A block where it goes: its function's block, `None` for the one under
/// all others, the block it is on, by its index among the placed, how far
/// up, and its start and width in the graph's unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Placed {
    pub(super) block: Option<u32>,
    pub(super) parent: Option<usize>,
    pub(super) depth: u32,
    pub(super) start: u64,
    pub(super) width: u64,
}

/// Lays out the stacks, root first, each child after the ones before it
/// in label order, on top of a block for all of them.
pub(super) fn layout(blocks: &[Block], paths: &[(Vec<u32>, u64)]) -> Vec<Placed> {
    struct Node {
        block: Option<u32>,
        amount: u64,
        children: Vec<usize>,
    }
    let mut nodes = vec![Node {
        block: None,
        amount: 0,
        children: Vec::new(),
    }];
    let mut child: HashMap<(usize, u32), usize> = HashMap::new();
    for (path, amount) in paths {
        let mut at = 0;
        nodes[0].amount += amount;
        for &block in path {
            at = match child.get(&(at, block)) {
                Some(&next) => next,
                None => {
                    nodes.push(Node {
                        block: Some(block),
                        amount: 0,
                        children: Vec::new(),
                    });
                    let next = nodes.len() - 1;
                    nodes[at].children.push(next);
                    child.insert((at, block), next);
                    next
                }
            };
            nodes[at].amount += amount;
        }
    }
    let total = nodes[0].amount;
    let narrowest = (total as f64 * MIN_WIDTH / (IMAGE_WIDTH - 2.0 * MARGIN)) as u64;
    let label = |node: &Node| node.block.map(|b| blocks[b as usize].label.as_str());
    // Each block after the one it is on.
    let mut placed = Vec::new();
    let mut pending = vec![(0, None, 0, 0)];
    while let Some((at, parent, depth, start)) = pending.pop() {
        let node = &nodes[at];
        if node.amount < narrowest.max(1) {
            continue;
        }
        placed.push(Placed {
            block: node.block,
            parent,
            depth,
            start,
            width: node.amount,
        });
        let index = Some(placed.len() - 1);
        let mut children = node.children.clone();
        children.sort_by(|&a, &b| label(&nodes[a]).cmp(&label(&nodes[b])));
        let mut x = start;
        for child in children {
            pending.push((child, index, depth + 1, x));
            x += nodes[child].amount;
        }
    }
    placed
}

/// Writes the SVG of the placed blocks, whose widths count `unit`. `title`
/// goes on top, then `subtitle`, and pointing at a block shows its amount
/// below.
pub(super) fn write(
    mut out: impl Write,
    blocks: &[Block],
    placed: &[Placed],
    unit: Unit,
    title: &str,
    subtitle: Option<&str>,
) -> io::Result<()> {
    let total = placed
        .iter()
        .find(|p| p.block.is_none())
        .map_or(0, |p| p.width);
    let depth = placed.iter().map(|p| p.depth).max().unwrap_or(0);
    let height = TOP + f64::from(depth + 1) * HEIGHT + BOTTOM;
    let width = IMAGE_WIDTH - 2.0 * MARGIN;
    let scale = width / total.max(1) as f64;
    let center = IMAGE_WIDTH / 2.0;
    writeln!(
        out,
        r##"<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<svg version="1.1" xmlns="http://www.w3.org/2000/svg" width="{IMAGE_WIDTH}" height="{height}" viewBox="0 0 {IMAGE_WIDTH} {height}" onload="init()">
<style>
text {{ font-family: monospace; font-size: {FONT_SIZE}px; fill: #000; }}
#title {{ font-size: 17px; }}
.button {{ fill: #555; cursor: pointer; }}
.button:hover {{ text-decoration: underline; }}
#blocks g {{ cursor: pointer; }}
#blocks g:hover rect {{ stroke: #000; stroke-width: 0.5; }}
#blocks g.caller rect {{ opacity: 0.5; }}
#blocks g.match rect {{ fill: rgb(220, 60, 220); }}
</style>
<script><![CDATA[
const WIDTH = {width};
const MARGIN = {MARGIN};
const GAP = {GAP};
const PADDING = {PADDING};
const CHAR_WIDTH = {CHAR_WIDTH};
{SCRIPT}]]></script>
<rect width="100%" height="100%" fill="#f6f6f2"/>
<text id="title" x="{center}" y="24" text-anchor="middle">{}</text>"##,
        escape(title),
    )?;
    if let Some(subtitle) = subtitle {
        writeln!(
            out,
            r#"<text x="{center}" y="44" text-anchor="middle">{}</text>"#,
            escape(subtitle)
        )?;
    }
    let below = height - 10.0;
    let right = IMAGE_WIDTH - MARGIN;
    writeln!(
        out,
        r#"<text id="reset" class="button" x="{MARGIN}" y="24" style="display: none">Reset zoom</text>
<text id="search" class="button" x="{right}" y="24" text-anchor="end">Search</text>
<text id="details" x="{MARGIN}" y="{below}"></text>
<text id="matched" x="{right}" y="{below}" text-anchor="end"></text>
<g id="blocks">"#
    )?;
    let mut line = String::new();
    for placed in placed {
        let (name, fill) = match placed.block {
            Some(block) => {
                let block = &blocks[block as usize];
                (block.label.as_str(), color(block))
            }
            None => ("all", (200, 200, 205)),
        };
        let x = MARGIN + placed.start as f64 * scale;
        let w = placed.width as f64 * scale;
        let y = TOP + f64::from(depth - placed.depth) * HEIGHT;
        let name = escape(name);
        // The block under all others is no function's, and is on none.
        let parent = placed
            .parent
            .map_or(String::new(), |parent| format!(r#" data-p="{parent}""#));
        line.clear();
        write!(
            line,
            r#"<g data-x="{}" data-w="{}"{parent} data-name="{name}"><title>{name}: {}, {:.2}%</title><rect x="{x:.2}" y="{y}" width="{:.2}" height="{}" rx="2" fill="rgb({}, {}, {})"/><text x="{:.2}" y="{:.1}">{}</text></g>"#,
            placed.start,
            placed.width,
            amount(placed.width, unit),
            100.0 * placed.width as f64 / total.max(1) as f64,
            (w - GAP).max(0.0),
            HEIGHT - GAP,
            fill.0,
            fill.1,
            fill.2,
            x + PADDING,
            y + HEIGHT - 4.5,
            escape(&fit(placed.block.map_or("all", |b| &blocks[b as usize].label), w)),
        )
        .expect("writing to a String");
        writeln!(out, "{line}")?;
    }
    writeln!(out, "</g>\n</svg>")
}

/// As much of `name` as fits in a block `width` pixels wide, as the
/// script fits it after a zoom.
fn fit(name: &str, width: f64) -> String {
    let chars = ((width - 2.0 * PADDING) / CHAR_WIDTH).floor().max(0.0) as usize;
    if name.chars().count() <= chars {
        return name.to_owned();
    }
    match chars {
        0..3 => String::new(),
        _ => name.chars().take(chars - 2).chain("..".chars()).collect(),
    }
}

/// A time as a person reads it, as in `1.25 s`, `12.50 ms` or `125 µs`.
fn amount(value: u64, unit: Unit) -> String {
    let at = value as f64;
    match (unit, value) {
        (Unit::Ns, 1_000_000_000..) => format!("{:.2} s", at / 1e9),
        (Unit::Ns, 1_000_000..) => format!("{:.2} ms", at / 1e6),
        (Unit::Ns, 1_000..) => format!("{:.0} µs", at / 1e3),
        (Unit::Ns, _) => format!("{value} ns"),
    }
}

/// Text as XML can hold it. XML can't hold most control characters, even
/// as references, so each is written as `\u` and four hex digits, as
/// recordings write what is no character.
fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            c if c.is_control() || matches!(c, '\u{fffe}' | '\u{ffff}') => {
                escaped.push_str(&format!("\\u{:04x}", u32::from(c)));
            }
            c => escaped.push(c),
        }
    }
    escaped
}

/// A block's color: red to yellow for native code, blue for the kernel,
/// green for a runtime's code, aqua for inlined code and grey for code
/// without a name, each varied by its label, so that a function keeps its
/// color from graph to graph.
fn color(block: &Block) -> (u8, u8, u8) {
    let v = (fnv1a(&[&block.label]) % 1000) as f64 / 1000.0;
    let mix = |low: u8, high: u8| low + ((high - low) as f64 * v) as u8;
    match block.kind {
        Kind::Native => (mix(205, 255), mix(60, 200), mix(0, 50)),
        Kind::Kernel => (mix(100, 140), mix(120, 160), mix(220, 255)),
        Kind::Program => (mix(50, 110), mix(170, 220), mix(50, 110)),
        Kind::Inlined => (mix(60, 110), mix(200, 230), mix(190, 220)),
        Kind::Unnamed => (mix(170, 200), mix(170, 200), mix(170, 200)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fits_a_label_in_its_block() {
        assert_eq!(fit("spin", 100.0), "spin");
        assert_eq!(fit("a_long_function_name", 60.0), "a_lon..");
        assert_eq!(fit("spin", 10.0), "");
    }

    #[test]
    fn escapes_what_xml_cannot_hold() {
        assert_eq!(
            escape("a<b>&\"'\0\u{1b}[31m\u{ffff}"),
            "a&lt;b&gt;&amp;&quot;&apos;\\u0000\\u001b[31m\\uffff"
        );
    }

    #[test]
    fn says_times_in_their_unit() {
        assert_eq!(amount(1_250_000_000, Unit::Ns), "1.25 s");
        assert_eq!(amount(12_500_000, Unit::Ns), "12.50 ms");
        assert_eq!(amount(125_000, Unit::Ns), "125 µs");
        assert_eq!(amount(125, Unit::Ns), "125 ns");
    }

    #[test]
    fn lays_out_children_in_label_order_on_their_caller() {
        let block = |label: &str| Block {
            label: label.to_owned(),
            kind: Kind::Native,
        };
        let blocks = [block("main"), block("b"), block("a"), block("spin")];
        let paths = [(vec![0, 1], 2), (vec![0, 2, 3], 6), (vec![0, 2], 1)];
        let placed = layout(&blocks, &paths);
        // Each block comes after the one it is on, one down.
        for (at, p) in placed.iter().enumerate() {
            match p.parent {
                Some(parent) => {
                    assert!(parent < at, "{p:?}");
                    assert_eq!(placed[parent].depth + 1, p.depth, "{p:?}");
                }
                None => assert_eq!(p.block, None),
            }
        }
        let mut placed: Vec<_> = placed
            .into_iter()
            .map(|p| (p.depth, p.start, p.width, p.block))
            .collect();
        placed.sort();
        assert_eq!(
            placed,
            [
                (0, 0, 9, None),
                (1, 0, 9, Some(0)),
                (2, 0, 7, Some(2)),
                (2, 7, 2, Some(1)),
                (3, 0, 6, Some(3)),
            ]
        );
    }

    #[test]
    fn leaves_out_blocks_too_narrow_to_see() {
        let blocks = [Block {
            label: "tiny".to_owned(),
            kind: Kind::Native,
        }];
        let placed = layout(&blocks, &[(vec![0], 1), (vec![], 1_000_000)]);
        assert_eq!(placed.len(), 1, "{placed:?}");
    }
}
