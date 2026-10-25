use std::collections::BTreeMap;

use serde::Serialize;

use crate::recording::{Collector, MissingSignal, Origin, Recording, Signal, Unwinding};
use crate::symbols::{Source, SourceStatus, Symbols};

/// What a result can't see because of how the recording was made. Every
/// result carries it.
#[derive(Debug, Clone, Serialize)]
pub struct Coverage {
    /// This and the next four count the whole recording, whatever the
    /// filter. The stack counts cover every stack: one per CPU sample, and
    /// one per thread going off CPU.
    pub lost_events: u64,
    pub throttle_events: u64,
    pub stacks_at_stack_limit: u64,
    /// Stacks that went on past the end of their stack copy, so their outer
    /// callers are missing. `None` without DWARF unwinding.
    pub stacks_cut_at_stack_copy: Option<u64>,
    /// Stacks of 32-bit code, which DWARF unwinding cannot walk. `None`
    /// without DWARF unwinding.
    pub stacks_not_unwound: Option<u64>,
    pub missing_signals: Vec<MissingSignal>,
    /// What this result cannot account for because it was not measured.
    pub unknown: Vec<String>,
    pub known_biases: Vec<String>,
}

impl Coverage {
    pub(crate) fn of(recording: &Recording) -> Self {
        let mut coverage = Coverage {
            lost_events: 0,
            throttle_events: 0,
            stacks_at_stack_limit: 0,
            stacks_cut_at_stack_copy: None,
            stacks_not_unwound: None,
            missing_signals: Vec::new(),
            unknown: Vec::new(),
            known_biases: Vec::new(),
        };
        for stream in &recording.manifest.streams {
            let c = &stream.coverage;
            coverage.lost_events += c.lost_events;
            coverage.throttle_events += c.throttle_events;
            coverage.stacks_at_stack_limit += c.stacks_at_stack_limit;
            if let Some(cut) = c.stacks_cut_at_stack_copy {
                *coverage.stacks_cut_at_stack_copy.get_or_insert(0) += cut;
            }
            if let Some(skipped) = c.stacks_not_unwound {
                *coverage.stacks_not_unwound.get_or_insert(0) += skipped;
                if skipped > 0 {
                    coverage.unknown.push(format!(
                        "callers in {skipped} stacks of 32-bit code in stream {}, which DWARF \
                         unwinding cannot walk",
                        stream.id
                    ));
                }
            }
            coverage
                .missing_signals
                .extend(stream.missing_signals.iter().cloned());
            if stream
                .missing_signals
                .iter()
                .any(|m| m.signal == Signal::KernelCPUSamples)
            {
                coverage.unknown.push(format!(
                    "CPU time in the kernel: stream {} did not sample it, so totals and shares \
                     leave it out",
                    stream.id
                ));
            }
            coverage.known_biases.extend(c.known_biases.iter().cloned());
            if c.overhead_ns.is_none() {
                coverage
                    .unknown
                    .push(format!("profiler overhead of stream {}", stream.id));
            }
            let Collector::Perf {
                unwinding,
                stack_copy_bytes,
                ..
            } = &stream.collector;
            match (unwinding, c.stacks_cut_at_stack_copy) {
                (Unwinding::FramePointers, _) => coverage.unknown.push(format!(
                    "stacks of stream {} cut short where frame pointers are missing",
                    stream.id
                )),
                (Unwinding::Dwarf, Some(cut)) if cut > 0 => coverage.unknown.push(format!(
                    "outer callers of {cut} stacks of stream {}, which were deeper than \
                     their {}-byte stack copy",
                    stream.id,
                    stack_copy_bytes.unwrap_or_default()
                )),
                (Unwinding::Dwarf, _) => {}
            }
        }
        coverage
    }
}

/// Whether a result could name the code it shows.
#[derive(Debug, Clone, Serialize)]
pub struct SymbolCoverage {
    pub symbolized: bool,
    /// Files whose frames got no names, or names that could not be checked.
    pub symbol_problems: Vec<Source>,
    /// Files with named code but no debug info for any of it. Calls inlined
    /// there are not expanded, so their time counts for the function they
    /// were inlined into.
    pub without_debug_info: Vec<String>,
}

impl SymbolCoverage {
    pub(crate) fn of(recording: &Recording, symbols: Option<&Symbols>) -> Self {
        let Some(symbols) = symbols else {
            return Self {
                symbolized: false,
                symbol_problems: Vec::new(),
                without_debug_info: Vec::new(),
            };
        };
        // Startup code and hand-written assembly often lack debug info even
        // in a file built with it, so only a file without any counts.
        let mut debug_info: BTreeMap<&str, bool> = BTreeMap::new();
        for (id, frame) in recording.frames.iter().enumerate() {
            if let (Origin::Binary, Some(mapping)) = (frame.origin, frame.mapping)
                && symbols.names[id].is_some()
            {
                let path = recording.mappings[mapping as usize].path.as_str();
                *debug_info.entry(path).or_default() |= !symbols.inline[id].is_empty();
            }
        }
        let without_debug_info = debug_info
            .into_iter()
            .filter(|&(_, has)| !has)
            .map(|(path, _)| path.to_owned());
        Self {
            symbolized: true,
            symbol_problems: symbols
                .sources
                .iter()
                .filter(|s| s.status != SourceStatus::Resolved)
                .cloned()
                .collect(),
            without_debug_info: without_debug_info.collect(),
        }
    }
}
