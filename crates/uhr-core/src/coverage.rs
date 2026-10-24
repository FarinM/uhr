use serde::Serialize;

use crate::recording::{Collector, MissingSignal, Recording, Signal, Unwinding};
use crate::symbols::{Source, SourceStatus, Symbols};

/// What a result can't see because of how the recording was made. Every
/// result carries it.
#[derive(Debug, Clone, Serialize)]
pub struct Coverage {
    /// This and the next two count the whole recording, whatever the filter.
    pub lost_events: u64,
    pub throttle_events: u64,
    pub samples_at_stack_limit: u64,
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
}

/// Whether a result could name the code it shows.
#[derive(Debug, Clone, Serialize)]
pub struct SymbolCoverage {
    pub symbolized: bool,
    /// Files whose frames got no names, or names that could not be checked.
    pub symbol_problems: Vec<Source>,
}

impl SymbolCoverage {
    /// Also adds to `coverage` what symbols leave unknown.
    pub(crate) fn of(symbols: Option<&Symbols>, coverage: &mut Coverage) -> Self {
        let Some(symbols) = symbols else {
            return Self {
                symbolized: false,
                symbol_problems: Vec::new(),
            };
        };
        coverage.unknown.push(
            "inline call chains are not expanded; self time is attributed to the enclosing machine function".into(),
        );
        Self {
            symbolized: true,
            symbol_problems: symbols
                .sources
                .iter()
                .filter(|s| s.status != SourceStatus::Resolved)
                .cloned()
                .collect(),
        }
    }
}
