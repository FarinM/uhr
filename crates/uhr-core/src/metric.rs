use serde::Serialize;

use crate::filter::{self, Filter};
use crate::functions::Functions;
use crate::recording::{Mode, Recording, Signal};

/// What results weigh stacks by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Metric {
    /// CPU time, from CPU samples.
    #[serde(rename = "cpu")]
    OnCPU,
    /// Time threads spent switched out, runnable or blocked.
    #[serde(rename = "off_cpu")]
    OffCPU,
    /// Both, so all the time each thread was alive, summed over threads.
    #[serde(rename = "wall")]
    Wall,
    /// Page faults, from samples of them, which show the code that first
    /// touched memory.
    #[serde(rename = "page_faults")]
    PageFaults,
}

/// What a metric's amounts count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Unit {
    /// Nanoseconds.
    Ns,
    /// Page faults.
    Faults,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "the recording has no off-CPU time: context switches were not recorded. Record without \
         --no-off-cpu"
    )]
    NoContextSwitches,
    #[error("the recording has no page faults. Record without --no-page-faults")]
    NoPageFaults,
}

impl Metric {
    pub fn unit(self) -> Unit {
        match self {
            Metric::OnCPU | Metric::OffCPU | Metric::Wall => Unit::Ns,
            Metric::PageFaults => Unit::Faults,
        }
    }

    /// Fails if the recording lacks what the metric is made of.
    pub(crate) fn check(self, recording: &Recording) -> Result<(), Error> {
        let has = |signal| {
            recording
                .manifest
                .streams
                .iter()
                .any(|s| s.signals.contains(&signal))
        };
        match self {
            Metric::OnCPU => Ok(()),
            Metric::OffCPU | Metric::Wall if !has(Signal::OffCPUTime) => {
                Err(Error::NoContextSwitches)
            }
            Metric::OffCPU | Metric::Wall => Ok(()),
            Metric::PageFaults if !has(Signal::PageFaults) => Err(Error::NoPageFaults),
            Metric::PageFaults => Ok(()),
        }
    }
}

/// The metric's amount of what passed a filter, by stack.
pub(crate) struct StackAmounts {
    /// By stack id.
    pub by_stack: Vec<u64>,
    /// Of `by_stack`, the amount of samples taken in user mode.
    pub user: Vec<u64>,
    /// Off-CPU time whose stack was not recorded.
    pub no_stack: u64,
    /// CPU samples, or page-fault samples, as the metric counts.
    pub samples: u64,
    pub off_cpu_intervals: u64,
}

impl StackAmounts {
    pub fn total(&self) -> u64 {
        self.by_stack.iter().sum::<u64>() + self.no_stack
    }
}

/// Fails if the filter does.
pub(crate) fn stack_amounts(
    recording: &Recording,
    functions: &Functions,
    filter: &Filter,
    metric: Metric,
) -> Result<StackAmounts, filter::Error> {
    let mut amounts = StackAmounts {
        by_stack: vec![0; recording.stacks.len()],
        user: vec![0; recording.stacks.len()],
        no_stack: 0,
        samples: 0,
        off_cpu_intervals: 0,
    };
    if metric == Metric::PageFaults {
        for sample in filter.page_faults(recording, functions)? {
            amounts.by_stack[sample.stack as usize] += sample.faults;
            if sample.mode == Mode::User {
                amounts.user[sample.stack as usize] += sample.faults;
            }
            amounts.samples += 1;
        }
        return Ok(amounts);
    }
    if metric != Metric::OffCPU {
        for sample in filter.samples(recording, functions)? {
            amounts.by_stack[sample.stack as usize] += sample.cpu_ns;
            if sample.mode == Mode::User {
                amounts.user[sample.stack as usize] += sample.cpu_ns;
            }
            amounts.samples += 1;
        }
    }
    if metric != Metric::OnCPU {
        for (interval, ns) in filter.off_cpu(recording, functions)? {
            match interval.stack {
                Some(stack) => amounts.by_stack[stack as usize] += ns,
                None => amounts.no_stack += ns,
            }
            amounts.off_cpu_intervals += 1;
        }
    }
    Ok(amounts)
}
