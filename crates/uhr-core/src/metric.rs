use serde::Serialize;

use crate::filter::{self, Filter};
use crate::functions::Functions;
use crate::recording::{Mode, Recording, Signal};

/// The time results weigh stacks by.
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
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "the recording has no off-CPU time: context switches were not recorded. Record without \
         --no-off-cpu"
    )]
    NoContextSwitches,
}

impl Metric {
    /// Fails if the recording lacks what the metric is made of.
    pub(crate) fn check(self, recording: &Recording) -> Result<(), Error> {
        let switches = recording
            .manifest
            .streams
            .iter()
            .any(|s| s.signals.contains(&Signal::OffCPUTime));
        if self != Metric::OnCPU && !switches {
            return Err(Error::NoContextSwitches);
        }
        Ok(())
    }
}

/// The time of what passed a filter, by stack.
pub(crate) struct StackTimes {
    /// By stack id.
    pub ns: Vec<u64>,
    /// Of `ns`, the time of CPU samples taken in user mode.
    pub user_ns: Vec<u64>,
    /// Off-CPU time whose stack was not recorded.
    pub no_stack_ns: u64,
    pub samples: u64,
    pub off_cpu_intervals: u64,
}

impl StackTimes {
    pub fn total_ns(&self) -> u64 {
        self.ns.iter().sum::<u64>() + self.no_stack_ns
    }
}

/// Fails if the filter does.
pub(crate) fn stack_times(
    recording: &Recording,
    functions: &Functions,
    filter: &Filter,
    metric: Metric,
) -> Result<StackTimes, filter::Error> {
    let mut times = StackTimes {
        ns: vec![0; recording.stacks.len()],
        user_ns: vec![0; recording.stacks.len()],
        no_stack_ns: 0,
        samples: 0,
        off_cpu_intervals: 0,
    };
    if metric != Metric::OffCPU {
        for sample in filter.samples(recording, functions)? {
            times.ns[sample.stack as usize] += sample.cpu_ns;
            if sample.mode == Mode::User {
                times.user_ns[sample.stack as usize] += sample.cpu_ns;
            }
            times.samples += 1;
        }
    }
    if metric != Metric::OnCPU {
        for (interval, ns) in filter.off_cpu(recording, functions)? {
            match interval.stack {
                Some(stack) => times.ns[stack as usize] += ns,
                None => times.no_stack_ns += ns,
            }
            times.off_cpu_intervals += 1;
        }
    }
    Ok(times)
}
