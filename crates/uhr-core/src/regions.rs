//! Which region of a process's memory each page fault was in.

use std::collections::HashMap;

use crate::recording::{MemoryRegion, Recording};

/// The region each page-fault sample was in, as its row in the recording's
/// regions, by sample. `None` where no region recorded held its address.
pub(crate) fn of_faults(recording: &Recording) -> Vec<Option<u32>> {
    let regions = Regions::new(&recording.regions);
    recording
        .page_faults
        .iter()
        .map(|fault| regions.at(fault.pid, fault.address, fault.time_ns))
        .collect()
}

struct Regions<'a> {
    all: &'a [MemoryRegion],
    by_pid: HashMap<u32, Process>,
}

/// A process's regions, by start.
#[derive(Default)]
struct Process {
    rows: Vec<u32>,
    /// The furthest any region up to each reaches, so a search back from an
    /// address can stop where none reaches it.
    reach: Vec<u64>,
}

impl<'a> Regions<'a> {
    fn new(all: &'a [MemoryRegion]) -> Self {
        let mut by_pid: HashMap<u32, Process> = HashMap::new();
        for (row, region) in all.iter().enumerate() {
            by_pid.entry(region.pid).or_default().rows.push(row as u32);
        }
        for process in by_pid.values_mut() {
            process.rows.sort_by_key(|&row| all[row as usize].start);
            let mut reach = 0;
            process.reach = process
                .rows
                .iter()
                .map(|&row| {
                    reach = reach.max(all[row as usize].end);
                    reach
                })
                .collect();
        }
        Self { all, by_pid }
    }

    /// The region of `pid` that held `address` at `time_ns`. A process's
    /// regions don't overlap at any one time, so there is at most one.
    fn at(&self, pid: u32, address: u64, time_ns: u64) -> Option<u32> {
        let process = self.by_pid.get(&pid)?;
        let after = process
            .rows
            .partition_point(|&row| self.all[row as usize].start <= address);
        (0..after)
            .rev()
            .take_while(|&at| process.reach[at] > address)
            .map(|at| process.rows[at])
            .find(|&row| {
                let region = &self.all[row as usize];
                // Before the recording, if not when.
                address < region.end
                    && region.time_ns.unwrap_or(0) <= time_ns
                    && region.unmapped_ns.is_none_or(|unmapped| time_ns < unmapped)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recording::RegionKind;

    fn region(
        pid: u32,
        (start, end): (u64, u64),
        (time_ns, unmapped_ns): (Option<u64>, Option<u64>),
    ) -> MemoryRegion {
        MemoryRegion {
            pid,
            start,
            end,
            permissions: "rw-p".into(),
            file_offset: 0,
            path: None,
            kind: RegionKind::Anonymous,
            time_ns,
            unmapped_ns,
        }
    }

    #[test]
    fn finds_the_region_that_held_an_address_when_it_faulted() {
        let all = [
            // A large region from before, and in part of it a smaller one
            // that took its place at 200.
            region(1, (0x1000, 0x2000), (None, Some(200))),
            region(1, (0x2000, 0x3000), (Some(200), None)),
            region(1, (0x3000, 0x9000), (None, None)),
            region(2, (0x2000, 0x3000), (Some(100), None)),
        ];
        let regions = Regions::new(&all);
        assert_eq!(regions.at(1, 0x1800, 150), Some(0));
        assert_eq!(regions.at(1, 0x1800, 250), None);
        assert_eq!(regions.at(1, 0x2800, 250), Some(1));
        assert_eq!(regions.at(1, 0x2800, 150), None);
        assert_eq!(regions.at(1, 0x8000, 50), Some(2));
        assert_eq!(regions.at(1, 0x9000, 50), None);
        assert_eq!(regions.at(2, 0x2800, 50), None);
        assert_eq!(regions.at(3, 0x2800, 250), None);
    }
}
