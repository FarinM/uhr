use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::recording::{JitSymbol, Origin, Recording};

/// The names a runtime gave the code it compiled, from its perf map, one
/// `start size name` line per piece of code, in hex. Where code took the
/// place of older code, the newer name holds.
#[derive(Debug, Default)]
pub struct PerfMap {
    /// By start: the end, exclusive, and the name.
    code: BTreeMap<u64, (u64, String)>,
}

impl PerfMap {
    pub fn parse(text: &str) -> Self {
        let mut map = Self::default();
        for line in text.lines() {
            let mut fields = line.splitn(3, ' ');
            let (Some(start), Some(size), Some(name)) =
                (fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            let (Ok(start), Ok(size)) = (
                u64::from_str_radix(start, 16),
                u64::from_str_radix(size, 16),
            ) else {
                continue;
            };
            if let Some(end) = start.checked_add(size).filter(|&end| end > start) {
                map.insert(start, end, name.trim_end());
            }
        }
        map
    }

    fn insert(&mut self, start: u64, end: u64, name: &str) {
        let older: Vec<u64> = self
            .code
            .range(..end)
            .rev()
            .take_while(|(_, (older_end, _))| *older_end > start)
            .map(|(&older_start, _)| older_start)
            .collect();
        for older_start in older {
            let (older_end, older_name) = self.code.remove(&older_start).expect("listed");
            if older_start < start {
                self.code.insert(older_start, (start, older_name.clone()));
            }
            if older_end > end {
                self.code.insert(end, (older_end, older_name));
            }
        }
        self.code.insert(start, (end, name.to_owned()));
    }

    /// The code `address` falls in: its start, end and name.
    pub fn find(&self, address: u64) -> Option<(u64, u64, &str)> {
        let (&start, (end, name)) = self.code.range(..=address).next_back()?;
        (address < *end).then_some((start, *end, name.as_str()))
    }
}

/// Names the frames of anonymous memory that a process's perf map, from
/// `map_of`, covers, making them JIT frames, and keeps the code they fall
/// in. Returns the processes whose maps named frames.
pub fn name_jit_frames(
    recording: &mut Recording,
    mut map_of: impl FnMut(u32) -> Option<PerfMap>,
) -> Vec<u32> {
    let mut maps: HashMap<u32, Option<PerfMap>> = HashMap::new();
    let mut code = BTreeSet::new();
    for frame in &mut recording.frames {
        let pid = frame
            .mapping
            .and_then(|m| recording.mappings[m as usize].pid);
        let (Origin::Unresolved, Some(pid)) = (frame.origin, pid) else {
            continue;
        };
        let map = maps.entry(pid).or_insert_with(|| map_of(pid));
        let address = frame
            .address
            .saturating_sub(u64::from(frame.return_address));
        if let Some((start, end, name)) = map.as_ref().and_then(|m| m.find(address)) {
            frame.origin = Origin::Jit;
            code.insert((pid, start, end, name.to_owned()));
        }
    }
    let named: BTreeSet<u32> = code.iter().map(|&(pid, ..)| pid).collect();
    recording.jit_symbols = code
        .into_iter()
        .map(|(pid, start, end, name)| JitSymbol {
            pid,
            start,
            end,
            name,
        })
        .collect();
    named.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_newest_code_at_an_address() {
        let map = PerfMap::parse(
            "1000 100 py::old:/a.py\n\
             2000 10 JS:~f /b.js:1:1\n\
             1080 40 py::new:/a.py\n\
             not a line\n\
             zz 10 bad start\n",
        );
        assert_eq!(map.find(0x1000), Some((0x1000, 0x1080, "py::old:/a.py")));
        assert_eq!(map.find(0x10a0), Some((0x1080, 0x10c0, "py::new:/a.py")));
        // What is left of the older code after the newer.
        assert_eq!(map.find(0x10f0), Some((0x10c0, 0x1100, "py::old:/a.py")));
        assert_eq!(map.find(0x2009), Some((0x2000, 0x2010, "JS:~f /b.js:1:1")));
        assert_eq!(map.find(0x2010), None);
        assert_eq!(map.find(0xfff), None);
    }

    #[test]
    fn newer_code_can_cover_several_older_pieces() {
        let map = PerfMap::parse("10 10 a\n20 10 b\n30 10 c\n18 20 d\n");
        assert_eq!(map.find(0x10), Some((0x10, 0x18, "a")));
        assert_eq!(map.find(0x20), Some((0x18, 0x38, "d")));
        assert_eq!(map.find(0x38), Some((0x38, 0x40, "c")));
    }
}
