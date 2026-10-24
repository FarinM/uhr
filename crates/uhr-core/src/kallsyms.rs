use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io;

use crate::recording::{Frame, KERNEL, KernelSymbol, Mapping, Origin};

const KALLSYMS: &str = "/proc/kallsyms";
const KPTR_RESTRICT: &str = "/proc/sys/kernel/kptr_restrict";
const PERF_EVENT_PARANOID: &str = "/proc/sys/kernel/perf_event_paranoid";

/// Why the kernel's symbols could not be read.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("reading {KALLSYMS}: {0}")]
    Read(io::Error),
    /// The two settings that decide who sees the addresses, `None` if
    /// unreadable.
    #[error(
        "{KALLSYMS} hid the kernel's addresses{}",
        settings(.kptr_restrict, .perf_event_paranoid)
    )]
    Hidden {
        kptr_restrict: Option<i32>,
        perf_event_paranoid: Option<i32>,
    },
}

fn settings(kptr_restrict: &Option<i32>, perf_event_paranoid: &Option<i32>) -> String {
    let known: Vec<String> = [
        ("kernel.kptr_restrict", kptr_restrict),
        ("kernel.perf_event_paranoid", perf_event_paranoid),
    ]
    .into_iter()
    .filter_map(|(name, value)| value.map(|v| format!("{name} is {v}")))
    .collect();
    if known.is_empty() {
        String::new()
    } else {
        format!(" ({})", known.join(", "))
    }
}

/// The functions of the running kernel, its modules and BPF programs, by
/// module, each sorted by address. The kernel itself is `None`.
pub(crate) struct Kallsyms {
    modules: HashMap<Option<String>, Vec<Symbol>>,
}

struct Symbol {
    start: u64,
    name: String,
}

fn hidden() -> Error {
    let read = |path| fs::read_to_string(path).ok()?.trim().parse().ok();
    Error::Hidden {
        kptr_restrict: read(KPTR_RESTRICT),
        perf_event_paranoid: read(PERF_EVENT_PARANOID),
    }
}

/// The start, name, module and type of a function in a line of kallsyms.
fn symbol(line: &str) -> Option<(u64, &str, Option<&str>, char)> {
    let mut fields = line.split_whitespace();
    let start = u64::from_str_radix(fields.next()?, 16).ok()?;
    let kind = fields.next()?.chars().next()?;
    let name = fields.next()?;
    let module = fields
        .next()
        .map(|m| m.trim_start_matches('[').trim_end_matches(']'));
    // The markers ARM and RISC-V put between code and data, which the
    // kernel's own lookups skip in the same way.
    let marker = name.starts_with('$') || name.starts_with(".L") || name.starts_with("L0");
    (matches!(kind, 't' | 'T' | 'w' | 'W') && !marker).then_some((start, name, module, kind))
}

/// The module a kernel mapping holds: `Some(None)` for the kernel itself,
/// `None` if the mapping is neither.
fn module_of(mapping: &Mapping) -> Option<Option<&str>> {
    if mapping.path == KERNEL {
        return Some(None);
    }
    let name = mapping.path.strip_prefix('[')?.strip_suffix(']')?;
    Some(Some(name))
}

impl Kallsyms {
    pub(crate) fn read() -> Result<Self, Error> {
        let text = fs::read_to_string(KALLSYMS).map_err(Error::Read)?;
        Self::parse(&text).ok_or_else(hidden)
    }

    /// `None` if every function is at address 0, as the kernel shows them
    /// when it hides addresses.
    fn parse(text: &str) -> Option<Self> {
        let mut modules: HashMap<Option<String>, Vec<(Symbol, char)>> = HashMap::new();
        let mut any_address = false;
        for (start, name, module, kind) in text.lines().filter_map(symbol) {
            any_address |= start != 0;
            let symbol = Symbol {
                start,
                name: name.to_owned(),
            };
            modules
                .entry(module.map(str::to_owned))
                .or_default()
                .push((symbol, kind));
        }
        if !any_address {
            return None;
        }
        let modules = modules
            .into_iter()
            .map(|(module, mut symbols)| {
                // Of a module's names at one address keep the one perf
                // shows: not weak, then global, then with fewer leading
                // underscores, then longest.
                symbols.sort_by_key(|(s, kind)| {
                    (
                        s.start,
                        kind.eq_ignore_ascii_case(&'w'),
                        kind.is_ascii_lowercase(),
                        s.name.len() - s.name.trim_start_matches('_').len(),
                        std::cmp::Reverse(s.name.len()),
                    )
                });
                symbols.dedup_by_key(|(s, _)| s.start);
                (module, symbols.into_iter().map(|(s, _)| s).collect())
            })
            .collect();
        Some(Self { modules })
    }

    /// The functions kernel frames fall in, without overlaps. A module can
    /// list stale names at addresses another module now holds, so a frame
    /// in a mapping is only looked up in the mapping's module, and its
    /// function ends where the module's next one starts or the mapping
    /// ends. Frames outside every mapping, such as in BPF programs, are
    /// looked up in the modules without a mapping, and their functions end
    /// before the next mapping.
    pub(crate) fn covering(&self, frames: &[Frame], mappings: &[Mapping]) -> Vec<KernelSymbol> {
        let kernel: Vec<&Mapping> = mappings.iter().filter(|m| m.pid.is_none()).collect();
        let mapped: HashSet<Option<&str>> = kernel.iter().filter_map(|m| module_of(m)).collect();
        let mut unmapped: Vec<(&Symbol, Option<&str>)> = self
            .modules
            .iter()
            .filter(|(module, _)| !mapped.contains(&module.as_deref()))
            .flat_map(|(module, symbols)| symbols.iter().map(move |s| (s, module.as_deref())))
            .collect();
        unmapped.sort_by_key(|&(s, module)| (s.start, module));
        let mut mapping_starts: Vec<u64> = kernel.iter().map(|m| m.start).collect();
        mapping_starts.sort_unstable();

        let mut found = BTreeMap::new();
        for frame in frames.iter().filter(|f| f.origin == Origin::Kernel) {
            let address = frame
                .address
                .saturating_sub(u64::from(frame.return_address));
            let symbol = match frame.mapping {
                Some(mapping) => self.in_mapping(&mappings[mapping as usize], address),
                None => outside_mappings(&unmapped, &kernel, &mapping_starts, address),
            };
            if let Some(symbol) = symbol {
                found.entry(symbol.start).or_insert(symbol);
            }
        }
        found.into_values().collect()
    }

    fn in_mapping(&self, mapping: &Mapping, address: u64) -> Option<KernelSymbol> {
        let module = module_of(mapping)?;
        let symbols = self.modules.get(&module.map(str::to_owned))?;
        let index = symbols
            .partition_point(|s| s.start <= address)
            .checked_sub(1)?;
        let symbol = &symbols[index];
        // Then the function belongs to whatever comes before the mapping.
        if symbol.start < mapping.start {
            return None;
        }
        let end = symbols
            .get(index + 1)
            .map_or(mapping.end, |next| next.start.min(mapping.end));
        (address < end).then(|| KernelSymbol {
            start: symbol.start,
            end,
            name: symbol.name.clone(),
            module: module.map(str::to_owned),
        })
    }
}

fn outside_mappings(
    unmapped: &[(&Symbol, Option<&str>)],
    mappings: &[&Mapping],
    mapping_starts: &[u64],
    address: u64,
) -> Option<KernelSymbol> {
    let index = unmapped
        .partition_point(|(s, _)| s.start <= address)
        .checked_sub(1)?;
    let (symbol, module) = unmapped[index];
    if mappings
        .iter()
        .any(|m| m.start <= symbol.start && symbol.start < m.end)
    {
        return None;
    }
    let next = unmapped.get(index + 1).map(|(s, _)| s.start);
    let next_mapping = mapping_starts
        .get(mapping_starts.partition_point(|&start| start <= symbol.start))
        .copied();
    // Without either, the last function has no known end.
    let end = next.into_iter().chain(next_mapping).min()?;
    (address < end).then(|| KernelSymbol {
        start: symbol.start,
        end,
        name: symbol.name.clone(),
        module: module.map(str::to_owned),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KALLSYMS: &str = "\
0000000000000000 A fixed_percpu_data
ffffffff81000000 T _stext
ffffffff81000000 T _text
ffffffff81000000 t startup_64
ffffffff81001000 t __pfx_vfs_read
ffffffff81001010 T vfs_read
ffffffff81001010 W vfs_read_alias
ffffffff81001200 r vfs_read_data
ffffffff81001400 T ksys_read
ffffffff81002000 T _etext
ffffffffc0001000 t ext4_read\t[ext4]
ffffffffc0001100 t ext4_write\t[ext4]
ffffffffc0003010 t __clmul_gf128mul_ble\t[ghash]
ffffffffc0003010 T virtio_rng_driver_init\t[virtio_rng]
ffffffffc0003100 t ghash_update\t[ghash]
ffffffffc0005000 t arm_crc\t[arm]
ffffffffc0005040 t $d\t[arm]
ffffffffc0005050 t $x.1\t[arm]
ffffffffc0005100 t arm_crc_final\t[arm]
ffffffffc0009000 t bpf_prog_6deef7357e7b4530_sd_fw_egress\t[bpf]
ffffffffc000a000 t bpf_prog_ee0e253c78993a24_sd_fw_ingress\t[bpf]
";

    fn frame(address: u64, mapping: Option<u32>, return_address: bool) -> Frame {
        Frame {
            origin: Origin::Kernel,
            address,
            mapping,
            file_offset: None,
            return_address,
        }
    }

    fn mapping(start: u64, end: u64, path: &str) -> Mapping {
        Mapping {
            pid: None,
            start,
            end,
            file_offset: 0,
            path: path.into(),
            build_id: None,
            time_ns: None,
        }
    }

    fn found(frames: &[Frame], mappings: &[Mapping]) -> Vec<(String, u64, Option<String>)> {
        Kallsyms::parse(KALLSYMS)
            .unwrap()
            .covering(frames, mappings)
            .into_iter()
            .map(|s| (s.name, s.end, s.module))
            .collect()
    }

    #[test]
    fn keeps_the_name_perf_shows_of_a_modules_names_at_one_address() {
        let kallsyms = Kallsyms::parse(KALLSYMS).unwrap();
        let names: Vec<_> = kallsyms.modules[&None]
            .iter()
            .map(|s| s.name.as_str())
            .collect();
        assert_eq!(
            names,
            [
                "_stext",
                "__pfx_vfs_read",
                "vfs_read",
                "ksys_read",
                "_etext"
            ]
        );
    }

    #[test]
    fn sees_hidden_addresses() {
        let hidden = "0000000000000000 T _text\n0000000000000000 T vfs_read\n";
        assert!(Kallsyms::parse(hidden).is_none());
    }

    #[test]
    fn takes_a_frames_function_from_its_mappings_module() {
        let mappings = vec![
            mapping(0xffffffff81000000, 0xffffffff82000000, "[kernel]"),
            mapping(0xffffffffc0001000, 0xffffffffc0001180, "[ext4]"),
            mapping(0xffffffffc0002000, 0xffffffffc0002800, "[other]"),
            mapping(0xffffffffc0003000, 0xffffffffc0004000, "[ghash]"),
            mapping(0xffffffffc0007000, 0xffffffffc0008000, "[virtio_rng]"),
        ];
        let frames = [
            frame(0xffffffff81001010, Some(0), false),
            // Returns to the first byte of ksys_read, but called from vfs_read.
            frame(0xffffffff81001400, Some(0), true),
            frame(0xffffffff81001420, Some(0), false),
            // Past the last function of ext4, but in its mapping.
            frame(0xffffffffc0001170, Some(1), false),
            // In a mapping whose module lists no functions.
            frame(0xffffffffc0002010, Some(2), false),
            // virtio_rng lists a stale name here, in ghash's mapping.
            frame(0xffffffffc0003020, Some(3), false),
        ];
        let module = |m: &str| Some(m.to_owned());
        assert_eq!(
            found(&frames, &mappings),
            [
                ("vfs_read".into(), 0xffffffff81001400, None),
                ("ksys_read".into(), 0xffffffff81002000, None),
                ("ext4_write".into(), 0xffffffffc0001180, module("ext4")),
                (
                    "__clmul_gf128mul_ble".into(),
                    0xffffffffc0003100,
                    module("ghash")
                ),
            ]
        );
    }

    #[test]
    fn skips_the_markers_between_code_and_data() {
        let mappings = vec![mapping(0xffffffffc0005000, 0xffffffffc0006000, "[arm]")];
        let frames = [frame(0xffffffffc0005060, Some(0), false)];
        assert_eq!(
            found(&frames, &mappings),
            [("arm_crc".into(), 0xffffffffc0005100, Some("arm".into()))]
        );
    }

    #[test]
    fn ends_functions_outside_mappings_before_the_next_mapping() {
        let mappings = vec![mapping(0xffffffffc0009800, 0xffffffffc0009900, "[ext4]")];
        let frames = [
            frame(0xffffffffc0009010, None, false),
            // Past the start of the mapping after the program.
            frame(0xffffffffc0009a00, None, false),
            // Without a mapping after it, the last function has no known end.
            frame(0xffffffffc000a010, None, false),
            frame(0xffffffff80000000, None, false),
        ];
        assert_eq!(
            found(&frames, &mappings),
            [(
                "bpf_prog_6deef7357e7b4530_sd_fw_egress".into(),
                0xffffffffc0009800,
                Some("bpf".into())
            )]
        );
    }
}
