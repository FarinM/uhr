use std::collections::HashMap;
use std::fs;
use std::ops::Range;
use std::sync::Arc;

use framehop::x86_64::{CacheX86_64, UnwindRegsX86_64, UnwinderX86_64};
use framehop::{Error as UnwindError, ExplicitModuleSectionInfo, FrameAddress, Module, Unwinder};
use gimli::{
    BaseAddresses, CieOrFde, DebugFrame, EhFrame, EndianSlice, LittleEndian, UnwindSection,
};
use tracing::debug;
use wholesym::samply_symbols::object::{
    self, Object, ObjectSection, ObjectSegment, SegmentFlags, elf,
};
use wholesym::samply_symbols::relative_address_base;

use uhr_core::recording::Mapping;

type Data = Arc<[u8]>;

/// x86-64 Linux maps files in 4 KiB pages.
const PAGE: u64 = 4096;

/// User stacks from the stack copy perf takes with each sample, unwound
/// with the unwind tables of the mapped files. Where a file has none, as
/// for JIT code, framehop falls back to frame pointers.
pub(super) struct Unwinding {
    /// By path and recorded build-id. `None` if the file could not be read
    /// or is not the one that ran.
    files: HashMap<(String, Option<String>), Option<Arc<Sections>>>,
    processes: HashMap<u32, Process>,
    cache: CacheX86_64,
}

struct Process {
    /// Length and last id of the mapping list the unwinder was built from.
    /// Lists only grow, and exec starts a new one.
    built_from: (usize, Option<u32>),
    unwinder: UnwinderX86_64<Data>,
}

/// What framehop needs of a file, read once for every process that maps it.
struct Sections {
    base_svma: u64,
    segments: Vec<Segment>,
    text: Option<(Range<u64>, Data)>,
    eh_frame: Option<(Range<u64>, Data)>,
    eh_frame_hdr: Option<(Range<u64>, Data)>,
    debug_frame: Option<Data>,
    got: Option<Range<u64>>,
    /// Addresses only `.debug_frame` has unwind rules for, sorted. framehop
    /// reads one CFI section per module, so these get modules of their own.
    debug_frame_only: Vec<Range<u64>>,
}

struct Segment {
    file_offset: u64,
    file_size: u64,
    address: u64,
    executable: bool,
}

/// A sample's user registers, and its copy of the user stack from the
/// stack pointer up.
pub(super) struct UserCopy<'a> {
    pub(super) ip: u64,
    pub(super) sp: u64,
    pub(super) bp: u64,
    /// The registers are those of 32-bit code.
    pub(super) compat: bool,
    pub(super) stack: &'a [u8],
}

pub(super) struct UserStack {
    /// Leaf first, and whether each is a return address.
    pub(super) frames: Vec<(u64, bool)>,
    /// Unwinding stopped at the end of the stack copy, so outer callers are
    /// missing.
    pub(super) cut: bool,
    /// The sample is of 32-bit code, so only the sampled instruction is
    /// kept.
    pub(super) not_unwound: bool,
}

impl Unwinding {
    pub(super) fn new() -> Self {
        Self {
            files: HashMap::new(),
            processes: HashMap::new(),
            cache: CacheX86_64::new(),
        }
    }

    /// `ids` are the process's mappings, oldest first.
    pub(super) fn unwind(
        &mut self,
        copy: &UserCopy,
        pid: u32,
        ids: &[u32],
        mappings: &[Mapping],
        max_frames: usize,
    ) -> UserStack {
        let UserCopy {
            ip,
            sp,
            bp,
            compat,
            stack,
        } = *copy;
        // The x86-64 unwinder would read a 32-bit stack as 8-byte words.
        if compat {
            return UserStack {
                frames: vec![(ip, false)],
                cut: false,
                not_unwound: true,
            };
        }
        let built_from = (ids.len(), ids.last().copied());
        let process = match self.processes.get_mut(&pid) {
            Some(process) if process.built_from == built_from => process,
            _ => {
                let unwinder = build(&mut self.files, ids, mappings);
                self.processes.insert(
                    pid,
                    Process {
                        built_from,
                        unwinder,
                    },
                );
                self.processes.get_mut(&pid).unwrap()
            }
        };

        let end = sp.saturating_add(stack.len() as u64);
        let mut read_stack = |address: u64| {
            let offset = address.checked_sub(sp).ok_or(())? as usize;
            let bytes = stack
                .get(offset..offset.checked_add(8).ok_or(())?)
                .ok_or(())?;
            Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
        };
        let mut frames = Vec::new();
        let mut cut = false;
        let mut iter = process.unwinder.iter_frames(
            ip,
            UnwindRegsX86_64::new(ip, sp, bp),
            &mut self.cache,
            &mut read_stack,
        );
        while frames.len() < max_frames {
            match iter.next() {
                Ok(Some(frame)) => frames.push((
                    frame.address(),
                    matches!(frame, FrameAddress::ReturnAddress(_)),
                )),
                Ok(None) => break,
                Err(UnwindError::CouldNotReadStack(address)) => {
                    // A word can start in the copy and end past it.
                    cut = address >= sp && address.saturating_add(8) > end;
                    break;
                }
                // Corrupt or unusual stacks end where unwinding cannot go on.
                Err(_) => break,
            }
        }
        UserStack {
            frames,
            cut,
            not_unwound: false,
        }
    }
}

fn build(
    files: &mut HashMap<(String, Option<String>), Option<Arc<Sections>>>,
    ids: &[u32],
    mappings: &[Mapping],
) -> UnwinderX86_64<Data> {
    let mut unwinder = UnwinderX86_64::new();
    for (id, pieces) in visible(ids, mappings) {
        let mapping = &mappings[id as usize];
        if !mapping.path.starts_with('/') {
            continue;
        }
        let key = (mapping.path.clone(), mapping.build_id.clone());
        let sections = files
            .entry(key)
            .or_insert_with(|| read(&mapping.path, mapping.build_id.as_deref()))
            .clone();
        let Some(sections) = sections else {
            continue;
        };
        let Some(svma) = sections.svma_of(mapping.file_offset) else {
            continue;
        };
        let bias = mapping.start.wrapping_sub(svma);
        for piece in pieces {
            for (range, debug_frame) in split_by_cfi(&sections, piece, bias) {
                unwinder.add_module(module(&mapping.path, range, bias, &sections, debug_frame));
            }
        }
    }
    unwinder
}

/// The address ranges of each mapping that no newer mapping hides, newest
/// mapping first. Mappings without unwind tables hide older ones too.
fn visible(ids: &[u32], mappings: &[Mapping]) -> Vec<(u32, Vec<Range<u64>>)> {
    let mut taken: Vec<Range<u64>> = Vec::new();
    let mut result = Vec::new();
    for &id in ids.iter().rev() {
        let mapping = &mappings[id as usize];
        let range = mapping.start..mapping.end;
        let pieces = difference(std::slice::from_ref(&range), &taken);
        taken = merge(taken.into_iter().chain([range]).collect());
        if !pieces.is_empty() {
            result.push((id, pieces));
        }
    }
    result
}

/// Splits a mapped range into the parts whose unwind rules come from
/// `.eh_frame` (`false`) and those only `.debug_frame` has (`true`).
fn split_by_cfi(sections: &Sections, piece: Range<u64>, bias: u64) -> Vec<(Range<u64>, bool)> {
    let debug_only: Vec<Range<u64>> = sections
        .debug_frame_only
        .iter()
        .map(|r| r.start.wrapping_add(bias)..r.end.wrapping_add(bias))
        .collect();
    let inside = |ranges: Vec<Range<u64>>, debug_frame| {
        ranges.into_iter().filter_map(move |r| {
            let r = r.start.max(piece.start)..r.end.min(piece.end);
            (r.start < r.end).then_some((r, debug_frame))
        })
    };
    let mut parts: Vec<(Range<u64>, bool)> = inside(debug_only.clone(), true)
        .chain(inside(
            difference(std::slice::from_ref(&piece), &debug_only),
            false,
        ))
        .collect();
    parts.sort_by_key(|(r, _)| r.start);
    parts
}

fn module(
    path: &str,
    range: Range<u64>,
    bias: u64,
    sections: &Sections,
    debug_frame: bool,
) -> Module<Data> {
    let (eh_frame, eh_frame_hdr, debug) = if debug_frame {
        (None, None, sections.debug_frame.clone())
    } else {
        (
            sections.eh_frame.clone(),
            sections.eh_frame_hdr.clone(),
            sections
                .debug_frame
                .clone()
                .filter(|_| sections.eh_frame.is_none()),
        )
    };
    Module::new(
        path.to_owned(),
        range,
        sections.base_svma.wrapping_add(bias),
        ExplicitModuleSectionInfo {
            base_svma: sections.base_svma,
            text_svma: sections.text.as_ref().map(|(r, _)| r.clone()),
            text: sections.text.as_ref().map(|(_, d)| d.clone()),
            stubs_svma: None,
            stub_helper_svma: None,
            got_svma: sections.got.clone(),
            unwind_info: None,
            eh_frame_svma: eh_frame.as_ref().map(|(r, _)| r.clone()),
            eh_frame: eh_frame.map(|(_, d)| d),
            eh_frame_hdr_svma: eh_frame_hdr.as_ref().map(|(r, _)| r.clone()),
            eh_frame_hdr: eh_frame_hdr.map(|(_, d)| d),
            debug_frame: debug,
            text_segment_svma: None,
            text_segment: None,
        },
    )
}

/// `None` if the file is gone, unreadable, not the build that ran, or 32-bit
/// code, whose unwind rules are not for x86-64 registers.
fn read(path: &str, build_id: Option<&str>) -> Option<Arc<Sections>> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            debug!(path, %error, "no unwind tables");
            return None;
        }
    };
    let file = object::File::parse(&*bytes).ok()?;
    if !file.is_64() {
        return None;
    }
    if let Some(recorded) = build_id {
        let on_disk = file.build_id().ok().flatten().map(hex);
        if on_disk.as_deref() != Some(recorded) {
            debug!(
                path,
                "the file changed since recording, so its unwind tables are not used"
            );
            return None;
        }
    }
    let section = |name: &str| {
        let section = file.section_by_name(name)?;
        // Debug sections can be compressed; the unwinder needs the bytes.
        let data: Data = section.uncompressed_data().ok()?.into();
        Some((section.address()..section.address() + section.size(), data))
    };
    let text = section(".text");
    let eh_frame = section(".eh_frame");
    let eh_frame_hdr = section(".eh_frame_hdr");
    let debug_frame = section(".debug_frame").map(|(_, data)| data);
    let got = section(".got").map(|(range, _)| range);
    let debug_frame_only = match (&eh_frame, &debug_frame) {
        (Some((eh_range, eh_data)), Some(debug_data)) => {
            let mut bases = BaseAddresses::default().set_eh_frame(eh_range.start);
            if let Some((text_range, _)) = &text {
                bases = bases.set_text(text_range.start);
            }
            if let Some(got) = &got {
                bases = bases.set_got(got.start);
            }
            let mut eh = EhFrame::new(eh_data, LittleEndian);
            eh.set_address_size(8);
            let mut debug = DebugFrame::new(debug_data, LittleEndian);
            debug.set_address_size(8);
            difference(
                &merge(described(&debug, &bases)),
                &merge(described(&eh, &bases)),
            )
        }
        _ => Vec::new(),
    };
    Some(Arc::new(Sections {
        base_svma: relative_address_base(&file),
        segments: file
            .segments()
            .map(|segment| {
                let (file_offset, file_size) = segment.file_range();
                let executable = matches!(
                    segment.flags(),
                    SegmentFlags::Elf { p_flags } if p_flags & elf::PF_X != 0
                );
                Segment {
                    file_offset,
                    file_size,
                    address: segment.address(),
                    executable,
                }
            })
            .collect(),
        text,
        eh_frame,
        eh_frame_hdr,
        debug_frame,
        got,
        debug_frame_only,
    }))
}

/// The address ranges a CFI section has unwind rules for.
fn described<'a, S>(section: &S, bases: &BaseAddresses) -> Vec<Range<u64>>
where
    S: UnwindSection<EndianSlice<'a, LittleEndian>>,
{
    let mut ranges = Vec::new();
    let mut entries = section.entries(bases);
    while let Ok(Some(entry)) = entries.next() {
        if let CieOrFde::Fde(partial) = entry
            && let Ok(fde) =
                partial.parse(|section, bases, offset| section.cie_from_offset(bases, offset))
        {
            let start = fde.initial_address();
            ranges.push(start..start.saturating_add(fde.len()));
        }
    }
    ranges
}

impl Sections {
    /// The address the file offset of an executable mapping is loaded at,
    /// before relocation. Linkers such as lld start a segment partway into
    /// a page, so the page a mapping starts at can also belong to the
    /// segment before; only the executable one maps it as code.
    fn svma_of(&self, file_offset: u64) -> Option<u64> {
        self.segments
            .iter()
            .find(|s| {
                s.executable
                    && s.file_offset / PAGE * PAGE <= file_offset
                    && file_offset < s.file_offset + s.file_size
            })
            .map(|s| {
                s.address
                    .wrapping_add(file_offset)
                    .wrapping_sub(s.file_offset)
            })
    }
}

/// Sorts and joins overlapping or touching ranges.
fn merge(mut ranges: Vec<Range<u64>>) -> Vec<Range<u64>> {
    ranges.retain(|r| r.start < r.end);
    ranges.sort_by_key(|r| r.start);
    let mut merged: Vec<Range<u64>> = Vec::with_capacity(ranges.len());
    for range in ranges {
        match merged.last_mut() {
            Some(last) if range.start <= last.end => last.end = last.end.max(range.end),
            _ => merged.push(range),
        }
    }
    merged
}

/// `ranges` minus `remove`, both sorted and merged.
fn difference(ranges: &[Range<u64>], remove: &[Range<u64>]) -> Vec<Range<u64>> {
    let mut result = Vec::new();
    let mut remove = remove.iter().peekable();
    for range in ranges {
        let mut start = range.start;
        while let Some(r) = remove.peek() {
            if r.end <= start {
                remove.next();
                continue;
            }
            if r.start >= range.end {
                break;
            }
            if r.start > start {
                result.push(start..r.start);
            }
            start = start.max(r.end);
            if r.end > range.end {
                break;
            }
            remove.next();
        }
        if start < range.end {
            result.push(start..range.end);
        }
    }
    result
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
// A list holding one range is what these tests mean, not a mistyped range.
#[allow(clippy::single_range_in_vec_init)]
mod tests {
    use super::*;

    fn mapping(start: u64, end: u64, path: &str) -> Mapping {
        Mapping {
            pid: Some(1),
            start,
            end,
            file_offset: 0,
            path: path.into(),
            build_id: None,
            time_ns: None,
        }
    }

    #[test]
    fn subtracts_and_merges_ranges() {
        assert_eq!(merge(vec![5..9, 0..3, 3..4, 8..12]), [0..4, 5..12]);
        assert_eq!(difference(&[0..10], &[2..3, 5..7]), [0..2, 3..5, 7..10]);
        assert_eq!(difference(&[0..10, 20..30], &[8..22]), [0..8, 22..30]);
        assert_eq!(difference(&[0..10], &[0..10]), Vec::<Range<u64>>::new());
        assert_eq!(difference(&[4..6], &[]), [4..6]);
    }

    #[test]
    fn newer_mappings_hide_older_ones_even_without_unwind_tables() {
        let mappings = vec![
            mapping(0x1000, 0x5000, "/lib/old.so"),
            mapping(0x2000, 0x3000, "//anon"),
            mapping(0x4000, 0x6000, "/lib/new.so"),
        ];
        let visible = visible(&[0, 1, 2], &mappings);
        assert_eq!(
            visible,
            [
                (2, vec![0x4000..0x6000]),
                (1, vec![0x2000..0x3000]),
                (0, vec![0x1000..0x2000, 0x3000..0x4000]),
            ]
        );
    }

    #[test]
    fn finds_the_executable_segment_of_a_page_shared_with_another() {
        // As lld lays out a Rust binary: the code segment starts partway
        // into the page that ends the read-only segment.
        let sections = Sections {
            base_svma: 0,
            segments: vec![
                Segment {
                    file_offset: 0,
                    file_size: 0x12d74,
                    address: 0,
                    executable: false,
                },
                Segment {
                    file_offset: 0x12d80,
                    file_size: 0x3d5c0,
                    address: 0x13d80,
                    executable: true,
                },
            ],
            text: None,
            eh_frame: None,
            eh_frame_hdr: None,
            debug_frame: None,
            got: None,
            debug_frame_only: Vec::new(),
        };
        assert_eq!(sections.svma_of(0x12000), Some(0x13000));
        assert_eq!(sections.svma_of(0x20000), Some(0x21000));
        assert_eq!(sections.svma_of(0x1000), None, "not mapped as code");
    }

    #[test]
    fn gives_debug_frame_rules_their_own_modules() {
        let sections = Sections {
            base_svma: 0,
            segments: Vec::new(),
            text: None,
            eh_frame: None,
            eh_frame_hdr: None,
            debug_frame: None,
            got: None,
            debug_frame_only: vec![0x1100..0x1200, 0x1400..0x1500],
        };
        let parts = split_by_cfi(&sections, 0x101000..0x101450, 0x100000);
        assert_eq!(
            parts,
            [
                (0x101000..0x101100, false),
                (0x101100..0x101200, true),
                (0x101200..0x101400, false),
                (0x101400..0x101450, true),
            ]
        );
    }

    #[test]
    fn counts_a_stack_cut_where_a_word_runs_past_the_copy() {
        // Without unwind tables, the caller's frame pointer is at bp and
        // the return address right after it, past the 9 bytes copied.
        let stack = [0; 9];
        let copy = UserCopy {
            ip: 0x1000,
            sp: 0x7000,
            bp: 0x7000,
            compat: false,
            stack: &stack,
        };
        let user = Unwinding::new().unwind(&copy, 1, &[], &[], 10);
        assert_eq!(user.frames, [(0x1000, false)]);
        assert!(user.cut);
    }

    fn object(dir: &std::path::Path, name: &str, flags: &[&str]) -> String {
        let source = dir.join("code.c");
        fs::write(&source, "int f(int x) { return x * 3; }\n").unwrap();
        let object = dir.join(name);
        let status = std::process::Command::new("cc")
            .args(flags)
            .arg("-c")
            .arg("-o")
            .arg(&object)
            .arg(&source)
            .status()
            .unwrap();
        assert!(status.success());
        object.to_str().unwrap().to_owned()
    }

    #[test]
    fn leaves_out_the_unwind_tables_of_32_bit_code() {
        let dir = tempfile::tempdir().unwrap();
        for (flags, elf32) in [(&["-m32"][..], true), (&[][..], false)] {
            let path = object(dir.path(), if elf32 { "32.o" } else { "64.o" }, flags);
            assert_eq!(read(&path, None).is_none(), elf32, "{flags:?}");
        }
    }
}
