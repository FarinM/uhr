use std::ops::{Deref, Range};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use addr2line::{Context, LookupContinuation, LookupResult, SplitDwarfLoad};
use gimli::{
    AttributeValue, DebugInfoOffset, EndianReader, Reader as _, RunTimeEndian, SectionId,
    UnitHeader, UnitOffset, UnitRef,
};
use wholesym::samply_symbols::FileLocation;
use wholesym::samply_symbols::object::{self, CompressionFormat, Object, ObjectSection};

use super::InlineFrame;
use super::files::{Files, Location, Snapshot};

type Reader = EndianReader<RunTimeEndian, Bytes>;

/// Section bytes: in place in the file snapshot when stored uncompressed,
/// so large debug info is not copied.
#[derive(Clone)]
enum Bytes {
    Mapped(Snapshot, Range<usize>),
    Decompressed(Arc<[u8]>),
}

impl Deref for Bytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Bytes::Mapped(snapshot, range) => &snapshot[range.clone()],
            Bytes::Decompressed(data) => data,
        }
    }
}

impl std::fmt::Debug for Bytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} bytes", self.len())
    }
}

// SAFETY: both kinds hold their bytes behind an Arc, which does not move
// them, and a snapshot's private mapping never changes.
unsafe impl stable_deref_trait::StableDeref for Bytes {}
unsafe impl stable_deref_trait::CloneStableDeref for Bytes {}

/// The DWARF of one binary, read with addr2line rather than through wholesym:
/// wholesym strips a leading underscore from names it cannot demangle, which
/// is right for Mach-O but merges distinct ELF functions, and it gives no
/// declaration to tell inlined functions apart by.
pub(super) struct DebugInfo<'a> {
    context: Context<Reader>,
    dwarf: Arc<gimli::Dwarf<Reader>>,
    files: &'a Files,
    /// Where the DWARF came from, which split DWARF paths are relative to.
    location: Location,
    /// Every unit by where it starts, for references across units, which
    /// LTO builds make for functions inlined from another crate. A unit is
    /// parsed when a reference first reaches it.
    units: Vec<LazyUnit>,
}

struct LazyUnit {
    start: DebugInfoOffset,
    header: UnitHeader<Reader>,
    parsed: OnceLock<Option<gimli::Unit<Reader>>>,
}

impl<'a> DebugInfo<'a> {
    /// `None` if the file has no DWARF.
    pub(super) fn load(files: &'a Files, path: &Path) -> Result<Option<Self>, String> {
        let data = files.read(path).map_err(|e| e.to_string())?;
        let object = object::File::parse(&*data).map_err(|e| e.to_string())?;
        if object.section_by_name(".debug_info").is_none() {
            return Ok(None);
        }
        let dwarf = Arc::new(dwarf(&data, &object, SectionId::name)?);
        let mut units = Vec::new();
        let mut headers = dwarf.units();
        while let Ok(Some(header)) = headers.next() {
            if let Some(start) = header.offset().as_debug_info_offset() {
                units.push(LazyUnit {
                    start,
                    header,
                    parsed: OnceLock::new(),
                });
            }
        }
        let context = Context::from_arc_dwarf(dwarf.clone()).map_err(|e| e.to_string())?;
        Ok(Some(Self {
            context,
            dwarf,
            files,
            location: Location(path.to_owned()),
            units,
        }))
    }

    /// The functions at `address`, innermost inlined call first; the last is
    /// the function the machine code belongs to. Empty if no unit covers it.
    pub(super) fn chain(&self, address: u64) -> Vec<InlineFrame> {
        let Ok(mut frames) = self.resolve(self.context.find_frames(address)) else {
            return Vec::new();
        };
        let unit = self.resolve(self.context.find_dwarf_and_unit(address));
        let mut chain = Vec::new();
        while let Ok(Some(frame)) = frames.next() {
            let declaration = unit
                .zip(frame.dw_die_offset)
                .and_then(|(unit, offset)| self.declaration(unit, offset));
            let (decl_file, decl_line) = declaration.unzip();
            chain.push(InlineFrame {
                function: frame
                    .function
                    .as_ref()
                    .and_then(|f| f.demangle().ok())
                    .map(|name| name.into_owned()),
                file: frame
                    .location
                    .as_ref()
                    .and_then(|l| l.file)
                    .map(str::to_owned),
                line: frame.location.as_ref().and_then(|l| l.line),
                decl_file,
                decl_line: decl_line.flatten(),
            });
        }
        chain
    }

    /// Runs a lookup, loading split DWARF it asks for.
    fn resolve<T>(&self, mut lookup: LookupResult<T>) -> T::Output
    where
        T: LookupContinuation<Buf = Reader>,
    {
        loop {
            match lookup {
                LookupResult::Output(output) => return output,
                LookupResult::Load { load, continuation } => {
                    lookup = continuation.resume(self.split(&load));
                }
            }
        }
    }

    /// The `.dwo` file a skeleton unit names, or the `.dwp` package beside
    /// the binary.
    fn split(&self, load: &SplitDwarfLoad<Reader>) -> Option<Arc<gimli::Dwarf<Reader>>> {
        let text = |r: &Option<Reader>| {
            r.as_ref()
                .and_then(|r| r.to_string_lossy().ok().map(|s| s.into_owned()))
        };
        let dwo = text(&load.path).and_then(|path| {
            self.location
                .location_for_dwo(&text(&load.comp_dir).unwrap_or_default(), &path)
        });
        if let Some(Location(path)) = dwo
            && let Ok(data) = self.files.read(&path)
            && let Ok(object) = object::File::parse(&*data)
            && let Ok(mut dwarf) = dwarf(&data, &object, |id| id.dwo_name().unwrap_or_default())
        {
            dwarf.make_dwo(&load.parent);
            return Some(Arc::new(dwarf));
        }
        let Location(path) = self.location.location_for_dwp()?;
        let data = self.files.read(&path).ok()?;
        let object = object::File::parse(&*data).ok()?;
        let endian = endian(&object);
        let empty = EndianReader::new(Bytes::Decompressed(Arc::from(&[][..])), endian);
        let package = gimli::DwarfPackage::load(
            |id| section(&data, &object, id.dwo_name().unwrap_or_default(), endian),
            empty,
        )
        .ok()?;
        let dwarf = package.find_cu(load.dwo_id, &load.parent).ok()??;
        Some(Arc::new(dwarf))
    }

    /// The source file and line a function was declared at, following an
    /// inlined call or a definition to the declaration it refers to.
    fn declaration(
        &self,
        unit: UnitRef<Reader>,
        offset: UnitOffset,
    ) -> Option<(String, Option<u32>)> {
        let (mut unit, mut offset) = (unit, offset);
        // Each step goes from an inlined call or a definition to what it was
        // made from; real DWARF needs two or three.
        for _ in 0..8 {
            let entry = unit.entry(offset).ok()?;
            if let Some(AttributeValue::FileIndex(file)) =
                entry.attr_value(gimli::DW_AT_decl_file).ok()?
            {
                let line = entry
                    .attr_value(gimli::DW_AT_decl_line)
                    .ok()?
                    .and_then(|v| v.udata_value())
                    .and_then(|line| u32::try_from(line).ok());
                return Some((file_path(unit, file)?, line));
            }
            let origin = entry
                .attr_value(gimli::DW_AT_abstract_origin)
                .ok()?
                .or(entry.attr_value(gimli::DW_AT_specification).ok()?)?;
            match origin {
                AttributeValue::UnitRef(next) => offset = next,
                // In split DWARF the offset is into the .dwo, whose units
                // these are not.
                AttributeValue::DebugInfoRef(target) if std::ptr::eq(unit.dwarf, &*self.dwarf) => {
                    let index = self
                        .units
                        .partition_point(|u| u.start.0 <= target.0)
                        .checked_sub(1)?;
                    let lazy = &self.units[index];
                    let other = lazy
                        .parsed
                        .get_or_init(|| self.dwarf.unit(lazy.header.clone()).ok())
                        .as_ref()?;
                    offset = UnitOffset(target.0 - lazy.start.0);
                    unit = UnitRef::new(&self.dwarf, other);
                }
                _ => return None,
            }
        }
        None
    }
}

fn file_path(unit: UnitRef<Reader>, index: u64) -> Option<String> {
    let header = unit.line_program.as_ref()?.header();
    let file = header.file(index)?;
    let text = |value| {
        unit.attr_string(value)
            .ok()
            .and_then(|r| r.to_string_lossy().ok().map(|s| s.into_owned()))
    };
    let mut path = PathBuf::new();
    if let Some(dir) = unit.comp_dir.as_ref() {
        path.push(dir.to_string_lossy().ok()?.as_ref());
    }
    if let Some(dir) = file.directory(header).and_then(text) {
        path.push(dir);
    }
    path.push(text(file.path_name())?);
    Some(path.to_string_lossy().into_owned())
}

/// `object` is parsed from `snapshot`.
fn dwarf(
    snapshot: &Snapshot,
    object: &object::File,
    name: impl Fn(SectionId) -> &'static str,
) -> Result<gimli::Dwarf<Reader>, String> {
    let endian = endian(object);
    gimli::Dwarf::load(|id| section(snapshot, object, name(id), endian)).map_err(|e| e.to_string())
}

/// Missing sections are empty, as gimli expects.
fn section(
    snapshot: &Snapshot,
    object: &object::File,
    name: &str,
    endian: RunTimeEndian,
) -> Result<Reader, gimli::Error> {
    let Some(section) = object.section_by_name(name) else {
        return Ok(EndianReader::new(
            Bytes::Decompressed(Arc::from(&[][..])),
            endian,
        ));
    };
    let bytes = match section.compressed_file_range() {
        Ok(range) if range.format == CompressionFormat::None => {
            let start = range.offset as usize;
            Bytes::Mapped(
                snapshot.clone(),
                start..start + range.uncompressed_size as usize,
            )
        }
        _ => Bytes::Decompressed(section.uncompressed_data().unwrap_or_default().into()),
    };
    Ok(EndianReader::new(bytes, endian))
}

fn endian(object: &object::File) -> RunTimeEndian {
    if object.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    }
}
