//! The images of macOS's dyld shared cache, which holds the system's
//! libraries in place of files of their own. Read with `object` rather than
//! through wholesym, whose reader of the cache takes an image's base from
//! the addresses of its exports, some of which, in the caches of macOS 26
//! and later, lie below it.

use std::fs::File;
use std::ops::Range;
use std::path::{Path, PathBuf};

use memmap2::Mmap;
use wholesym::samply_symbols::demangle_any;
use wholesym::samply_symbols::object::macho::{self, DyldCacheHeader, MachHeader64};
use wholesym::samply_symbols::object::read::macho::{
    DyldCache, DyldSubCacheSlice, LoadCommandVariant, MachHeader, Segment,
};
use wholesym::samply_symbols::object::{
    self, Endianness, Object, ObjectSection, ObjectSymbol, SectionKind, SymbolKind,
};
use wholesym::samply_symbols::relative_address_base;

/// Where macOS keeps the cache: on the sealed system volume, which only an
/// update of the system changes.
const DIRS: [&str; 2] = [
    "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld",
    "/System/Library/dyld",
];

/// The caches on this machine, one for each architecture it runs, with
/// their subcaches, mapped rather than read, as they are gigabytes.
pub(super) struct Caches {
    caches: Vec<Mapped>,
}

struct Mapped {
    path: PathBuf,
    main: Mmap,
    subcaches: Vec<Mmap>,
}

pub(super) enum Lookup {
    Found(Image),
    /// The cache has an image at the path, with another UUID: the system
    /// was updated since.
    Mismatch(String),
    Missing,
}

/// One image of the cache, as needed to name the code in it.
pub(super) struct Image {
    /// Where functions start, relative to the image's base, sorted, with
    /// their names where the cache has them.
    functions: Vec<(u32, Option<String>)>,
    /// Where its code is, relative to its base.
    code: Vec<Range<u32>>,
}

impl Caches {
    /// The caches that could be read. A cache that can't is left out, so
    /// its images are missing.
    pub(super) fn open() -> Self {
        let mut caches = Vec::new();
        for dir in DIRS {
            let Ok(entries) = std::fs::read_dir(dir) else {
                continue;
            };
            let mut paths: Vec<PathBuf> = entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .and_then(|name| name.strip_prefix("dyld_shared_cache_"))
                        .is_some_and(|arch| !arch.contains('.'))
                })
                .collect();
            paths.sort();
            caches.extend(paths.into_iter().filter_map(|path| {
                Mapped::open(&path)
                    .inspect_err(|error| {
                        tracing::warn!(path = %path.display(), %error, "reading the dyld shared cache")
                    })
                    .ok()
            }));
        }
        Self { caches }
    }

    /// The image at `path` with `uuid`.
    pub(super) fn find(&self, path: &str, uuid: [u8; 16]) -> Result<Lookup, String> {
        let mut mismatch = None;
        for cache in &self.caches {
            match cache.find(path, uuid)? {
                Lookup::Found(image) => return Ok(Lookup::Found(image)),
                Lookup::Mismatch(found) => mismatch = Some(found),
                Lookup::Missing => {}
            }
        }
        Ok(mismatch.map_or(Lookup::Missing, Lookup::Mismatch))
    }
}

impl Mapped {
    fn open(path: &Path) -> Result<Self, String> {
        let main = map(path)?;
        let subcaches = suffixes(&main)?
            .into_iter()
            .map(|suffix| {
                let mut subcache = path.as_os_str().to_owned();
                subcache.push(&suffix);
                map(Path::new(&subcache))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            path: path.to_owned(),
            main,
            subcaches,
        })
    }

    fn find(&self, path: &str, uuid: [u8; 16]) -> Result<Lookup, String> {
        let error = |e: object::Error| format!("{}: {e}", self.path.display());
        let subcaches: Vec<&[u8]> = self.subcaches.iter().map(|m| &m[..]).collect();
        let cache = DyldCache::<Endianness>::parse(&self.main[..], &subcaches).map_err(error)?;
        let Some(image) = cache.images().find(|image| image.path() == Ok(path)) else {
            return Ok(Lookup::Missing);
        };
        let object = image.parse_object().map_err(error)?;
        match object.mach_uuid().map_err(error)? {
            Some(found) if found == uuid => {}
            found => return Ok(Lookup::Mismatch(found.map(hex).unwrap_or_default())),
        }
        let base = relative_address_base(&object);
        let relative = |address: u64| u32::try_from(address.checked_sub(base)?).ok();
        let code: Vec<Range<u32>> = object
            .sections()
            .filter(|section| section.kind() == SectionKind::Text)
            .filter_map(|section| {
                let start = relative(section.address())?;
                Some(start..start.checked_add(u32::try_from(section.size()).ok()?)?)
            })
            .collect();
        let mut functions: Vec<(u32, Option<String>)> = object
            .symbols()
            .filter(|symbol| symbol.kind() == SymbolKind::Text && symbol.is_definition())
            .filter_map(|symbol| {
                let start = relative(symbol.address())?;
                let name = symbol
                    .name()
                    .ok()
                    .filter(|n| !n.is_empty() && *n != "<redacted>")?;
                Some((start, Some(demangle(name))))
            })
            .collect();
        // Every function's start, named or not, so that one without a name
        // does not take the name of the one before.
        let (data, header_offset) = image.image_data_and_offset().map_err(error)?;
        let starts = function_starts(&cache, data, header_offset).map_err(error)?;
        functions.extend(
            starts
                .into_iter()
                .filter_map(|a| Some((relative(a)?, None))),
        );
        // Named ones first at each start.
        functions.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.is_some().cmp(&a.1.is_some())));
        functions.dedup_by_key(|(start, _)| *start);
        Ok(Lookup::Found(Image { functions, code }))
    }
}

impl Image {
    /// The function the relative `address` is in: where it starts and ends,
    /// and its name, if the cache has one.
    pub(super) fn function(&self, address: u32) -> Option<(Range<u32>, Option<&str>)> {
        let code = self.code.iter().find(|code| code.contains(&address))?;
        let index = self
            .functions
            .partition_point(|&(start, _)| start <= address)
            .checked_sub(1)?;
        let (start, name) = &self.functions[index];
        let end = self
            .functions
            .get(index + 1)
            .map_or(code.end, |&(next, _)| next.min(code.end));
        Some((*start..end, name.as_deref()))
    }
}

fn map(path: &Path) -> Result<Mmap, String> {
    let file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    // SAFETY: the sealed system volume does not change under a running
    // system.
    unsafe { Mmap::map(&file) }.map_err(|e| format!("{}: {e}", path.display()))
}

/// The file name suffixes of the subcaches, in the order `DyldCache::parse`
/// takes them: since macOS 13 written in the main cache, as `.01` or
/// `.25.dylddata`.
fn suffixes(main: &[u8]) -> Result<Vec<String>, String> {
    let error = |e: object::Error| e.to_string();
    let header = DyldCacheHeader::<Endianness>::parse(main).map_err(error)?;
    let (_, endian) = header.parse_magic().map_err(error)?;
    let mut suffixes: Vec<String> = match header.subcaches(endian, main).map_err(error)? {
        None => Vec::new(),
        Some(DyldSubCacheSlice::V1(subcaches)) => {
            (1..=subcaches.len()).map(|i| format!(".{i}")).collect()
        }
        Some(DyldSubCacheSlice::V2(subcaches)) => subcaches
            .iter()
            .map(|subcache| {
                let suffix = &subcache.file_suffix;
                let len = suffix.iter().position(|&b| b == 0).unwrap_or(suffix.len());
                String::from_utf8_lossy(&suffix[..len]).into_owned()
            })
            .collect(),
        Some(_) => return Err("a layout of subcaches this build does not know".into()),
    };
    if header.symbols_subcache_uuid(endian).is_some() {
        suffixes.push(".symbols".into());
    }
    Ok(suffixes)
}

/// The starts of the image's functions, from `LC_FUNCTION_STARTS`, as
/// addresses. The list is in the subcache that holds the image's
/// `__LINKEDIT`, at an offset in that file.
fn function_starts<'data>(
    cache: &DyldCache<'data, Endianness, &'data [u8]>,
    data: &'data [u8],
    header_offset: u64,
) -> Result<Vec<u64>, object::Error> {
    let header = MachHeader64::<Endianness>::parse(data, header_offset)?;
    let endian = header.endian()?;
    let (mut text, mut linkedit, mut starts) = (None, None, None);
    let mut commands = header.load_commands(endian, data, header_offset)?;
    while let Some(command) = commands.next()? {
        match command.variant()? {
            LoadCommandVariant::Segment64(segment, _) => match segment.name() {
                b"__TEXT" => text = Some(segment.vmaddr(endian)),
                b"__LINKEDIT" => linkedit = Some(segment.vmaddr(endian)),
                _ => {}
            },
            LoadCommandVariant::LinkeditData(command)
                if command.cmd.get(endian) == macho::LC_FUNCTION_STARTS =>
            {
                starts = Some((command.dataoff.get(endian), command.datasize.get(endian)));
            }
            _ => {}
        }
    }
    let (Some(text), Some(linkedit), Some((offset, size))) = (text, linkedit, starts) else {
        return Ok(Vec::new());
    };
    let Some((linkedit_data, _)) = cache.data_and_offset_for_address(linkedit) else {
        return Ok(Vec::new());
    };
    let Some(bytes) = linkedit_data.get(offset as usize..offset as usize + size as usize) else {
        return Ok(Vec::new());
    };
    Ok(crate::macho::decode_starts(text, bytes))
}

/// Mach-O names start with an underscore that C code does not write.
fn demangle(name: &str) -> String {
    let name = name.strip_prefix('_').unwrap_or(name);
    // Mangled C++ and Rust names keep the underscore their scheme starts
    // with.
    if name.starts_with("_Z") || name.starts_with("_R") {
        demangle_any(name)
    } else {
        name.to_owned()
    }
}

fn hex(uuid: [u8; 16]) -> String {
    uuid.iter().map(|b| format!("{b:02x}")).collect()
}
