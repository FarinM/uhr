mod debug_info;
mod files;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io;
use std::path::Path;

use debug_info::DebugInfo;
use files::{Files, Location};
use serde::Serialize;
use tracing::{debug, info, warn};
use wholesym::samply_symbols::object::{self, Object, ObjectSection, ObjectSegment, ObjectSymbol};
use wholesym::samply_symbols::relative_address_base;
use wholesym::samply_symbols::{LookupAddress, SymbolManager};

use crate::recording::table::{self, Column, Table};
use crate::recording::{self, JIT, KERNEL, KernelSymbols, Origin, Recording};

/// Why symbolizing failed. Files that can't be read only leave their frames
/// unnamed, with the reason in their source.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Recording(#[from] recording::Error),
    #[error("starting the runtime for symbol lookups")]
    Runtime(#[source] io::Error),
}

const NAMES: &str = "symbols.parquet";
const SOURCES: &str = "symbol_sources.parquet";
const INLINE: &str = "inline_frames.parquet";

/// Function names resolved after recording. Kept beside the recording,
/// which itself never changes; resolving again replaces these files.
#[derive(Debug, Clone, PartialEq)]
pub struct Symbols {
    /// Indexed by frame id. `None` if no name was found, and the frame's
    /// source says why.
    pub names: Vec<Option<FrameName>>,
    /// Relative function starts in the binary, indexed by frame id. For
    /// kernel code, relative to the start of the kernel's or the module's
    /// mapping.
    pub function_addresses: Vec<Option<u32>>,
    /// Indexed by frame id: the functions at the frame's address from debug
    /// info, innermost inlined call first. The last is the function the
    /// machine code belongs to. Empty without debug info.
    pub inline: Vec<Vec<InlineFrame>>,
    pub sources: Vec<Source>,
}

/// One function at an address, and where in its source the address is. For
/// a caller's frame that is the line of the call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlineFrame {
    pub function: Option<String>,
    /// As written in the debug info, usually absolute.
    pub file: Option<String>,
    pub line: Option<u32>,
    /// Where the function is declared, which stays the same wherever it
    /// was inlined, unlike `file`: code from macros or `#line` directives
    /// can sit in other files.
    pub decl_file: Option<String>,
    pub decl_line: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FrameName {
    /// From a symbol table or debug info.
    Symbol(String),
    /// Made up by wholesym from the address of code that has no symbol, such
    /// as `fun_1200` in a stripped binary. It tells functions apart but is
    /// not a name.
    Placeholder(String),
}

impl FrameName {
    pub fn symbol(&self) -> Option<&str> {
        match self {
            FrameName::Symbol(name) => Some(name),
            FrameName::Placeholder(_) => None,
        }
    }
}

/// One file that frames were resolved against, or would have been.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Source {
    pub path: String,
    pub build_id: Option<String>,
    pub status: SourceStatus,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceStatus {
    Resolved,
    /// Resolved, but the recording has no build-id to prove the file on
    /// disk is the one that ran.
    Unverified,
    MissingFile,
    /// The file on disk is not the one that ran, so its names would be wrong.
    BuildIdMismatch,
    Unsupported,
    Failed,
    /// The names could not be read while recording, the only time they
    /// could be.
    Unavailable,
}

impl SourceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            SourceStatus::Resolved => "resolved",
            SourceStatus::Unverified => "unverified",
            SourceStatus::MissingFile => "missing_file",
            SourceStatus::BuildIdMismatch => "build_id_mismatch",
            SourceStatus::Unsupported => "unsupported",
            SourceStatus::Failed => "failed",
            SourceStatus::Unavailable => "unavailable",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        Ok(match value {
            "resolved" => SourceStatus::Resolved,
            "unverified" => SourceStatus::Unverified,
            "missing_file" => SourceStatus::MissingFile,
            "build_id_mismatch" => SourceStatus::BuildIdMismatch,
            "unsupported" => SourceStatus::Unsupported,
            "failed" => SourceStatus::Failed,
            "unavailable" => SourceStatus::Unavailable,
            _ => return Err(format!("unknown symbol source status {value:?}")),
        })
    }
}

/// Path and recorded build-id of a mapped file.
type FileKey<'a> = (&'a str, Option<&'a str>);

/// Resolves the recording in `dir` against the files on this machine and
/// writes the result beside it.
pub fn symbolize(dir: &Path) -> Result<Symbols, Error> {
    let recording = Recording::read(dir)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(Error::Runtime)?;
    let symbols = runtime.block_on(resolve(&recording));
    symbols.write(dir)?;
    log_summary(&symbols);
    Ok(symbols)
}

fn log_summary(symbols: &Symbols) {
    for source in &symbols.sources {
        let path = source.path.as_str();
        let detail = source.detail.as_deref().unwrap_or_default();
        match source.status {
            SourceStatus::Resolved => debug!(path, detail, "resolved symbols"),
            SourceStatus::Unsupported => debug!(path, detail, "symbols not resolved"),
            SourceStatus::Unverified => {
                warn!(
                    path,
                    detail, "resolved symbols without a build-id to check the file"
                )
            }
            SourceStatus::MissingFile => {
                warn!(path, "the file is gone, so its frames have no names")
            }
            SourceStatus::BuildIdMismatch => {
                warn!(
                    path,
                    detail, "the file changed since recording, so its names are not used"
                )
            }
            SourceStatus::Failed => warn!(path, detail, "reading symbols failed"),
            SourceStatus::Unavailable => {
                warn!(
                    path,
                    detail, "the names were not saved while recording, so its frames have none"
                )
            }
        }
    }
    let named = symbols
        .names
        .iter()
        .flatten()
        .filter(|n| n.symbol().is_some());
    let placeholders = symbols.names.iter().flatten().count() - named.clone().count();
    info!(
        named = named.count(),
        placeholders,
        frames = symbols.names.len(),
        "resolved function names"
    );
}

async fn resolve(recording: &Recording) -> Symbols {
    let mut names = vec![None; recording.frames.len()];
    let mut function_addresses = vec![None; recording.frames.len()];
    let mut inline = vec![Vec::new(); recording.frames.len()];
    let mut sources = Vec::new();

    let mut by_file: BTreeMap<FileKey, Vec<(u32, u64)>> = BTreeMap::new();
    let mut kernel_frames = Vec::new();
    let mut jit_frames = Vec::new();
    let mut interpreted_frames = Vec::new();
    for (id, frame) in recording.frames.iter().enumerate() {
        match (frame.origin, frame.mapping, frame.file_offset) {
            (Origin::Binary, Some(mapping), Some(offset)) => {
                let mapping = &recording.mappings[mapping as usize];
                let lookup = offset.saturating_sub(u64::from(frame.return_address));
                by_file
                    .entry((&mapping.path, mapping.build_id.as_deref()))
                    .or_default()
                    .push((id as u32, lookup));
            }
            (Origin::Kernel, ..) => kernel_frames.push(id),
            (Origin::Jit, ..) => jit_frames.push(id),
            (Origin::Interpreted, ..) => interpreted_frames.push(id),
            _ => {}
        }
    }
    if !jit_frames.is_empty() {
        sources.push(resolve_jit(recording, &jit_frames, &mut names));
    }
    sources.extend(resolve_interpreted(
        recording,
        &interpreted_frames,
        &mut names,
    ));

    if !kernel_frames.is_empty() {
        sources.push(resolve_kernel(
            recording,
            &kernel_frames,
            &mut names,
            &mut function_addresses,
        ));
    }

    for ((path, build_id), frames) in by_file {
        let source = |status, detail: Option<String>| Source {
            path: path.to_owned(),
            build_id: build_id.map(str::to_owned),
            status,
            detail,
        };
        if !path.starts_with('/') {
            sources.push(source(
                SourceStatus::Unsupported,
                Some(format!("{path} is not read from memory")),
            ));
            continue;
        }
        if !Path::new(path).exists() {
            sources.push(source(SourceStatus::MissingFile, None));
            continue;
        }
        let manager = SymbolManager::with_helper(Files::default());
        let files = manager.helper();
        let snapshot = match files.read(Path::new(path)) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                sources.push(source(SourceStatus::Failed, Some(error.to_string())));
                continue;
            }
        };
        let info = match manager
            .load_binary_at_location(
                Location(path.into()),
                Path::new(path)
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned()),
                Some(path.into()),
                None,
            )
            .await
        {
            Ok(binary) => binary.library_info(),
            Err(error) => {
                sources.push(source(SourceStatus::Failed, Some(error.to_string())));
                continue;
            }
        };
        let on_disk = info
            .code_id
            .as_ref()
            .map(|id| id.to_string().to_lowercase());
        let status = match (build_id, on_disk.as_deref()) {
            (Some(recorded), Some(on_disk)) if recorded == on_disk => SourceStatus::Resolved,
            (Some(recorded), on_disk) => {
                sources.push(source(
                    SourceStatus::BuildIdMismatch,
                    Some(format!(
                        "recorded build-id {recorded}, file has {}",
                        on_disk.unwrap_or("none")
                    )),
                ));
                continue;
            }
            (None, _) => SourceStatus::Unverified,
        };
        let loaded = match Segments::read(&snapshot) {
            Ok(segments) => manager
                .load_symbol_map(&info)
                .await
                .map(|map| (segments, map))
                .map_err(|error| chain(&error)),
            Err(error) => Err(format!("parsing binary snapshot: {error}")),
        };
        let (segments, map) = match loaded {
            Ok(loaded) => loaded,
            Err(error) => {
                sources.push(source(SourceStatus::Failed, Some(error)));
                continue;
            }
        };
        let mut found = Vec::new();
        for &(frame, offset) in &frames {
            let Some(address) = segments.relative_address(offset) else {
                continue;
            };
            if let Some(info) = map.lookup(LookupAddress::Relative(address)).await {
                let debug_name = info
                    .frames
                    .as_ref()
                    .and_then(|frames| frames.last())
                    .and_then(|frame| frame.function.clone());
                found.push((
                    frame,
                    address,
                    info.symbol.address,
                    info.symbol.name,
                    debug_name,
                ));
            }
        }
        let starts: HashSet<u32> = found.iter().map(|&(_, _, start, _, _)| start).collect();
        let raw: HashMap<u32, String> = map
            .iter_symbols()
            .filter(|(start, _)| starts.contains(start))
            .map(|(start, name)| (start, name.into_owned()))
            .collect();
        let debug_path = map.debug_file_location().0.clone();
        let proper = proper_symbols(&files, Path::new(path), &snapshot, &starts, &debug_path);
        // Not needed any more, and the inline lookup below reads the same
        // debug info again.
        drop(map);
        let (debug_info, debug_problem) = match DebugInfo::load(&files, &debug_path) {
            Ok(debug_info) => (debug_info, None),
            Err(problem) => (None, Some(problem)),
        };
        if let Some(debug_info) = &debug_info {
            for &(frame, address, ..) in &found {
                inline[frame as usize] = debug_info.chain(u64::from(address) + segments.base);
            }
        }
        let mut placeholders = 0;
        for (frame, _, start, demangled, debug_name) in &found {
            // wholesym's debug name loses a leading underscore of ELF names.
            let debug_name = &inline[*frame as usize]
                .last()
                .and_then(|outer| outer.function.clone())
                .or_else(|| debug_name.clone());
            let name = match raw.get(start) {
                // wholesym strips a leading underscore from names it cannot
                // demangle, as Mach-O expects. On ELF that turns `_start` into
                // `start`, so keep the raw name.
                Some(raw) if raw.strip_prefix('_') == Some(demangled.as_str()) => raw.clone(),
                _ => demangled.clone(),
            };
            // A genuine ELF symbol may have exactly the same spelling as
            // a synthesized label. Check the verified objects, not a prefix.
            let real_symbol = raw
                .get(start)
                .is_some_and(|raw| proper.contains(&(*start, raw.clone())));
            let made_up = debug_name.is_none() && !real_symbol;
            let name = if real_symbol {
                name
            } else {
                debug_name.clone().unwrap_or(name)
            };
            function_addresses[*frame as usize] = Some(*start);
            names[*frame as usize] = Some(if made_up {
                placeholders += 1;
                FrameName::Placeholder(name)
            } else {
                FrameName::Symbol(name)
            });
        }
        let named = found.len() - placeholders;
        let mut detail = format!("named {named} of {} frames", frames.len());
        if placeholders > 0 {
            detail += &format!(", {placeholders} more with placeholder names");
        }
        if let Some(problem) = debug_problem {
            detail += &format!(", inlined calls not read: {problem}");
        }
        sources.push(source(status, Some(detail)));
    }

    Symbols {
        names,
        function_addresses,
        inline,
        sources,
    }
}

/// Names kernel frames from the kernel symbols saved while recording. Starts
/// count from the kernel's or the module's mapping, so they stay the same
/// across boots, which move the kernel.
fn resolve_kernel(
    recording: &Recording,
    frames: &[usize],
    names: &mut [Option<FrameName>],
    function_addresses: &mut [Option<u32>],
) -> Source {
    let source = |status, detail| Source {
        path: KERNEL.into(),
        build_id: None,
        status,
        detail: Some(detail),
    };
    if let KernelSymbols::Unavailable { reason } = &recording.manifest.kernel_symbols {
        return source(SourceStatus::Unavailable, reason.clone());
    }
    let mut named = 0;
    for &id in frames {
        let frame = &recording.frames[id];
        let Some(symbol) = recording.kernel_symbol(frame) else {
            continue;
        };
        names[id] = Some(FrameName::Symbol(symbol.name.clone()));
        function_addresses[id] = frame.mapping.and_then(|m| {
            let offset = symbol
                .start
                .checked_sub(recording.mappings[m as usize].start)?;
            u32::try_from(offset).ok()
        });
        named += 1;
    }
    source(
        SourceStatus::Resolved,
        format!("named {named} of {} frames", frames.len()),
    )
}

/// The names the runtimes' perf maps gave the code they compiled, which the
/// recording saved.
fn resolve_jit(recording: &Recording, frames: &[usize], names: &mut [Option<FrameName>]) -> Source {
    let mut named = 0;
    for &id in frames {
        if let Some(symbol) = recording.jit_symbol(&recording.frames[id]) {
            names[id] = Some(FrameName::Symbol(symbol.name.clone()));
            named += 1;
        }
    }
    Source {
        path: JIT.into(),
        build_id: None,
        status: SourceStatus::Resolved,
        detail: Some(format!("named {named} of {} frames", frames.len())),
    }
}

/// Names interpreted frames from the code uhr read while recording, with a
/// source for each runtime.
fn resolve_interpreted(
    recording: &Recording,
    frames: &[usize],
    names: &mut [Option<FrameName>],
) -> Vec<Source> {
    let mut counts: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for &id in frames {
        let Some(interpreted) = recording.frames[id].interpreted else {
            continue;
        };
        let code = &recording.interpreted_code[interpreted.code as usize];
        let (named, all) = counts.entry(&code.runtime).or_default();
        *all += 1;
        if let Some(name) = &code.name {
            names[id] = Some(FrameName::Symbol(name.clone()));
            *named += 1;
        }
    }
    counts
        .into_iter()
        .map(|(runtime, (named, all))| Source {
            path: format!("[{runtime}]"),
            build_id: None,
            status: if named > 0 {
                SourceStatus::Resolved
            } else {
                SourceStatus::Unavailable
            },
            detail: Some(format!("named {named} of {all} frames")),
        })
        .collect()
}

/// Only names from the binary or a matching debug artifact are evidence.
/// Rejected candidates can have coincident addresses and must not contribute.
fn proper_symbols(
    files: &Files,
    binary_path: &Path,
    binary: &[u8],
    starts: &HashSet<u32>,
    accepted_debug_path: &Path,
) -> HashSet<(u32, String)> {
    let Ok(original) = object::File::parse(binary) else {
        return HashSet::new();
    };
    let build_id = original.build_id().ok().flatten();
    let debug_link = original.gnu_debuglink().ok().flatten();
    let mut symbols = HashSet::new();
    for (path, data) in files.loaded() {
        let Ok(object) = object::File::parse(&*data) else {
            continue;
        };
        let matches_id = build_id.is_some() && object.build_id().ok().flatten() == build_id;
        let matches_link = debug_link.is_some_and(|(name, crc)| {
            path.file_name()
                .is_some_and(|p| p.as_encoded_bytes() == name)
                && crc32fast::hash(&data) == crc
        });
        if path != binary_path && path != accepted_debug_path && !matches_id && !matches_link {
            continue;
        }
        add_proper_symbols(&object, starts, &mut symbols);
        if let Some(section) = object.section_by_name(".gnu_debugdata")
            && let Ok(compressed) = section.data()
        {
            let mut bytes = Vec::new();
            if lzma_rs::xz_decompress(&mut std::io::Cursor::new(compressed), &mut bytes).is_ok()
                && let Ok(mini) = object::File::parse(bytes.as_slice())
            {
                add_proper_symbols(&mini, starts, &mut symbols);
            }
        }
    }
    symbols
}

fn add_proper_symbols(
    object: &object::File<'_>,
    starts: &HashSet<u32>,
    symbols: &mut HashSet<(u32, String)>,
) {
    let base = relative_address_base(object);
    for symbol in object.symbols().chain(object.dynamic_symbols()) {
        if !symbol.is_definition()
            || !matches!(
                symbol.kind(),
                object::SymbolKind::Text | object::SymbolKind::Label
            )
        {
            continue;
        }
        if let (Some(address), Ok(name)) = (
            symbol
                .address()
                .checked_sub(base)
                .and_then(|a| u32::try_from(a).ok()),
            symbol.name_bytes(),
        ) && starts.contains(&address)
        {
            symbols.insert((address, String::from_utf8_lossy(name).into_owned()));
        }
    }
}

/// The loadable segments of the binary that ran. Looking names up by file
/// offset goes wrong when they come from a separate debug file, whose layout
/// differs. Relative addresses are the same in both.
struct Segments {
    base: u64,
    /// File offset, file size and address of each segment.
    ranges: Vec<(u64, u64, u64)>,
}

impl Segments {
    fn read(bytes: &[u8]) -> Result<Self, object::Error> {
        let object = object::File::parse(bytes)?;
        let ranges = object
            .segments()
            .map(|segment| {
                let (offset, size) = segment.file_range();
                (offset, size, segment.address())
            })
            .collect();
        let base = relative_address_base(&object);
        Ok(Self { base, ranges })
    }

    fn relative_address(&self, file_offset: u64) -> Option<u32> {
        let &(offset, _, address) = self
            .ranges
            .iter()
            .find(|&&(offset, size, _)| offset <= file_offset && file_offset - offset < size)?;
        let svma = address.checked_add(file_offset - offset)?;
        u32::try_from(svma.checked_sub(self.base)?).ok()
    }
}

impl Symbols {
    /// `None` if the recording has not been symbolized.
    pub fn read(dir: &Path, recording: &Recording) -> Result<Option<Self>, recording::Error> {
        if !dir.join(NAMES).exists() {
            return Ok(None);
        }
        let table = Table::read(&dir.join(NAMES))?;
        let frame_ids = table.u32("frame_id")?;
        if frame_ids.len() != recording.frames.len()
            || frame_ids
                .iter()
                .enumerate()
                .any(|(i, &id)| id as usize != i)
        {
            return Err(table.invalid("must have one row per frame, in frame id order"));
        }
        let function_addresses = table.optional_u32("function_address")?;
        let functions = table.optional_string("function")?;
        let placeholders = table.optional_string("placeholder")?;
        let names = functions
            .into_iter()
            .zip(placeholders)
            .map(|names| match names {
                (Some(function), None) => Ok(Some(FrameName::Symbol(function))),
                (None, Some(placeholder)) => Ok(Some(FrameName::Placeholder(placeholder))),
                (None, None) => Ok(None),
                (Some(_), Some(_)) => {
                    Err(table.invalid("a frame has a function and a placeholder"))
                }
            })
            .collect::<Result<_, _>>()?;

        let table = Table::read(&dir.join(SOURCES))?;
        let path = table.string("path")?;
        let build_id = table.optional_string("build_id")?;
        let status = table.string("status")?;
        let detail = table.optional_string("detail")?;
        let sources = (0..table.len())
            .map(|i| {
                Ok(Source {
                    path: path[i].clone(),
                    build_id: build_id[i].clone(),
                    status: SourceStatus::parse(&status[i])
                        .map_err(|reason| table.invalid(reason))?,
                    detail: detail[i].clone(),
                })
            })
            .collect::<Result<_, recording::Error>>()?;

        let path = dir.join(INLINE);
        if !path.exists() {
            return Err(recording::Error::Invalid {
                path,
                reason: "missing: an older uhr resolved these symbols. Run `uhr symbolize` again"
                    .into(),
            });
        }
        let table = Table::read(&path)?;
        let frame_id = table.u32("frame_id")?;
        let depth = table.u32("depth")?;
        let mut function = table.optional_string("function")?;
        let mut file = table.optional_string("file")?;
        let line = table.optional_u32("line")?;
        let mut decl_file = table.optional_string("decl_file")?;
        let decl_line = table.optional_u32("decl_line")?;
        let mut inline = vec![Vec::new(); recording.frames.len()];
        for i in 0..table.len() {
            let Some(chain) = inline.get_mut(frame_id[i] as usize) else {
                return Err(table.invalid(format!("frame {} does not exist", frame_id[i])));
            };
            if depth[i] as usize != chain.len() {
                return Err(table.invalid(
                    "the rows of a frame must be together, with depths counting up from 0",
                ));
            }
            chain.push(InlineFrame {
                function: function[i].take(),
                file: file[i].take(),
                line: line[i],
                decl_file: decl_file[i].take(),
                decl_line: decl_line[i],
            });
        }
        Ok(Some(Self {
            names,
            function_addresses,
            inline,
            sources,
        }))
    }

    /// Each file is written under a temporary name and renamed, so a reader
    /// never sees a half-written file.
    fn write(&self, dir: &Path) -> Result<(), recording::Error> {
        let names_partial = dir.join(format!("{NAMES}.partial"));
        table::write(
            &names_partial,
            vec![
                Column::u32("frame_id", (0..self.names.len() as u32).collect()),
                Column::optional_u32("function_address", self.function_addresses.clone()),
                Column::optional_string(
                    "function",
                    self.names
                        .iter()
                        .map(|n| n.as_ref().and_then(FrameName::symbol))
                        .collect(),
                ),
                Column::optional_string(
                    "placeholder",
                    self.names
                        .iter()
                        .map(|n| match n {
                            Some(FrameName::Placeholder(name)) => Some(name.as_str()),
                            _ => None,
                        })
                        .collect(),
                ),
            ],
        )?;
        let sources_partial = dir.join(format!("{SOURCES}.partial"));
        let sources = &self.sources;
        table::write(
            &sources_partial,
            vec![
                Column::string("path", sources.iter().map(|s| s.path.as_str()).collect()),
                Column::optional_string(
                    "build_id",
                    sources.iter().map(|s| s.build_id.as_deref()).collect(),
                ),
                Column::string(
                    "status",
                    sources.iter().map(|s| s.status.as_str()).collect(),
                ),
                Column::optional_string(
                    "detail",
                    sources.iter().map(|s| s.detail.as_deref()).collect(),
                ),
            ],
        )?;
        let inline_partial = dir.join(format!("{INLINE}.partial"));
        let rows = || {
            self.inline
                .iter()
                .enumerate()
                .flat_map(|(frame, chain)| chain.iter().enumerate().map(move |row| (frame, row)))
        };
        table::write(
            &inline_partial,
            vec![
                Column::u32("frame_id", rows().map(|(frame, _)| frame as u32).collect()),
                Column::u32(
                    "depth",
                    rows().map(|(_, (depth, _))| depth as u32).collect(),
                ),
                Column::optional_string(
                    "function",
                    rows().map(|(_, (_, f))| f.function.as_deref()).collect(),
                ),
                Column::optional_string(
                    "file",
                    rows().map(|(_, (_, f))| f.file.as_deref()).collect(),
                ),
                Column::optional_u32("line", rows().map(|(_, (_, f))| f.line).collect()),
                Column::optional_string(
                    "decl_file",
                    rows().map(|(_, (_, f))| f.decl_file.as_deref()).collect(),
                ),
                Column::optional_u32("decl_line", rows().map(|(_, (_, f))| f.decl_line).collect()),
            ],
        )?;
        let inline = dir.join(INLINE);
        fs::rename(&inline_partial, &inline).map_err(recording::Error::io("replacing", &inline))?;
        let sources = dir.join(SOURCES);
        fs::rename(&sources_partial, &sources)
            .map_err(recording::Error::io("replacing", &sources))?;
        let names = dir.join(NAMES);
        fs::rename(&names_partial, &names).map_err(recording::Error::io("replacing", &names))?;
        Ok(())
    }
}

/// An error followed by each error that caused it.
fn chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut cause = error.source();
    while let Some(next) = cause {
        text.push_str(": ");
        text.push_str(&next.to_string());
        cause = next.source();
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recording::{
        Clock, FORMAT_VERSION, Frame, KernelSymbol, Manifest, Mapping, Platform, Target,
    };
    use std::process::Command;

    fn compile(dir: &Path, filename: &str, name: &str, value: u32) -> std::path::PathBuf {
        let source = dir.join(format!("{filename}.c"));
        fs::write(
            &source,
            format!("volatile unsigned result; void {name}(void) {{ result = {value}; }}"),
        )
        .unwrap();
        let binary = dir.join(filename);
        assert!(
            Command::new("cc")
                .args([
                    "-nostdlib",
                    "-no-pie",
                    "-Wl,--build-id",
                    &format!("-Wl,-e,{name}"),
                    "-o"
                ])
                .arg(&binary)
                .arg(source)
                .status()
                .unwrap()
                .success()
        );
        binary
    }

    fn relative_symbol(bytes: &[u8], name: &str) -> u32 {
        let object = object::File::parse(bytes).unwrap();
        let symbol = object
            .symbols()
            .find(|s| s.name().ok() == Some(name))
            .unwrap();
        (symbol.address() - relative_address_base(&object)) as u32
    }

    async fn load(
        manager: &SymbolManager<Files>,
        path: &Path,
    ) -> wholesym::samply_symbols::SymbolMap<Files> {
        let image = manager
            .load_binary_at_location(
                Location(path.into()),
                path.file_name().map(|s| s.to_string_lossy().into_owned()),
                Some(path.to_string_lossy().into_owned()),
                None,
            )
            .await
            .unwrap();
        manager
            .load_symbol_map(&image.library_info())
            .await
            .unwrap()
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn metadata_segments_and_symbols_share_the_snapshot_after_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let original = compile(dir.path(), "app", "EntryPoint", 1);
        let replacement = compile(dir.path(), "replacement", "different", 2);
        let manager = SymbolManager::with_helper(Files::default());
        let snapshot = manager.helper().read(&original).unwrap();
        let address = relative_symbol(&snapshot, "EntryPoint");
        fs::rename(replacement, &original).unwrap();
        runtime().block_on(async {
            let map = load(&manager, &original).await;
            assert_eq!(
                map.lookup(LookupAddress::Relative(address))
                    .await
                    .unwrap()
                    .symbol
                    .name,
                "EntryPoint"
            );
            assert_eq!(&*snapshot, &*manager.helper().read(&original).unwrap());
            let actual = fs::read(&original).unwrap();
            assert_ne!(
                object::File::parse(&*snapshot).unwrap().build_id().unwrap(),
                object::File::parse(actual.as_slice())
                    .unwrap()
                    .build_id()
                    .unwrap()
            );
        });
    }

    #[test]
    fn real_placeholder_spellings_have_symbol_provenance() {
        let dir = tempfile::tempdir().unwrap();
        let binary = compile(dir.path(), "app", "EntryPoint", 1);
        let files = Files::default();
        let bytes = files.read(&binary).unwrap();
        let address = relative_symbol(&bytes, "EntryPoint");
        let starts = HashSet::from([address]);
        assert!(
            proper_symbols(&files, &binary, &bytes, &starts, &binary)
                .contains(&(address, "EntryPoint".into()))
        );
        let renamed = dir.path().join("renamed");
        let label = format!("fun_{address:x}");
        assert!(
            Command::new("objcopy")
                .arg("--redefine-sym")
                .arg(format!("EntryPoint={label}"))
                .arg(&binary)
                .arg(&renamed)
                .status()
                .unwrap()
                .success()
        );
        let files = Files::default();
        let bytes = files.read(&renamed).unwrap();
        assert!(
            proper_symbols(&files, &renamed, &bytes, &starts, &renamed).contains(&(address, label))
        );
    }

    #[test]
    fn rejects_provenance_from_a_mismatched_debug_candidate() {
        let dir = tempfile::tempdir().unwrap();
        let binary = compile(dir.path(), "app.so", "EntryPoint", 1);
        compile(dir.path(), "app.so.dbg", "EntryPoint", 2);
        let address = relative_symbol(&fs::read(&binary).unwrap(), "EntryPoint");
        assert!(
            Command::new("strip")
                .arg(&binary)
                .status()
                .unwrap()
                .success()
        );
        let manager = SymbolManager::with_helper(Files::default());
        runtime().block_on(async {
            load(&manager, &binary).await;
        });
        let files = manager.helper();
        let bytes = files.read(&binary).unwrap();
        assert!(
            files
                .loaded()
                .iter()
                .any(|(p, _)| p.ends_with("app.so.dbg"))
        );
        assert!(
            !proper_symbols(&files, &binary, &bytes, &HashSet::from([address]), &binary)
                .contains(&(address, "EntryPoint".into()))
        );
    }

    #[test]
    fn keeps_accepted_debug_symbols_when_the_binary_has_no_build_id() {
        let dir = tempfile::tempdir().unwrap();
        let binary = compile(dir.path(), "app.so", "EntryPoint", 1);
        let address = relative_symbol(&fs::read(&binary).unwrap(), "EntryPoint");
        assert!(
            Command::new("objcopy")
                .arg("--remove-section=.note.gnu.build-id")
                .arg(&binary)
                .status()
                .unwrap()
                .success()
        );
        let debug = dir.path().join("app.so.dbg");
        fs::copy(&binary, &debug).unwrap();
        assert!(
            Command::new("strip")
                .arg(&binary)
                .status()
                .unwrap()
                .success()
        );
        let manager = SymbolManager::with_helper(Files::default());
        runtime().block_on(async {
            let map = load(&manager, &binary).await;
            assert_eq!(map.debug_file_location().0, debug);
            let files = manager.helper();
            let bytes = files.read(&binary).unwrap();
            assert!(
                proper_symbols(
                    &files,
                    &binary,
                    &bytes,
                    &HashSet::from([address]),
                    &map.debug_file_location().0
                )
                .contains(&(address, "EntryPoint".into()))
            );
        });
    }

    #[test]
    fn keeps_provenance_from_debug_links_and_minidebuginfo() {
        let dir = tempfile::tempdir().unwrap();
        for mini in [false, true] {
            let filename = if mini { "mini" } else { "linked" };
            let binary = compile(dir.path(), filename, "EntryPoint", 1);
            let address = relative_symbol(&fs::read(&binary).unwrap(), "EntryPoint");
            let debug = dir.path().join(format!("{filename}.debug"));
            assert!(
                Command::new("objcopy")
                    .arg("--only-keep-debug")
                    .arg(&binary)
                    .arg(&debug)
                    .status()
                    .unwrap()
                    .success()
            );
            assert!(
                Command::new("strip")
                    .arg(&binary)
                    .status()
                    .unwrap()
                    .success()
            );
            let option = if mini {
                let compressed = dir.path().join("debug.xz");
                let mut bytes = Vec::new();
                lzma_rs::xz_compress(
                    &mut std::io::Cursor::new(fs::read(&debug).unwrap()),
                    &mut bytes,
                )
                .unwrap();
                fs::write(&compressed, bytes).unwrap();
                format!("--add-section=.gnu_debugdata={}", compressed.display())
            } else {
                format!("--add-gnu-debuglink={}", debug.display())
            };
            assert!(
                Command::new("objcopy")
                    .arg(option)
                    .arg(&binary)
                    .status()
                    .unwrap()
                    .success()
            );
            let manager = SymbolManager::with_helper(Files::default());
            runtime().block_on(async {
                let map = load(&manager, &binary).await;
                assert_eq!(
                    map.lookup(LookupAddress::Relative(address))
                        .await
                        .unwrap()
                        .symbol
                        .name,
                    "EntryPoint"
                );
            });
            let files = manager.helper();
            let bytes = files.read(&binary).unwrap();
            assert!(
                proper_symbols(&files, &binary, &bytes, &HashSet::from([address]), &binary)
                    .contains(&(address, "EntryPoint".into())),
                "{filename}"
            );
        }
    }

    fn recording(frames: usize) -> Recording {
        Recording {
            manifest: Manifest {
                format_version: FORMAT_VERSION,
                platform: Platform {
                    os: "linux".into(),
                    arch: "x86_64".into(),
                },
                target: Target {
                    command: vec!["app".into()],
                    launched: true,
                    runtime_support: Some(Vec::new()),
                    exit: None,
                },
                clock: Clock::Monotonic,
                start_ns: None,
                end_ns: None,
                streams: Vec::new(),
                missing_signals: Vec::new(),
                kernel_symbols: KernelSymbols::Saved,
            },
            threads: Vec::new(),
            thread_names: Vec::new(),
            mappings: Vec::new(),
            frames: vec![
                Frame {
                    origin: Origin::Unresolved,
                    address: 0x10,
                    mapping: None,
                    file_offset: None,
                    return_address: false,
                    interpreted: None,
                };
                frames
            ],
            stacks: Vec::new(),
            samples: Vec::new(),
            page_faults: Vec::new(),
            off_cpu: Vec::new(),
            kernel_symbols: Vec::new(),
            jit_symbols: Vec::new(),
            interpreted_code: Vec::new(),
            syscall_calls: Vec::new(),
            memory: Vec::new(),
            regions: Vec::new(),
            region_memory: Vec::new(),
        }
    }

    fn symbols_with_inline_calls() -> Symbols {
        let frame = |function: &str, line| InlineFrame {
            function: Some(function.into()),
            file: Some("/src/app.c".into()),
            line: Some(line),
            decl_file: Some("/src/app.c".into()),
            decl_line: Some(line - 2),
        };
        Symbols {
            names: vec![
                Some(FrameName::Symbol("from_a".into())),
                None,
                Some(FrameName::Symbol("main".into())),
            ],
            function_addresses: vec![Some(0x10), None, Some(0x40)],
            inline: vec![
                vec![frame("mix", 37), frame("from_a", 47)],
                Vec::new(),
                vec![frame("main", 66)],
            ],
            sources: Vec::new(),
        }
    }

    #[test]
    fn names_kernel_frames_from_the_saved_symbols() {
        let mut recording = recording(4);
        let frame = |address, mapping, return_address| Frame {
            origin: Origin::Kernel,
            address,
            mapping,
            file_offset: None,
            return_address,
            interpreted: None,
        };
        recording.frames = vec![
            frame(0xffffffff81001020, Some(0), false),
            // Returns to the end of vfs_read, so the call is in it.
            frame(0xffffffff81001400, Some(0), true),
            frame(0xffffffffc0009010, None, false),
            frame(0xffffffff81003000, Some(0), false),
        ];
        recording.mappings = vec![Mapping {
            pid: None,
            start: 0xffffffff81000000,
            end: 0xffffffff82000000,
            file_offset: 0,
            path: KERNEL.into(),
            build_id: Some("61e84c0b".into()),
            time_ns: None,
        }];
        let symbol = |start, end, name: &str, module: Option<&str>| KernelSymbol {
            start,
            end,
            name: name.into(),
            module: module.map(str::to_owned),
        };
        recording.kernel_symbols = vec![
            symbol(0xffffffff81001010, 0xffffffff81001400, "vfs_read", None),
            symbol(
                0xffffffffc0009000,
                0xffffffffc000a000,
                "bpf_prog_6d_x",
                Some("bpf"),
            ),
        ];
        let mut names = vec![None; 4];
        let mut addresses = vec![None; 4];
        let source = resolve_kernel(&recording, &[0, 1, 2, 3], &mut names, &mut addresses);
        let name = |n: &str| Some(FrameName::Symbol(n.into()));
        assert_eq!(
            names,
            [
                name("vfs_read"),
                name("vfs_read"),
                name("bpf_prog_6d_x"),
                None
            ]
        );
        assert_eq!(addresses, [Some(0x1010), Some(0x1010), None, None]);
        assert_eq!(source.status, SourceStatus::Resolved);
        assert_eq!(source.detail.as_deref(), Some("named 3 of 4 frames"));

        recording.manifest.kernel_symbols = KernelSymbols::Unavailable {
            reason: "hidden".into(),
        };
        let mut names = vec![None; 4];
        let source = resolve_kernel(&recording, &[0, 1, 2, 3], &mut names, &mut addresses);
        assert_eq!(names, [None, None, None, None]);
        assert_eq!(
            (source.status, source.detail.as_deref()),
            (SourceStatus::Unavailable, Some("hidden"))
        );
    }

    #[test]
    fn reads_back_the_inline_calls_it_wrote() {
        let dir = tempfile::tempdir().unwrap();
        let symbols = symbols_with_inline_calls();
        symbols.write(dir.path()).unwrap();
        let read = Symbols::read(dir.path(), &recording(3)).unwrap();
        assert_eq!(read, Some(symbols));
    }

    #[test]
    fn symbols_from_before_inline_calls_must_be_resolved_again() {
        let dir = tempfile::tempdir().unwrap();
        symbols_with_inline_calls().write(dir.path()).unwrap();
        fs::remove_file(dir.path().join(INLINE)).unwrap();
        match Symbols::read(dir.path(), &recording(3)) {
            Err(recording::Error::Invalid { reason, .. }) => {
                assert!(reason.contains("uhr symbolize"), "{reason}");
            }
            other => panic!("{other:?}"),
        }
    }
}
