use std::collections::HashMap;
use std::fmt;
use std::fs::{File, Metadata};
use std::io;
use std::ops::Deref;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use wholesym::samply_symbols::object::{self, Object};
use wholesym::samply_symbols::{
    CandidatePathInfo, CodeId, ElfBuildId, FileAndPathHelper, FileAndPathHelperResult,
    FileLocation, LibraryInfo, OptionallySendFuture,
};

#[derive(Clone)]
pub(super) struct Snapshot(Arc<SnapshotData>);

struct SnapshotData {
    data: memmap2::Mmap,
    _file: File,
}

impl Deref for Snapshot {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0.data
    }
}

/// The logical paths still locate debug links and split DWARF, but every
/// read of a file sees the same private copy for this resolution attempt.
#[derive(Default)]
pub(super) struct Files {
    snapshots: Mutex<HashMap<PathBuf, Snapshot>>,
}

/// What a write to a file changes. Unix also changes the inode's change
/// time, which a write that sets the old modification time back can't hide.
#[cfg(unix)]
fn version(m: &Metadata) -> impl PartialEq {
    (
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}

#[cfg(not(unix))]
fn version(m: &Metadata) -> impl PartialEq {
    (m.len(), m.modified().ok())
}

/// Windows updates the modification time only once a writer closes the
/// file, so a writer must not have it open: without write sharing, the open
/// fails while one does, and no writer can open it during the copy.
#[cfg(windows)]
fn open(path: &Path) -> io::Result<File> {
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_DELETE: u32 = 0x4;
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .open(path)
}

#[cfg(not(windows))]
fn open(path: &Path) -> io::Result<File> {
    File::open(path)
}

impl Files {
    pub fn read(&self, path: &Path) -> io::Result<Snapshot> {
        let mut snapshots = self.snapshots.lock().unwrap();
        if let Some(data) = snapshots.get(path) {
            return Ok(data.clone());
        }
        let mut source = open(path)?;
        let before = source.metadata()?;
        let mut file = tempfile::tempfile()?;
        io::copy(&mut source, &mut file)?;
        let after = source.metadata()?;
        if version(&before) != version(&after) {
            return Err(io::Error::other(format!(
                "{} changed while being copied",
                path.display()
            )));
        }
        // Only this object owns the temporary file; nobody writes it after
        // this point, so the mapping cannot change or be truncated.
        let data = unsafe { memmap2::Mmap::map(&file)? };
        let snapshot = Snapshot(Arc::new(SnapshotData { data, _file: file }));
        snapshots.insert(path.to_owned(), snapshot.clone());
        Ok(snapshot)
    }

    pub fn loaded(&self) -> Vec<(PathBuf, Snapshot)> {
        self.snapshots
            .lock()
            .unwrap()
            .iter()
            .map(|(path, data)| (path.clone(), data.clone()))
            .collect()
    }
}

#[derive(Clone, Debug)]
pub(super) struct Location(pub PathBuf);

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.display().fmt(f)
    }
}

impl FileLocation for Location {
    fn location_for_dyld_subcache(&self, _suffix: &str) -> Option<Self> {
        None
    }
    fn location_for_external_object_file(&self, path: &str) -> Option<Self> {
        Some(Self(path.into()))
    }
    fn location_for_pdb_from_binary(&self, _path: &str) -> Option<Self> {
        None
    }
    fn location_for_source_file(&self, path: &str) -> Option<Self> {
        Some(Self(path.into()))
    }
    fn location_for_breakpad_symindex(&self) -> Option<Self> {
        None
    }
    fn location_for_dwo(&self, comp_dir: &str, path: &str) -> Option<Self> {
        let path = Path::new(comp_dir).join(path);
        Some(Self(if path.is_absolute() {
            path
        } else {
            self.0.parent()?.join(path)
        }))
    }
    fn location_for_dwp(&self) -> Option<Self> {
        let mut path = self.0.as_os_str().to_owned();
        path.push(".dwp");
        Some(Self(path.into()))
    }
}

impl FileAndPathHelper for Files {
    type F = Snapshot;
    type FL = Location;

    fn get_candidate_paths_for_debug_file(
        &self,
        info: &LibraryInfo,
    ) -> FileAndPathHelperResult<Vec<CandidatePathInfo<Location>>> {
        let mut paths = Vec::new();
        if let Some(path) = info.path.as_deref().filter(|p| p.ends_with(".so")) {
            paths.push(PathBuf::from(format!("{path}.dbg")));
        }
        if let Some(CodeId::ElfBuildId(id)) = &info.code_id {
            let id = id.to_string();
            if id.len() > 2 {
                paths.push(PathBuf::from(format!(
                    "/usr/lib/debug/.build-id/{}/{}.debug",
                    &id[..2],
                    &id[2..]
                )));
            }
        }
        if let Some(path) = &info.path {
            paths.push(path.into());
        }
        // Samply's DebugId uses only part of an ELF build id. Check the full
        // id against the same snapshot that it will parse.
        if let Some(CodeId::ElfBuildId(expected)) = &info.code_id {
            paths.retain(|path| {
                let Ok(data) = self.read(path) else {
                    return false;
                };
                object::File::parse(&*data).ok().is_some_and(|object| {
                    object.build_id().ok().flatten() == Some(expected.0.as_slice())
                })
            });
        }
        Ok(paths
            .into_iter()
            .map(|p| CandidatePathInfo::SingleFile(Location(p)))
            .collect())
    }

    fn get_candidate_paths_for_binary(
        &self,
        info: &LibraryInfo,
    ) -> FileAndPathHelperResult<Vec<CandidatePathInfo<Location>>> {
        Ok(info
            .path
            .iter()
            .map(|p| CandidatePathInfo::SingleFile(Location(p.into())))
            .collect())
    }

    fn get_dyld_shared_cache_paths(
        &self,
        _arch: Option<&str>,
    ) -> FileAndPathHelperResult<Vec<Location>> {
        Ok(Vec::new())
    }

    fn get_candidate_paths_for_gnu_debug_link_dest(
        &self,
        original: &Location,
        name: &str,
    ) -> FileAndPathHelperResult<Vec<Location>> {
        let parent = original
            .0
            .parent()
            .ok_or("binary has no parent directory")?;
        let mut paths = vec![parent.join(name), parent.join(".debug").join(name)];
        if let Ok(relative) = parent.strip_prefix("/") {
            paths.push(Path::new("/usr/lib/debug").join(relative).join(name));
        }
        Ok(paths.into_iter().map(Location).collect())
    }

    fn get_candidate_paths_for_supplementary_debug_file(
        &self,
        original: &Location,
        path: &str,
        build_id: &ElfBuildId,
    ) -> FileAndPathHelperResult<Vec<Location>> {
        let mut paths = vec![Location(
            original.0.parent().unwrap_or(Path::new("/")).join(path),
        )];
        let id = build_id.to_string();
        if id.len() > 2 {
            paths.push(Location(PathBuf::from(format!(
                "/usr/lib/debug/.build-id/{}/{}.debug",
                &id[..2],
                &id[2..]
            ))));
        }
        Ok(paths)
    }

    fn load_file(
        &self,
        location: Location,
    ) -> std::pin::Pin<Box<dyn OptionallySendFuture<Output = FileAndPathHelperResult<Snapshot>> + '_>>
    {
        Box::pin(async move { Ok(self.read(&location.0)?) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_dwarf_paths_are_relative_to_the_binary() {
        let binary = Location("/build/app".into());
        assert_eq!(
            binary.location_for_dwo(".", "app.dwo").unwrap().0,
            PathBuf::from("/build/./app.dwo")
        );
        assert_eq!(
            binary.location_for_dwo("/sources", "app.dwo").unwrap().0,
            PathBuf::from("/sources/app.dwo")
        );
        assert_eq!(
            binary
                .location_for_dwo("/sources", "/debug/app.dwo")
                .unwrap()
                .0,
            PathBuf::from("/debug/app.dwo")
        );
    }
}
