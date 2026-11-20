//! What uhr reads of a Mach-O image: its segments and sections, from the
//! load commands at its start, and how it was signed.

use wholesym::samply_symbols::object::macho::{self, LC_CODE_SIGNATURE, MachHeader64};
use wholesym::samply_symbols::object::read::macho::{FatArch, MachHeader, MachOFatFile32, Segment};
use wholesym::samply_symbols::object::{Endianness, FileKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Header {
    pub uuid: Option<[u8; 16]>,
    pub segments: Vec<SegmentInfo>,
    pub sections: Vec<SectionInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SegmentInfo {
    pub name: String,
    /// Where the image was linked to load it. The image's slide moves it.
    pub vmaddr: u64,
    pub vmsize: u64,
    /// From the start of the file, or of its architecture's slice in a
    /// universal file. In the dyld shared cache, from the start of the
    /// cache file that holds it.
    pub fileoff: u64,
    pub executable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SectionInfo {
    pub segment: String,
    pub name: String,
    pub addr: u64,
    pub size: u64,
}

/// The size of a 64-bit Mach-O header.
pub(crate) const HEADER_SIZE: usize = size_of::<MachHeader64<Endianness>>();

/// The size of the header and load commands of an image whose first
/// `HEADER_SIZE` bytes are `start`.
pub(crate) fn commands_end(start: &[u8]) -> Result<usize, String> {
    let header = MachHeader64::<Endianness>::parse(start, 0).map_err(|e| e.to_string())?;
    let endian = header.endian().map_err(|e| e.to_string())?;
    Ok(HEADER_SIZE + header.sizeofcmds(endian) as usize)
}

impl Header {
    /// Reads the load commands of a 64-bit image, from `data`, which holds
    /// at least its header and load commands.
    pub(crate) fn parse(data: &[u8]) -> Result<Self, String> {
        let error = |e: wholesym::samply_symbols::object::Error| e.to_string();
        let header = MachHeader64::<Endianness>::parse(data, 0).map_err(error)?;
        let endian = header.endian().map_err(error)?;
        let mut commands = header.load_commands(endian, data, 0).map_err(error)?;
        let mut parsed = Self {
            uuid: None,
            segments: Vec::new(),
            sections: Vec::new(),
        };
        while let Some(command) = commands.next().map_err(error)? {
            if let Some(uuid) = command.uuid().map_err(error)? {
                parsed.uuid = Some(uuid.uuid);
            } else if let Some((segment, section_data)) = command.segment_64().map_err(error)? {
                let name = text(segment.name());
                parsed.segments.push(SegmentInfo {
                    name: name.clone(),
                    vmaddr: segment.vmaddr.get(endian),
                    vmsize: segment.vmsize.get(endian),
                    fileoff: segment.fileoff.get(endian),
                    executable: segment.initprot.get(endian) & macho::VM_PROT_EXECUTE != 0,
                });
                for section in segment.sections(endian, section_data).map_err(error)? {
                    parsed.sections.push(SectionInfo {
                        segment: name.clone(),
                        name: text(&section.sectname),
                        addr: section.addr.get(endian),
                        size: section.size.get(endian),
                    });
                }
            }
        }
        Ok(parsed)
    }

    pub(crate) fn segment(&self, name: &str) -> Option<&SegmentInfo> {
        self.segments.iter().find(|s| s.name == name)
    }

    pub(crate) fn section(&self, segment: &str, name: &str) -> Option<&SectionInfo> {
        self.sections
            .iter()
            .find(|s| s.segment == segment && s.name == name)
    }
}

fn text(name: &[u8]) -> String {
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    String::from_utf8_lossy(&name[..end]).into_owned()
}

/// What a program's signature says about the variables that make dyld load
/// a library into it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Signing {
    /// Built for the hardened runtime, which ignores the variables unless
    /// its entitlements allow them.
    pub hardened: bool,
    pub allows_dyld_variables: bool,
    /// Whether it loads libraries that no one with its team signed, as
    /// uhr's.
    pub loads_any_library: bool,
    /// Marked restricted, as by a `__RESTRICT` segment, which ignores them
    /// too.
    pub restricted: bool,
}

impl Signing {
    /// Whether dyld would load a library named in DYLD_INSERT_LIBRARIES.
    pub(crate) fn takes_inserted_libraries(&self) -> bool {
        !self.restricted
            && (!self.hardened || (self.allows_dyld_variables && self.loads_any_library))
    }
}

const CS_RESTRICT: u32 = 0x800;
const CS_RUNTIME: u32 = 0x1_0000;
const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xfade_7171;

/// How the slice of `file` for this machine's architecture was signed.
/// `None` if `file` is not a Mach-O program, or has no such slice.
pub(crate) fn signing(file: &[u8]) -> Option<Signing> {
    let slice = match FileKind::parse(file).ok()? {
        FileKind::MachO64 => file,
        FileKind::MachOFat32 => {
            let fat = MachOFatFile32::parse(file).ok()?;
            let arch = fat
                .arches()
                .iter()
                .find(|arch| arch.cputype() == HOST_CPU_TYPE)?;
            arch.data(file).ok()?
        }
        _ => return None,
    };
    let header = MachHeader64::<Endianness>::parse(slice, 0).ok()?;
    let endian = header.endian().ok()?;
    if header.cputype(endian) != HOST_CPU_TYPE {
        return None;
    }
    let mut signing = Signing::default();
    let mut commands = header.load_commands(endian, slice, 0).ok()?;
    while let Some(command) = commands.next().ok()? {
        if let Ok(Some((segment, _))) = command.segment_64() {
            signing.restricted |= segment.name() == b"__RESTRICT";
        }
        if command.cmd() == LC_CODE_SIGNATURE {
            let linkedit: &macho::LinkeditDataCommand<Endianness> = command.data().ok()?;
            let start = linkedit.dataoff.get(endian) as usize;
            let end = start + linkedit.datasize.get(endian) as usize;
            read_signature(slice.get(start..end)?, &mut signing);
        }
    }
    Some(signing)
}

#[cfg(target_arch = "aarch64")]
const HOST_CPU_TYPE: u32 = macho::CPU_TYPE_ARM64;
#[cfg(not(target_arch = "aarch64"))]
const HOST_CPU_TYPE: u32 = macho::CPU_TYPE_X86_64;

/// Code signatures are big-endian, whatever the code.
fn read_signature(blob: &[u8], signing: &mut Signing) {
    let u32_at = |data: &[u8], at: usize| {
        data.get(at..at + 4)
            .map(|b| u32::from_be_bytes(b.try_into().expect("four bytes")))
    };
    if u32_at(blob, 0) != Some(CSMAGIC_EMBEDDED_SIGNATURE) {
        return;
    }
    let count = u32_at(blob, 8).unwrap_or(0) as usize;
    for i in 0..count {
        let Some(offset) = u32_at(blob, 12 + i * 8 + 4) else {
            return;
        };
        let offset = offset as usize;
        let Some(sub) = blob.get(offset..) else {
            continue;
        };
        match u32_at(sub, 0) {
            Some(CSMAGIC_CODEDIRECTORY) => {
                let flags = u32_at(sub, 12).unwrap_or(0);
                signing.hardened |= flags & CS_RUNTIME != 0;
                signing.restricted |= flags & CS_RESTRICT != 0;
            }
            Some(CSMAGIC_EMBEDDED_ENTITLEMENTS) => {
                let len = u32_at(sub, 4).unwrap_or(0) as usize;
                let plist = sub.get(8..len.max(8)).unwrap_or_default();
                let has = |key: &str| {
                    plist
                        .windows(key.len())
                        .any(|window| window == key.as_bytes())
                };
                signing.allows_dyld_variables |=
                    has("com.apple.security.cs.allow-dyld-environment-variables");
                signing.loads_any_library |=
                    has("com.apple.security.cs.disable-library-validation");
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(entries: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(CSMAGIC_EMBEDDED_SIGNATURE.to_be_bytes());
        out.extend(0u32.to_be_bytes());
        out.extend((entries.len() as u32).to_be_bytes());
        let mut offset = 12 + entries.len() * 8;
        for (kind, data) in entries {
            out.extend(kind.to_be_bytes());
            out.extend((offset as u32).to_be_bytes());
            offset += data.len();
        }
        for (_, data) in entries {
            out.extend(data);
        }
        out
    }

    fn code_directory(flags: u32) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend(CSMAGIC_CODEDIRECTORY.to_be_bytes());
        data.extend(44u32.to_be_bytes());
        data.extend(0x2_0400u32.to_be_bytes());
        data.extend(flags.to_be_bytes());
        data.resize(44, 0);
        data
    }

    fn entitlements(keys: &[&str]) -> Vec<u8> {
        let plist: String = keys
            .iter()
            .map(|k| format!("<key>{k}</key><true/>"))
            .collect();
        let mut data = Vec::new();
        data.extend(CSMAGIC_EMBEDDED_ENTITLEMENTS.to_be_bytes());
        data.extend(((plist.len() + 8) as u32).to_be_bytes());
        data.extend(plist.as_bytes());
        data
    }

    #[test]
    fn an_ad_hoc_signature_takes_inserted_libraries() {
        let mut signing = Signing::default();
        read_signature(&blob(&[(0, code_directory(0x2_0002))]), &mut signing);
        assert!(!signing.hardened);
        assert!(signing.takes_inserted_libraries());
    }

    #[test]
    fn the_hardened_runtime_needs_both_entitlements() {
        let hardened = code_directory(CS_RUNTIME);
        let mut signing = Signing::default();
        read_signature(&blob(&[(0, hardened.clone())]), &mut signing);
        assert!(signing.hardened && !signing.takes_inserted_libraries());

        let mut signing = Signing::default();
        let one = entitlements(&["com.apple.security.cs.allow-dyld-environment-variables"]);
        read_signature(&blob(&[(0, hardened.clone()), (5, one)]), &mut signing);
        assert!(!signing.takes_inserted_libraries());

        let mut signing = Signing::default();
        let both = entitlements(&[
            "com.apple.security.cs.allow-dyld-environment-variables",
            "com.apple.security.cs.disable-library-validation",
        ]);
        read_signature(&blob(&[(0, hardened), (5, both)]), &mut signing);
        assert!(signing.takes_inserted_libraries());
    }

    #[test]
    fn a_restricted_program_ignores_them() {
        let mut signing = Signing::default();
        read_signature(&blob(&[(0, code_directory(CS_RESTRICT))]), &mut signing);
        assert!(!signing.takes_inserted_libraries());
    }
}
