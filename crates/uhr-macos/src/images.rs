//! The images dyld loaded into a process, from the list it keeps there for
//! debuggers: `dyld_all_image_infos`, whose layout is in
//! `<mach-o/dyld_images.h>`.

use std::io;

use uhr_core::runtimes::Memory;

use crate::macho::{self, Header};

/// An image as loaded in a process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Image {
    pub path: String,
    /// Where its Mach-O header is.
    pub address: u64,
    pub header: Header,
}

impl Image {
    /// How far it was moved from where it was linked to load.
    pub(crate) fn slide(&self) -> Option<u64> {
        let text = self.header.segment("__TEXT")?;
        Some(self.address.wrapping_sub(text.vmaddr))
    }

    /// Where its executable segments are, slid, with the offset of each
    /// from the start of its `__TEXT` segment. That is where the code is in
    /// the image's file too, as `__TEXT` starts it, and the same for an
    /// image of the dyld shared cache, whose segments are not where its
    /// file, if it has one, has them.
    pub(crate) fn code(&self) -> Vec<Code> {
        let (Some(slide), Some(text)) = (self.slide(), self.header.segment("__TEXT")) else {
            return Vec::new();
        };
        self.header
            .segments
            .iter()
            .filter(|s| s.executable && s.vmsize > 0)
            .map(|s| Code {
                start: s.vmaddr.wrapping_add(slide),
                end: s.vmaddr.wrapping_add(slide) + s.vmsize,
                offset: s.vmaddr.wrapping_sub(text.vmaddr),
            })
            .collect()
    }

    /// Its UUID, as uhr keeps build ids: lowercase hex.
    pub(crate) fn build_id(&self) -> Option<String> {
        self.header
            .uuid
            .map(|uuid| uuid.iter().map(|b| format!("{b:02x}")).collect())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Code {
    pub start: u64,
    pub end: u64,
    /// From the start of the image's `__TEXT` segment.
    pub offset: u64,
}

/// Where in `dyld_all_image_infos` its fields are, in a 64-bit process.
mod field {
    pub const VERSION: u64 = 0;
    pub const COUNT: u64 = 4;
    pub const ARRAY: u64 = 8;
    pub const DYLD_ADDRESS: u64 = 32;
    pub const TIMESTAMP: u64 = 184;
    pub const DYLD_PATH: u64 = 192;
    pub const END: usize = 200;
}

/// `infoArrayChangeTimestamp` and `dyldPath` came in version 15, with macOS
/// 10.12.
const MIN_VERSION: u32 = 15;

/// Each entry of `infoArray`: where the image is, its path, and a time.
const ENTRY_SIZE: usize = 24;

/// A path is read up to this long, as `PATH_MAX`.
const MAX_PATH: usize = 1024;

/// What a reading of the list found: where each image is, and its path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Listed {
    /// Bumped by dyld at each change to the list.
    pub timestamp: u64,
    pub images: Vec<(u64, String)>,
}

/// dyld's list in one process.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ImageInfos {
    address: u64,
}

impl ImageInfos {
    /// The list at `address`, as `task_info(TASK_DYLD_INFO)` gives it.
    pub(crate) fn at(memory: &dyn Memory, address: u64) -> io::Result<Self> {
        let mut version = [0; 4];
        memory.read(address + field::VERSION, &mut version)?;
        let version = u32::from_ne_bytes(version);
        if version < MIN_VERSION {
            return Err(io::Error::other(format!(
                "dyld keeps its list of images in version {version}, older than {MIN_VERSION}"
            )));
        }
        Ok(Self { address })
    }

    pub(crate) fn timestamp(&self, memory: &dyn Memory) -> io::Result<u64> {
        read_u64(memory, self.address + field::TIMESTAMP)
    }

    /// The images listed, dyld's own among them. `None` while dyld changes
    /// the list, which it marks by taking the array away.
    pub(crate) fn list(&self, memory: &dyn Memory) -> io::Result<Option<Listed>> {
        let mut infos = [0; field::END];
        memory.read(self.address, &mut infos)?;
        let u32_at = |at: u64| u32::from_ne_bytes(infos[at as usize..][..4].try_into().unwrap());
        let u64_at = |at: u64| u64::from_ne_bytes(infos[at as usize..][..8].try_into().unwrap());
        let (count, array) = (u32_at(field::COUNT), u64_at(field::ARRAY));
        if array == 0 {
            return Ok(None);
        }
        let mut entries = vec![0; count as usize * ENTRY_SIZE];
        memory.read(array, &mut entries)?;
        let mut images = Vec::with_capacity(count as usize + 1);
        for entry in entries.chunks_exact(ENTRY_SIZE) {
            let address = u64::from_ne_bytes(entry[..8].try_into().unwrap());
            let path = u64::from_ne_bytes(entry[8..16].try_into().unwrap());
            if address == 0 {
                continue;
            }
            images.push((address, read_string(memory, path, MAX_PATH)?));
        }
        let dyld = u64_at(field::DYLD_ADDRESS);
        if dyld != 0 && images.iter().all(|&(address, _)| address != dyld) {
            let path = match u64_at(field::DYLD_PATH) {
                0 => "/usr/lib/dyld".to_owned(),
                path => read_string(memory, path, MAX_PATH)?,
            };
            images.push((dyld, path));
        }
        // The array can change as it is read, which a stamp that moved
        // shows.
        let timestamp = u64_at(field::TIMESTAMP);
        if self.timestamp(memory)? != timestamp {
            return Ok(None);
        }
        Ok(Some(Listed { timestamp, images }))
    }
}

/// Reads the header and load commands of the image at `address`.
pub(crate) fn read_image(memory: &dyn Memory, address: u64, path: String) -> io::Result<Image> {
    let mut start = [0; macho::HEADER_SIZE];
    memory.read(address, &mut start)?;
    let end = macho::commands_end(&start).map_err(io::Error::other)?;
    let mut data = vec![0; end];
    memory.read(address, &mut data)?;
    let header = Header::parse(&data).map_err(io::Error::other)?;
    Ok(Image {
        path,
        address,
        header,
    })
}

fn read_u64(memory: &dyn Memory, address: u64) -> io::Result<u64> {
    let mut bytes = [0; 8];
    memory.read(address, &mut bytes)?;
    Ok(u64::from_ne_bytes(bytes))
}

/// A NUL-terminated string, read in chunks that end at 4 KiB boundaries, so
/// one at the end of a mapping can be read whatever the page size.
pub(crate) fn read_string(memory: &dyn Memory, address: u64, max: usize) -> io::Result<String> {
    const CHUNK: u64 = 4096;
    let mut bytes = Vec::new();
    let mut at = address;
    while bytes.len() < max {
        let len = (CHUNK - at % CHUNK).min((max - bytes.len()) as u64) as usize;
        let start = bytes.len();
        bytes.resize(start + len, 0);
        memory.read(at, &mut bytes[start..])?;
        if let Some(end) = bytes[start..].iter().position(|&b| b == 0) {
            bytes.truncate(start + end);
            break;
        }
        at += len as u64;
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use super::*;

    /// A process's memory as pages of 4 KiB, of which only those written
    /// can be read.
    #[derive(Default)]
    struct Fake {
        pages: RefCell<BTreeMap<u64, Vec<u8>>>,
    }

    impl Fake {
        fn write(&self, address: u64, bytes: &[u8]) {
            let mut pages = self.pages.borrow_mut();
            for (i, &byte) in bytes.iter().enumerate() {
                let at = address + i as u64;
                pages.entry(at / 4096).or_insert_with(|| vec![0; 4096])[(at % 4096) as usize] =
                    byte;
            }
        }
    }

    impl Memory for Fake {
        fn read(&self, address: u64, into: &mut [u8]) -> io::Result<()> {
            let pages = self.pages.borrow();
            for (i, byte) in into.iter_mut().enumerate() {
                let at = address + i as u64;
                let page = pages
                    .get(&(at / 4096))
                    .ok_or_else(|| io::Error::other(format!("{at:#x} is not mapped")))?;
                *byte = page[(at % 4096) as usize];
            }
            Ok(())
        }
    }

    /// A 64-bit arm64 Mach-O header with a `__TEXT` segment of one
    /// `__text` section, and a UUID.
    fn macho(vmaddr: u64) -> Vec<u8> {
        let mut segment = Vec::new();
        segment.extend(0x19u32.to_le_bytes());
        segment.extend((72u32 + 80).to_le_bytes());
        segment.extend(*b"__TEXT\0\0\0\0\0\0\0\0\0\0");
        segment.extend(vmaddr.to_le_bytes());
        segment.extend(0x4000u64.to_le_bytes());
        segment.extend(0u64.to_le_bytes());
        segment.extend(0x4000u64.to_le_bytes());
        segment.extend(5u32.to_le_bytes());
        segment.extend(5u32.to_le_bytes());
        segment.extend(1u32.to_le_bytes());
        segment.extend(0u32.to_le_bytes());
        segment.extend(*b"__text\0\0\0\0\0\0\0\0\0\0");
        segment.extend(*b"__TEXT\0\0\0\0\0\0\0\0\0\0");
        segment.extend((vmaddr + 0x400).to_le_bytes());
        segment.extend(0x100u64.to_le_bytes());
        segment.extend([0; 32]);
        let mut uuid = Vec::new();
        uuid.extend(0x1bu32.to_le_bytes());
        uuid.extend(24u32.to_le_bytes());
        uuid.extend([0xab; 16]);
        let mut header = Vec::new();
        header.extend(0xfeed_facfu32.to_le_bytes());
        header.extend(0x0100_000cu32.to_le_bytes());
        header.extend(0u32.to_le_bytes());
        header.extend(2u32.to_le_bytes());
        header.extend(2u32.to_le_bytes());
        header.extend(((segment.len() + uuid.len()) as u32).to_le_bytes());
        header.extend(0u32.to_le_bytes());
        header.extend(0u32.to_le_bytes());
        header.extend(segment);
        header.extend(uuid);
        header
    }

    fn infos(fake: &Fake, at: u64, count: u32, array: u64, timestamp: u64) {
        let mut infos = vec![0; field::END];
        infos[..4].copy_from_slice(&17u32.to_ne_bytes());
        infos[4..8].copy_from_slice(&count.to_ne_bytes());
        infos[8..16].copy_from_slice(&array.to_ne_bytes());
        infos[32..40].copy_from_slice(&0x1_8000_0000u64.to_ne_bytes());
        infos[184..192].copy_from_slice(&timestamp.to_ne_bytes());
        infos[192..200].copy_from_slice(&0x9000u64.to_ne_bytes());
        fake.write(at, &infos);
    }

    #[test]
    fn lists_the_images_and_dyld() {
        let fake = Fake::default();
        infos(&fake, 0x1000, 2, 0x2000, 7);
        let mut array = Vec::new();
        for (address, path) in [(0x1_0000_4000u64, 0x3000u64), (0x1_9000_0000, 0x3100)] {
            array.extend(address.to_ne_bytes());
            array.extend(path.to_ne_bytes());
            array.extend(0u64.to_ne_bytes());
        }
        fake.write(0x2000, &array);
        fake.write(0x3000, b"/tmp/prog\0");
        // Ends at the end of the only page there.
        fake.write(0x3100, b"/usr/lib/libSystem.B.dylib\0");
        fake.write(0x9000, b"/usr/lib/dyld\0");
        let list = ImageInfos::at(&fake, 0x1000).unwrap();
        assert_eq!(list.timestamp(&fake).unwrap(), 7);
        assert_eq!(
            list.list(&fake).unwrap(),
            Some(Listed {
                timestamp: 7,
                images: vec![
                    (0x1_0000_4000, "/tmp/prog".into()),
                    (0x1_9000_0000, "/usr/lib/libSystem.B.dylib".into()),
                    (0x1_8000_0000, "/usr/lib/dyld".into()),
                ],
            })
        );
    }

    #[test]
    fn a_list_being_changed_is_read_again_later() {
        let fake = Fake::default();
        infos(&fake, 0x1000, 2, 0, 7);
        let list = ImageInfos::at(&fake, 0x1000).unwrap();
        assert_eq!(list.list(&fake).unwrap(), None);
    }

    #[test]
    fn reads_an_image_and_where_its_code_is() {
        let fake = Fake::default();
        fake.write(0x1_0000_4000, &macho(0x1_0000_0000));
        let image = read_image(&fake, 0x1_0000_4000, "/tmp/prog".into()).unwrap();
        assert_eq!(image.slide(), Some(0x4000));
        assert_eq!(image.build_id().unwrap(), "ab".repeat(16));
        assert_eq!(
            image.code(),
            [Code {
                start: 0x1_0000_4000,
                end: 0x1_0000_8000,
                offset: 0,
            }]
        );
        let text = image.header.section("__TEXT", "__text").unwrap();
        assert_eq!((text.addr, text.size), (0x1_0000_0400, 0x100));
    }

    #[test]
    fn an_old_dyld_is_refused() {
        let fake = Fake::default();
        fake.write(0x1000, &[0; field::END]);
        fake.write(0x1000, &13u32.to_ne_bytes());
        assert!(ImageInfos::at(&fake, 0x1000).is_err());
    }
}
