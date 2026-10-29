//! Fields of the kernel's files about processes, in `/proc`. They hold
//! names and paths as the bytes they are, which need not be UTF-8: the
//! kernel cuts a thread's name at 15 bytes, within a character too, and a
//! process can set any name. So the files are read as bytes, and only the
//! fields wanted are decoded.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use uhr_core::recording::RegionKind;

/// Reads the file at `path` into `bytes`, which keeps its buffer across
/// reads.
pub(crate) fn read(path: impl AsRef<Path>, bytes: &mut Vec<u8>) -> io::Result<()> {
    bytes.clear();
    File::open(path)?.read_to_end(bytes)?;
    Ok(())
}

/// The value of the field `name` in a `status` file, as of `Tgid`, without
/// the spaces around it.
pub(crate) fn status_field<'a>(status: &'a [u8], name: &str) -> Option<&'a str> {
    status.split(|&b| b == b'\n').find_map(|line| {
        let value = line.strip_prefix(name.as_bytes())?.strip_prefix(b":")?;
        Some(std::str::from_utf8(value).ok()?.trim())
    })
}

/// What uhr reads of a process's `stat` file.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Stat {
    pub(crate) parent: u32,
    /// When it started, in clock ticks since boot.
    pub(crate) start_ticks: u64,
}

pub(crate) fn stat(stat: &[u8]) -> Option<Stat> {
    // The name, in parentheses, can hold any byte, `)` too. Its state, then
    // its parent, and 18 fields later its start come after it.
    let close = stat.iter().rposition(|&b| b == b')')?;
    let mut fields = std::str::from_utf8(&stat[close + 1..])
        .ok()?
        .split_ascii_whitespace();
    let parent = fields.nth(1)?.parse().ok()?;
    let start_ticks = fields.nth(17)?.parse().ok()?;
    Some(Stat {
        parent,
        start_ticks,
    })
}

/// A line of a process's `maps`: a region of its memory.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct MapsLine {
    pub(crate) start: u64,
    /// Exclusive.
    pub(crate) end: u64,
    /// As in `r-xp`: whether it can be read, written and run, and `p` for
    /// private or `s` for shared.
    pub(crate) permissions: String,
    pub(crate) file_offset: u64,
    /// The file mapped, or the kernel's name for the region, as `[heap]`.
    /// `None` for memory that maps no file. What is not UTF-8 in a path
    /// keeps a replacement.
    pub(crate) path: Option<String>,
}

/// The lines of a process's `maps`.
pub(crate) fn maps(maps: &[u8]) -> impl Iterator<Item = MapsLine> + '_ {
    maps.split(|&b| b == b'\n').filter_map(maps_line)
}

/// `start-end perms offset dev inode`, then the path after spaces, which
/// can hold spaces of its own.
fn maps_line(line: &[u8]) -> Option<MapsLine> {
    let mut rest = line;
    let mut fields: [&[u8]; 5] = [&[]; 5];
    for field in &mut fields {
        rest = rest.trim_ascii_start();
        let end = rest.iter().position(|&b| b == b' ').unwrap_or(rest.len());
        (*field, rest) = rest.split_at(end);
    }
    let text = |bytes| std::str::from_utf8(bytes).ok();
    let hex = |bytes| u64::from_str_radix(text(bytes)?, 16).ok();
    let (start, end) = text(fields[0])?.split_once('-')?;
    let path = rest.trim_ascii_start();
    Some(MapsLine {
        start: u64::from_str_radix(start, 16).ok()?,
        end: u64::from_str_radix(end, 16).ok()?,
        permissions: text(fields[1])?.to_owned(),
        file_offset: hex(fields[2])?,
        path: (!path.is_empty()).then(|| String::from_utf8_lossy(path).into_owned()),
    })
}

/// What `smaps` says of a region: its line as `maps` has it, and how much
/// of it is resident, and in swap, in bytes.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SmapsRegion {
    pub(crate) line: MapsLine,
    pub(crate) rss: u64,
    pub(crate) swap: u64,
}

/// The regions of a process's `smaps`: each line as in `maps`, followed by
/// lines of its counts, as `Rss:  1234 kB`.
pub(crate) fn smaps(smaps: &[u8]) -> Vec<SmapsRegion> {
    let kb = |line: &[u8], name: &[u8]| {
        let value = line.strip_prefix(name)?.strip_suffix(b" kB")?;
        std::str::from_utf8(value).ok()?.trim().parse::<u64>().ok()
    };
    let mut regions: Vec<SmapsRegion> = Vec::new();
    for line in smaps.split(|&b| b == b'\n') {
        if let Some(region) = regions.last_mut() {
            if let Some(rss) = kb(line, b"Rss:") {
                region.rss = rss * 1024;
                continue;
            }
            if let Some(swap) = kb(line, b"Swap:") {
                region.swap = swap * 1024;
                continue;
            }
        }
        // A count is no line of `maps`, which starts with an address range.
        if let Some(line) = maps_line(line) {
            regions.push(SmapsRegion {
                line,
                rss: 0,
                swap: 0,
            });
        }
    }
    regions
}

/// The name a process gave memory of its own that maps no file, from its
/// path in `maps`, as `[anon:name]`. Without a number that ends it, as the
/// id of the thread whose stack glibc names, so that memory used alike has
/// one name. `None` for memory it gave none.
pub(crate) fn memory_name(path: Option<&str>) -> Option<String> {
    let name = path?.strip_prefix("[anon:")?.strip_suffix(']')?;
    let numbered = name
        .trim_end_matches(|c: char| c.is_ascii_digit())
        .trim_end()
        .strip_suffix(':')
        .filter(|_| name.ends_with(|c: char| c.is_ascii_digit()));
    Some(format!("[anon:{}]", numbered.unwrap_or(name)))
}

/// What a region of memory is, from its permissions and its path in
/// `maps`, `None` for memory that maps no file and has no name.
pub(crate) fn region_kind(permissions: &str, path: Option<&str>) -> RegionKind {
    let shared = permissions.ends_with('s');
    let code = permissions.as_bytes().get(2) == Some(&b'x');
    let anonymous = || match (shared, code) {
        (true, _) => RegionKind::Shared,
        (false, true) => RegionKind::AnonymousCode,
        (false, false) => RegionKind::Anonymous,
    };
    let Some(path) = path else {
        return anonymous();
    };
    match path {
        "[heap]" => RegionKind::Heap,
        "[stack]" => RegionKind::Stack,
        // As a process names it with PR_SET_VMA_ANON_NAME.
        _ if path.starts_with("[anon:") => anonymous(),
        _ if path.starts_with("[anon_shmem:") => RegionKind::Shared,
        // The kernel's own, as [vdso], [vvar] and [vsyscall].
        _ if path.starts_with('[') => RegionKind::Kernel,
        // Memory in huge pages that maps no file, as MAP_HUGETLB gives.
        _ if path.starts_with("/anon_hugepage") => anonymous(),
        // Shared memory that is no file of the program's.
        _ if shared
            && ["/dev/zero", "/SYSV", "/memfd:", "/dev/shm/"]
                .iter()
                .any(|prefix| path.starts_with(prefix)) =>
        {
            RegionKind::Shared
        }
        _ if code => RegionKind::Code,
        _ => RegionKind::File,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A name the kernel cut within its last character, and holding `)`.
    const NAME: &[u8] = b"a) \xc3\xa9\xc3\xa9\xc3";

    #[test]
    fn finds_a_status_field_whatever_the_name() {
        let status = [
            b"Name:\t".as_slice(),
            NAME,
            b"\nTgid:\t 12\nVmRSS:\t   4096 kB\n",
        ]
        .concat();
        assert_eq!(status_field(&status, "Tgid"), Some("12"));
        assert_eq!(status_field(&status, "VmRSS"), Some("4096 kB"));
        assert_eq!(status_field(&status, "VmSwap"), None);
    }

    #[test]
    fn finds_the_parent_and_start_after_any_name() {
        let file = [
            b"12 (".as_slice(),
            NAME,
            b") S 7 12 12 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 5555 1000\n",
        ]
        .concat();
        assert_eq!(
            stat(&file),
            Some(Stat {
                parent: 7,
                start_ticks: 5555,
            })
        );
    }

    #[test]
    fn reads_each_region_of_maps_with_its_path() {
        let file = b"7f1c2a000000-7f1c2a1c3000 r-xp 00028000 08:01 393  /opt/my  app/lib\xc3.so\n\
                     55d0e9a00000-55d0e9a21000 rw-p 00000000 00:00 0                          [heap]\n\
                     7ffd1000-7ffd2000 rw-p 00000000 00:00 0 \n";
        let lines: Vec<MapsLine> = maps(file).collect();
        assert_eq!(
            lines[0],
            MapsLine {
                start: 0x7f1c2a000000,
                end: 0x7f1c2a1c3000,
                permissions: "r-xp".into(),
                file_offset: 0x28000,
                path: Some("/opt/my  app/lib\u{fffd}.so".into()),
            }
        );
        assert_eq!(lines[1].path.as_deref(), Some("[heap]"));
        assert_eq!(lines[2].path, None);
        assert_eq!(lines.len(), 3);
    }

    #[test]
    fn reads_how_much_of_each_region_is_resident() {
        let file = b"55d0e9a00000-55d0e9a21000 rw-p 00000000 00:00 0      [heap]\n\
                     Size:                132 kB\n\
                     Rss:                  84 kB\n\
                     SwapPss:               4 kB\n\
                     Swap:                  8 kB\n\
                     VmFlags: rd wr mr mw me ac sd\n\
                     7ffd1000-7ffd2000 rw-p 00000000 00:00 0 \n\
                     Rss:                   4 kB\n";
        let regions = smaps(file);
        let counts: Vec<_> = regions
            .iter()
            .map(|r| (r.line.path.as_deref(), r.rss, r.swap))
            .collect();
        assert_eq!(
            counts,
            [(Some("[heap]"), 84 << 10, 8 << 10), (None, 4 << 10, 0)]
        );
    }

    #[test]
    fn reads_the_name_a_process_gave_its_memory_without_a_number() {
        let cases = [
            (Some("[anon: glibc: malloc]"), Some("[anon: glibc: malloc]")),
            (
                Some("[anon: glibc: pthread stack: 2130147]"),
                Some("[anon: glibc: pthread stack]"),
            ),
            (
                Some("[anon:stack_and_tls:22379]"),
                Some("[anon:stack_and_tls]"),
            ),
            (Some("[anon:v8]"), Some("[anon:v8]")),
            (Some("[anon:ends:]"), Some("[anon:ends:]")),
            (Some("[anon_shmem:queue]"), None),
            (Some("[heap]"), None),
            (Some("/usr/lib/libc.so.6"), None),
            (None, None),
        ];
        for (path, expected) in cases {
            assert_eq!(memory_name(path).as_deref(), expected, "{path:?}");
        }
    }

    #[test]
    fn tells_what_each_region_is_from_how_it_was_mapped() {
        let cases = [
            ("rw-p", Some("[heap]"), RegionKind::Heap),
            ("rw-p", Some("[stack]"), RegionKind::Stack),
            ("rw-p", None, RegionKind::Anonymous),
            ("rw-p", Some("[anon:glibc malloc]"), RegionKind::Anonymous),
            ("r-xp", None, RegionKind::AnonymousCode),
            ("rw-s", None, RegionKind::Shared),
            ("rw-s", Some("/dev/zero (deleted)"), RegionKind::Shared),
            ("rw-s", Some("/memfd:wayland (deleted)"), RegionKind::Shared),
            (
                "rw-p",
                Some("/anon_hugepage (deleted)"),
                RegionKind::Anonymous,
            ),
            ("rw-s", Some("/anon_hugepage (deleted)"), RegionKind::Shared),
            ("rw-s", Some("/data/table.db"), RegionKind::File),
            ("r-xp", Some("/usr/lib/libc.so.6"), RegionKind::Code),
            ("r--p", Some("/usr/lib/libc.so.6"), RegionKind::File),
            ("r-xp", Some("[vdso]"), RegionKind::Kernel),
        ];
        for (permissions, path, expected) in cases {
            assert_eq!(
                region_kind(permissions, path),
                expected,
                "{permissions} {path:?}"
            );
        }
    }
}
