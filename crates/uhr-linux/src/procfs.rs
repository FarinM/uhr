//! Fields of the kernel's files about processes, in `/proc`. They hold
//! names and paths as the bytes they are, which need not be UTF-8: the
//! kernel cuts a thread's name at 15 bytes, within a character too, and a
//! process can set any name. So the files are read as bytes, and only the
//! fields wanted are decoded.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

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
}
