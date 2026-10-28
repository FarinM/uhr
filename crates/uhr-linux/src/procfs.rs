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
}
