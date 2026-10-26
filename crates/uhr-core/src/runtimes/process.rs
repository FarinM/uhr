//! A running process as runtimes read it. Each platform says how to read
//! its memory and files; what a runtime keeps where is the runtime's.

use std::io;

use super::Error;
use crate::recording::Mapping;

pub trait Memory {
    /// Reads `into.len()` bytes at `address`.
    fn read(&self, address: u64, into: &mut [u8]) -> io::Result<()>;
}

pub trait Process {
    fn pid(&self) -> u32;
    /// Its mappings of files, by start.
    fn mappings(&self) -> &[Mapping];
    /// What the file of a mapping holds: the one mapped, even if its path
    /// now holds another.
    fn file(&self, mapping: &Mapping) -> io::Result<Vec<u8>>;
    fn memory(&self) -> &dyn Memory;
}

/// Reads one plain number at `address`, as `what`.
pub(super) fn read<const N: usize>(
    memory: &dyn Memory,
    what: &'static str,
    address: u64,
) -> Result<[u8; N], Error> {
    let mut bytes = [0; N];
    memory
        .read(address, &mut bytes)
        .map_err(|source| Error::Read {
            what,
            address,
            source,
        })?;
    Ok(bytes)
}

pub(super) fn u64_at(memory: &dyn Memory, what: &'static str, address: u64) -> Result<u64, Error> {
    read(memory, what, address).map(u64::from_ne_bytes)
}

pub(super) fn u32_at(memory: &dyn Memory, what: &'static str, address: u64) -> Result<u32, Error> {
    read(memory, what, address).map(u32::from_ne_bytes)
}
