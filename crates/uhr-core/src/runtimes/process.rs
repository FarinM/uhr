//! A running process as runtimes read it. Each platform says how to read
//! its memory and files; what a runtime keeps where is the runtime's.

use std::collections::HashMap;
use std::io;
use std::ops::Range;

use wholesym::samply_symbols::object::{self, Object, ObjectSegment, ObjectSymbol};

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

/// Where the symbols `wanted` of a mapping's file are in the process: from
/// its symbol table, or its dynamic one if it has none.
pub(super) fn symbols(
    process: &dyn Process,
    mapping: &Mapping,
    wanted: impl Fn(&str) -> bool,
) -> Result<HashMap<String, Range<u64>>, Error> {
    let file_error = |source| Error::File {
        path: mapping.path.clone(),
        source,
    };
    let bytes = process.file(mapping).map_err(file_error)?;
    let file = object::File::parse(&*bytes)
        .map_err(|e| file_error(io::Error::new(io::ErrorKind::InvalidData, e)))?;
    let bias = bias(&file, mapping)
        .ok_or_else(|| Error::Invalid(format!("{} is not mapped as code", mapping.path)))?;
    let mut found = HashMap::new();
    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        let Ok(name) = symbol.name() else {
            continue;
        };
        if symbol.is_definition() && wanted(name) {
            let start = symbol.address().wrapping_add(bias);
            found
                .entry(name.to_owned())
                .or_insert(start..start + symbol.size());
        }
    }
    Ok(found)
}

/// What to add to an address in the file to get where the process has it.
fn bias(file: &object::File, mapping: &Mapping) -> Option<u64> {
    const PAGE: u64 = 4096;
    file.segments().find_map(|segment| {
        let (offset, size) = segment.file_range();
        let inside =
            offset / PAGE * PAGE <= mapping.file_offset && mapping.file_offset < offset + size;
        inside.then(|| {
            let address = segment
                .address()
                .wrapping_add(mapping.file_offset)
                .wrapping_sub(offset);
            mapping.start.wrapping_sub(address)
        })
    })
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

pub(super) fn bytes_at(
    memory: &dyn Memory,
    what: &'static str,
    address: u64,
    len: usize,
) -> Result<Vec<u8>, Error> {
    let mut bytes = vec![0; len];
    memory
        .read(address, &mut bytes)
        .map_err(|source| Error::Read {
            what,
            address,
            source,
        })?;
    Ok(bytes)
}
