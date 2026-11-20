//! What uhr reads of Mach-O files, both to name frames and to find the
//! runtimes a process runs.

use std::ops::Range;

use wholesym::samply_symbols::object::read::macho::{FatArch, LoadCommandVariant};
use wholesym::samply_symbols::object::{self, Object, ObjectSegment, macho};

/// Where in `data` the object with `uuid` is: for a universal Mach-O file,
/// the slice with that UUID, and else all of it.
pub(crate) fn slice(data: &[u8], uuid: Option<[u8; 16]>) -> Range<usize> {
    let all = 0..data.len();
    let Some(uuid) = uuid else {
        return all;
    };
    let arches: Vec<(u64, u64)> = match object::FileKind::parse(data) {
        Ok(object::FileKind::MachOFat32) => object::read::macho::MachOFatFile32::parse(data)
            .map(|fat| fat.arches().iter().map(|arch| arch.file_range()).collect()),
        Ok(object::FileKind::MachOFat64) => object::read::macho::MachOFatFile64::parse(data)
            .map(|fat| fat.arches().iter().map(|arch| arch.file_range()).collect()),
        _ => return all,
    }
    .unwrap_or_default();
    arches
        .into_iter()
        .map(|(offset, size)| offset as usize..(offset + size) as usize)
        .find(|range: &Range<usize>| {
            data.get(range.clone())
                .and_then(|slice| object::File::parse(slice).ok())
                .is_some_and(|object: object::File| object.mach_uuid().ok().flatten() == Some(uuid))
        })
        .unwrap_or(all)
}

/// A Mach-O UUID, as uhr records build ids: lowercase hex.
pub(crate) fn uuid(build_id: &str) -> Option<[u8; 16]> {
    if build_id.len() != 32 {
        return None;
    }
    let mut uuid = [0; 16];
    for (i, byte) in uuid.iter_mut().enumerate() {
        *byte = u8::from_str_radix(build_id.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(uuid)
}

/// The starts of a Mach-O file's functions, from `LC_FUNCTION_STARTS`, as
/// addresses in it. `data` is the file, or its slice of a universal one.
pub(crate) fn function_starts(file: &object::File, data: &[u8]) -> Vec<u64> {
    let object::File::MachO64(file) = file else {
        return Vec::new();
    };
    let endian = file.endian();
    let Some(text) = file
        .segments()
        .find(|segment| segment.name() == Ok(Some("__TEXT")))
    else {
        return Vec::new();
    };
    let Ok(mut commands) = file.macho_load_commands() else {
        return Vec::new();
    };
    while let Ok(Some(command)) = commands.next() {
        if let Ok(LoadCommandVariant::LinkeditData(command)) = command.variant()
            && command.cmd.get(endian) == macho::LC_FUNCTION_STARTS
        {
            let (offset, size) = (command.dataoff.get(endian), command.datasize.get(endian));
            return data
                .get(offset as usize..offset as usize + size as usize)
                .map_or_else(Vec::new, |bytes| decode_starts(text.address(), bytes));
        }
    }
    Vec::new()
}

/// The addresses `LC_FUNCTION_STARTS` lists: ULEB128 deltas, the first from
/// the start of `__TEXT`, ending at a 0.
pub(crate) fn decode_starts(text: u64, bytes: &[u8]) -> Vec<u64> {
    let mut addresses = Vec::new();
    let (mut address, mut delta, mut shift) = (text, 0u64, 0);
    for &byte in bytes {
        if shift >= u64::BITS {
            break;
        }
        delta |= u64::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 != 0 {
            continue;
        }
        if delta == 0 {
            break;
        }
        address += delta;
        addresses.push(address);
        (delta, shift) = (0, 0);
    }
    addresses
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_function_starts_as_deltas() {
        // 0x10 on from __TEXT, then 0x90 on, which takes two bytes.
        assert_eq!(
            decode_starts(0x1000, &[0x10, 0x90, 0x01, 0x00, 0x05]),
            [0x1010, 0x10a0]
        );
        assert_eq!(decode_starts(0x1000, &[]), Vec::<u64>::new());
    }
}
