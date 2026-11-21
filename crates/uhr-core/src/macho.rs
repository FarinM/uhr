//! What uhr reads of Mach-O files, both to name frames and to find the
//! runtimes a process runs.

use std::ops::Range;

use wholesym::samply_symbols::demangle_any;
use wholesym::samply_symbols::object::read::macho::{FatArch, LoadCommandVariant};
use wholesym::samply_symbols::object::{
    self, Object, ObjectSection, ObjectSegment, ObjectSymbol, SectionFlags, macho,
};

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

/// A Mach-O name as C and C++ write it: without the underscore Mach-O
/// starts names with, and demangled.
pub(crate) fn demangle(name: &str) -> String {
    let name = name.strip_prefix('_').unwrap_or(name);
    // Mangled C++ and Rust names keep the underscore their scheme starts
    // with.
    if name.starts_with("_Z") || name.starts_with("_R") {
        demangle_any(name)
    } else {
        name.to_owned()
    }
}

/// The functions of a Mach-O file in its sections of code other than
/// `__text`, by address from `base`: where each starts and ends, and its
/// name, sorted. Each ends where the next symbol of its section starts, or
/// where the section ends.
pub(crate) fn other_code(file: &object::File, base: u64) -> Vec<(u32, u32, String)> {
    let code = macho::S_ATTR_PURE_INSTRUCTIONS | macho::S_ATTR_SOME_INSTRUCTIONS;
    let sections: Vec<_> = file
        .sections()
        .filter(|section| {
            matches!(section.flags(), SectionFlags::MachO { flags } if flags & code != 0)
                && section.name() != Ok("__text")
        })
        .filter_map(|section| {
            let start = u32::try_from(section.address().checked_sub(base)?).ok()?;
            let end = start.checked_add(u32::try_from(section.size()).ok()?)?;
            Some((section.index(), start..end))
        })
        .collect();
    let mut starts: Vec<(u32, u32, String)> = file
        .symbols()
        .filter(|symbol| symbol.is_definition())
        .filter_map(|symbol| {
            let index = symbol.section_index()?;
            let (_, range) = sections.iter().find(|(i, _)| *i == index)?;
            let start = u32::try_from(symbol.address().checked_sub(base)?).ok()?;
            let name = symbol.name().ok().filter(|name| !name.is_empty())?;
            Some((start, range.end, demangle(name)))
        })
        .collect();
    starts.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.2.cmp(&b.2)));
    starts.dedup_by_key(|(start, _, _)| *start);
    let next: Vec<u32> = starts.iter().skip(1).map(|(start, _, _)| *start).collect();
    for (i, function) in starts.iter_mut().enumerate() {
        if let Some(&next) = next.get(i) {
            function.1 = function.1.min(next);
        }
    }
    starts
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

#[cfg(all(test, target_os = "macos"))]
mod files {
    use std::fs;
    use std::process::Command;

    use super::*;

    #[test]
    fn finds_functions_in_code_outside_text() {
        let dir = std::env::temp_dir().join(format!("uhr-macho-code-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let source = dir.join("interp.c");
        // Two functions in a section of their own, as JavaScriptCore's
        // interpreter, and one in __text.
        fs::write(
            &source,
            "__attribute__((section(\"__TEXT,__interp,regular,pure_instructions\")))\n\
             int first(int x) { return x * 3; }\n\
             __attribute__((section(\"__TEXT,__interp,regular,pure_instructions\")))\n\
             int second(int x) { return first(x) + 1; }\n\
             int elsewhere(int x) { return second(x) - 1; }\n",
        )
        .unwrap();
        let library = dir.join("libinterp.dylib");
        let built = Command::new("cc")
            .args(["-shared", "-O1", "-o"])
            .arg(&library)
            .arg(&source)
            .status()
            .unwrap();
        assert!(built.success(), "cc failed");
        let data = fs::read(&library).unwrap();
        let file = object::File::parse(&*data).unwrap();
        let functions = other_code(&file, 0);
        let names: Vec<&str> = functions.iter().map(|(_, _, name)| name.as_str()).collect();
        assert_eq!(names, ["first", "second"], "{functions:?}");
        let section = file.section_by_name("__interp").unwrap();
        let end = (section.address() + section.size()) as u32;
        assert_eq!(functions[0].1, functions[1].0);
        assert_eq!(functions[1].1, end);
        fs::remove_dir_all(&dir).unwrap();
    }
}
