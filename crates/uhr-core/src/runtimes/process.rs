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
    /// The separate file of debug info of the file whose build id is
    /// `build_id`, where the system keeps one.
    fn debug_file(&self, _build_id: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn memory(&self) -> &dyn Memory;
}

/// Where the symbols `wanted` of a mapping's file are in the process: from
/// its symbol table, or its dynamic one if it has none, and from its
/// separate debug info where the system keeps that, as for the functions
/// of a stripped library only that names.
pub(super) fn symbols(
    process: &dyn Process,
    mapping: &Mapping,
    wanted: impl Fn(&str) -> bool,
) -> Result<HashMap<String, Range<u64>>, Error> {
    let bytes = read_file(process, mapping)?;
    let file = parse(&bytes, mapping)?;
    let bias = bias(&file, mapping)
        .ok_or_else(|| Error::Invalid(format!("{} is not mapped as code", mapping.path)))?;
    let mut found = HashMap::new();
    let mut add = |file: &object::File| {
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
    };
    add(&file);
    let debug = file
        .build_id()
        .ok()
        .flatten()
        .and_then(|id| process.debug_file(id));
    if let Some(debug) = debug
        && let Ok(debug) = object::File::parse(&*debug)
    {
        add(&debug);
    }
    Ok(found)
}

fn read_file(process: &dyn Process, mapping: &Mapping) -> Result<Vec<u8>, Error> {
    process.file(mapping).map_err(|source| Error::File {
        path: mapping.path.clone(),
        source,
    })
}

fn parse<'a>(bytes: &'a [u8], mapping: &Mapping) -> Result<object::File<'a>, Error> {
    object::File::parse(bytes).map_err(|e| Error::File {
        path: mapping.path.clone(),
        source: io::Error::new(io::ErrorKind::InvalidData, e),
    })
}

/// The most modules with thread-locals a process has, past which the
/// dynamic linker has written no index of one.
const MAX_MODULES: u64 = 1 << 16;

/// The pointers to follow from a thread's thread pointer to its thread-local
/// `symbol` of a mapping's file, as glibc finds those of a library: the
/// dynamic linker writes where the variable is where the file's relocation
/// of it says. `None` until it has.
///
/// A relocation of the module's index has the dynamic linker write the
/// index it gave the module, by which the thread finds its block of the
/// module's thread-locals, in a table the thread pointer points to. One of
/// a TLS descriptor has it write a function that finds the variable, and
/// its argument: for a block the thread was given at its start, the
/// variable's offset from the thread pointer, else the module's index and
/// the variable's offset in its block.
pub(super) fn thread_local(
    process: &dyn Process,
    mapping: &Mapping,
    symbol: &str,
) -> Result<Option<Vec<i32>>, Error> {
    let bytes = read_file(process, mapping)?;
    let file = parse(&bytes, mapping)?;
    let bias = bias(&file, mapping)
        .ok_or_else(|| Error::Invalid(format!("{} is not mapped as code", mapping.path)))?;
    let missing = || Error::Invalid(format!("{} has no thread-local {symbol}", mapping.path));
    let architecture = file.architecture();
    // Where glibc's thread control block keeps the table, and the
    // relocations of a module's index and of a descriptor.
    let (table, module_index, descriptor) = match architecture {
        object::Architecture::X86_64 => (
            8,
            object::elf::R_X86_64_DTPMOD64,
            object::elf::R_X86_64_TLSDESC,
        ),
        object::Architecture::Aarch64 => (
            0,
            object::elf::R_AARCH64_TLS_DTPMOD,
            object::elf::R_AARCH64_TLSDESC,
        ),
        other => {
            return Err(Error::Invalid(format!(
                "uhr can't find thread-locals on {other:?}"
            )));
        }
    };
    let (index, variable) = file
        .dynamic_symbols()
        .find(|s| s.name() == Ok(symbol) && s.kind() == object::SymbolKind::Tls)
        .map(|s| (s.index(), s.address()))
        .ok_or_else(missing)?;
    let (slot, kind) = file
        .dynamic_relocations()
        .into_iter()
        .flatten()
        .find_map(|(offset, relocation)| {
            let object::RelocationFlags::Elf { r_type } = relocation.flags() else {
                return None;
            };
            (relocation.target() == object::RelocationTarget::Symbol(index)
                && (r_type == module_index || r_type == descriptor))
                .then_some((offset.wrapping_add(bias), r_type))
        })
        .ok_or_else(missing)?;
    let memory = process.memory();
    let too_far = |offset: u64| Error::Invalid(format!("{symbol} is {offset:#x} in"));
    if kind == module_index {
        let module = u64_at(memory, "a module's index", slot)?;
        return in_block(table, module, variable).map_err(too_far);
    }
    let function = u64_at(memory, "a TLS descriptor", slot)?;
    let argument = u64_at(memory, "a TLS descriptor", slot + 8)?;
    if function == 0 {
        return Ok(None);
    }
    if returns_its_argument(memory, architecture, function) {
        let offset = i32::try_from(argument as i64).map_err(|_| too_far(argument))?;
        return Ok(Some(vec![offset]));
    }
    let module = u64_at(memory, "a TLS descriptor's module", argument)?;
    let offset = u64_at(memory, "a TLS descriptor's offset", argument + 8)?;
    in_block(table, module, offset).map_err(too_far)
}

/// The path to the variable at `offset` in the block of module `module`,
/// or the offset, too far to follow. The dynamic linker gives modules
/// indexes from 1, so 0 is one it has not written yet.
fn in_block(table: i32, module: u64, offset: u64) -> Result<Option<Vec<i32>>, u64> {
    if !(1..MAX_MODULES).contains(&module) {
        return Ok(None);
    }
    // Each entry of the table is a pointer and what to free.
    let entry = (module * 16) as i32;
    let offset = i32::try_from(offset).map_err(|_| offset)?;
    Ok(Some(vec![table, entry, offset]))
}

/// Whether the function a TLS descriptor holds is glibc's for a block the
/// thread was given at its start, which returns the descriptor's argument.
/// The dynamic linker keeps no symbols, so it is known by its code.
fn returns_its_argument(
    memory: &dyn Memory,
    architecture: object::Architecture,
    function: u64,
) -> bool {
    let Ok(code) = bytes_at(memory, "a TLS descriptor's function", function, 12) else {
        return false;
    };
    match architecture {
        // An optional `endbr64`, `mov rax, [rax + 8]`, `ret`.
        object::Architecture::X86_64 => {
            let code = code
                .strip_prefix(&[0xf3, 0x0f, 0x1e, 0xfa])
                .unwrap_or(&code);
            code.starts_with(&[0x48, 0x8b, 0x40, 0x08, 0xc3])
        }
        // `bti c`, or a `nop` in its place where glibc is built without
        // BTI, then `ldr x0, [x0, #8]`, `ret`.
        object::Architecture::Aarch64 => {
            let words: Vec<u32> = code
                .chunks_exact(4)
                .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
                .collect();
            let words = match words.first() {
                Some(0xd503_245f | 0xd503_201f) => &words[1..],
                _ => &words[..],
            };
            words.starts_with(&[0xf940_0400, 0xd65f_03c0])
        }
        _ => false,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    struct Code(Vec<u8>);

    impl Memory for Code {
        fn read(&self, address: u64, into: &mut [u8]) -> io::Result<()> {
            let code = self.0.get(address as usize..address as usize + into.len());
            into.copy_from_slice(code.ok_or(io::ErrorKind::InvalidInput)?);
            Ok(())
        }
    }

    #[test]
    fn knows_the_function_of_a_block_given_at_the_start() {
        let arm = |words: &[u32]| {
            let mut code: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
            code.resize(16, 0);
            returns_its_argument(&Code(code), object::Architecture::Aarch64, 0)
        };
        // As Ubuntu 24.04's glibc for arm64 has it, without BTI.
        assert!(arm(&[0xd503_201f, 0xf940_0400, 0xd65f_03c0]));
        assert!(arm(&[0xd503_245f, 0xf940_0400, 0xd65f_03c0]));
        assert!(!arm(&[0xf81f_0fe1, 0xf940_0400, 0xd53b_d041]));
        let mut code = vec![0xf3, 0x0f, 0x1e, 0xfa, 0x48, 0x8b, 0x40, 0x08, 0xc3];
        code.resize(16, 0xcc);
        assert!(returns_its_argument(
            &Code(code),
            object::Architecture::X86_64,
            0
        ));
    }

    #[test]
    fn waits_for_the_dynamic_linker() {
        assert_eq!(in_block(8, 0, 16), Ok(None));
        assert_eq!(in_block(8, 2, 16), Ok(Some(vec![8, 32, 16])));
        assert_eq!(in_block(8, 2, 1 << 40), Err(1 << 40));
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod glibc {
    use std::ffi::{CString, c_char, c_int, c_void};
    use std::fs::{self, File};
    use std::os::unix::fs::FileExt;
    use std::path::Path;
    use std::process::Command;

    use super::*;

    unsafe extern "C" {
        fn dlopen(file: *const c_char, mode: c_int) -> *mut c_void;
        fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
    }

    /// This process, as uhr reads another.
    struct Itself {
        mappings: Vec<Mapping>,
        memory: File,
    }

    impl Memory for Itself {
        fn read(&self, address: u64, into: &mut [u8]) -> io::Result<()> {
            self.memory.read_exact_at(into, address)
        }
    }

    impl Process for Itself {
        fn pid(&self) -> u32 {
            std::process::id()
        }
        fn mappings(&self) -> &[Mapping] {
            &self.mappings
        }
        fn memory(&self) -> &dyn Memory {
            self
        }
        fn file(&self, mapping: &Mapping) -> io::Result<Vec<u8>> {
            fs::read(&mapping.path)
        }
    }

    fn itself() -> Itself {
        let maps = fs::read_to_string("/proc/self/maps").unwrap();
        let mappings = maps
            .lines()
            .filter_map(|line| {
                let fields: Vec<&str> = line.split_whitespace().collect();
                let (start, end) = fields[0].split_once('-')?;
                Some(Mapping {
                    pid: Some(std::process::id()),
                    start: u64::from_str_radix(start, 16).ok()?,
                    end: u64::from_str_radix(end, 16).ok()?,
                    file_offset: u64::from_str_radix(fields[2], 16).ok()?,
                    path: fields.get(5)?.to_string(),
                    build_id: None,
                    time_ns: None,
                })
            })
            .collect();
        let memory = File::open("/proc/self/mem").unwrap();
        Itself { mappings, memory }
    }

    /// Builds a library whose thread-local `current` `set` sets, and loads
    /// it.
    fn load(dir: &Path, name: &str, flags: &[&str]) -> Option<unsafe extern "C" fn(u64)> {
        let source = dir.join(format!("{name}.c"));
        // A large block is past what glibc gives a thread at its start.
        let large = if name.contains("large") { 1 << 16 } else { 1 };
        fs::write(
            &source,
            format!(
                "__thread unsigned long current, pad[{large}];\n\
                 void set(unsigned long value) {{ current = value; pad[0] = value; }}\n"
            ),
        )
        .unwrap();
        let library = dir.join(format!("lib{name}.so"));
        let built = Command::new("cc")
            .args(["-shared", "-fPIC", "-O2", "-o"])
            .arg(&library)
            .args(flags)
            .arg(&source)
            .status()
            .ok()?;
        assert!(built.success(), "cc failed");
        let path = CString::new(library.to_str().unwrap()).unwrap();
        let handle = unsafe { dlopen(path.as_ptr(), 2) };
        assert!(!handle.is_null());
        let set = unsafe { dlsym(handle, c"set".as_ptr()) };
        assert!(!set.is_null());
        Some(unsafe { std::mem::transmute::<*mut c_void, unsafe extern "C" fn(u64)>(set) })
    }

    /// What the path from this thread's thread pointer leads to.
    fn follow(process: &Itself, path: &[i32]) -> u64 {
        let pointer: u64;
        // glibc's thread control block starts with a pointer to itself.
        unsafe { std::arch::asm!("mov {}, fs:0", out(reg) pointer) };
        path.iter().fold(pointer, |at, &offset| {
            u64_at(process, "a test", at.wrapping_add_signed(i64::from(offset))).unwrap()
        })
    }

    #[test]
    fn finds_thread_locals_as_glibc_does() {
        let dir = std::env::temp_dir().join(format!("uhr-tls-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        // Each with the pointers its path follows: by the module's index,
        // from the thread pointer, then by the index a descriptor holds.
        let libraries = [
            ("module", &[][..], 3),
            ("descriptor", &["-mtls-dialect=gnu2"][..], 1),
            ("large_descriptor", &["-mtls-dialect=gnu2"][..], 3),
        ];
        for (name, flags, pointers) in libraries {
            let Some(set) = load(&dir, name, flags) else {
                eprintln!("skipped: needs a C compiler");
                break;
            };
            let value = 0x1234_5678 + name.len() as u64;
            unsafe { set(value) };
            let process = itself();
            let mapping = process
                .mappings
                .iter()
                .find(|m| m.path.ends_with(&format!("/lib{name}.so")) && m.file_offset == 0)
                .unwrap();
            let path = thread_local(&process, mapping, "current").unwrap().unwrap();
            assert_eq!(path.len(), pointers, "{name}: {path:?}");
            assert_eq!(follow(&process, &path), value, "{name}: {path:?}");
        }
        fs::remove_dir_all(&dir).unwrap();
    }
}
