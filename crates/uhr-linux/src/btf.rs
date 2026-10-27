//! The kernel's BTF, for where its structures keep their fields.

use std::fs;

const MAGIC: u16 = 0xeb9f;
const STRUCT: u32 = 4;
const UNION: u32 = 5;

/// Where a `task_struct` keeps the user thread pointer.
#[cfg(target_arch = "x86_64")]
pub(crate) const THREAD_POINTER: &str = "thread.fsbase";
#[cfg(target_arch = "aarch64")]
pub(crate) const THREAD_POINTER: &str = "thread.uw.tp_value";
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub(crate) const THREAD_POINTER: &str = "";

/// The offset in bytes of each member, by its structure and its name, in
/// the running kernel. A name can go through members, as in `thread.fsbase`.
/// `None` for one not found, or all if the kernel has no BTF.
pub(crate) fn kernel_member_offsets<const N: usize>(
    members: [(&str, &str); N],
) -> [Option<u32>; N] {
    let btf = fs::read("/sys/kernel/btf/vmlinux").unwrap_or_default();
    let btf = Btf::parse(&btf);
    members.map(|(structure, member)| btf.as_ref()?.member_offset(structure, member))
}

struct Btf<'a> {
    types: &'a [u8],
    strings: &'a [u8],
    /// Where each type starts in `types`, by its id, which counts from 1.
    starts: Vec<usize>,
}

fn word(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

impl<'a> Btf<'a> {
    fn parse(btf: &'a [u8]) -> Option<Self> {
        if u16::from_ne_bytes(btf.get(0..2)?.try_into().ok()?) != MAGIC {
            return None;
        }
        let header = word(btf, 4)? as usize;
        let section = |at: usize| {
            let start = header + word(btf, at)? as usize;
            btf.get(start..start + word(btf, at + 4)? as usize)
        };
        let (types, strings) = (section(8)?, section(16)?);
        let mut starts = vec![0];
        let mut at = 0;
        while at < types.len() {
            starts.push(at);
            let info = word(types, at + 4)?;
            let vlen = (info & 0xffff) as usize;
            let extra = match (info >> 24) & 0x1f {
                // A pointer, a forward declaration, a typedef, a qualifier,
                // a function, a float or a type tag.
                2 | 7..=12 | 16 | 18 => 0,
                // An int, a variable or a declaration tag.
                1 | 14 | 17 => 4,
                3 => 12,
                // Structures and unions, data sections and 64-bit enums.
                4 | 5 | 15 | 19 => vlen * 12,
                // Enums and function prototypes.
                6 | 13 => vlen * 8,
                _ => return None,
            };
            at += 12 + extra;
        }
        Some(Self {
            types,
            strings,
            starts,
        })
    }

    fn word(&self, at: usize) -> Option<u32> {
        word(self.types, at)
    }

    fn kind(&self, id: u32) -> Option<u32> {
        Some((self.word(*self.starts.get(id as usize)? + 4)? >> 24) & 0x1f)
    }

    fn name(&self, offset: u32) -> Option<&'a str> {
        let rest = self.strings.get(offset as usize..)?;
        let end = rest.iter().position(|&b| b == 0)?;
        std::str::from_utf8(&rest[..end]).ok()
    }

    /// The offset in bytes of `member` in `structure`, looking into its
    /// anonymous structures and unions, and through the members `member`
    /// names before its last dot. `None` if either is not there, or the
    /// member is a bit field.
    fn member_offset(&self, structure: &str, member: &str) -> Option<u32> {
        let mut id = (1..self.starts.len() as u32).find(|&id| {
            let named = self
                .word(self.starts[id as usize])
                .and_then(|n| self.name(n));
            self.kind(id) == Some(STRUCT) && named == Some(structure)
        })?;
        let mut bits = 0;
        for (i, name) in member.split('.').enumerate() {
            if i > 0 {
                id = self.structure_of(id)?;
            }
            (bits, id) = self.find(id, bits, name)?;
        }
        (bits % 8 == 0).then_some(bits / 8)
    }

    /// The structure or union the type `id` is, through typedefs and
    /// qualifiers.
    fn structure_of(&self, mut id: u32) -> Option<u32> {
        // Bounded, as a malformed BTF can loop.
        for _ in 0..16 {
            match self.kind(id)? {
                STRUCT | UNION => return Some(id),
                // A typedef, `volatile`, `const` or `restrict`.
                8..=11 => id = self.word(*self.starts.get(id as usize)? + 8)?,
                _ => return None,
            }
        }
        None
    }

    /// The offset in bits of `member` in the structure or union `id`, which
    /// starts `base` bits in, and its type.
    fn find(&self, id: u32, base: u32, member: &str) -> Option<(u32, u32)> {
        let at = *self.starts.get(id as usize)?;
        let info = self.word(at + 4)?;
        let bitfields = info >> 31 == 1;
        for m in 0..(info & 0xffff) as usize {
            let at = at + 12 + m * 12;
            let (name, kind) = (self.word(at)?, self.word(at + 4)?);
            let offset = self.word(at + 8)?;
            let bits = base
                + if bitfields {
                    offset & 0xff_ffff
                } else {
                    offset
                };
            match (name, self.kind(kind)) {
                (0, Some(STRUCT | UNION)) => {
                    if let Some(found) = self.find(kind, bits, member) {
                        return Some(found);
                    }
                }
                _ if self.name(name) == Some(member) => {
                    let bitfield = bitfields && offset >> 24 != 0;
                    return (!bitfield).then_some((bits, kind));
                }
                _ => {}
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A BTF with an int, `struct task { int state; union { int a; int
    /// flags; }; }` with the union at bit 64, and a forward declaration.
    fn btf() -> Vec<u8> {
        let strings = b"\0int\0task\0state\0a\0flags\0fwd\0outer\0inner\0";
        let at = |name: &str| {
            let name = format!("\0{name}\0");
            let found = strings
                .windows(name.len())
                .position(|w| w == name.as_bytes());
            found.unwrap() as u32 + 1
        };
        let kind = |kind: u32, vlen: u32| kind << 24 | vlen;
        let types: Vec<u32> = [
            // 1: int, 4 bytes.
            &[at("int"), kind(1, 0), 4, 32][..],
            // 2: the anonymous union.
            &[0, kind(5, 2), 4, at("a"), 1, 0, at("flags"), 1, 0],
            // 3: the structure.
            &[at("task"), kind(4, 2), 12, at("state"), 1, 0, 0, 2, 64],
            // 4: a forward declaration.
            &[at("fwd"), kind(7, 0), 0],
            // 5: a structure that holds a task 16 bytes in.
            &[at("outer"), kind(4, 1), 28, at("inner"), 3, 128],
        ]
        .concat();
        let types: Vec<u8> = types.iter().flat_map(|w| w.to_ne_bytes()).collect();
        let mut btf = Vec::new();
        btf.extend(MAGIC.to_ne_bytes());
        btf.extend([1, 0]);
        let header = [
            24,
            0,
            types.len() as u32,
            types.len() as u32,
            strings.len() as u32,
        ];
        btf.extend(header.iter().flat_map(|w| w.to_ne_bytes()));
        btf.extend(types);
        btf.extend(strings);
        btf
    }

    #[test]
    fn finds_members_of_anonymous_unions() {
        let btf = btf();
        let parsed = Btf::parse(&btf).unwrap();
        assert_eq!(parsed.member_offset("task", "state"), Some(0));
        assert_eq!(parsed.member_offset("task", "flags"), Some(8));
        assert_eq!(parsed.member_offset("task", "missing"), None);
        assert_eq!(parsed.member_offset("fwd", "flags"), None);
        assert_eq!(parsed.member_offset("outer", "inner.flags"), Some(24));
        assert_eq!(parsed.member_offset("outer", "inner.missing"), None);
        assert!(Btf::parse(&btf[1..]).is_none());
    }

    #[test]
    fn finds_what_uhr_reads_of_the_running_kernels_tasks() {
        if fs::metadata("/sys/kernel/btf/vmlinux").is_err() {
            eprintln!("skipped: the kernel has no BTF");
            return;
        }
        let [flags, signal, live, thread_pointer] = kernel_member_offsets([
            ("task_struct", "flags"),
            ("task_struct", "signal"),
            ("signal_struct", "live"),
            ("task_struct", THREAD_POINTER),
        ]);
        // After the thread info and the state, and well inside the
        // structure.
        assert!(
            flags.is_some_and(|offset| (8..256).contains(&offset)),
            "{flags:?}"
        );
        assert!(signal.is_some() && live.is_some());
        // The thread structure comes last.
        assert!(
            thread_pointer.is_some_and(|offset| offset > 1024),
            "{thread_pointer:?}"
        );
    }
}
