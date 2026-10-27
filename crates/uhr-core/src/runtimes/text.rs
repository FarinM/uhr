//! The text runtimes keep, as recordings write it: `\` as `\\`, and what is
//! no character as `\u` and four hex digits, so that two names that differ
//! in memory differ as text too.

/// Text of code points, which may be no characters, as CPython's lone
/// surrogates are.
pub(super) fn chars(chars: impl IntoIterator<Item = u32>) -> String {
    let mut text = String::new();
    for c in chars {
        match char::from_u32(c) {
            Some(c) => push(&mut text, c),
            None => text.push_str(&format!("\\u{c:04x}")),
        }
    }
    text
}

fn push(text: &mut String, c: char) {
    match c {
        '\\' => text.push_str("\\\\"),
        c => text.push(c),
    }
}

/// Text of bytes that should be UTF-8, with each byte that is not as
/// CPython keeps it, as a lone surrogate from U+DC80.
pub(super) fn utf8(bytes: &[u8]) -> String {
    let mut text = String::new();
    for chunk in bytes.utf8_chunks() {
        chunk.valid().chars().for_each(|c| push(&mut text, c));
        for byte in chunk.invalid() {
            text.push_str(&format!("\\u{:04x}", 0xdc00 + u32::from(*byte)));
        }
    }
    text
}

/// Text of UTF-16, which may hold lone surrogates.
pub(super) fn utf16(units: impl IntoIterator<Item = u16>) -> String {
    let mut text = String::new();
    for c in char::decode_utf16(units) {
        match c {
            Ok(c) => push(&mut text, c),
            Err(lone) => text.push_str(&format!("\\u{:04x}", lone.unpaired_surrogate())),
        }
    }
    text
}

/// Text of the modified UTF-8 the JVM keeps names in: UTF-8 of UTF-16, each
/// surrogate on its own, with NUL in two bytes.
pub(super) fn modified_utf8(bytes: &[u8]) -> String {
    let continues = |at: usize| bytes.get(at).filter(|&&b| b & 0xc0 == 0x80);
    let mut units = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        let byte = bytes[at];
        let (unit, length) = match byte {
            0x01..0x80 => (Some(u16::from(byte)), 1),
            0xc0..0xe0 => match continues(at + 1) {
                Some(next) => (
                    Some(u16::from(byte & 0x1f) << 6 | u16::from(next & 0x3f)),
                    2,
                ),
                None => (None, 1),
            },
            0xe0..0xf0 => match (continues(at + 1), continues(at + 2)) {
                (Some(second), Some(third)) => (
                    Some(
                        u16::from(byte & 0x0f) << 12
                            | u16::from(second & 0x3f) << 6
                            | u16::from(third & 0x3f),
                    ),
                    3,
                ),
                _ => (None, 1),
            },
            _ => (None, 1),
        };
        // A byte that is none of it, as an invalid byte of UTF-8 is.
        units.push(unit.ok_or(byte));
        at += length;
    }
    let mut text = String::new();
    let mut units = units.into_iter().peekable();
    while let Some(unit) = units.next() {
        match unit {
            Ok(high @ 0xd800..0xdc00) => match units.peek() {
                Some(&Ok(low @ 0xdc00..0xe000)) => {
                    units.next();
                    text.push_str(&utf16([high, low]));
                }
                _ => text.push_str(&utf16([high])),
            },
            Ok(unit) => text.push_str(&utf16([unit])),
            Err(byte) => text.push_str(&format!("\\u{:04x}", 0xdc00 + u32::from(byte))),
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_what_is_no_character() {
        assert_eq!(chars([0x61, 0x5c, 0xd800]), "a\\\\\\ud800");
    }

    #[test]
    fn escapes_lone_surrogates() {
        assert_eq!(utf16([0x61, 0xd801, 0xdc00, 0xdc01]), "a\u{10400}\\udc01");
    }

    #[test]
    fn escapes_bytes_that_are_no_utf8_as_cpython_keeps_them() {
        assert_eq!(utf8(b"caf\xe9 \xc3\xa9"), "caf\\udce9 \u{e9}");
    }

    #[test]
    fn reads_the_jvms_modified_utf8() {
        // U+10400 as two surrogates, NUL in two bytes, and U+E9.
        let name = [0xed, 0xa0, 0x81, 0xed, 0xb0, 0x80, 0xc0, 0x80, 0xc3, 0xa9];
        assert_eq!(modified_utf8(&name), "\u{10400}\0\u{e9}");
        assert_eq!(modified_utf8(&[0xed, 0xb0, 0x81]), "\\udc01");
        assert_eq!(modified_utf8(&[0x61, 0xff]), "a\\udcff");
        assert_ne!(
            modified_utf8(&[0xed, 0xa0, 0x81, 0xed, 0xb0, 0x80]),
            modified_utf8(&[0xed, 0xa0, 0x81, 0xed, 0xb0, 0x81])
        );
    }
}
