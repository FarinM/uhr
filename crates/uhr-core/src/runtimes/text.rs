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
}
