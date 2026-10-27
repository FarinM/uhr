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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_what_is_no_character() {
        assert_eq!(chars([0x61, 0x5c, 0xd800]), "a\\\\\\ud800");
    }
}
