//! Which two names are the same name.
//!
//! Long-name mounts compare case-insensitively by default, which is why a
//! directory cannot hold both `Makefile` and `MAKEFILE`. Two rules decide it:
//! a trailing run of dots is not part of a name, and the comparison folds
//! case through the mount's IO charset rather than through Unicode — so the
//! answer depends on the charset, not on the characters.

use super::flags::MAX_LONG_NAME;

use syscall::errno::Errno;

/// Charset used for long-name comparison.  FAT keeps this separate from the
/// on-disk short-name code page: Linux's `nls_io` is the table consulted by
/// `nls_strnicmp`, while `nls_disk` is used only to decode 8.3 bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IoCharset {
    Iso88591,
    Utf8,
}

impl IoCharset {
    pub const DEFAULT: Self = Self::Iso88591;

    pub const fn name(self) -> &'static str {
        match self {
            Self::Iso88591 => "iso8859-1",
            Self::Utf8 => "utf8",
        }
    }
}

/// Characters a long name may not contain at all. Below the space they are
/// control codes; the rest are the ones a path or a shell would swallow.
const BAD: [char; 9] = ['*', '?', '<', '>', '|', '"', ':', '/', '\\'];

/// Length of `name` with any trailing dots removed.
///
/// A name that ends in dots is the same name without them: the format cannot
/// store the dots, so accepting the name and then failing to find it again is
/// the alternative. # C: O(name length)
pub fn striptail_len(name: &str) -> usize {
    let b = name.as_bytes();
    let mut len = b.len();
    while len > 0 && b[len - 1] == b'.' { len -= 1; }
    len
}

/// `name` with its trailing dots removed. # C: O(name length)
pub fn striptail(name: &str) -> &str { &name[..striptail_len(name)] }

/// Whether a long name may be stored.
///
/// `EINVAL` for a character the format forbids and for a trailing space,
/// which would be indistinguishable from the padding a reader strips.
/// `ENAMETOOLONG` past what the slots can address.
/// # C: O(name length)
pub fn validate(name: &str) -> Result<(), Errno> {
    let units = name.encode_utf16().count();
    if units == 0 { return Err(Errno::Enoent); }
    if units > MAX_LONG_NAME { return Err(Errno::Enametoolong); }
    for c in name.chars() {
        if (c as u32) < 0x20 || BAD.contains(&c) { return Err(Errno::Einval); }
    }
    if name.ends_with(' ') { return Err(Errno::Einval); }
    Ok(())
}

/// Lowercase of one byte under the default IO charset.
///
/// The fold is over BYTES, not characters, and covers the Latin-1 range the
/// default charset spells one byte per character. A multi-byte character's
/// bytes fall outside it and compare as they stand, which is the reference's
/// behaviour and the reason a name differing only in the case of a non-Latin
/// letter is two names. # C: O(1)
pub fn fold_byte(b: u8) -> u8 { fold_byte_with(b, IoCharset::DEFAULT) }

/// Fold one byte through the selected IO charset's NLS table.  UTF-8's Linux
/// NLS table deliberately has identity byte case maps; its non-ASCII bytes
/// are not individually case-foldable. # C: O(1)
pub fn fold_byte_with(b: u8, charset: IoCharset) -> u8 {
    if charset == IoCharset::Utf8 { return b; }
    const UPPER_LATIN_FIRST: u8 = 0xc0;
    const UPPER_LATIN_LAST: u8 = 0xde;
    /// The multiplication sign sits inside the uppercase run and is not a
    /// letter.
    const NOT_A_LETTER: u8 = 0xd7;
    const CASE_DELTA: u8 = 0x20;
    if b.is_ascii_uppercase() { return b + CASE_DELTA; }
    if (UPPER_LATIN_FIRST..=UPPER_LATIN_LAST).contains(&b) && b != NOT_A_LETTER {
        return b + CASE_DELTA;
    }
    b
}

/// Whether two names are the same, comparing case exactly. # C: O(length)
pub fn eq_sensitive(a: &str, b: &str) -> bool {
    striptail(a).as_bytes() == striptail(b).as_bytes()
}

/// Whether two names are the same, ignoring case. # C: O(length)
pub fn eq_insensitive(a: &str, b: &str) -> bool {
    eq_insensitive_with(a, b, IoCharset::DEFAULT)
}

/// Whether two names are the same under a selected IO charset. # C: O(length)
pub fn eq_insensitive_with(a: &str, b: &str, charset: IoCharset) -> bool {
    let (a, b) = (striptail(a), striptail(b));
    match charset {
        // The hosted path API has already decoded the caller's bytes to
        // Unicode.  Apply the same Latin-1 table to those codepoints that
        // Linux's iso8859-1 NLS table would have folded byte-by-byte.
        IoCharset::Iso88591 => a.chars().count() == b.chars().count()
            && a.chars().zip(b.chars()).all(|(x, y)| fold_latin1(x) == fold_latin1(y)),
        // nls_utf8 intentionally has identity case maps.
        IoCharset::Utf8 => a == b,
    }
}

fn fold_latin1(c: char) -> char {
    match c as u32 {
        0x41..=0x5a | 0xc0..=0xd6 | 0xd8..=0xde =>
            char::from_u32(c as u32 + 0x20).unwrap(),
        _ => c,
    }
}

/// Whether two names are the same under a mount's `check=` rule. # C: O(length)
pub fn eq(a: &str, b: &str, case_sensitive: bool) -> bool {
    eq_with(a, b, case_sensitive, IoCharset::DEFAULT)
}

/// Compare under the mount's case rule and IO charset. # C: O(length)
pub fn eq_with(a: &str, b: &str, case_sensitive: bool, charset: IoCharset) -> bool {
    if case_sensitive { eq_sensitive(a, b) } else { eq_insensitive_with(a, b, charset) }
}
