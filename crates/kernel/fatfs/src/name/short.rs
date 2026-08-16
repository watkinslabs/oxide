//! Reading the 8.3 name out of a short entry.
//!
//! Three things happen between the eleven bytes and the name a user sees:
//! the escaped first byte becomes the value it stands for, each byte becomes
//! the character its code page says it is, and the case bits decide whether
//! the base and the extension are folded down. Trailing spaces are padding,
//! never name, and the dot survives only when the extension does.

use alloc::string::String;

use super::codepage::CodePage;
use super::flags::{CASE_LOWER_BASE, CASE_LOWER_EXT, DELETED_FLAG, ESCAPED_DELETED,
                   SFN_DISPLAY_LOWER, SFN_DISPLAY_WIN95, SFN_DISPLAY_WINNT,
                   SHORT_BASE_LEN, SHORT_NAME_LEN};

/// The character a byte that cannot be translated becomes.
const UNTRANSLATABLE: u16 = 0x003f;

/// The character a byte means, folded to lowercase first. # C: O(1)
fn to_lower_char(cp: &CodePage, byte: u8) -> u16 {
    let c = cp.to_char(cp.to_lower(byte));
    if c == 0 && byte != 0 { UNTRANSLATABLE } else { c }
}

/// The character a byte means, as it stands. # C: O(1)
fn to_char(cp: &CodePage, byte: u8) -> u16 {
    let c = cp.to_char(byte);
    if c == 0 && byte != 0 { UNTRANSLATABLE } else { c }
}

/// One name byte as a character, under the display rule and the entry's own
/// case bit.
///
/// The lower rule folds everything; the win95 rule folds nothing; the winnt
/// rule folds exactly what the entry says was lowercase when it was written,
/// which is the only one of the three that can round-trip a mixed-case name
/// with no long-name slots. # C: O(1)
fn display_char(cp: &CodePage, byte: u8, opts: u16, lower: bool) -> u16 {
    if opts & SFN_DISPLAY_LOWER != 0 { return to_lower_char(cp, byte); }
    if opts & SFN_DISPLAY_WIN95 != 0 { return to_char(cp, byte); }
    if opts & SFN_DISPLAY_WINNT != 0 {
        return if lower { to_lower_char(cp, byte) } else { to_char(cp, byte) };
    }
    to_char(cp, byte)
}

/// The 8.3 name an entry's raw bytes spell.
///
/// Empty when the entry carries no name at all — eleven spaces, or a leading
/// NUL — which a caller treats as an entry with nothing to show rather than
/// as an error.
/// # C: O(SHORT_NAME_LEN)
pub fn decode(raw: &[u8; SHORT_NAME_LEN], lcase: u8, cp: &CodePage, opts: u16) -> String {
    let mut work = *raw;
    if work[0] == ESCAPED_DELETED { work[0] = DELETED_FLAG; }

    let mut units = alloc::vec::Vec::<u16>::with_capacity(SHORT_NAME_LEN + 1);
    let mut keep = 0usize;
    let lower_base = lcase & CASE_LOWER_BASE != 0;
    for byte in work[..SHORT_BASE_LEN].iter().copied() {
        if byte == 0 { break; }
        units.push(display_char(cp, byte, opts, lower_base));
        if byte != b' ' { keep = units.len(); }
    }

    // The separator is written at the first position past the base's last
    // real character, so the base's padding is gone before it lands. It stays
    // only if the extension puts something after it.
    units.truncate(keep);
    units.push(u16::from(b'.'));

    let lower_ext = lcase & CASE_LOWER_EXT != 0;
    for byte in work[SHORT_BASE_LEN..].iter().copied() {
        if byte == 0 { break; }
        units.push(display_char(cp, byte, opts, lower_ext));
        if byte != b' ' { keep = units.len(); }
    }
    units.truncate(keep);

    char::decode_utf16(units.into_iter())
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}
