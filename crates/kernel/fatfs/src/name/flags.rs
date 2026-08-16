//! Name-handling constants: the short-name display and creation modes, the
//! case bits a short entry carries, and the lengths the format fixes.

/// `shortname=` chooses one display rule and one creation rule. They are
/// independent bits of one word because a mount can display by one machine's
/// convention while creating by another's, which is what the default does.
pub const SFN_DISPLAY_LOWER: u16 = 0x0001;
pub const SFN_DISPLAY_WIN95: u16 = 0x0002;
pub const SFN_DISPLAY_WINNT: u16 = 0x0004;
pub const SFN_CREATE_WIN95: u16 = 0x0100;
pub const SFN_CREATE_WINNT: u16 = 0x0200;

/// What a long-name mount uses when `shortname=` is absent: display by the
/// case bits, create names that carry none.
pub const SFN_DEFAULT: u16 = SFN_DISPLAY_WINNT | SFN_CREATE_WIN95;

/// What an 8.3-only mount uses: no rule at all, since it neither reads nor
/// writes the case bits.
pub const SFN_MSDOS: u16 = 0;

/// The case bits in a short entry's `lcase` byte. They are the only record of
/// a name that was all-lowercase but otherwise 8.3-legal, which is why such a
/// name needs no long-name slots at all.
pub const CASE_LOWER_BASE: u8 = 8;
pub const CASE_LOWER_EXT: u8 = 16;

/// Longest name the long-name slots can carry.
pub const MAX_LONG_NAME: usize = 255;
/// Most slots one entry may use, long slots plus the short one.
pub const MAX_SLOTS: usize = 21;
/// Bytes of name in a short entry: eight of base, three of extension.
pub const SHORT_NAME_LEN: usize = 11;
/// Where the extension starts within those bytes.
pub const SHORT_BASE_LEN: usize = 8;

/// First name byte of a deleted entry, and the byte that escapes it.
///
/// A name may legitimately begin with the deleted marker's value, so it is
/// stored as the escape and translated back on the way out. Only the FIRST
/// byte is ever escaped.
pub const DELETED_FLAG: u8 = 0xe5;
pub const ESCAPED_DELETED: u8 = 0x05;

/// The mode name a `shortname=` option carries, as its bits. # C: O(1)
pub fn shortname_mode(name: &str) -> Option<u16> {
    match name {
        "lower" => Some(SFN_DISPLAY_LOWER | SFN_CREATE_WIN95),
        "win95" => Some(SFN_DISPLAY_WIN95 | SFN_CREATE_WIN95),
        "winnt" => Some(SFN_DISPLAY_WINNT | SFN_CREATE_WINNT),
        "mixed" => Some(SFN_DISPLAY_WINNT | SFN_CREATE_WIN95),
        _ => None,
    }
}
