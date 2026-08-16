//! The code page the 11 name bytes are written in, and the two directions
//! across it.
//!
//! The 8.3 name is not text. It is eleven bytes in whatever single-byte code
//! page the machine that wrote them used, and the mount names that code page
//! (`codepage=`). Reading them as characters of the same value is right for
//! ASCII and for nothing above it: a name written with an accented or
//! box-drawing character comes back as a different character entirely.
//!
//! The reverse direction matters as much, because a name this filesystem
//! CREATES has to be storable: a character with no byte in the code page is
//! not an error, it is what makes the short name an alias and forces the long
//! name to be stored beside it.

use super::cp437;

/// The code page number a mount defaults to when it names none.
pub const DEFAULT_CODEPAGE: u32 = 437;

/// A single-byte code page: the character each byte means, and the case
/// mapping over the bytes themselves.
///
/// Case is a property of the CODE PAGE, not of the characters: the reference
/// folds case by table lookup on the byte, so a byte whose character has an
/// uppercase form that the code page cannot store stays as it is.
pub struct CodePage {
    /// Number the mount option names this page by.
    pub number: u32,
    to_uni: &'static [u16; 256],
    to_lower: &'static [u8; 256],
    to_upper: &'static [u8; 256],
}

/// Code page 437, the FAT default.
pub static CP437: CodePage = CodePage {
    number: DEFAULT_CODEPAGE,
    to_uni: &cp437::CHARSET2UNI,
    to_lower: &cp437::CHARSET2LOWER,
    to_upper: &cp437::CHARSET2UPPER,
};

/// The code page a mount option names, or `None` when this build has no table
/// for it. # C: O(1)
pub fn by_number(number: u32) -> Option<&'static CodePage> {
    match number { DEFAULT_CODEPAGE => Some(&CP437), _ => None }
}

impl CodePage {
    /// The character `byte` means on this page. # C: O(1)
    pub fn to_char(&self, byte: u8) -> u16 { self.to_uni[usize::from(byte)] }

    /// The byte that stores `ch`, when this page has one.
    ///
    /// A search rather than a table: the forward table is injective, so
    /// inverting it is exact and a second table would be a second place for
    /// the same fact to be wrong. # C: O(256)
    pub fn from_char(&self, ch: u16) -> Option<u8> {
        self.to_uni.iter().position(|c| *c == ch).map(|i| i as u8)
    }

    /// Lowercase of `byte` on this page, or `byte` when it has none. # C: O(1)
    pub fn to_lower(&self, byte: u8) -> u8 {
        let c = self.to_lower[usize::from(byte)];
        if c == 0 { byte } else { c }
    }

    /// Uppercase of `byte` on this page, or `byte` when it has none. # C: O(1)
    pub fn to_upper(&self, byte: u8) -> u8 {
        let c = self.to_upper[usize::from(byte)];
        if c == 0 { byte } else { c }
    }
}
