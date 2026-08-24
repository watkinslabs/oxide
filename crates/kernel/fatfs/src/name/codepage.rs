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

use super::{cp437, cp850, cp852, cp855, cp857, cp860, cp861, cp862};

/// The code page number a mount defaults to when it names none.
pub const DEFAULT_CODEPAGE: u32 = 437;

#[derive(Copy, Clone)]
enum Tables { Cp437, Cp850, Cp852, Cp855, Cp857, Cp860, Cp861, Cp862 }

/// A single-byte code page: the character each byte means, and the case
/// mapping over the bytes themselves.
///
/// Case is a property of the CODE PAGE, not of the characters: the reference
/// folds case by table lookup on the byte, so a byte whose character has an
/// uppercase form that the code page cannot store stays as it is.
pub struct CodePage {
    /// Number the mount option names this page by.
    pub number: u32,
    tables: Tables,
}

/// Code page 437, the FAT default.
pub static CP437: CodePage = CodePage {
    number: DEFAULT_CODEPAGE,
    tables: Tables::Cp437,
};

/// Code page 850, the Linux `nls_cp850` single-byte table.
pub static CP850: CodePage = CodePage { number: 850, tables: Tables::Cp850 };

/// Code page 852, the Linux `nls_cp852` Central European table.
pub static CP852: CodePage = CodePage { number: 852, tables: Tables::Cp852 };

/// Code page 855, the Linux `nls_cp855` Cyrillic table.
pub static CP855: CodePage = CodePage { number: 855, tables: Tables::Cp855 };

/// Code page 857, the Linux `nls_cp857` Turkish table.
pub static CP857: CodePage = CodePage { number: 857, tables: Tables::Cp857 };

/// Code page 860, the Linux `nls_cp860` Portuguese table.
pub static CP860: CodePage = CodePage { number: 860, tables: Tables::Cp860 };

/// Code page 861, the Linux `nls_cp861` Icelandic table.
pub static CP861: CodePage = CodePage { number: 861, tables: Tables::Cp861 };

/// Code page 862, the Linux `nls_cp862` Hebrew table.
pub static CP862: CodePage = CodePage { number: 862, tables: Tables::Cp862 };

/// The code page a mount option names, or `None` when this build has no table
/// for it. # C: O(1)
pub fn by_number(number: u32) -> Option<&'static CodePage> {
    match number { DEFAULT_CODEPAGE => Some(&CP437), 850 => Some(&CP850), 852 => Some(&CP852), 855 => Some(&CP855), 857 => Some(&CP857), 860 => Some(&CP860), 861 => Some(&CP861), 862 => Some(&CP862), _ => None }
}

impl CodePage {
    /// The character `byte` means on this page. # C: O(1)
    pub fn to_char(&self, byte: u8) -> u16 {
        if byte < 128 { return u16::from(byte); }
        match self.tables {
            Tables::Cp437 => cp437::CHARSET2UNI[usize::from(byte)],
            Tables::Cp850 => cp850::CHARSET2UNI[usize::from(byte - 128)],
            Tables::Cp852 => cp852::CHARSET2UNI[usize::from(byte - 128)],
            Tables::Cp855 => cp855::CHARSET2UNI[usize::from(byte - 128)],
            Tables::Cp857 => cp857::CHARSET2UNI[usize::from(byte - 128)],
            Tables::Cp860 => cp860::CHARSET2UNI[usize::from(byte - 128)],
            Tables::Cp861 => cp861::CHARSET2UNI[usize::from(byte - 128)],
            Tables::Cp862 => cp862::CHARSET2UNI[usize::from(byte - 128)],
        }
    }

    /// The byte that stores `ch`, when this page has one.
    ///
    /// A search rather than a table: the forward table is injective, so
    /// inverting it is exact and a second table would be a second place for
    /// the same fact to be wrong. # C: O(256)
    pub fn from_char(&self, ch: u16) -> Option<u8> {
        (0..=u8::MAX).find(|byte| self.to_char(*byte) == ch)
    }

    /// Lowercase of `byte` on this page, or `byte` when it has none. # C: O(1)
    pub fn to_lower(&self, byte: u8) -> u8 {
        let c = if byte < 128 {
            if byte.is_ascii_uppercase() { byte + (b'a' - b'A') } else { byte }
        } else { match self.tables {
            Tables::Cp437 => cp437::CHARSET2LOWER[usize::from(byte)],
            Tables::Cp850 => cp850::CHARSET2LOWER[usize::from(byte - 128)],
            Tables::Cp852 => cp852::CHARSET2LOWER[usize::from(byte - 128)],
            Tables::Cp855 => cp855::CHARSET2LOWER[usize::from(byte - 128)],
            Tables::Cp857 => cp857::CHARSET2LOWER[usize::from(byte - 128)],
            Tables::Cp860 => cp860::CHARSET2LOWER[usize::from(byte - 128)],
            Tables::Cp861 => cp861::CHARSET2LOWER[usize::from(byte - 128)],
            Tables::Cp862 => cp862::CHARSET2LOWER[usize::from(byte - 128)],
        }};
        if c == 0 { byte } else { c }
    }

    /// Uppercase of `byte` on this page, or `byte` when it has none. # C: O(1)
    pub fn to_upper(&self, byte: u8) -> u8 {
        let c = if byte < 128 {
            if byte.is_ascii_lowercase() { byte - (b'a' - b'A') } else { byte }
        } else { match self.tables {
            Tables::Cp437 => cp437::CHARSET2UPPER[usize::from(byte)],
            Tables::Cp850 => cp850::CHARSET2UPPER[usize::from(byte - 128)],
            Tables::Cp852 => cp852::CHARSET2UPPER[usize::from(byte - 128)],
            Tables::Cp855 => cp855::CHARSET2UPPER[usize::from(byte - 128)],
            Tables::Cp857 => cp857::CHARSET2UPPER[usize::from(byte - 128)],
            Tables::Cp860 => cp860::CHARSET2UPPER[usize::from(byte - 128)],
            Tables::Cp861 => cp861::CHARSET2UPPER[usize::from(byte - 128)],
            Tables::Cp862 => cp862::CHARSET2UPPER[usize::from(byte - 128)],
        }};
        if c == 0 { byte } else { c }
    }
}
