//! The encryption a key names, and the three widths that naming fixes.
//!
//! Inline encryption defines FEWER modes than a filesystem's own encryption
//! does, and deliberately so: a mode is only here if a storage controller can
//! be asked to perform it over a data unit it addresses. The filename modes a
//! filesystem uses have no counterpart, because no device encrypts a
//! directory entry.
//!
//! The three widths are not free parameters. `key_size` is how many bytes the
//! construction consumes as a key — twice the block cipher's own key for the
//! tweakable modes, which take two. `security_strength` is the shortest key a
//! derivation may produce for it, and is NOT the same number: the tweakable
//! modes' two cipher keys come from one 256-bit secret. `iv_size` bounds how
//! wide a data unit number may be, since the number IS the low bytes of the
//! IV.

/// A mode, numbered as a profile's capability array indexes it.
///
/// The numbering starts at one because zero is the absence of a mode. A
/// profile's per-mode array keeps the zero slot so that indexing by a mode
/// never has to subtract, and that slot stays empty forever — a device
/// advertising support for "no mode" would be advertising nothing.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Mode {
    /// Tweakable narrow-block over the 128-bit-block Western cipher, keyed by
    /// two 256-bit keys.
    Aes256Xts = 1,
    /// Chaining under an IV that is itself enciphered, so a bare data unit
    /// number does not become a predictable IV.
    Aes128CbcEssiv = 2,
    /// Wide-block over a stream cipher and two hashing passes; takes the
    /// widest tweak of the four.
    Adiantum = 3,
    /// Tweakable narrow-block over the other block cipher, keyed by two
    /// 128-bit keys.
    Sm4Xts = 4,
}

/// Entries a per-mode capability array carries, the empty zero slot included.
pub const MODE_SLOTS: usize = 5;

/// The widths a mode fixes.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct ModeParams {
    /// Bytes of key material the construction consumes.
    pub key_size: usize,
    /// Shortest key a derivation may produce for this mode.
    pub security_strength: usize,
    /// Bytes of IV the construction takes, which bounds the data unit number.
    pub iv_size: usize,
}

impl Mode {
    /// This mode's index into a per-mode capability array. # C: O(1)
    pub const fn index(self) -> usize { self as usize }

    /// The widths this mode fixes. # C: O(1)
    pub const fn params(self) -> ModeParams {
        match self {
            Mode::Aes256Xts => ModeParams { key_size: 64, security_strength: 32, iv_size: 16 },
            Mode::Aes128CbcEssiv => ModeParams { key_size: 16, security_strength: 16, iv_size: 16 },
            Mode::Adiantum => ModeParams { key_size: 32, security_strength: 32, iv_size: 32 },
            Mode::Sm4Xts => ModeParams { key_size: 32, security_strength: 16, iv_size: 16 },
        }
    }

    /// The mode a capability-array index names, or `None` for the empty slot
    /// and for anything past the last mode. # C: O(1)
    pub const fn from_index(i: usize) -> Option<Mode> {
        match i {
            1 => Some(Mode::Aes256Xts),
            2 => Some(Mode::Aes128CbcEssiv),
            3 => Some(Mode::Adiantum),
            4 => Some(Mode::Sm4Xts),
            _ => None,
        }
    }

    /// Every mode, in capability-array order. # C: O(1)
    pub const ALL: [Mode; 4] =
        [Mode::Aes256Xts, Mode::Aes128CbcEssiv, Mode::Adiantum, Mode::Sm4Xts];
}

/// No mode's key is wider than a raw key may be, no mode's strength exceeds
/// its own key, and no mode's IV is wider than a data unit number may be.
/// Held here rather than checked at boot: a mode added with an impossible
/// width should not compile.
const _: () = {
    let mut i = 0;
    while i < Mode::ALL.len() {
        let p = Mode::ALL[i].params();
        assert!(p.key_size <= crate::crypto::key::MAX_RAW_KEY_SIZE);
        assert!(p.security_strength <= p.key_size);
        assert!(p.iv_size <= crate::crypto::dun::MAX_IV_SIZE);
        i += 1;
    }
};
