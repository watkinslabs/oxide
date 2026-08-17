//! What a mode number means: key width, IV width, and the security strength
//! that decides how short a master key may be.
//!
//! The key size is the size of the DERIVED key, not of the block cipher's key.
//! The tweakable mode takes two cipher keys in one buffer, so its key size is
//! twice the cipher's; deriving a cipher-sized key for it silently halves the
//! keyspace and still round-trips.

use super::uapi::*;
use super::FscryptError;

/// A mode's parameters.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Mode {
    pub num: u8,
    /// Bytes of derived key material the mode consumes.
    pub key_size: usize,
    /// The strength a master key must have for a v2 policy to derive this.
    pub security_strength: usize,
    /// Bytes of IV the mode takes.
    pub iv_size: usize,
}

/// AES-256-XTS: two 256-bit cipher keys.
pub const AES_256_XTS: Mode =
    Mode { num: MODE_AES_256_XTS, key_size: 64, security_strength: 32, iv_size: 16 };
/// AES-256-CBC-CTS, the filename mode that pairs with it.
pub const AES_256_CTS: Mode =
    Mode { num: MODE_AES_256_CTS, key_size: 32, security_strength: 32, iv_size: 16 };
/// AES-128-CBC-ESSIV.
pub const AES_128_CBC: Mode =
    Mode { num: MODE_AES_128_CBC, key_size: 16, security_strength: 16, iv_size: 16 };
/// AES-128-CBC-CTS.
pub const AES_128_CTS: Mode =
    Mode { num: MODE_AES_128_CTS, key_size: 16, security_strength: 16, iv_size: 16 };
/// SM4-XTS: two 128-bit cipher keys, so half the width of the AES pairing.
/// Its strength is the cipher's key width, not the derived key's.
pub const SM4_XTS: Mode =
    Mode { num: MODE_SM4_XTS, key_size: 32, security_strength: 16, iv_size: 16 };
/// SM4-CBC-CTS, the filename mode that pairs with it.
pub const SM4_CTS: Mode =
    Mode { num: MODE_SM4_CTS, key_size: 16, security_strength: 16, iv_size: 16 };
/// Adiantum: a wide-block mode over a stream cipher and two hashing passes,
/// taking a 32-byte tweak — wide enough to carry a file nonce, which is what
/// makes it the one mode the direct-key flag can use.
pub const ADIANTUM: Mode =
    Mode { num: MODE_ADIANTUM, key_size: 32, security_strength: 32, iv_size: 32 };
/// AES-256-HCTR2: a wide-block mode, likewise on a 32-byte tweak.
pub const AES_256_HCTR2: Mode =
    Mode { num: MODE_AES_256_HCTR2, key_size: 32, security_strength: 32, iv_size: 32 };

/// The mode a number names, or the reason this build cannot use it.
///
/// A number the format assigns but this build has no cipher for is
/// `UnsupportedMode`, which is a different answer from a number the format
/// does not assign at all — one is a file another reader could open, the
/// other is a corrupt policy. Every number the format assigns now has a
/// cipher, so only the second answer is reachable from here.
/// # C: O(1)
pub fn by_number(num: u8) -> Result<Mode, FscryptError> {
    match num {
        MODE_AES_256_XTS => Ok(AES_256_XTS),
        MODE_AES_256_CTS => Ok(AES_256_CTS),
        MODE_AES_128_CBC => Ok(AES_128_CBC),
        MODE_AES_128_CTS => Ok(AES_128_CTS),
        MODE_SM4_XTS => Ok(SM4_XTS),
        MODE_SM4_CTS => Ok(SM4_CTS),
        MODE_ADIANTUM => Ok(ADIANTUM),
        MODE_AES_256_HCTR2 => Ok(AES_256_HCTR2),
        _ => Err(FscryptError::UnknownMode(num)),
    }
}

/// Whether a mode's IV is wide enough to carry a file nonce beside the data
/// unit index, which is what the direct-key flag requires. # C: O(1)
pub fn iv_holds_nonce(m: Mode) -> bool { m.iv_size >= 8 + FILE_NONCE_SIZE }
