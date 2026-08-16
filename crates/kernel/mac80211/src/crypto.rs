// Link ciphers. Each module here owns one cipher end to end: the header it
// writes and parses, the additional authenticated data it derives from the
// frame, the nonce, the transform, and the replay check.
//
// Replay detection lives with the cipher and not with the receive chain,
// because the counter's width, its position in the header and the rule for
// comparing it are all cipher-specific — a shared "last packet number seen"
// in the chain would be wrong for at least one of them.
//
// Module manifest:
// - `aad`:     the masked-header additional authenticated data both
//              counter-mode ciphers authenticate, and the nonce they derive.
// - `pn`:      packet-number encode/decode and the per-traffic-identifier
//              replay window.
// - `ccmp`:    counter mode with CBC-MAC, 128- and 256-bit.
// - `gcmp`:    Galois counter mode, 128- and 256-bit.
// - `tkip`:    the temporal-key cipher: key mixing, the stream cipher and the
//              integrity check value.
// - `michael`: the message integrity code the temporal-key cipher adds.
// - `rc4`:     the stream cipher the temporal-key and wired-equivalent
//              ciphers use.
// - `crc32`:   the integrity check value both of those append.
// - `wep`:     the wired-equivalent cipher, for a network that offers nothing
//              better.
// - `bip`:     management-frame integrity.

#[path = "crypto/aad.rs"] pub mod aad;
#[path = "crypto/pn.rs"] pub mod pn;
#[path = "crypto/ccmp.rs"] pub mod ccmp;
#[path = "crypto/gcmp.rs"] pub mod gcmp;
#[path = "crypto/tkip.rs"] pub mod tkip;
#[path = "crypto/michael.rs"] pub mod michael;
#[path = "crypto/rc4.rs"] pub mod rc4;
#[path = "crypto/crc32.rs"] pub mod crc32;
#[path = "crypto/wep.rs"] pub mod wep;
#[path = "crypto/bip.rs"] pub mod bip;

/// Why a frame did not come out of the cipher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
    /// The frame is shorter than the cipher's own header and trailer.
    TooShort,
    /// The header does not carry the extended-identifier bit the cipher
    /// requires, so it was not produced by this cipher at all.
    NoExtIv,
    /// The header names a different key index than the one installed.
    WrongKeyIdx,
    /// The packet number is not newer than the last one accepted.
    Replay,
    /// The integrity check failed: the frame was altered or the key is wrong.
    IntegrityFailure,
    /// The key is not usable for this operation.
    BadKey,
}

/// Result of a cipher operation.
pub type CryptoResult<T> = Result<T, CryptoError>;
