//! The initialisation vector for one data unit.
//!
//! The IV is a data unit INDEX in its low eight bytes, little-endian, and what
//! else it carries depends on which key-derivation flag the policy set:
//!
//! - Ordinarily the key is per file, so the index alone is enough — two files
//!   never share a key, so they may share an index.
//! - `IV_INO_LBLK_64` shares one key across the whole volume, so the inode
//!   number goes in the index's HIGH half to keep files apart. The index is
//!   therefore limited to 32 bits, which is why the policy is only allowed on
//!   a volume whose files are short enough.
//! - `IV_INO_LBLK_32` also shares the key, but adds a keyed HASH of the inode
//!   number to the index and wraps at 32 bits — hardware that cannot carry a
//!   64-bit value needs the whole thing to fit in one word.
//! - `DIRECT_KEY` shares the key across a mode, so the file's nonce travels in
//!   the IV beside the index. That needs an IV at least 24 bytes wide, so no
//!   mode this build carries can use it.
//!
//! Every one of these produces a well-formed IV under the wrong rule; the
//! symptom of choosing wrong is a file that decrypts to noise with no error.

use super::uapi::*;

/// The IV bytes for `index` within a file.
///
/// Only the first `iv_size` bytes are meaningful; the rest stay zero.
/// # C: O(1)
pub fn generate(
    flags: u8,
    nonce: &[u8; FILE_NONCE_SIZE],
    ino: u32,
    hashed_ino: u32,
    index: u64,
) -> [u8; MAX_IV_SIZE] {
    let mut iv = [0u8; MAX_IV_SIZE];
    let value = if flags & FLAG_IV_INO_LBLK_64 != 0 {
        index | (u64::from(ino) << 32)
    } else if flags & FLAG_IV_INO_LBLK_32 != 0 {
        u64::from(hashed_ino.wrapping_add(index as u32))
    } else {
        if flags & FLAG_DIRECT_KEY != 0 {
            iv[8..8 + FILE_NONCE_SIZE].copy_from_slice(nonce);
        }
        index
    };
    iv[..8].copy_from_slice(&value.to_le_bytes());
    iv
}

/// The 16-byte IV the block modes take. # C: O(1)
pub fn block_iv(iv: &[u8; MAX_IV_SIZE]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&iv[..16]);
    out
}
