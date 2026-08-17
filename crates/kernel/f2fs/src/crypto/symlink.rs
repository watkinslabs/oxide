//! An encrypted symbolic link's target.
//!
//! The stored form is a two-byte little-endian ciphertext length followed by
//! the ciphertext, and then a terminator that is counted in the file's size
//! but is not part of the ciphertext. The length is redundant with the file's
//! size and is stored anyway, for the same reason it always has been: a reader
//! that trusts the size instead reads the terminator as ciphertext and
//! produces a target one block wrong.
//!
//! The target is encrypted the way a NAME is, not the way contents are — it is
//! a path, padded and encrypted whole under the link's own key.

use alloc::vec::Vec;

use super::inode::Info;
use super::uapi::*;
use super::{fname, nokey, FscryptError};

/// Bytes the stored length field takes.
const LEN_FIELD: usize = 2;

/// The bytes stored for a link whose target is `target`.
///
/// A trailing zero is written after the ciphertext and counted in the file's
/// size, matching what a reader expects to skip.
/// # C: O(len(target))
pub fn encode(info: &Info, target: &[u8]) -> Result<Vec<u8>, FscryptError> {
    if target.is_empty() { return Err(FscryptError::CorruptName); }
    let olen = fname::encrypted_size(target.len(), info.policy().padding(), crate::uapi::NAME_LEN)
        .ok_or(FscryptError::NameTooLong)?;
    if olen < target.len() { return Err(FscryptError::NameTooLong); }
    let ct = info.encrypt_name(target)?;
    if ct.len() != olen { return Err(FscryptError::BadLength(ct.len())); }
    let mut out = Vec::with_capacity(LEN_FIELD + olen + 1);
    out.extend_from_slice(&(olen as u16).to_le_bytes());
    out.extend_from_slice(&ct);
    out.push(0);
    Ok(out)
}

/// The ciphertext a stored link holds. # C: O(1)
pub fn ciphertext(stored: &[u8]) -> Result<&[u8], FscryptError> {
    if stored.len() < LEN_FIELD + 1 { return Err(FscryptError::CorruptName); }
    let len = usize::from(u16::from_le_bytes([stored[0], stored[1]]));
    if len == 0 || len + LEN_FIELD > stored.len() { return Err(FscryptError::CorruptName); }
    Ok(&stored[LEN_FIELD..LEN_FIELD + len])
}

/// The target a link presents: the plaintext with the key, and the encoded
/// form without it.
///
/// A link has no directory hash to carry, so the encoded form's hash words are
/// zero — the entry is found by the link's own inode, not by a bucket.
/// # C: O(len(stored))
pub fn present(info: Option<&Info>, stored: &[u8]) -> Result<Vec<u8>, FscryptError> {
    let ct = ciphertext(stored)?;
    if ct.len() < FNAME_MIN_MSG_LEN { return Err(FscryptError::CorruptName); }
    let out = match info {
        Some(i) => i.decrypt_name(ct)?,
        None => nokey::present(0, 0, ct)?,
    };
    // A target that decrypts to nothing is a link to nowhere, which is a
    // corrupt record rather than an empty path.
    if out.is_empty() { return Err(FscryptError::CorruptName); }
    Ok(out)
}
