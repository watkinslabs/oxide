//! Encrypting and decrypting a filename.
//!
//! A name is encrypted whole, as one message, with the data unit index zero —
//! there is no per-name index, so two identical names in one directory
//! encrypt identically. That is deliberate and is what makes lookup by
//! ciphertext possible.
//!
//! Two length rules decide the stored size, and both leak information if
//! skipped:
//!
//! - A name shorter than the minimum message length is zero-padded up to it,
//!   so a one-character name is not distinguishable from a fifteen-character
//!   one by its size alone.
//! - The result is rounded up to the policy's padding, which is what hides
//!   the exact length of longer names.
//!
//! Decryption cannot know how much of the tail was padding, so it strips
//! trailing zero bytes. A plaintext name may not contain a zero byte, so
//! nothing real is lost.

use alloc::vec::Vec;

use super::uapi::*;
use super::FscryptError;

/// The stored length of a name of `orig_len` bytes under `padding`, capped at
/// `max_len`.
///
/// `None` when the name is already longer than the cap: the length cannot be
/// reduced, so such a name does not fit this directory.
/// # C: O(1)
pub fn encrypted_size(orig_len: usize, padding: usize, max_len: usize) -> Option<usize> {
    if orig_len > max_len { return None; }
    let n = orig_len.max(FNAME_MIN_MSG_LEN);
    let rounded = n.div_ceil(padding) * padding;
    Some(rounded.min(max_len))
}

/// The zero-padded plaintext a name is encrypted from. # C: O(olen)
pub fn padded(name: &[u8], olen: usize) -> Result<Vec<u8>, FscryptError> {
    if olen < name.len() { return Err(FscryptError::BadLength(olen)); }
    let mut out = alloc::vec![0u8; olen];
    out[..name.len()].copy_from_slice(name);
    Ok(out)
}

/// The plaintext a decryption produced, with its padding removed.
///
/// A name may not contain a zero byte, so the first one ends the name.
/// # C: O(len(plain))
pub fn unpad(plain: &[u8]) -> &[u8] {
    match plain.iter().position(|&b| b == 0) { Some(i) => &plain[..i], None => plain }
}
