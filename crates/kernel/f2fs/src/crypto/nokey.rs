//! The name a locked directory shows, and how a lookup finds an entry by it.
//!
//! Without the key a listing cannot show plaintext, and it cannot show the
//! ciphertext either: that may contain a zero byte or a slash, neither of
//! which a name may hold. So the ciphertext is encoded — but a full-length
//! ciphertext encodes to more than a name may be, so long ones are abbreviated
//! by a digest of their tail.
//!
//! The encoded record therefore holds three things, and each is needed for a
//! different reason:
//!
//! - The directory HASH, because a filesystem that finds entries by hash
//!   cannot recompute one from an abbreviated name, and cannot recompute a
//!   keyed one at all.
//! - Up to 149 bytes of the ciphertext, which is the whole of almost every
//!   name and is what an exact match compares.
//! - For anything longer, a digest of the remainder — so two long names that
//!   share their first 149 bytes still resolve to different entries.
//!
//! A name presented this way must round-trip: what a listing shows is what a
//! later lookup, unlink or rename is given back, so the encoding is part of
//! the interface and not a display convenience.

use alloc::vec::Vec;

use super::base64;
use super::uapi::*;
use super::FscryptError;

/// Offsets within the encoded record.
const OFF_BYTES: usize = NOKEY_DIRHASH;
const OFF_SHA256: usize = OFF_BYTES + NOKEY_BYTES;

/// A no-key name, decoded.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NoKeyName {
    /// The stored directory hash, and its second word — zero on a format that
    /// keeps only one.
    pub hash: u32,
    pub minor_hash: u32,
    /// The ciphertext prefix the record carries.
    pub bytes: Vec<u8>,
    /// Set only when the ciphertext was abbreviated; then `bytes` is the full
    /// 149-byte prefix and this covers everything after it.
    pub digest: Option<[u8; NOKEY_SHA256]>,
}

/// Present `disk_name` — the ciphertext stored in the entry — as the name a
/// locked directory shows.
///
/// The two names that are never encrypted pass through: a directory without
/// its key still has a `.` and a `..`.
/// # C: O(len(disk_name))
pub fn present(hash: u32, minor_hash: u32, disk_name: &[u8]) -> Result<Vec<u8>, FscryptError> {
    if crate::hash::is_dot_or_dotdot(disk_name) { return Ok(Vec::from(disk_name)); }
    // Every ciphertext name is padded to at least the minimum message length,
    // so a shorter one did not come from this construction.
    if disk_name.len() < FNAME_MIN_MSG_LEN { return Err(FscryptError::CorruptName); }
    let mut rec = [0u8; NOKEY_NAME_MAX];
    rec[..4].copy_from_slice(&hash.to_le_bytes());
    rec[4..8].copy_from_slice(&minor_hash.to_le_bytes());
    let size = if disk_name.len() <= NOKEY_BYTES {
        rec[OFF_BYTES..OFF_BYTES + disk_name.len()].copy_from_slice(disk_name);
        OFF_BYTES + disk_name.len()
    } else {
        rec[OFF_BYTES..OFF_SHA256].copy_from_slice(&disk_name[..NOKEY_BYTES]);
        let d = crypt::sha256::sha256(&disk_name[NOKEY_BYTES..]);
        rec[OFF_SHA256..NOKEY_NAME_MAX].copy_from_slice(&d);
        NOKEY_NAME_MAX
    };
    let mut out = alloc::vec![0u8; base64::encoded_len(size)];
    let n = base64::encode(&rec[..size], &mut out);
    out.truncate(n);
    Ok(out)
}

/// Read back a name a listing presented.
///
/// A name that does not decode to a well-formed record names no entry, which
/// is `ENOENT` and not an error about the directory.
/// # C: O(len(name))
pub fn parse(name: &[u8]) -> Result<NoKeyName, FscryptError> {
    if name.len() > NOKEY_NAME_MAX_ENCODED { return Err(FscryptError::NoSuchName); }
    let mut rec = [0u8; NOKEY_NAME_MAX];
    let n = base64::decode(name, &mut rec).ok_or(FscryptError::NoSuchName)?;
    // Below the hash plus one ciphertext byte there is no name; above the
    // ciphertext field the only legal size is the full record, because the
    // digest is present or absent whole.
    if n < OFF_BYTES + 1 || (n > OFF_SHA256 && n != NOKEY_NAME_MAX) {
        return Err(FscryptError::NoSuchName);
    }
    let hash = u32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]);
    let minor_hash = u32::from_le_bytes([rec[4], rec[5], rec[6], rec[7]]);
    if n == NOKEY_NAME_MAX {
        let mut d = [0u8; NOKEY_SHA256];
        d.copy_from_slice(&rec[OFF_SHA256..]);
        Ok(NoKeyName {
            hash, minor_hash,
            bytes: Vec::from(&rec[OFF_BYTES..OFF_SHA256]),
            digest: Some(d),
        })
    } else {
        Ok(NoKeyName { hash, minor_hash, bytes: Vec::from(&rec[OFF_BYTES..n]), digest: None })
    }
}

impl NoKeyName {
    /// The full ciphertext, when the record carries it. An abbreviated record
    /// has none, and must be matched by [`NoKeyName::matches`]. # C: O(1)
    pub fn disk_name(&self) -> Option<&[u8]> {
        match self.digest { None => Some(&self.bytes), Some(_) => None }
    }

    /// Whether the entry whose stored name is `de_name` is the one this record
    /// names. # C: O(len(de_name))
    pub fn matches(&self, de_name: &[u8]) -> bool {
        match self.digest {
            None => de_name == &self.bytes[..],
            Some(want) => {
                // An abbreviated record only ever names a name longer than the
                // prefix it carries; a shorter entry would have been stored
                // whole and cannot be this one.
                if de_name.len() <= NOKEY_BYTES { return false; }
                if de_name[..NOKEY_BYTES] != self.bytes[..] { return false; }
                crypt::sha256::sha256(&de_name[NOKEY_BYTES..]) == want
            }
        }
    }
}
