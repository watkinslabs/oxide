//! The record marking an object whose data is still in the lower layer.
//!
//! Copying a large file up only to change its owner is the cost this avoids: a
//! `chown -R` over an image layer would otherwise rewrite every byte of it. The
//! marker's presence is what tells every later reader that the upper object is
//! metadata only, so a missing one loses the file's contents and a stale one
//! reads a file that is really there as empty.

extern crate alloc;

use alloc::vec::Vec;
use syscall::errno::Errno;

use crate::limits::{MAX_DIGEST_SIZE, METACOPY_MAX_SIZE, METACOPY_MIN_SIZE};

/// A decoded marker.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Metacopy {
    /// Reserved for a later format; a record naming a version this kernel does
    /// not know is an error rather than a guess, because guessing wrong reads
    /// a digest from the wrong offset.
    pub version: u8,
    /// Reserved for later flags.
    pub flags: u8,
    /// Hash algorithm of `digest`, zero when none was recorded.
    pub digest_algo: u8,
    /// Digest of the lower data, checked before the data is used when the
    /// mount asked for verification.
    pub digest: Vec<u8>,
}

impl Metacopy {
    /// An empty marker: the object is metadata-only and nothing about its data
    /// is recorded. # C: O(1)
    pub fn empty() -> Self { Metacopy { version: 0, flags: 0, digest_algo: 0, digest: Vec::new() } }
    /// Does this marker carry a digest to check against? # C: O(1)
    pub fn has_digest(&self) -> bool { self.digest_algo != 0 && !self.digest.is_empty() }
    /// Stored form. A marker with nothing to say is written as a ZERO-LENGTH
    /// value rather than as its header, which is what an older kernel that
    /// knows only the presence of the attribute expects to find. # C: O(len)
    pub fn encode(&self) -> Vec<u8> {
        if self.version == 0 && self.flags == 0 && self.digest_algo == 0 { return Vec::new(); }
        let mut out = Vec::with_capacity(METACOPY_MIN_SIZE + self.digest.len());
        out.push(self.version);
        out.push((METACOPY_MIN_SIZE + self.digest.len()) as u8);
        out.push(self.flags);
        out.push(self.digest_algo);
        out.extend_from_slice(&self.digest);
        out
    }
}

/// Read a marker's value.
///
/// A zero-length value is the legal empty form, not a truncated record. Any
/// other length shorter than the header, a version this kernel does not know,
/// or a length byte disagreeing with the value's real size is `EIO`: each
/// would make a digest be read from the wrong bytes, and a digest checked
/// against the wrong bytes either rejects good data or accepts bad.
/// # C: O(len(value))
pub fn decode(value: &[u8]) -> Result<Metacopy, Errno> {
    if value.is_empty() { return Ok(Metacopy::empty()); }
    if value.len() < METACOPY_MIN_SIZE || value.len() > METACOPY_MAX_SIZE { return Err(Errno::Eio); }
    if value[0] != 0 { return Err(Errno::Eio); }
    if value[1] as usize != value.len() { return Err(Errno::Eio); }
    let digest = value[METACOPY_MIN_SIZE..].to_vec();
    if digest.len() > MAX_DIGEST_SIZE { return Err(Errno::Eio); }
    Ok(Metacopy { version: value[0], flags: value[2], digest_algo: value[3], digest })
}

/// Size a decoded record reports, which is what lookup uses to tell a marker
/// carrying a digest from a bare one. Zero means no marker at all. # C: O(1)
pub fn recorded_size(value: Option<&[u8]>) -> usize {
    match value {
        None => 0,
        Some(v) if v.is_empty() => METACOPY_MIN_SIZE,
        Some(v) => v.len(),
    }
}

#[cfg(test)]
#[path = "metacopy/tests.rs"]
mod tests;
