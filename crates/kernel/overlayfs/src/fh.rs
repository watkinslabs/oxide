//! The record that says which lower object an upper one was copied from.
//!
//! It is written into the upper layer and read back by a different mount,
//! possibly a different kernel, so it is a wire format: fixed field order,
//! an explicit length, a magic byte, and a flag saying which byte order the
//! writer used. A record this kernel does not understand means "origin
//! unknown" rather than "corrupt" — the object is still perfectly usable, it
//! just loses the identity it shared with its lower half.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use syscall::errno::Errno;

use crate::uapi::{FB_HEADER_LEN, FH_FLAG_ALL, FH_FLAG_ANY_ENDIAN, FH_FLAG_BIG_ENDIAN,
                  FH_FLAG_CPU_ENDIAN, FH_FLAG_PATH_UPPER, FH_MAGIC, FH_VERSION};

/// Longest identifier a layer may encode into a record. The whole record has
/// to fit the single length byte alongside its header.
pub const MAX_FID_LEN: usize = 255 - FB_HEADER_LEN;

/// A decoded origin record.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Fh {
    /// Identifier type the layer's own encoder chose.
    pub fid_type: u8,
    /// Identity of the filesystem the identifier belongs to, or all zero when
    /// the mount was told not to record one.
    pub uuid: [u8; 16],
    /// Layer-private identifier.
    pub fid: Vec<u8>,
    /// Record names an object in the upper layer.
    pub is_upper: bool,
}

/// Why a record could not be used.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FhError {
    /// Malformed: too short for its own length, or not one of ours.
    Invalid,
    /// Well formed but from a version or byte order this kernel cannot read.
    /// Treated as "origin unknown", never as an error to the caller.
    Unknown,
}

impl FhError {
    /// Errno a caller that must fail sees. # C: O(1)
    pub fn errno(self) -> Errno {
        match self { FhError::Invalid => Errno::Einval, FhError::Unknown => Errno::Enodata }
    }
}

/// Build a record for `fid`. # C: O(len(fid))
pub fn encode(fid_type: u8, uuid: [u8; 16], fid: &[u8], is_upper: bool) -> Result<Vec<u8>, Errno> {
    if fid.len() > MAX_FID_LEN { return Err(Errno::Eio); }
    let len = FB_HEADER_LEN + fid.len();
    let mut out = Vec::with_capacity(len);
    out.push(FH_VERSION);
    out.push(FH_MAGIC);
    out.push(len as u8);
    out.push(FH_FLAG_CPU_ENDIAN | if is_upper { FH_FLAG_PATH_UPPER } else { 0 });
    out.push(fid_type);
    out.extend_from_slice(&uuid);
    out.extend_from_slice(fid);
    Ok(out)
}

/// Check a record's framing without interpreting its body.
///
/// A record longer than what was read, or shorter than the header, is refused:
/// the length byte is the only thing that says where the identifier ends, so a
/// wrong one would hand the layer's decoder a truncated identifier.
/// # C: O(1)
pub fn check(buf: &[u8]) -> Result<(), FhError> {
    if buf.len() < FB_HEADER_LEN { return Err(FhError::Invalid); }
    if buf.len() < buf[2] as usize { return Err(FhError::Invalid); }
    if buf[1] != FH_MAGIC { return Err(FhError::Invalid); }
    let flags = buf[3];
    if buf[0] > FH_VERSION || flags & !FH_FLAG_ALL != 0 { return Err(FhError::Unknown); }
    if flags & FH_FLAG_ANY_ENDIAN == 0 && flags & FH_FLAG_BIG_ENDIAN != FH_FLAG_CPU_ENDIAN {
        return Err(FhError::Unknown);
    }
    Ok(())
}

/// Read a record. # C: O(len(buf))
pub fn decode(buf: &[u8]) -> Result<Fh, FhError> {
    check(buf)?;
    let len = buf[2] as usize;
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&buf[5..21]);
    Ok(Fh {
        fid_type: buf[4],
        uuid,
        fid: buf[FB_HEADER_LEN..len].to_vec(),
        is_upper: buf[3] & FH_FLAG_PATH_UPPER != 0,
    })
}

/// Do two records name the same object? Compared as bytes over the recorded
/// length, so a record padded by a longer read still matches. # C: O(len)
pub fn same(a: &[u8], b: &[u8]) -> bool {
    match (check(a), check(b)) {
        (Ok(()), Ok(())) => a[2] == b[2] && a[..a[2] as usize] == b[..b[2] as usize],
        _ => false,
    }
}

/// Name of the index entry for a record: its bytes in hex, which is a valid
/// filename on every layer and needs no escaping. # C: O(len(buf))
pub fn index_name(buf: &[u8]) -> Result<String, Errno> {
    check(buf).map_err(FhError::errno)?;
    let len = buf[2] as usize;
    let mut s = String::with_capacity(len * 2);
    for b in &buf[..len] {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    Ok(s)
}

/// Recover a record from an index entry's name. # C: O(len(name))
pub fn from_index_name(name: &str) -> Result<Vec<u8>, Errno> {
    if name.len() < FB_HEADER_LEN * 2 || name.len() % 2 != 0 { return Err(Errno::Einval); }
    let b = name.as_bytes();
    let mut out = Vec::with_capacity(name.len() / 2);
    for pair in b.chunks(2) {
        out.push(nibble(pair[0])? << 4 | nibble(pair[1])?);
    }
    check(&out).map_err(FhError::errno)?;
    Ok(out)
}

/// One hex digit. # C: O(1)
fn nibble(c: u8) -> Result<u8, Errno> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(Errno::Einval),
    }
}

/// Lowercase hex, the form an index entry is written in.
const HEX: &[u8; 16] = b"0123456789abcdef";

#[cfg(test)]
#[path = "fh/tests.rs"]
mod tests;
