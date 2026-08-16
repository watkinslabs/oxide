//! One identity's record: what it is limited to, and what it is using.
//!
//! Two scales meet here and they are not the same. Usage is stored in BYTES;
//! the two space LIMITS beside it are stored in units of a thousand and
//! twenty-four bytes. Decoding a limit without scaling it makes every limit
//! a thousand times smaller than it is, which denies writes on a volume with
//! quota barely enabled — so both directions convert, and the encode rounds
//! UP so a limit never shrinks by being written back.
//!
//! An all-zero record means "no record here", which is how a leaf block marks
//! a free slot. A record that genuinely has nothing set would be
//! indistinguishable from free, so the format escapes it by writing one into
//! the inode grace field; the decode undoes that.

use alloc::vec;
use alloc::vec::Vec;

use super::info::Revision;
use super::uapi::*;
use super::QuotaError;

/// One identity's limits and usage, in the scale everything else uses:
/// space in bytes, inodes as a count, grace as an absolute time.
#[derive(Copy, Clone, Default, PartialEq, Eq, Debug)]
pub struct Dqblk {
    /// Space this identity may not exceed, in bytes. Zero means unlimited.
    pub bhardlimit: u64,
    /// Space it may exceed only while its grace lasts. Zero means unlimited.
    pub bsoftlimit: u64,
    /// Space it occupies, in bytes.
    pub curspace: u64,
    pub ihardlimit: u64,
    pub isoftlimit: u64,
    pub curinodes: u64,
    /// When the space grace expires. Zero means no grace has started.
    pub btime: u64,
    /// When the inode grace expires.
    pub itime: u64,
}

/// Bytes a count of space units stands for. # C: O(1)
pub fn units_to_bytes(units: u64) -> u64 { units.saturating_mul(SPACE_UNIT) }

/// Space units a byte count occupies, rounded up so a limit written back is
/// never narrower than the one that was read. # C: O(1)
pub fn bytes_to_units(bytes: u64) -> u64 {
    (bytes.saturating_add(SPACE_UNIT - 1)) >> SPACE_UNIT_BITS
}

fn le32(b: &[u8], at: usize) -> u64 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]) as u64
}

fn le64(b: &[u8], at: usize) -> u64 {
    let mut v = [0u8; U64_LEN];
    v.copy_from_slice(&b[at..at + U64_LEN]);
    u64::from_le_bytes(v)
}

/// Whether every byte of a record is zero, which is how a free slot reads.
/// # C: O(entry bytes)
pub fn unused(entry: &[u8]) -> bool { entry.iter().all(|&b| b == 0) }

/// The identity a record belongs to, or `None` when the slot is free.
/// # C: O(entry bytes)
pub fn id_of(entry: &[u8], rev: Revision) -> Option<u32> {
    if entry.len() < rev.entry_size() || unused(entry) { return None; }
    let at = match rev { Revision::R0 => R0_ID, Revision::R1 => R1_ID };
    Some(le32(entry, at) as u32)
}

/// Whether a record is the escaped form of an otherwise-empty one: every
/// field zero but the inode grace, which carries one purely so the record
/// does not read as a free slot. # C: O(entry bytes)
fn is_escaped_empty(entry: &[u8], rev: Revision) -> bool {
    let itime = match rev { Revision::R0 => R0_ITIME, Revision::R1 => R1_ITIME };
    if le64(entry, itime) != EMPTY_ESCAPE { return false; }
    entry.iter().enumerate().all(|(i, &b)| (i >= itime && i < itime + U64_LEN) || b == 0)
}

/// Read one record.
///
/// Both space limits are scaled out of their stored unit here, so every
/// comparison above this layer is byte against byte.
/// # C: O(entry bytes)
pub fn parse(entry: &[u8], rev: Revision) -> Result<Dqblk, QuotaError> {
    if entry.len() < rev.entry_size() { return Err(QuotaError::Truncated); }
    let mut d = match rev {
        Revision::R0 => Dqblk {
            ihardlimit: le32(entry, R0_IHARDLIMIT),
            isoftlimit: le32(entry, R0_ISOFTLIMIT),
            curinodes: le32(entry, R0_CURINODES),
            bhardlimit: units_to_bytes(le32(entry, R0_BHARDLIMIT)),
            bsoftlimit: units_to_bytes(le32(entry, R0_BSOFTLIMIT)),
            curspace: le64(entry, R0_CURSPACE),
            btime: le64(entry, R0_BTIME),
            itime: le64(entry, R0_ITIME),
        },
        Revision::R1 => Dqblk {
            ihardlimit: le64(entry, R1_IHARDLIMIT),
            isoftlimit: le64(entry, R1_ISOFTLIMIT),
            curinodes: le64(entry, R1_CURINODES),
            bhardlimit: units_to_bytes(le64(entry, R1_BHARDLIMIT)),
            bsoftlimit: units_to_bytes(le64(entry, R1_BSOFTLIMIT)),
            curspace: le64(entry, R1_CURSPACE),
            btime: le64(entry, R1_BTIME),
            itime: le64(entry, R1_ITIME),
        },
    };
    if is_escaped_empty(&entry[..rev.entry_size()], rev) { d.itime = 0; }
    Ok(d)
}

fn put32(out: &mut [u8], at: usize, v: u64) { out[at..at + U32_LEN].copy_from_slice(&(v as u32).to_le_bytes()); }
fn put64(out: &mut [u8], at: usize, v: u64) { out[at..at + U64_LEN].copy_from_slice(&v.to_le_bytes()); }

/// Write one record for `id`.
///
/// A record with nothing set would read back as a free slot, so it is escaped
/// the way the format wants — the exact inverse of what [`parse`] undoes.
/// # C: O(entry bytes)
pub fn encode(d: &Dqblk, id: u32, rev: Revision) -> Vec<u8> {
    let mut out = vec![0u8; rev.entry_size()];
    match rev {
        Revision::R0 => {
            put32(&mut out, R0_ID, id as u64);
            put32(&mut out, R0_IHARDLIMIT, d.ihardlimit);
            put32(&mut out, R0_ISOFTLIMIT, d.isoftlimit);
            put32(&mut out, R0_CURINODES, d.curinodes);
            put32(&mut out, R0_BHARDLIMIT, bytes_to_units(d.bhardlimit));
            put32(&mut out, R0_BSOFTLIMIT, bytes_to_units(d.bsoftlimit));
            put64(&mut out, R0_CURSPACE, d.curspace);
            put64(&mut out, R0_BTIME, d.btime);
            put64(&mut out, R0_ITIME, d.itime);
        }
        Revision::R1 => {
            put32(&mut out, R1_ID, id as u64);
            put32(&mut out, R1_PAD, 0);
            put64(&mut out, R1_IHARDLIMIT, d.ihardlimit);
            put64(&mut out, R1_ISOFTLIMIT, d.isoftlimit);
            put64(&mut out, R1_CURINODES, d.curinodes);
            put64(&mut out, R1_BHARDLIMIT, bytes_to_units(d.bhardlimit));
            put64(&mut out, R1_BSOFTLIMIT, bytes_to_units(d.bsoftlimit));
            put64(&mut out, R1_CURSPACE, d.curspace);
            put64(&mut out, R1_BTIME, d.btime);
            put64(&mut out, R1_ITIME, d.itime);
        }
    }
    if unused(&out) {
        let itime = match rev { Revision::R0 => R0_ITIME, Revision::R1 => R1_ITIME };
        put64(&mut out, itime, EMPTY_ESCAPE);
    }
    out
}

/// Whether a limit is expressible in `rev`'s field widths.
///
/// A limit past what the record can hold would be truncated on the way down
/// and read back as a far smaller one, which turns a raised limit into a
/// lowered one. # C: O(1)
pub fn limits_fit(d: &Dqblk, rev: Revision) -> bool {
    d.bhardlimit <= rev.max_space_limit()
        && d.bsoftlimit <= rev.max_space_limit()
        && d.ihardlimit <= rev.max_inode_limit()
        && d.isoftlimit <= rev.max_inode_limit()
}
