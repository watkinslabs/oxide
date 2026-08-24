//! The summary block, and the two journals riding in its spare room.
//!
//! A summary block is one entry per block of a segment, then a journal, then a
//! five-byte footer. The journal is the part that matters at mount: the last
//! checkpoint parked recently-changed NAT and SIT entries there instead of
//! rewriting whole table blocks, and a journalled entry **overrides** the
//! on-disk table. A reader that consults only the table gets the address the
//! entry had before the change — a stale node, read without error.
//!
//! Two shapes hold the journals, chosen by a checkpoint flag:
//!
//! - **Compact.** One block at the start of the pack holds the NAT journal,
//!   then the SIT journal, back to back, with no entry array ahead of either.
//! - **Normal.** Each current-segment log has its own summary block, and the
//!   journal sits after that block's entry array. NAT rides the hot-data log,
//!   SIT the cold-data log.

use alloc::vec::Vec;

use crate::uapi::*;

/// One NAT entry, wherever it came from.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct NatEntry {
    pub version: u8,
    pub ino: u32,
    pub block_addr: u32,
}

/// One SIT entry: how many of a segment's blocks are live, which, and when
/// the segment was last written.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SitEntry {
    pub vblocks: u16,
    pub valid_map: [u8; SIT_VBLOCK_MAP_SIZE],
    pub mtime: u64,
}

impl SitEntry {
    /// Live blocks in the segment. # C: O(1)
    pub fn valid_blocks(&self) -> u16 { self.vblocks & SIT_VBLOCKS_MASK }

    /// The log the segment belongs to. # C: O(1)
    pub fn seg_type(&self) -> u8 { ((self.vblocks & !SIT_VBLOCKS_MASK) >> SIT_VBLOCKS_SHIFT) as u8 }

    /// Whether block `n` of the segment is live. # C: O(1)
    pub fn is_valid(&self, n: usize) -> bool {
        match self.valid_map.get(n / 8) { Some(b) => b & (1 << (n % 8)) != 0, None => false }
    }
}

/// Read one NAT entry out of `b` at `off`. # C: O(1)
pub fn nat_entry(b: &[u8], off: usize) -> Option<NatEntry> {
    Some(NatEntry {
        version: *b.get(off + NAT_VERSION)?,
        ino: le32(b, off + NAT_INO)?,
        block_addr: le32(b, off + NAT_BLOCK_ADDR)?,
    })
}

/// Read one SIT entry out of `b` at `off`. # C: O(1)
pub fn sit_entry(b: &[u8], off: usize) -> Option<SitEntry> {
    let mut valid_map = [0u8; SIT_VBLOCK_MAP_SIZE];
    let at = off + SIT_VALID_MAP;
    valid_map.copy_from_slice(b.get(at..at + SIT_VBLOCK_MAP_SIZE)?);
    Some(SitEntry {
        vblocks: le16(b, off + SIT_VBLOCKS)?,
        valid_map,
        mtime: le64(b, off + SIT_MTIME)?,
    })
}

/// A nid and the entry journalled for it.
pub type NatJournal = Vec<(u32, NatEntry)>;
/// A segment number and the entry journalled for it.
pub type SitJournal = Vec<(u32, SitEntry)>;

/// Decode the NAT journal that begins at `off` in `b`.
///
/// The stored count is clamped to what the region can hold, so a corrupted
/// count reads fewer entries rather than reading past the journal into the
/// footer or the next block.
/// # C: O(entries)
pub fn nat_journal(b: &[u8], off: usize) -> Option<NatJournal> {
    let n = (le16(b, off)? as usize).min(NAT_JOURNAL_ENTRIES);
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let at = off + 2 + i * NAT_JOURNAL_ENTRY_SIZE;
        out.push((le32(b, at)?, nat_entry(b, at + 4)?));
    }
    Some(out)
}

/// Decode the SIT journal that begins at `off` in `b`. # C: O(entries)
pub fn sit_journal(b: &[u8], off: usize) -> Option<SitJournal> {
    let n = (le16(b, off)? as usize).min(SIT_JOURNAL_ENTRIES);
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let at = off + 2 + i * SIT_JOURNAL_ENTRY_SIZE;
        out.push((le32(b, at)?, sit_entry(b, at + 4)?));
    }
    Some(out)
}

/// Where each journal starts, for the two block shapes.
///
/// `compact` puts both journals at the head of one block; `normal` puts one
/// journal after that block's entry array.
pub mod at {
    use super::*;

    /// NAT journal offset in a compact summary block. # C: O(1)
    pub const COMPACT_NAT: usize = 0;
    /// SIT journal offset in the same block. # C: O(1)
    pub const COMPACT_SIT: usize = SUM_JOURNAL_SIZE;
    /// Journal offset in a normal summary block, either kind. # C: O(1)
    pub const NORMAL: usize = SUM_JOURNAL_OFF;
    /// Durable write counter in the journal's extra-info union. # C: O(1)
    pub const LIFETIME_KBYTES: usize = SUM_JOURNAL_OFF + 2;
}

/// Read Linux's durable lifetime-write counter from a summary journal. # C: O(1)
pub fn lifetime_kbytes(b: &[u8]) -> Option<u64> {
    le64(b, at::LIFETIME_KBYTES)
}

/// Write Linux's durable lifetime-write counter into a summary journal. # C: O(1)
pub fn write_lifetime_kbytes(b: &mut [u8], value: u64) {
    b[at::LIFETIME_KBYTES..at::LIFETIME_KBYTES + 8]
        .copy_from_slice(&value.to_le_bytes());
}

/// Block address of the summary block for current-segment log `log`.
///
/// The persistent logs' summary blocks are the LAST blocks of the pack, in
/// order, so the address counts backwards from the pack's end. `base` is how
/// many of them were written: all six after a clean unmount, the three data
/// ones otherwise.
/// # C: O(1)
pub fn normal_sum_addr(cp_start: u32, pack_total: u32, base: usize, log: usize) -> u32 {
    cp_start + pack_total - (base as u32 + 1) + log as u32
}

#[cfg(test)]
#[path = "tests/summary.rs"]
mod tests;
