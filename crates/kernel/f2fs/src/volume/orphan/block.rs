//! The orphan block, and the arithmetic a pack's length depends on.
//!
//! Nothing here touches a volume. The encode/decode pair and the four numbers
//! below are the whole contract between a checkpoint's writer and its reader,
//! so they are pure and directly testable — the layer that owns a medium
//! cannot be, and every mistake in this file is silent on the writing side.
//!
//! Layout of one block: an array of inode numbers filling all but the last
//! four words, then a reserved word, a one-based index into the pack's orphan
//! blocks, how many such blocks the pack holds, how many entries THIS block
//! carries, and a checksum word.

use alloc::vec;
use alloc::vec::Vec;

use crate::flags::CP_ORPHAN_PRESENT_FLAG;
use crate::uapi::{le16, le32, BLKSIZE, CP_PACKS, NR_CURSEG_PERSIST_TYPE};

/// Words the trailer takes off the end of the block: reserved, the index pair
/// packed as two halves of one word, the entry count, and the checksum.
const TRAILER_WORDS: usize = 4;

/// Inode numbers one orphan block carries.
pub const ORPHANS_PER_BLOCK: usize = (BLKSIZE - 4 * TRAILER_WORDS) / 4;

/// Where the inode array starts.
pub const AT_INO: usize = 0;
/// The reserved word, written zero.
pub const AT_RESERVED: usize = ORPHANS_PER_BLOCK * 4;
/// This block's one-based position among the pack's orphan blocks.
pub const AT_BLK_ADDR: usize = AT_RESERVED + 4;
/// How many orphan blocks the pack holds.
pub const AT_BLK_COUNT: usize = AT_BLK_ADDR + 2;
/// How many entries of the array this block uses.
pub const AT_ENTRY_COUNT: usize = AT_BLK_COUNT + 2;
/// The checksum word. Carried, never computed and never verified: a written
/// volume leaves it zero, so computing one here would produce blocks the
/// format's other implementations reject, and verifying one would reject
/// theirs.
pub const AT_CHECK_SUM: usize = AT_ENTRY_COUNT + 4;

/// One orphan block, decoded.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OrphanBlock {
    pub inos: Vec<u32>,
    /// One-based position among the pack's orphan blocks.
    pub index: u16,
    /// How many orphan blocks the pack claims to hold.
    pub count: u16,
    /// The stored checksum word, passed through unexamined.
    pub check_sum: u32,
}

fn p16(b: &mut [u8], at: usize, v: u16) { b[at..at + 2].copy_from_slice(&v.to_le_bytes()); }
fn p32(b: &mut [u8], at: usize, v: u32) { b[at..at + 4].copy_from_slice(&v.to_le_bytes()); }

/// Lay `inos` into one block, positioned `index` of `count`.
///
/// Refuses more entries than the array holds rather than truncating: a
/// silently dropped inode is a leak nothing later can find.
/// # C: O(BLKSIZE)
pub fn encode(inos: &[u32], index: u16, count: u16) -> Option<Vec<u8>> {
    if inos.len() > ORPHANS_PER_BLOCK { return None; }
    let mut b = vec![0u8; BLKSIZE];
    for (i, ino) in inos.iter().enumerate() { p32(&mut b, AT_INO + i * 4, *ino); }
    p16(&mut b, AT_BLK_ADDR, index);
    p16(&mut b, AT_BLK_COUNT, count);
    p32(&mut b, AT_ENTRY_COUNT, inos.len() as u32);
    Some(b)
}

/// Every block a whole orphan list needs, in order.
///
/// The index counters are filled from the WHOLE list, not per call: a block
/// that says it is one of one while three were written describes a pack that
/// does not exist.
/// # C: O(inos)
pub fn encode_all(inos: &[u32]) -> Vec<Vec<u8>> {
    let count = blocks_for(inos.len()) as u16;
    let mut out = Vec::with_capacity(count as usize);
    for (i, chunk) in inos.chunks(ORPHANS_PER_BLOCK).enumerate() {
        if let Some(b) = encode(chunk, i as u16 + 1, count) { out.push(b); }
    }
    out
}

/// Read one orphan block back, or refuse it.
///
/// The entry count is bounded BEFORE the array is walked. The trailer sits
/// immediately past the array, so an unbounded count reads the index
/// counters and the checksum back as inode numbers — and every one of those
/// is then freed, which is a corruption a reader hands itself.
/// # C: O(entries)
pub fn decode(block: &[u8]) -> Option<OrphanBlock> {
    if block.len() < BLKSIZE { return None; }
    let n = le32(block, AT_ENTRY_COUNT)? as usize;
    if n > ORPHANS_PER_BLOCK { return None; }
    let mut inos = Vec::with_capacity(n);
    for i in 0..n { inos.push(le32(block, AT_INO + i * 4)?); }
    Some(OrphanBlock {
        inos,
        index: le16(block, AT_BLK_ADDR)?,
        count: le16(block, AT_BLK_COUNT)?,
        check_sum: le32(block, AT_CHECK_SUM)?,
    })
}

/// Blocks a list of `n` orphans occupies. Zero orphans occupy none, which is
/// what keeps an idle volume's pack the length it has always been.
/// # C: O(1)
pub fn blocks_for(n: usize) -> u32 { n.div_ceil(ORPHANS_PER_BLOCK) as u32 }

/// The most orphans a volume can park: what is left of one segment once the
/// two pack copies of the header, the payload and the summaries have taken
/// their blocks. Past this the pack would run out of its segment.
///
/// Costed against the LONGEST pack — the one that keeps every summary. A cap
/// set from a shorter pack would be met right up until an unmount, which is
/// the one checkpoint that must not fail.
/// # C: O(1)
pub fn max_orphans(blks_per_seg: u32, payload: u32) -> u64 {
    let fixed = CP_PACKS + NR_CURSEG_PERSIST_TYPE as u32 + payload;
    u64::from(blks_per_seg.saturating_sub(fixed)) * ORPHANS_PER_BLOCK as u64
}

/// Where the summaries begin inside a pack that carries `orphan_blocks`.
///
/// The orphan blocks sit between the payload and the summaries, so this is
/// also the only record of how many there are: a reader recovers the count by
/// subtracting, and a writer that leaves this number alone hands the reader an
/// orphan block where it expects a journal.
/// # C: O(1)
pub fn pack_start_sum(payload: u32, orphan_blocks: u32) -> u32 { 1 + payload + orphan_blocks }

/// How long the whole pack is: head, payload, orphans, `summaries`, tail.
///
/// The summary count is the caller's because it depends on why the checkpoint
/// is being written — a pack that keeps the node logs is longer than one that
/// parks them in the summary area. The orphan region is the same size either
/// way, which is why `pack_start_sum` above does not take it. The tail is
/// located by counting from this total, so one that ignores the orphan blocks
/// writes the tail on top of a summary.
/// # C: O(1)
pub fn pack_total(payload: u32, orphan_blocks: u32, summaries: usize) -> u32 {
    CP_PACKS + payload + orphan_blocks + summaries as u32
}

/// How many orphan blocks a pack holds, recovered from where its summaries
/// start. `None` when the pack claims summaries before its own payload ends,
/// which no writer produces and which would otherwise underflow.
/// # C: O(1)
pub fn blocks_in_pack(pack_start_sum: u32, payload: u32) -> Option<u32> {
    pack_start_sum.checked_sub(1 + payload)
}

/// The checkpoint flag word for a pack about to carry `orphans` of them.
///
/// Set AND cleared: a stale bit sends the next mount looking for orphan blocks
/// in a pack that has none, and a missing one leaves the blocks unread and the
/// inodes leaked.
/// # C: O(1)
pub fn flag_word(flags: u32, orphans: usize) -> u32 {
    if orphans == 0 { flags & !CP_ORPHAN_PRESENT_FLAG } else { flags | CP_ORPHAN_PRESENT_FLAG }
}
