//! Which ids of each table block are free, remembered a block at a time.
//!
//! The point of the map is the SECOND pass. Reading a table block to find its
//! free ids costs a block read; the map records what that read found, so a
//! later pass that needs ids can re-walk what is already known instead of
//! reading the table again. That only works if the map is trusted exactly as
//! far as it has been filled — hence the scanned set: a block nobody has read
//! has no map, and an absent bit there means "unknown", not "in use".
//!
//! A block's map is allocated when the block is first scanned, not at mount.
//! A volume's table can be thousands of blocks and a mount typically touches a
//! handful, so sizing the map by the table would cost every mount the memory
//! of a table walk that never happens.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use crate::uapi::NAT_ENTRY_PER_BLOCK;

use super::limits::{NAT_BLOCK_MAP_BYTES, BITS_PER_NAT_BLOCK};

/// One table block's map, and how many bits in it are set.
///
/// The count is carried rather than recomputed because the only reader that
/// wants it is the walk that skips empty blocks, and recomputing it there
/// would make the skip cost the same as not skipping.
struct Block {
    bits: Vec<u8>,
    free: u32,
}

/// The maps, by the table block each describes.
#[derive(Default)]
pub struct Bitmaps {
    blocks: BTreeMap<u32, Block>,
}

/// Which table block an id's entry sits in. # C: O(1)
pub fn nat_ofs(nid: u32) -> u32 { nid / NAT_ENTRY_PER_BLOCK as u32 }

/// The first id of the table block holding `nid`. # C: O(1)
pub fn start_nid(nid: u32) -> u32 { nat_ofs(nid) * NAT_ENTRY_PER_BLOCK as u32 }

impl Bitmaps {
    /// Nothing scanned yet. # C: O(1)
    pub fn new() -> Self { Self { blocks: BTreeMap::new() } }

    /// Note that a table block has been read, so its map may be believed.
    ///
    /// Called BEFORE the block's entries are folded in: an update against an
    /// unscanned block is dropped, so marking afterwards would discard every
    /// bit the scan just established.
    /// # C: O(log blocks), plus one map on the first call for a block
    pub fn mark_scanned(&mut self, ofs: u32) {
        self.blocks.entry(ofs)
            .or_insert_with(|| Block { bits: vec![0u8; NAT_BLOCK_MAP_BYTES], free: 0 });
    }

    /// Whether a table block has been read. # C: O(log blocks)
    pub fn scanned(&self, ofs: u32) -> bool { self.blocks.contains_key(&ofs) }

    /// Record that `nid` is free, or that it is not.
    ///
    /// A block nobody has read is left alone: its map does not exist, and
    /// creating one from a single id would claim every other id in the block
    /// is in use. `build` says the caller is folding in a whole freshly-read
    /// block, in which case a bit going down is the scan establishing the
    /// count rather than an id leaving the free set — so the count is not
    /// lowered for something it never counted.
    /// # C: O(log blocks)
    pub fn update(&mut self, nid: u32, set: bool, build: bool) {
        let ofs = nat_ofs(nid);
        let Some(b) = self.blocks.get_mut(&ofs) else { return };
        let idx = (nid - start_nid(nid)) as usize;
        if idx >= BITS_PER_NAT_BLOCK { return; }
        let (byte, mask) = (idx / 8, 1u8 << (idx % 8));
        let was = b.bits[byte] & mask != 0;
        if set {
            if was { return; }
            b.bits[byte] |= mask;
            b.free += 1;
        } else {
            if !was { return; }
            b.bits[byte] &= !mask;
            if !build { b.free = b.free.saturating_sub(1); }
        }
    }

    /// Whether the map says `nid` is free. `false` for an unscanned block,
    /// which is the honest answer: nothing is known there. # C: O(log blocks)
    pub fn is_free(&self, nid: u32) -> bool {
        let Some(b) = self.blocks.get(&nat_ofs(nid)) else { return false };
        let idx = (nid - start_nid(nid)) as usize;
        idx < BITS_PER_NAT_BLOCK && b.bits[idx / 8] & (1u8 << (idx % 8)) != 0
    }

    /// Ids the map calls free in one table block, in order. # C: O(ids in a block)
    pub fn free_in_block(&self, ofs: u32) -> Vec<u32> {
        let Some(b) = self.blocks.get(&ofs) else { return Vec::new() };
        let base = ofs * NAT_ENTRY_PER_BLOCK as u32;
        (0..BITS_PER_NAT_BLOCK)
            .filter(|i| b.bits[i / 8] & (1u8 << (i % 8)) != 0)
            .map(|i| base + i as u32)
            .collect()
    }

    /// The scanned table blocks that the map says hold at least one free id,
    /// in order. A block with none is skipped by the walk that uses this, and
    /// skipping it is the whole reason the count is kept.
    /// # C: O(scanned blocks)
    pub fn blocks_with_free(&self) -> Vec<u32> {
        self.blocks.iter().filter(|(_, b)| b.free > 0).map(|(&o, _)| o).collect()
    }

    /// How many ids the map calls free in one table block. # C: O(log blocks)
    pub fn free_count(&self, ofs: u32) -> u32 {
        self.blocks.get(&ofs).map_or(0, |b| b.free)
    }

    /// Table blocks that have been read. # C: O(1)
    pub fn scanned_blocks(&self) -> usize { self.blocks.len() }

    /// Bytes the maps hold. # C: O(1)
    pub fn mem_bytes(&self) -> u64 {
        self.blocks.len() as u64
            * (NAT_BLOCK_MAP_BYTES + core::mem::size_of::<u32>() * 2) as u64
    }
}

#[cfg(test)]
#[path = "../tests/freenid/bitmap.rs"]
mod tests;
