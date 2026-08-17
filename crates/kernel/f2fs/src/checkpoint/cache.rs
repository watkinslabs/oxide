//! The mount's mapping of METADATA blocks, as they lie on the medium.
//!
//! Everything outside the main area is metadata by the layout's own
//! definition: the two checkpoint packs, the two copies of the node table, the
//! two copies of the segment table, and the summary area. Those blocks are
//! read over and over — resolving one node id reads a table block, and the
//! next node id in the same block reads it again — so without a mapping every
//! lookup, every allocation and every checkpoint pays the medium for bytes the
//! mount already had.
//!
//! Keyed by BLOCK ADDRESS, in the mapping of the volume's own metadata inode.
//! That inode number is the format's, not one invented here: the superblock
//! names it and no file may use it, so the mapping cannot collide with a
//! file's pages and it is the same index the reference files the same blocks
//! under.
//!
//! COHERENT BY WRITE-THROUGH, not by invalidation-after-the-fact. A metadata
//! block lives at a fixed address for the life of the volume — the table block
//! for a node id is where the version bitmap says it is, a summary block is
//! its segment's — so a metadata block never goes out of use the way a file's
//! block does. What it does is CHANGE, and the write that changes it is the
//! one event the mapping has to see. Every metadata write in this filesystem
//! passes through one function, and that is where the new bytes land here too;
//! a mapping that only invalidated would still be correct but would throw away
//! the block a checkpoint is about to read back.

use alloc::vec::Vec;

use core::cell::Cell;

use block::types::{InodeId, PAGE_BYTES};
use block::PageCache;

use crate::uapi::BLKSIZE;

/// Blocks one mount's metadata mapping holds before it stops taking more.
///
/// RECLAIM IS THE PRIMARY BOUND, and it is the reference's only one: the
/// per-cache free-memory share that gates the compressed-block cache has no
/// metadata term, so the reference lets this mapping grow and lets page
/// reclaim take from it like any other. That holds here too. Every block
/// arrives clean — this cache inserts and never dirties — so the shared
/// cache's shrinker may evict any of them, and an evicted block costs a
/// re-read and nothing else.
///
/// This ceiling is a SECOND bound on top of reclaim, for the one thing reclaim
/// cannot express: it reacts to machine pressure after the fact, so one mount
/// walking a large summary area in order could push the machine's file cache
/// out before that feedback arrives. Sixteen MiB per MOUNT at this build's
/// block size, and not a share of the volume, so no volume can make it grow.
///
/// Declining at the ceiling rather than evicting is deliberate: choosing a
/// victim is the shared cache's job, and a private replacement policy here
/// would be a second answer to "which cached page goes next" that would
/// disagree with the real one the moment either changed. Unlike the
/// compressed-block cache — written when nothing reclaimed, so a full cache
/// stayed full for the life of the mount — declining here is not a wall:
/// reclaim keeps freeing slots, so the mapping follows a moving working set
/// instead of freezing on whichever blocks were read first.
pub const META_CACHE_MAX_BLOCKS: usize = 4096;

// The mapping is indexed in pages and this cache is indexed in blocks, so the
// two units have to be the same one. They are, on every target this builds
// for; an arch where they are not needs a decision about which of the two the
// index counts, not a silent misfiling of every block.
const _: () = assert!(PAGE_BYTES == BLKSIZE);

/// One mount's metadata mapping.
pub struct Cache {
    pages: PageCache,
    /// The mapping these blocks are filed under: the volume's metadata inode,
    /// as the superblock names it.
    ino: InodeId,
    /// First metadata block, and one past the last.
    ///
    /// Held rather than recomputed from the superblock at each call because
    /// this is asked on EVERY block read the volume makes, including the main
    /// area's, and because it is the one place that decides what "metadata"
    /// means for the mapping — a second derivation elsewhere could disagree
    /// and file a file's block here.
    start: u32,
    end: u32,
    /// Blocks this mount served from here rather than from the medium. Never
    /// derivable afterwards — the whole point of the mapping is that the read
    /// left no trace at the device — so it is counted as it happens.
    hits: Cell<u64>,
}

impl Cache {
    /// The mapping for a volume whose metadata runs from `cp_blkaddr` up to
    /// `main_blkaddr`, filed under `meta_ino`.
    ///
    /// The superblock copies sit BELOW `cp_blkaddr` and are deliberately
    /// outside: they are read once at mount and are written by a path that
    /// does not go through this volume's block writer, so a mapping that held
    /// them could be left holding the previous copy.
    /// # C: O(1)
    pub fn new(meta_ino: u32, cp_blkaddr: u32, main_blkaddr: u32) -> Self {
        Self {
            pages: PageCache::new(),
            ino: InodeId(u64::from(meta_ino)),
            start: cp_blkaddr,
            end: main_blkaddr.max(cp_blkaddr),
            hits: Cell::new(0),
        }
    }

    /// Whether `addr` is a block this mapping is responsible for. # C: O(1)
    pub fn covers(&self, addr: u32) -> bool { addr >= self.start && addr < self.end }

    /// # C: O(1)
    fn off(addr: u32) -> u64 { u64::from(addr) * BLKSIZE as u64 }

    /// The block at `addr`, if this mount has it.
    ///
    /// A hit is counted here rather than at the caller so that every path that
    /// can be served from the mapping is counted by construction.
    /// # C: O(log cached)
    pub fn load(&self, addr: u32) -> Option<Vec<u8>> {
        let page = self.pages.lookup(self.ino, Self::off(addr))?;
        let bytes = page.data.lock().to_vec();
        self.hits.set(self.hits.get() + 1);
        Some(bytes)
    }

    /// Offer the block just read at `addr`.
    ///
    /// Declining is not an error and is not reported: the caller holds the
    /// bytes either way, and the only difference a decline makes is to the
    /// next read of the same address.
    /// # C: O(log cached)
    pub fn store(&self, addr: u32, data: &[u8]) {
        if data.len() != BLKSIZE { return; }
        self.pages.insert_new(self.ino, Self::off(addr), data.to_vec(), 0,
                              META_CACHE_MAX_BLOCKS);
    }

    /// Say that `addr` now holds `data`, because a write just put it there.
    ///
    /// This is the one that keeps the mapping honest, and it is the reason a
    /// metadata read may be served without asking the medium at all: a block
    /// the mount rewrote and then read back must come back as what was
    /// written, not as what was there before it.
    ///
    /// A block the mapping does not already hold is NOT taken. Writing does
    /// not make a block worth holding — a checkpoint writes every summary
    /// block it owns and reads none of them back — and filling the mapping
    /// from the write path would spend the whole ceiling on the blocks a
    /// checkpoint pushed through it.
    /// # C: O(log cached + BLKSIZE)
    pub fn overwrite(&self, addr: u32, data: &[u8]) {
        if data.len() != BLKSIZE { return; }
        let Some(page) = self.pages.lookup(self.ino, Self::off(addr)) else { return };
        page.data.lock().copy_from_slice(data);
    }

    /// Forget `len` blocks from `addr`.
    ///
    /// For a write whose bytes this mount cannot know: the medium was handed
    /// something it will transform before it lands, so what is at the address
    /// afterwards is not what was passed down, and keeping the old block would
    /// serve bytes the address no longer holds.
    /// # C: O(log cached + dropped)
    pub fn invalidate_range(&self, addr: u32, len: u32) {
        if len == 0 { return; }
        self.pages.invalidate_range(self.ino, Self::off(addr),
                                    Self::off(addr) + u64::from(len) * BLKSIZE as u64);
    }

    /// Blocks held right now. # C: O(1)
    pub fn blocks(&self) -> usize { self.pages.cached_count() }

    /// Reads served from here since the mount. # C: O(1)
    pub fn hits(&self) -> u64 { self.hits.get() }
}

#[cfg(test)]
#[path = "../tests/checkpoint/cache.rs"]
mod tests;
