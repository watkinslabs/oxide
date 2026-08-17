//! The mount's cache of compressed cluster blocks, as they lie on the medium.
//!
//! A compressed cluster is read as a run of blocks and then decompressed, so a
//! second read of the SAME cluster pays for the same blocks twice. This keeps
//! the compressed blocks — not the decompressed bytes — because that is what
//! the medium hands back and what a re-read would ask for again, and because
//! the compressed form is the small one: a cluster that compressed four blocks
//! into one costs one block here.
//!
//! Keyed by BLOCK ADDRESS rather than by file and offset. A block address is
//! what the read has in hand at the point the cache can answer, and it is what
//! goes stale: a cluster rewritten out of place leaves its old addresses no
//! longer part of any file, and every one of them must be dropped or the next
//! reader of that address gets the bytes that used to be there.
//!
//! The store is the shared page cache, under an inode number no file can have.
//! That is deliberate rather than convenient: a private map of cached blocks
//! beside the one the rest of the kernel keeps would be a second answer to
//! "what is cached", and the two would disagree the first time one of them was
//! invalidated and the other was not.
//!
//! Not the decompressed cluster: caching that would mean holding a whole
//! cluster's plain bytes per cluster and inventing an invalidation of its own,
//! and it is the medium traffic — not the codec — that a second read is paying
//! for.

use alloc::vec::Vec;

use core::cell::Cell;

use block::types::{InodeId, PAGE_BYTES};
use block::PageCache;

use crate::uapi::BLKSIZE;

/// Blocks one mount's compress cache holds before it stops taking more.
///
/// The reference gates each insertion on free memory — a share of what the
/// machine has, re-read every time — and DECLINES when it is short rather than
/// evicting something. Neither term of that share is observable here, so the
/// share becomes a fixed ceiling; what is kept is the behaviour AT the ceiling,
/// which is the part that is visible: a full cache stops taking new blocks and
/// keeps the ones it has. Evicting instead would make which reads are served
/// depend on the order of unrelated reads elsewhere in the volume.
///
/// Four thousand and ninety-six blocks is 16 MiB per mount at this build's
/// block size, and it is per MOUNT rather than per file or per volume size, so
/// no volume can make it grow.
pub const COMPRESS_CACHE_MAX_BLOCKS: usize = 4096;

// The mapping is indexed in pages and this cache is indexed in blocks, so the
// two units have to be the same one. They are, on every target this builds
// for; an arch where they are not needs a decision about which of the two the
// index counts, not a silent misfiling of every block.
const _: () = assert!(PAGE_BYTES == BLKSIZE);

/// One mount's compressed-block cache.
pub struct Cache {
    /// Absent when the mount did not ask for the cache. Absent rather than
    /// empty-and-ignored: an empty store that every path still consulted would
    /// be a lookup and a bound check per block on every mount.
    pages: Option<PageCache>,
    /// The mapping these blocks are filed under: an inode number one past the
    /// last a node id can take, so nothing that names a real file collides
    /// with it.
    ino: InodeId,
    /// Blocks this mount served from here rather than from the medium. Never
    /// derivable afterwards — the whole point of the cache is that the read
    /// left no trace at the device — so it is counted as it happens.
    hits: Cell<u64>,
}

impl Cache {
    /// # C: O(1)
    pub fn new(enabled: bool, compress_ino: u32) -> Self {
        Self {
            pages: if enabled { Some(PageCache::new()) } else { None },
            ino: InodeId(u64::from(compress_ino)),
            hits: Cell::new(0),
        }
    }

    /// Whether this mount caches compressed blocks at all. # C: O(1)
    pub fn enabled(&self) -> bool { self.pages.is_some() }

    /// # C: O(1)
    fn off(addr: u32) -> u64 { u64::from(addr) * BLKSIZE as u64 }

    /// The block at `addr`, if this mount has it.
    ///
    /// A hit is counted here rather than at the caller so that every path that
    /// can be served from the cache is counted by construction.
    /// # C: O(log cached)
    pub fn load(&self, addr: u32) -> Option<Vec<u8>> {
        let pages = self.pages.as_ref()?;
        let page = pages.lookup(self.ino, Self::off(addr))?;
        let bytes = page.data.lock().to_vec();
        self.hits.set(self.hits.get() + 1);
        Some(bytes)
    }

    /// Offer the block just read at `addr`, which belongs to file `ino`.
    ///
    /// The owner is recorded because the key cannot carry it: an address says
    /// nothing about which file it is part of, and dropping one file's cached
    /// blocks is a thing the mount has to be able to do.
    ///
    /// Declining is not an error and is not reported: the caller holds the
    /// bytes either way, and the only difference a decline makes is to the
    /// next read of the same address.
    /// # C: O(log cached)
    pub fn store(&self, addr: u32, ino: u32, data: &[u8]) {
        let Some(pages) = self.pages.as_ref() else { return };
        if data.len() != BLKSIZE { return; }
        pages.insert_new(self.ino, Self::off(addr), data.to_vec(), u64::from(ino),
                         COMPRESS_CACHE_MAX_BLOCKS);
    }

    /// Forget `len` blocks from `addr`, because they are no longer what any
    /// file's cluster is stored in.
    ///
    /// This is the one that keeps the cache honest. A cluster rewritten out of
    /// place leaves its old blocks holding the PREVIOUS contents; serving one
    /// of those to a later read of the same address — the address will be
    /// handed out again — returns bytes the file no longer has.
    /// # C: O(log cached + dropped)
    pub fn invalidate_range(&self, addr: u32, len: u32) {
        let Some(pages) = self.pages.as_ref() else { return };
        if len == 0 { return; }
        pages.invalidate_range(self.ino, Self::off(addr),
                               Self::off(addr) + u64::from(len) * BLKSIZE as u64);
    }

    /// Forget everything cached for file `ino`. # C: O(cached)
    pub fn invalidate_ino(&self, ino: u32) {
        let Some(pages) = self.pages.as_ref() else { return };
        pages.invalidate_tagged(self.ino, u64::from(ino));
    }

    /// Blocks held right now. # C: O(1)
    pub fn blocks(&self) -> usize { self.pages.as_ref().map_or(0, |p| p.cached_count()) }

    /// Reads served from here since the mount. # C: O(1)
    pub fn hits(&self) -> u64 { self.hits.get() }
}

#[cfg(test)]
#[path = "../tests/compress/cache.rs"]
mod tests;
