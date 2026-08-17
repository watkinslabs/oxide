//! A file's own pages — the per-inode mapping a file's DATA is read through.
//!
//! Keyed by `(inode number, file page index)`, which is the key the rest of
//! the kernel's page cache is keyed by and the key the reference files a
//! file's data under. That choice is the whole design, and it is not the one
//! the other two mappings in this filesystem made:
//!
//! - The metadata mapping and the compressed-block cache are keyed by BLOCK
//!   ADDRESS, because a metadata block lives at a fixed address and a stored
//!   compressed image is asked for by the address the cluster reader has in
//!   hand.
//! - A file's page is asked for by OFFSET, and its address moves. Every write
//!   is out of place and the cleaner relocates live blocks, so an
//!   address-keyed mapping of file data would have to be invalidated on every
//!   move of bytes that did not change — and, worse, would answer a read of
//!   the new address with nothing while holding the identical bytes under the
//!   old one. Keying by offset makes a relocation invisible to the mapping,
//!   which is what it should be.
//!
//! What is held is PLAINTEXT, decrypted on the way in, and attested on the
//! way in where the file is sealed. That is what a reader gets and it is
//! where the reference does both: caching ciphertext would make every hit pay
//! the cipher again, and checking the tree per ACCESS rather than per fill
//! would hash the same page on every read of it.
//!
//! COHERENT BY INVALIDATION, at the points where a file's contents at an
//! offset stop being what the mapping holds. Every content change in this
//! filesystem either lands at a NEW address, which one notification covers,
//! or is one of the two writers that change a block WHERE IT LIES:
//!
//! | event | site |
//! |---|---|
//! | a block's address changes | the one mapping-change notification every out-of-place writer funnels through |
//! | a file is shortened | the range invalidation the tail trim already makes, since a whole subtree goes without per-address notice |
//! | a pinned file's block is rewritten in place | the in-place writer |
//! | a file's blocks are erased in place | the secure-erase loop |
//! | an inode number is about to be reused | the inode free |
//! | a file is sealed behind a hash tree | the seal, because everything filed before it was filed unattested |
//!
//! A file with an atomic-write span open is read out of its shadow inode and
//! is not filed here at all; the commit that hands the shadow's blocks to the
//! file goes through the address notification like any other writer.
//!
//! ONLY the plain data path is filed here. A compressed file's unpacked
//! cluster is not: the cluster writer SKIPS the address update for a slot
//! whose stored value does not change — the head slot holds the same sentinel
//! before and after a rewrite — so the per-address notification does not fire
//! for the cluster's first page, and filing unpacked pages without a
//! cluster-wide invalidation beside it would serve the pre-rewrite bytes. The
//! compressed blocks themselves are already held, keyed by address.
//!
//! Nothing here is ever dirty. A write reaches the medium inside the call
//! that makes it and drops the page, so every page in this mapping is clean
//! and machine-wide reclaim may take any of them; an evicted page costs a
//! re-read and nothing else. Deferred allocation — dirty pages written back
//! at a checkpoint, the address chosen then — is the write side of this
//! mapping and is not here.

use alloc::vec::Vec;

use core::cell::Cell;

use syscall::errno::Errno;

use block::types::{BlockError, InodeId, PAGE_BYTES};
use block::PageCache;

use crate::uapi::BLKSIZE;

// The mapping is indexed in pages and a file is addressed in blocks, so the
// two units have to be the same one. They are, on every target this builds
// for; an arch where they are not needs a decision about which of the two the
// index counts, not a silent misfiling of every block.
const _: () = assert!(PAGE_BYTES == BLKSIZE);

/// One mount's mapping of its files' data pages.
pub struct Cache {
    pages: PageCache,
    /// Pages this mount served from here rather than from the medium. Never
    /// derivable afterwards — the whole point of the mapping is that the read
    /// left no trace at the device — so it is counted as it happens.
    hits: Cell<u64>,
    /// Pages the mapping could not answer and a reader had to fetch.
    misses: Cell<u64>,
}

impl Default for Cache {
    fn default() -> Self { Self::new() }
}

impl Cache {
    /// # C: O(1)
    pub fn new() -> Self {
        Self { pages: PageCache::new(), hits: Cell::new(0), misses: Cell::new(0) }
    }

    /// # C: O(1)
    fn key(ino: u32) -> InodeId { InodeId(u64::from(ino)) }

    /// # C: O(1)
    fn off(index: u64) -> u64 { index.wrapping_mul(BLKSIZE as u64) }

    /// Page `index` of file `ino`, fetching it with `fetch` on a miss.
    ///
    /// `fetch` runs at most once per miss and its bytes are what the mapping
    /// keeps, so a fetch that fails leaves nothing behind to be served later.
    /// A fetch that returns the wrong length is refused rather than padded:
    /// a short page filed here would answer a later read with zeroes the file
    /// does not have.
    /// # C: O(height) on a hit, O(fetch) on a miss
    pub fn read<F>(&self, ino: u32, index: u64, fetch: F) -> Result<Vec<u8>, Errno>
    where F: FnOnce() -> Result<Vec<u8>, Errno>
    {
        let (key, off) = (Self::key(ino), Self::off(index));
        if let Some(page) = self.pages.lookup(key, off) {
            self.hits.set(self.hits.get() + 1);
            return Ok(page.data.lock().clone());
        }
        self.misses.set(self.misses.get() + 1);
        // The fetch's OWN error has to survive the round trip: the cache
        // speaks one error type and this filesystem speaks another, and
        // folding `ENOKEY` or `EFBIG` into a generic I/O error at the boundary
        // would report a missing key as a broken disk.
        let held: Cell<Option<Errno>> = Cell::new(None);
        let got = self.pages.read_page_with(key, off, || match fetch() {
            Ok(bytes) if bytes.len() == BLKSIZE => Ok(bytes),
            Ok(_) => { held.set(Some(Errno::Eio)); Err(BlockError::Eio) }
            Err(e) => { held.set(Some(e)); Err(BlockError::Eio) }
        });
        match got {
            Ok(page) => Ok(page.data.lock().clone()),
            Err(_) => Err(held.get().unwrap_or(Errno::Eio)),
        }
    }

    /// Forget page `index` of `ino`, because what the file has at that offset
    /// is no longer what the mapping holds.
    /// # C: O(height)
    pub fn forget(&self, ino: u32, index: u64) {
        let off = Self::off(index);
        self.pages.invalidate_range(Self::key(ino), off, off + BLKSIZE as u64);
    }

    /// Forget every page of `ino` from `first` on — what shortening a file
    /// leaves behind. A page past the new end that survived would answer a
    /// read after the file grew again with the bytes it used to have.
    /// # C: O(pages of this inode)
    pub fn forget_from(&self, ino: u32, first: u64) {
        self.pages.invalidate_range(Self::key(ino), Self::off(first), u64::MAX);
    }

    /// Forget everything held for `ino`.
    ///
    /// For an inode number about to be handed to something else: a page left
    /// behind would answer for whatever file next takes the id.
    /// # C: O(pages of this inode)
    pub fn forget_inode(&self, ino: u32) { self.pages.invalidate(Self::key(ino)); }

    /// Pages held right now. # C: O(inodes)
    pub fn pages(&self) -> usize { self.pages.cached_count() }

    /// Reads served from here since the mount. # C: O(1)
    pub fn hits(&self) -> u64 { self.hits.get() }

    /// Reads this mapping could not answer since the mount. # C: O(1)
    pub fn misses(&self) -> u64 { self.misses.get() }
}

#[cfg(test)]
#[path = "tests/filemap.rs"]
mod tests;
