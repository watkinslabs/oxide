// Handing a cached page to a user page table.
//
// The two entry points differ in whether they are allowed to allocate, and the
// difference is not cosmetic:
//
// | ask | this file | may allocate |
// |---|---|---|
// | what frame does this page live in | `frame_of` | no |
// | this page must be mappable | `ensure_frame` | yes |
//
// A residency question — `mincore`, a fault-around, a census — must not turn
// into a frame allocation, because the caller asked instead of touching. A
// write fault is the opposite: it has already decided the page will be written
// through a user PTE, so a page still on the heap has to become a frame there
// or the write has nowhere correct to land.

use crate::types::{InodeId, PAGE_BYTES};

use super::cache::PageCache;

fn index_of(page_offset: u64) -> u64 { page_offset / PAGE_BYTES as u64 }

impl PageCache {
    /// The machine frame page `page_offset` of `inode` already lives in, if it
    /// is resident and has one.
    ///
    /// Never converts, so asking is free and an unmapped page stays on the
    /// heap. # C: O(log inodes + height)
    pub fn frame_of(&self, inode: InodeId, page_offset: u64) -> Option<u64> {
        self.lookup(inode, page_offset)?.pa()
    }

    /// Make page `page_offset` of `inode` mappable and report its frame.
    ///
    /// `None` means the page is not resident, or no frame could be had. It is
    /// never a heap page silently handed out as if it were mappable: a caller
    /// that installed a user PTE over a heap buffer would be writing to memory
    /// this cache does not consider the page, which is the silent lost-write
    /// this whole surface exists to prevent.
    /// # C: O(page) on the first call for that page, O(1) after
    pub fn ensure_frame(&self, inode: InodeId, page_offset: u64) -> Option<u64> {
        self.lookup(inode, page_offset)?.to_frame()
    }

    /// Whether a user page table maps page `index` of `inode` right now.
    /// # C: O(height)
    pub fn page_user_mapped(&self, inode: InodeId, index: u64) -> bool {
        let Some(map) = self.mapping(inode) else { return false; };
        map.get(index).is_some_and(|p| p.user_mapped())
    }

    /// The page index a byte offset falls in. # C: O(1)
    pub fn index_of_offset(off: u64) -> u64 { index_of(off) }
}
