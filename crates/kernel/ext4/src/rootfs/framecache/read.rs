// Shared-frame lookup and read-side cache facts.

use vfs::{KResult, VfsError};

use super::{Ext4FrameStore, PG};

impl Ext4FrameStore {
    /// Fallible shared lookup preserving memcg admission ENOMEM. # C: O(PG/bs)
    /// Acquire a MAP_SHARED PTE reference while the page-cache store lock
    /// proves the frame remains published, closing reclaim versus fault races.
    /// # C: O(PG/bs) miss; O(log N) hit
    pub(crate) fn shared_frame(&self, off: u64) -> KResult<Option<vfs::SharedFrame>> {
        let idx = off / PG as u64;
        // Fast path: a cached page needs NO inode read. Reading the inode on
        // every fault (a block-device read of the inode table + a metadata_csum
        // recompute) made process startup pay ~one block read per page faulted —
        // the dominant boot/service-startup latency (bash: ~14ms × ~1000 pages =
        // ~14s just to reach its first command). `ensure_page` already returns a
        // cached page without touching the inode; only a cache MISS needs the
        // inode's extent tree to fill a new page. A page is only ever cached for
        // a regular file, so the `is_reg` gate is implied on the hit path.
        // Copy the cached PA out and DROP the lock before branching — holding
        // the `pages` guard across the else arm would deadlock against
        // `ensure_page`, which re-locks `pages`.
        let cached = self.pages.lock().get(&idx).map(|page| page.pa);
        let pa = if let Some(pa) = cached {
            pa
        } else {
            let dinode = self.st.mount.read_inode(self.ino).map_err(|_| VfsError::Eio)?;
            if !dinode.is_reg() { return Ok(None); }
            self.ensure_page(&dinode, idx)?
        };
        let g = self.pages.lock();
        if g.get(&idx).map(|page| page.pa) != Some(pa) { return Err(VfsError::Eio); }
        // SAFETY: the published object reference is protected by `pages` until
        // this matching PTE reference has been added.
        unsafe { pmm::setup::inc_ref(pa); }
        drop(g);
        self.mark_dirty(idx);
        Ok(Some(vfs::SharedFrame { pa, map_ref_held: true }))
    }

    /// Non-faulting `mincore(2)` cache residency query. # C: O(log N_pages)
    pub(crate) fn mincore_page(&self, off: u64) -> bool {
        self.pages.lock().contains_key(&(off / PG as u64))
    }
}
