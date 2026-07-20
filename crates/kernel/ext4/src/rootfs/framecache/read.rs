// Shared-frame lookup and read-side cache facts.

use vfs::{KResult, VfsError};

use super::{Ext4FrameStore, PG};

impl Ext4FrameStore {
    /// Fallible shared lookup preserving memcg admission ENOMEM. # C: O(PG/bs)
    /// Acquire a MAP_SHARED PTE reference while the page-cache store lock
    /// proves the frame remains published, closing reclaim versus fault races.
    /// # C: O(PG/bs) miss; O(log N) hit
    pub(crate) fn shared_frame(&self, off: u64) -> KResult<Option<vfs::SharedFrame>> {
        let dinode = self.st.mount.read_inode(self.ino).map_err(|_| VfsError::Eio)?;
        if !dinode.is_reg() { return Ok(None); }
        let idx = off / PG as u64;
        let pa = self.ensure_page(&dinode, idx)?;
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
