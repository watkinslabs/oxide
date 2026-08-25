use super::{File, FileRaState, DEFAULT_RA_PAGES};

impl File {
    /// Snapshot of the `f_ra` readahead window state. # C: O(1)
    pub fn ra_state(&self) -> FileRaState { *self.f_ra.lock() }

    /// Set the readahead window ceiling in pages (Linux `POSIX_FADV_SEQUENTIAL`
    /// doubles the default, `POSIX_FADV_RANDOM` zeroes it to disable RA). # C: O(1)
    pub fn set_ra_pages(&self, pages: u32) { self.f_ra.lock().ra_pages = pages; }

    /// `POSIX_FADV_NORMAL` — restore the backing device's default readahead
    /// window (`file->f_ra.ra_pages = bdi->ra_pages`).
    /// The ceiling itself is `f_ra`'s to own, so fadvise names the intent and
    /// does not carry the number. # C: O(1)
    pub fn ra_set_normal(&self) { self.set_ra_pages(DEFAULT_RA_PAGES); }

    /// `POSIX_FADV_SEQUENTIAL` — use the backend's Linux sequential multiplier.
    /// # C: O(1)
    pub fn ra_set_sequential(&self) {
        let multiplier = self.f_op.sequential_ra_multiplier(self);
        self.set_ra_pages(DEFAULT_RA_PAGES.saturating_mul(multiplier));
    }

    /// `POSIX_FADV_RANDOM` — disable readahead for this open. Linux expresses
    /// this as `FMODE_RANDOM`, which `page_cache_sync_ra` reads to bypass the
    /// sequential heuristic; [`File::ra_ondemand`] expresses the same state as
    /// `ra_pages == 0`, so there is one representation of "no readahead", not
    /// two that can disagree. # C: O(1)
    pub fn ra_set_random(&self) { self.set_ra_pages(0); }

    /// On-demand readahead advance (Linux `ondemand_readahead` core): from the
    /// read's first page `index`, page count `req`, and whether the PG_readahead
    /// marker was hit, update `f_ra` and return the `(start, size, async_size)`
    /// window to submit (page-cache fill is the block lane). `ra_pages == 0`
    /// (FADV_RANDOM) disables RA; a sequential continuation (`index==start+size`)
    /// or marker hit grows via `next_ra_size`; SOF / a jump re-seeds via
    /// `init_ra_size`. # C: O(1)
    pub fn ra_ondemand(&self, index: u64, req: u32, hit_marker: bool) -> (u64, u32, u32) {
        let mut ra = self.f_ra.lock();
        let max = ra.ra_pages;
        if max == 0 { *ra = FileRaState { start: index, ..*ra }; return (index, 0, 0); }
        let sequential = index == ra.start + ra.size as u64;
        if index != 0 && (sequential || hit_marker) {
            ra.start = if sequential { ra.start + ra.size as u64 } else { index + 1 };
            ra.size = ra.next_ra_size(max);
            ra.async_size = ra.size;
        } else {
            ra.start = index;
            ra.size = FileRaState::init_ra_size(req, max);
            ra.async_size = if ra.size > req { ra.size - req } else { ra.size };
        }
        (ra.start, ra.size, ra.async_size)
    }

    /// Advance the readahead window and hand it to the address space to fill
    /// (Linux `page_cache_sync_readahead` -> `page_cache_ra_unbounded`). This
    /// is the ONE place the window computed by [`File::ra_ondemand`] becomes
    /// I/O; without it `ra_pages` — and therefore every `posix_fadvise` hint
    /// that sets it — is dead state.
    /// # C: O(window) on a miss
    pub fn submit_readahead(&self, index: u64, req: u32) {
        let (start, size, _async_size) = self.ra_ondemand(index, req, false);
        if size == 0 { return; } // FADV_RANDOM: no readahead for this open
        if let Some(m) = self.inode.i_mapping() { m.readahead(start, size as u64); }
    }

}
