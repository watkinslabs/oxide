// Per-mount huge-page accounting — Linux `hugepage_subpool`.
//
// A hugetlbfs mount's `size=` becomes a maximum and its `min_size=` becomes a
// reservation taken once at mount time and held for the mount's lifetime. Both
// are optional and independent; `NO_LIMIT` marks an absent one.
//
// Pure accounting, no allocator contact: the caller performs whatever global
// reservation the returned charge names.

/// Sentinel for an unset maximum or minimum.
pub const NO_LIMIT: i64 = -1;

/// A subpool's answer to a request for `delta` pages.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SubpoolCharge {
    /// Pages the GLOBAL pool must additionally reserve. Smaller than the
    /// request when the mount's minimum-size reservation already covers part
    /// of it, because those pages were reserved globally at mount time.
    pub global_delta: i64,
}

/// Per-mount maximum/minimum huge-page accounting.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Subpool {
    /// `size=` in pages, or [`NO_LIMIT`].
    pub max_hpages: i64,
    /// `min_size=` in pages, or [`NO_LIMIT`].
    pub min_hpages: i64,
    /// Pages currently charged to the mount.
    pub used_hpages: i64,
    /// Unconsumed remainder of the minimum-size reservation.
    pub rsv_hpages: i64,
}

impl Subpool {
    /// A subpool with both limits set. `min_hpages` starts fully reserved
    /// because the mount took that reservation globally when it was created.
    /// # C: O(1)
    pub const fn new(max_hpages: i64, min_hpages: i64) -> Self {
        Self { max_hpages, min_hpages, used_hpages: 0, rsv_hpages: if min_hpages == NO_LIMIT { 0 } else { min_hpages } }
    }

    /// Whether either limit is set — a mount with neither needs no subpool at
    /// all and charges straight through to the global pool.
    /// # C: O(1)
    pub const fn is_limited(max_hpages: i64, min_hpages: i64) -> bool {
        max_hpages != NO_LIMIT || min_hpages != NO_LIMIT
    }

    /// Charge `delta` pages. `Err(())` means the mount's maximum is reached
    /// and nothing was charged.
    /// # C: O(1)
    pub fn get_pages(&mut self, delta: i64) -> Result<SubpoolCharge, ()> {
        let mut ret = delta;
        if self.max_hpages != NO_LIMIT {
            if self.used_hpages + delta > self.max_hpages { return Err(()); }
            self.used_hpages += delta;
        }
        if self.min_hpages != NO_LIMIT && self.rsv_hpages != 0 {
            if delta > self.rsv_hpages {
                ret = delta - self.rsv_hpages;
                self.rsv_hpages = 0;
            } else {
                ret = 0;
                self.rsv_hpages -= delta;
            }
        }
        Ok(SubpoolCharge { global_delta: ret })
    }

    /// Uncharge `delta` pages, returning how many GLOBAL reservations the
    /// caller must drop. Fewer than `delta` when the mount takes the pages
    /// back into its minimum-size reservation, which it keeps for its lifetime.
    /// # C: O(1)
    pub fn put_pages(&mut self, delta: i64) -> i64 {
        let mut ret = delta;
        if self.max_hpages != NO_LIMIT { self.used_hpages -= delta; }
        if self.min_hpages != NO_LIMIT && self.used_hpages < self.min_hpages {
            ret = if self.rsv_hpages + delta <= self.min_hpages { 0 }
                  else { self.rsv_hpages + delta - self.min_hpages };
            self.rsv_hpages += delta;
            if self.rsv_hpages > self.min_hpages { self.rsv_hpages = self.min_hpages; }
        }
        ret
    }

    /// Pages the mount reports as its total, or `None` when unlimited.
    /// # C: O(1)
    pub const fn blocks(&self) -> Option<u64> {
        if self.max_hpages == NO_LIMIT { None } else { Some(self.max_hpages as u64) }
    }

    /// Pages the mount reports as available, or `None` when unlimited.
    /// # C: O(1)
    pub const fn blocks_free(&self) -> Option<u64> {
        if self.max_hpages == NO_LIMIT { None } else { Some((self.max_hpages - self.used_hpages) as u64) }
    }
}
