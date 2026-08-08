// Per-granule pool counters and their state machine.
//
// Pure accounting: no allocator contact, no locks, no globals — so every
// decision below (how many pages a resize must add or release, whether a
// reservation is satisfiable, whether a hand-out consumes a reservation) is
// driven directly by hosted tests. `pool` owns the single locked instance and
// performs the physical work each plan describes.

/// Counters for one huge-page granule.
///
/// `nr` counts every page the pool owns, persistent and surplus alike;
/// `surplus` counts the subset taken beyond the operator's target while a
/// reservation demanded them, so `persistent = nr - surplus` is the count the
/// operator actually asked for.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct HstateCounts {
    /// Operator target for the persistent pool.
    pub max: u64,
    /// Pages the pool owns (persistent + surplus).
    pub nr: u64,
    /// Pages the pool owns and has not handed out.
    pub free: u64,
    /// Pages promised to a mapping that has not faulted them yet.
    pub resv: u64,
    /// Pages taken beyond `max` to satisfy a reservation.
    pub surplus: u64,
    /// Ceiling on `surplus`.
    pub overcommit: u64,
}

/// Work a resize of the persistent pool requires.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct ResizePlan {
    /// Surplus pages to reclassify as persistent — already owned, no
    /// allocation needed.
    pub absorb_surplus: u64,
    /// Fresh pages to take from the buddy allocator.
    pub alloc: u64,
    /// Free pages to release back to the buddy allocator.
    pub release: u64,
}

impl HstateCounts {
    /// Pages held on the operator's behalf rather than to cover an
    /// over-commitment.
    /// # C: O(1)
    pub const fn persistent(&self) -> u64 { self.nr - self.surplus }

    /// Free pages not already promised to some mapping.
    /// # C: O(1)
    pub const fn unreserved_free(&self) -> u64 { self.free.saturating_sub(self.resv) }

    /// Work needed to move the persistent pool to `count`.
    ///
    /// Growing absorbs surplus pages before allocating: they are already
    /// owned, so charging the operator for a fresh allocation would double
    /// the memory the pool holds for one requested page.
    ///
    /// Shrinking never releases a page a reservation still covers — the floor
    /// is the count that keeps every outstanding promise satisfiable, so a
    /// `nr_hugepages` write cannot revoke memory a running mapping is owed.
    /// # C: O(1)
    pub fn plan_resize(&self, count: u64) -> ResizePlan {
        let persistent = self.persistent();
        if count > persistent {
            let needed = count - persistent;
            let absorb = core::cmp::min(needed, self.surplus);
            return ResizePlan { absorb_surplus: absorb, alloc: needed - absorb, release: 0 };
        }
        let promised = self.resv.saturating_add(persistent).saturating_sub(self.free);
        let floor = core::cmp::max(count, promised);
        let release = persistent.saturating_sub(floor);
        ResizePlan { absorb_surplus: 0, alloc: 0, release: core::cmp::min(release, self.free) }
    }

    /// Apply a completed resize. `absorbed`/`allocated`/`released` are what
    /// the pool actually managed, which may be short of the plan when the
    /// buddy allocator ran out.
    /// # C: O(1)
    pub fn commit_resize(&mut self, count: u64, absorbed: u64, allocated: u64, released: u64) {
        self.surplus -= absorbed;
        self.nr += allocated;
        self.free += allocated;
        self.nr -= released;
        self.free -= released;
        self.max = count;
    }

    /// Surplus pages that must be allocated for a `delta`-page reservation, or
    /// `Err(())` when the request exceeds what the pool may hold.
    ///
    /// A reservation is a promise the pool will not later break, so it is
    /// admitted against pages that are free AND unpromised; anything beyond
    /// that must be backed by new memory before the promise is made.
    /// # C: O(1)
    pub fn plan_reserve(&self, delta: u64) -> Result<u64, ()> {
        let available = self.unreserved_free();
        if delta <= available { return Ok(0); }
        let needed = delta - available;
        if self.surplus + needed > self.overcommit { return Err(()); }
        Ok(needed)
    }

    /// Record a reservation whose `surplus_added` backing pages were obtained.
    /// # C: O(1)
    pub fn commit_reserve(&mut self, delta: u64, surplus_added: u64) {
        self.nr += surplus_added;
        self.free += surplus_added;
        self.surplus += surplus_added;
        self.resv += delta;
    }

    /// Drop a reservation of `delta` pages that was never consumed.
    /// # C: O(1)
    pub fn unreserve(&mut self, delta: u64) { self.resv = self.resv.saturating_sub(delta); }

    /// Take one page off the free list. `reserved` says the caller holds a
    /// reservation covering it, which is consumed with the page; without one
    /// the page may only come from the unpromised remainder, so a mapping
    /// with no reservation can never eat the pages another mapping is owed.
    /// # C: O(1)
    pub fn dequeue(&mut self, reserved: bool) -> bool {
        if reserved {
            if self.free == 0 || self.resv == 0 { return false; }
            self.free -= 1;
            self.resv -= 1;
            return true;
        }
        if self.unreserved_free() == 0 { return false; }
        self.free -= 1;
        true
    }

    /// Return one page to the free list.
    /// # C: O(1)
    pub fn enqueue(&mut self) { self.free += 1; }

    /// Surplus pages the pool may now give back: free pages beyond both the
    /// operator's target and every outstanding promise.
    /// # C: O(1)
    pub fn surplus_to_return(&self) -> u64 {
        let spare = self.free.saturating_sub(self.resv);
        core::cmp::min(self.surplus, spare)
    }

    /// Record `n` surplus pages handed back to the buddy allocator.
    /// # C: O(1)
    pub fn commit_return_surplus(&mut self, n: u64) {
        self.surplus -= n;
        self.nr -= n;
        self.free -= n;
    }
}
