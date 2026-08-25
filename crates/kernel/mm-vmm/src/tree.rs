// VMA tree per `11§4`. `BTreeMap<UserVirtAddr, Vma>` keyed by VMA start;
// invariant 1 (non-overlap, `11§2`) enforced on every `insert` and
// preserved by `remove_range` / `mprotect_range`. Adjacent VMAs with
// identical prot/flags/backing-kind and contiguous file offsets are
// merged after insert (`11§4`).
//
// The tree is the inner state of `AddressSpace.vmas`; the outer
// `RwLock<VmaTree>` (`11§9`) lives at the AS layer once `AddressSpace`
// is implemented in a later P1-N.
//
// Page-table walks, TLB shootdowns, and per-page metadata are out of
// scope for this PR; this is the data-structure foundation only.

use core::ops::Bound;

use alloc::collections::BTreeMap;
use hal::{UserVirtAddr, USER_VA_END};

use crate::vma::Vma;
use crate::Error;

mod anon_name;
mod lookup;
// Module manifest: anon_name = PR_SET_VMA_ANON_NAME range writer;
// policy = mbind(2)/set_mempolicy_home_node(2) range writers.
mod policy;
#[path = "tree_ranges.rs"]
mod ranges;
pub use policy::HomeNodeErr;

fn raw_end_key(end: u64) -> Option<UserVirtAddr> {
    UserVirtAddr::new(end).or_else(|| if end == USER_VA_END { UserVirtAddr::new(USER_VA_END - 1) } else { None })
}

/// Sorted, non-overlapping set of VMAs covering some subset of user
/// virtual address space. Lookup `O(log N)` (`11§4`); insert worst-case
/// `O(log N)` plus up to two adjacent merges.
pub struct VmaTree {
    pub(crate) map: BTreeMap<UserVirtAddr, Vma>,
}

impl Drop for VmaTree {
    /// Linux `exit_mmap` -> `remove_vma`: every VMA still mapped when the
    /// address space goes away runs `vm_ops->close`. Without it a process
    /// that exits without calling `shmdt` — the normal case — leaves
    /// `shm_nattch` permanently raised, so an `IPC_RMID`ed segment is never
    /// reclaimed and `ipcs -m` reports attachers that no longer exist.
    /// # C: O(N_vmas)
    fn drop(&mut self) {
        for v in self.map.values() { crate::vm_ops::vma_closed(v); }
    }
}

impl VmaTree {
    /// # C: O(1)
    pub fn new() -> Self { Self { map: BTreeMap::new() } }

    /// Every VMA that enters the tree goes through here, so Linux's
    /// `vm_ops->open` runs exactly once per VMA birth — `shmat`'s mmap, a
    /// fork copy, and each fragment of a split alike.
    /// # C: O(log N)
    fn map_put(&mut self, key: UserVirtAddr, vma: Vma) {
        crate::vm_ops::vma_opened(&vma);
        self.map.insert(key, vma);
    }

    /// Put a VMA back that never left as far as `vm_ops` is concerned — a
    /// re-key, not a birth. Pairs with [`VmaTree::map_take`].
    /// # C: O(log N)
    fn map_reinsert(&mut self, key: UserVirtAddr, vma: Vma) { self.map.insert(key, vma); }

    /// Take a VMA out WITHOUT running `vm_ops->close`. Every caller either
    /// re-keys it or replaces it with fragments and then closes it
    /// explicitly. Splits MUST open the fragments before closing the
    /// original: closing first would take a one-attachment `SHM_DEST`
    /// segment to zero mid-mprotect, destroying it under the fragments that
    /// are about to reference it.
    /// # C: O(log N)
    fn map_take(&mut self, key: &UserVirtAddr) -> Option<Vma> { self.map.remove(key) }

    /// # C: O(1)
    pub fn len(&self) -> usize { self.map.len() }

    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.map.is_empty() }

    /// Find the VMA containing `va`. Returns `None` if `va` falls in a
    /// hole. Lookup is `O(log N)` per `11§4`.
    /// # C: O(log N)
    pub fn find_containing(&self, va: UserVirtAddr) -> Option<&Vma> {
        let (_, v) = self.map.range(..=va).next_back()?;
        if v.contains(va) { Some(v) } else { None }
    }

    /// F158: find a `MAP_GROWSDOWN` VMA whose `start` lies in
    /// `(va, va + max_gap]` — used by the page-fault handler to
    /// auto-extend a stack VMA when access lands just below it.
    /// Linux uses a 64 KiB stack guard gap by default. Returns the
    /// VMA reference for the kernel-side caller to extend.
    /// # C: O(log N)
    pub fn find_growsdown_above(&self, va: UserVirtAddr, max_gap: u64) -> Option<&Vma> {
        // The next-key-up entry from va.
        let (_, v) = self.map.range(va..).next()?;
        if !v.flags.contains(crate::vma::VmaFlags::GROWSDOWN) { return None; }
        let gap = v.start.as_u64().checked_sub(va.as_u64())?;
        if gap > max_gap { return None; }
        Some(v)
    }

    /// F158: extend the `start` of a `MAP_GROWSDOWN` VMA at
    /// `current_start` downward to `new_start` (page-aligned, less
    /// than `current_start`). Returns `Err(Inval)` if the VMA isn't
    /// present, isn't GROWSDOWN, or `new_start` overlaps a lower
    /// neighbor. Used by the stack-grow page-fault path.
    /// # C: O(log N)
    pub fn extend_growsdown_start(
        &mut self,
        current_start: UserVirtAddr,
        new_start: UserVirtAddr,
    ) -> Result<(), Error> {
        if new_start.as_u64() >= current_start.as_u64() { return Err(Error::Inval); }
        if (new_start.as_u64() & (hal::PAGE_SIZE_BYTES - 1)) != 0 { return Err(Error::Inval); }
        // Lower neighbor must not overlap the new range.
        if let Some((_, lower)) = self.map.range(..current_start).next_back() {
            if lower.end.as_u64() > new_start.as_u64() { return Err(Error::Inval); }
        }
        // Take the VMA out, mutate, re-insert under the new key.
        let mut v = self.map_take(&current_start).ok_or(Error::Inval)?;
        if !v.flags.contains(crate::vma::VmaFlags::GROWSDOWN) {
            // Re-insert unchanged on misuse.
            self.map_reinsert(current_start, v);
            return Err(Error::Inval);
        }
        v.start = new_start;
        self.map_reinsert(new_start, v);
        Ok(())
    }

    /// Iterator over VMAs in ascending address order.
    /// # C: O(N) total
    pub fn iter(&self) -> impl Iterator<Item = &Vma> {
        self.map.values()
    }

    /// Insert `vma`. Returns `Err(Inval)` if the range is degenerate or
    /// overlaps an existing VMA — caller (`mmap MAP_FIXED`) must call
    /// `remove_range` first to clear the destination per `11§6`.
    ///
    /// After insert, attempts to merge with left and right neighbors
    /// per `11§4` if they are abutting + compatible.
    /// # C: O(log N)
    pub fn insert(&mut self, vma: Vma) -> Result<(), Error> {
        if vma.start.as_u64() >= vma.end.as_u64() {
            return Err(Error::Inval);
        }
        // Floor: largest entry whose key ≤ vma.start. If its end overruns
        // vma.start, we overlap.
        if let Some((_, prev)) = self.map.range(..=vma.start).next_back() {
            if prev.end.as_u64() > vma.start.as_u64() {
                return Err(Error::Inval);
            }
        }
        // Ceil: smallest entry whose key > vma.start (strictly, since
        // the floor branch covered key == vma.start). If its start lies
        // before vma.end, we overlap.
        if let Some((_, next)) = self.map
            .range((Bound::Excluded(vma.start), Bound::Unbounded))
            .next()
        {
            if next.start.as_u64() < vma.end.as_u64() {
                return Err(Error::Inval);
            }
        }
        let key = vma.start;
        self.map_put(key, vma);
        self.try_merge_left(key);
        // After a left-merge, the entry now lives under the left key;
        // try_merge_right needs to operate from whichever key still
        // exists. Easiest correct path: scan once more from `key` or
        // its predecessor.
        let after_left = if self.map.contains_key(&key) {
            key
        } else {
            // Left-merge consumed `key`; its content now lives under
            // the floor of `key`.
            self.map.range(..key).next_back().map(|(k, _)| *k).unwrap_or(key)
        };
        self.try_merge_right(after_left);
        Ok(())
    }

    fn try_merge_left(&mut self, key: UserVirtAddr) {
        let Some((&lk, _)) = self.map.range(..key).next_back() else { return; };
        let mergeable = {
            let left = &self.map[&lk];
            let cur  = &self.map[&key];
            left.mergeable_with_next(cur)
        };
        if !mergeable { return; }
        // Linux `vma_merge` -> `remove_vma`: the absorbed VMA is freed, so
        // its `vm_ops->close` runs even though the range stays mapped.
        let cur = self.map_take(&key).expect("just-inserted key");
        crate::vm_ops::vma_closed(&cur);
        let left = self.map.get_mut(&lk).expect("left-floor key");
        left.end = cur.end;
        let combined = left.rss.load(core::sync::atomic::Ordering::Relaxed)
            + cur.rss.load(core::sync::atomic::Ordering::Relaxed);
        left.rss.store(combined, core::sync::atomic::Ordering::Relaxed);
    }

    fn try_merge_right(&mut self, key: UserVirtAddr) {
        let Some((&rk, _)) = self.map
            .range((Bound::Excluded(key), Bound::Unbounded))
            .next()
        else { return; };
        let mergeable = {
            let cur   = &self.map[&key];
            let right = &self.map[&rk];
            cur.mergeable_with_next(right)
        };
        if !mergeable { return; }
        let right = self.map_take(&rk).expect("right-ceil key");
        crate::vm_ops::vma_closed(&right);
        let cur = self.map.get_mut(&key).expect("merge-target key");
        cur.end = right.end;
        let combined = cur.rss.load(core::sync::atomic::Ordering::Relaxed)
            + right.rss.load(core::sync::atomic::Ordering::Relaxed);
        cur.rss.store(combined, core::sync::atomic::Ordering::Relaxed);
    }

}

impl Default for VmaTree {
    fn default() -> Self { Self::new() }
}
