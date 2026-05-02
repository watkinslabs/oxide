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
use alloc::vec::Vec;

use hal::UserVirtAddr;

use crate::vma::Vma;
use crate::Error;

/// Sorted, non-overlapping set of VMAs covering some subset of user
/// virtual address space. Lookup `O(log N)` (`11§4`); insert worst-case
/// `O(log N)` plus up to two adjacent merges.
pub struct VmaTree {
    map: BTreeMap<UserVirtAddr, Vma>,
}

impl VmaTree {
    /// # C: O(1)
    pub fn new() -> Self { Self { map: BTreeMap::new() } }

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
        self.map.insert(key, vma);
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
        let cur = self.map.remove(&key).expect("just-inserted key");
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
        let right = self.map.remove(&rk).expect("right-ceil key");
        let cur = self.map.get_mut(&key).expect("merge-target key");
        cur.end = right.end;
        let combined = cur.rss.load(core::sync::atomic::Ordering::Relaxed)
            + right.rss.load(core::sync::atomic::Ordering::Relaxed);
        cur.rss.store(combined, core::sync::atomic::Ordering::Relaxed);
    }

    /// Remove every VMA intersecting `[start, end)`. Partial-overlap
    /// VMAs are split at the boundaries; the kept fragments are
    /// reinserted, the removed middles are returned. Mirrors the
    /// `munmap` core per `11§6` (PT walk + TLB shootdown handled at
    /// the AS layer in a later P1-N).
    ///
    /// Returns the removed-middle VMAs in ascending order.
    /// # C: O(K + log N), K = #intersecting VMAs
    pub fn remove_range(
        &mut self,
        start: UserVirtAddr,
        end: UserVirtAddr,
    ) -> Vec<Vma> {
        let mut removed = Vec::new();
        if start.as_u64() >= end.as_u64() { return removed; }

        // Collect keys of all VMAs overlapping [start, end). A VMA
        // overlaps iff its start < end AND its end > start. The map
        // range `..end` selects every VMA whose start < end; we then
        // filter on the opposite endpoint.
        let mut keys: Vec<UserVirtAddr> = Vec::new();
        for (k, v) in self.map.range(..end) {
            if v.end.as_u64() > start.as_u64() {
                keys.push(*k);
            }
        }

        for k in keys {
            let v = self.map.remove(&k).expect("collected key");
            let v_start = v.start.as_u64();
            let v_end   = v.end.as_u64();
            let s = start.as_u64().max(v_start);
            let e = end.as_u64().min(v_end);

            // Left-kept fragment.
            if v_start < s {
                let lend = UserVirtAddr::new(s).expect("UVA in valid range");
                let left = v.clone_subrange(v.start, lend);
                self.map.insert(left.start, left);
            }
            // Removed middle.
            let ms = UserVirtAddr::new(s).expect("UVA in valid range");
            let me = UserVirtAddr::new(e).expect("UVA in valid range");
            removed.push(v.clone_subrange(ms, me));
            // Right-kept fragment.
            if e < v_end {
                let rstart = UserVirtAddr::new(e).expect("UVA in valid range");
                let right = v.clone_subrange(rstart, v.end);
                self.map.insert(right.start, right);
            }
        }
        removed
    }

    /// Apply `new_prot` over `[start, end)`, splitting VMAs at the
    /// boundaries as needed. After update, attempts to merge each
    /// modified VMA with its neighbors. Mirrors `mprotect` core per
    /// `11§6` (PTE demote handled at the AS / HAL layer in a later
    /// P1-N).
    ///
    /// Returns `Err(Inval)` if any byte in `[start, end)` falls in a
    /// hole — partial mprotect is rejected per `11§6` ("walk affected
    /// VMAs"; missing VMA = nothing to walk).
    /// # C: O(K log N)
    pub fn mprotect_range(
        &mut self,
        start: UserVirtAddr,
        end:   UserVirtAddr,
        new_prot: crate::vma::VmaProt,
    ) -> Result<(), Error> {
        if start.as_u64() >= end.as_u64() { return Err(Error::Inval); }

        // First pass: validate full coverage. Walk in-tree from `start`
        // and ensure consecutive VMAs cover [start, end) without holes.
        let mut cursor = start.as_u64();
        for (_, v) in self.map.range(..end) {
            if v.end.as_u64() <= cursor { continue; }
            if v.start.as_u64() > cursor { return Err(Error::Inval); }
            cursor = v.end.as_u64();
            if cursor >= end.as_u64() { break; }
        }
        if cursor < end.as_u64() { return Err(Error::Inval); }

        // Second pass: collect overlapping keys, split at boundaries,
        // change prot, re-merge.
        let mut keys: Vec<UserVirtAddr> = Vec::new();
        for (k, v) in self.map.range(..end) {
            if v.end.as_u64() > start.as_u64() {
                keys.push(*k);
            }
        }
        for k in keys {
            let v = self.map.remove(&k).expect("collected key");
            let v_start = v.start.as_u64();
            let v_end   = v.end.as_u64();
            let s = start.as_u64().max(v_start);
            let e = end.as_u64().min(v_end);

            if v_start < s {
                let lend = UserVirtAddr::new(s).expect("UVA in range");
                let left = v.clone_subrange(v.start, lend);
                self.map.insert(left.start, left);
            }
            let ms = UserVirtAddr::new(s).expect("UVA in range");
            let me = UserVirtAddr::new(e).expect("UVA in range");
            let mut mid = v.clone_subrange(ms, me);
            mid.prot = new_prot;
            let mid_key = mid.start;
            self.map.insert(mid_key, mid);
            if e < v_end {
                let rstart = UserVirtAddr::new(e).expect("UVA in range");
                let right = v.clone_subrange(rstart, v.end);
                self.map.insert(right.start, right);
            }
            // Try merging the modified middle with its neighbors. The
            // boundary fragments retain the old prot, so they merge
            // back together with their original other halves only if
            // we've split a different VMA there earlier — `mergeable`
            // handles the prot check.
            self.try_merge_left(mid_key);
            let after_left = if self.map.contains_key(&mid_key) {
                mid_key
            } else {
                self.map.range(..mid_key).next_back().map(|(k, _)| *k).unwrap_or(mid_key)
            };
            self.try_merge_right(after_left);
        }
        Ok(())
    }

    /// Audit hook: verify invariant 1 (non-overlap, `11§2`) over the
    /// entire tree. Used by tests and by the `debug-vmm` cargo feature
    /// (`11§13`). Returns `Err(Inval)` on the first violation.
    /// # C: O(N)
    pub fn audit_no_overlap(&self) -> Result<(), Error> {
        let mut prev_end: u64 = 0;
        for v in self.map.values() {
            if v.start.as_u64() < prev_end { return Err(Error::Inval); }
            if v.end.as_u64() <= v.start.as_u64() { return Err(Error::Inval); }
            prev_end = v.end.as_u64();
        }
        Ok(())
    }
}

impl Default for VmaTree {
    fn default() -> Self { Self::new() }
}
