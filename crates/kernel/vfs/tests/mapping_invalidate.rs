//! address_space-B212: `AddressSpaceOps::invalidate_range` is the page-cache
//! truncate/hole-punch primitive (Linux `truncate_inode_pages_range`). A page
//! is evicted only when its WHOLE granule lies inside `[start, end)`; a page
//! straddling either boundary is retained (the caller zeroes the partial
//! bytes). Without it, post-truncate refaults serve stale post-EOF data.
//! Regression: a partial-boundary page must NOT be dropped, and `end ==
//! u64::MAX` truncates to EOF.

use std::collections::BTreeMap;
use std::sync::Mutex;

use vfs::AddressSpaceOps;

const PG: u64 = 4096;

/// Stateful toy address_space modelling shmem's per-inode frame set: resident
/// frames keyed by page index, evicted by `invalidate_range`.
struct CacheMapping { pages: Mutex<BTreeMap<u64, u64>>, len: u64 }

impl CacheMapping {
    fn with(idxs: &[u64], len: u64) -> Self {
        let mut m = BTreeMap::new();
        for &i in idxs { m.insert(i, 0x20_0000 + i * PG); }
        Self { pages: Mutex::new(m), len }
    }
    fn resident(&self) -> Vec<u64> { self.pages.lock().unwrap().keys().copied().collect() }
}

impl AddressSpaceOps for CacheMapping {
    fn shared_frame(&self, off: u64) -> vfs::KResult<Option<vfs::SharedFrame>> {
        Ok(self.pages.lock().unwrap().get(&(off / PG)).copied()
            .map(|pa| vfs::SharedFrame { pa, map_ref_held: false }))
    }
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> vfs::KResult<usize> { Ok(0) }
    fn size(&self) -> u64 { self.len }
    fn invalidate_range(&self, start: u64, end: u64) -> usize {
        let mut g = self.pages.lock().unwrap();
        // Whole pages fully inside [start, end): first index at/above the
        // rounded-up start; last (exclusive) is `end / PG` so a page whose
        // tail spills past `end` (partial) is kept.
        let first = start.div_ceil(PG);
        let last_excl = if end == u64::MAX { u64::MAX } else { end / PG };
        let victims: Vec<u64> = g.range(first..last_excl).map(|(&k, _)| k).collect();
        for k in &victims { g.remove(k); }
        victims.len()
    }
}

// Whole pages strictly inside the range drop; the start/end boundary pages
// that are only partially covered are retained.
#[test]
fn invalidate_drops_only_whole_pages_in_range() {
    let m = CacheMapping::with(&[0, 1, 2, 3], 4 * PG);
    // [PG, 3·PG): pages 1,2 fully inside; page 0 below, page 3 above → 2 dropped.
    assert_eq!(m.invalidate_range(PG, 3 * PG), 2);
    assert_eq!(m.resident(), vec![0, 3]);
    // The retained pages still hand out their frame; the dropped ones don't.
    assert!(m.shared_frame(0).unwrap().is_some());
    assert!(m.shared_frame(PG).unwrap().is_none());
    assert!(m.shared_frame(2 * PG).unwrap().is_none());
    assert!(m.shared_frame(3 * PG).unwrap().is_some());
}

// A range with partial head AND tail pages: only the fully-covered interior
// page drops; both boundary pages survive (Linux keeps + zeroes them).
#[test]
fn invalidate_retains_partial_boundary_pages() {
    let m = CacheMapping::with(&[0, 1, 2, 3], 4 * PG);
    // [PG/2, 3·PG + PG/2): head page 0 partial, tail page 3 partial,
    // interior pages 1,2 whole → 2 dropped, 0 and 3 kept.
    assert_eq!(m.invalidate_range(PG / 2, 3 * PG + PG / 2), 2);
    assert_eq!(m.resident(), vec![0, 3]);
}

// `end == u64::MAX` truncates to EOF: every resident page at/after the
// rounded-up start index drops.
#[test]
fn invalidate_to_eof_drops_tail() {
    let m = CacheMapping::with(&[0, 1, 2, 3], 4 * PG);
    assert_eq!(m.invalidate_range(2 * PG, u64::MAX), 2);
    assert_eq!(m.resident(), vec![0, 1]);
}

// Empty / sub-page range drops nothing (no whole page covered).
#[test]
fn invalidate_subpage_range_noop() {
    let m = CacheMapping::with(&[0, 1], 2 * PG);
    assert_eq!(m.invalidate_range(0, PG / 2), 0);
    assert_eq!(m.resident(), vec![0, 1]);
}

// The trait default is a no-op: an address space that computes frames on
// demand (no droppable store) reports zero evictions and keeps serving.
#[test]
fn default_invalidate_is_noop() {
    struct OnDemand;
    impl AddressSpaceOps for OnDemand {
        fn shared_frame(&self, off: u64) -> vfs::KResult<Option<vfs::SharedFrame>> {
            Ok(Some(vfs::SharedFrame { pa: 0x10_0000 + (off / PG) * PG, map_ref_held: false }))
        }
        fn read_at(&self, _off: u64, dst: &mut [u8]) -> vfs::KResult<usize> { Ok(dst.len()) }
        fn size(&self) -> u64 { 8192 }
    }
    let m = OnDemand;
    assert_eq!(m.invalidate_range(0, u64::MAX), 0);
    assert_eq!(m.shared_frame(0).map(|frame| frame.map(|frame| frame.pa)), Ok(Some(0x10_0000)));
}
