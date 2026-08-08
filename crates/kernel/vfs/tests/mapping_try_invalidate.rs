//! `AddressSpaceOps::try_invalidate_pages` is the BEST-EFFORT page-cache
//! eviction behind `POSIX_FADV_DONTNEED`, and it is a different primitive from
//! `invalidate_range` (truncate's unconditional drop). Its whole contract is
//! what it REFUSES to evict: a page that is mapped, dirty, or under writeback
//! belongs to someone else. Dropping a mapped page unshares a live
//! `MAP_SHARED` mapping — the next mapper refills a new frame and the two stop
//! aliasing the inode's one cache object.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use vfs::AddressSpaceOps;
use vfs::types::KResult;

const PG: u64 = 4096;

/// Page-indexed toy cache. `mapped`/`dirty` mark pages that must survive a
/// best-effort invalidate; `truncated` records what the unconditional
/// primitive was asked to drop, so the two cannot be confused for each other.
struct ToyCache {
    resident: Mutex<BTreeSet<u64>>,
    mapped: BTreeSet<u64>,
    dirty: BTreeSet<u64>,
    truncated: Mutex<Vec<(u64, u64)>>,
}

impl AddressSpaceOps for ToyCache {
    fn shared_frame(&self, _off: u64) -> KResult<Option<vfs::SharedFrame>> { Ok(None) }
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> KResult<usize> { Ok(0) }
    fn size(&self) -> u64 { 16 * PG }

    fn invalidate_range(&self, start: u64, end: u64) -> usize {
        self.truncated.lock().unwrap().push((start, end));
        let lo = (start + PG - 1) / PG;
        let hi = if end == u64::MAX { u64::MAX } else { end / PG };
        let mut r = self.resident.lock().unwrap();
        let before = r.len();
        r.retain(|&i| i < lo || i >= hi);
        before - r.len()
    }

    fn try_invalidate_pages(&self, start_idx: u64, end_idx: u64) -> usize {
        let mut r = self.resident.lock().unwrap();
        let before = r.len();
        r.retain(|&i| {
            let in_range = i >= start_idx && i <= end_idx;
            let pinned = self.mapped.contains(&i) || self.dirty.contains(&i);
            !in_range || pinned
        });
        before - r.len()
    }
}

fn toy() -> ToyCache {
    ToyCache {
        resident: Mutex::new((0..8).collect()),
        mapped: BTreeSet::from([2]),
        dirty: BTreeSet::from([5]),
        truncated: Mutex::new(Vec::new()),
    }
}

fn resident(m: &ToyCache) -> Vec<u64> { m.resident.lock().unwrap().iter().copied().collect() }

/// The range is INCLUSIVE on both ends, and the pinned pages inside it survive.
#[test]
fn inclusive_range_skips_mapped_and_dirty_pages() {
    let m = toy();
    // Pages 1..=6 requested; 2 (mapped) and 5 (dirty) are refused.
    assert_eq!(m.try_invalidate_pages(1, 6), 4);
    assert_eq!(resident(&m), vec![0, 2, 5, 7]);
    // The unconditional truncate primitive was never invoked.
    assert!(m.truncated.lock().unwrap().is_empty());
}

/// A single-index request is `start == end`, not an empty range: an
/// exclusive-end reading of the pair would silently discard nothing.
#[test]
fn single_page_range_is_start_equals_end() {
    let m = toy();
    assert_eq!(m.try_invalidate_pages(3, 3), 1);
    assert_eq!(resident(&m), vec![0, 1, 2, 4, 5, 6, 7]);
}

/// An inverted range evicts nothing.
#[test]
fn inverted_range_evicts_nothing() {
    let m = toy();
    assert_eq!(m.try_invalidate_pages(6, 2), 0);
    assert_eq!(resident(&m).len(), 8);
}

/// The DEFAULT implementation reports zero and must NOT forward to
/// `invalidate_range`: an unconditional drop is never a valid stand-in for a
/// best-effort one, and a default that forwarded would make every address
/// space that never opted in evict mapped pages on a hint.
#[test]
fn default_is_zero_and_does_not_forward_to_truncate() {
    struct Defaults(Mutex<usize>);
    impl AddressSpaceOps for Defaults {
        fn shared_frame(&self, _off: u64) -> KResult<Option<vfs::SharedFrame>> { Ok(None) }
        fn read_at(&self, _off: u64, _dst: &mut [u8]) -> KResult<usize> { Ok(0) }
        fn size(&self) -> u64 { 0 }
        fn invalidate_range(&self, _start: u64, _end: u64) -> usize {
            *self.0.lock().unwrap() += 1;
            0
        }
    }
    let d = Defaults(Mutex::new(0));
    assert_eq!(d.try_invalidate_pages(0, u64::MAX), 0);
    assert_eq!(*d.0.lock().unwrap(), 0, "default must not reach the truncate primitive");
}

/// The two primitives stay independent: a truncate still drops everything in
/// its byte range, pinned or not, because the bytes are gone.
#[test]
fn truncate_primitive_remains_unconditional() {
    let m = toy();
    assert_eq!(m.invalidate_range(0, 8 * PG), 8);
    assert!(resident(&m).is_empty());
    assert_eq!(*m.truncated.lock().unwrap(), vec![(0, 8 * PG)]);
}

/// Dispatch survives the shared trait-object hand-off the syscall shim uses
/// (`inode.i_mapping()` yields an `Arc<dyn AddressSpaceOps>`).
#[test]
fn dispatches_through_a_shared_handle() {
    let m: Arc<dyn AddressSpaceOps> = Arc::new(toy());
    assert_eq!(m.try_invalidate_pages(0, 1), 2);
}
