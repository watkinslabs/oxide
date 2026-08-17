//! Asking a mapping what it holds, and the eviction that is a HINT.
//!
//! The property that matters here is that a hint cannot lose a write. A
//! `POSIX_FADV_DONTNEED` over a range holding one dirty page must drop the
//! clean pages beside it and leave that one where it is, because the cache is
//! the only copy of those bytes until writeback places them.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::pagecache::tests::fresh_machine;
use crate::pagecache::{PageCache, PageOut, Writeback};
use crate::types::{InodeId, KResult, PAGE_BYTES};

const INO: InodeId = InodeId(11);
fn page(byte: u8) -> Vec<u8> { vec![byte; PAGE_BYTES] }
fn off(index: u64) -> u64 { index * PAGE_BYTES as u64 }

/// A target that accepts everything, so a page can be made dirty at all: the
/// cache refuses to dirty a page with nowhere to put it.
struct Sinkhole { medium: Mutex<BTreeMap<u64, Vec<u8>>> }

impl Writeback for Sinkhole {
    fn writepages(&self, _ino: InodeId, pages: &[PageOut<'_>], results: &mut [KResult<()>]) {
        let mut m = self.medium.lock().unwrap();
        for (i, p) in pages.iter().enumerate() { m.insert(p.offset, p.data.to_vec()); results[i] = Ok(()); }
    }
    fn sync_medium(&self) -> KResult<()> { Ok(()) }
}

/// A cache holding pages 0..=3 of `INO`, with a writeback target installed.
fn loaded() -> PageCache {
    let c = PageCache::new();
    c.set_writeback(INO, Arc::new(Sinkhole { medium: Mutex::new(BTreeMap::new()) }) as Arc<dyn Writeback>);
    for i in 0..4u64 {
        c.read_page_with(INO, off(i), || Ok(page(i as u8))).expect("fill");
    }
    c
}

#[test]
fn a_hint_drops_the_clean_pages_of_the_range_and_reports_how_many() {
    let _m = fresh_machine();
    let c = loaded();
    assert_eq!(c.try_invalidate_range(INO, 1, 2), 2, "pages 1 and 2 were droppable");
    assert!(c.holds(INO, 0) && c.holds(INO, 3), "outside the range is untouched");
    assert!(!c.holds(INO, 1) && !c.holds(INO, 2));
}

#[test]
fn a_hint_never_drops_a_dirty_page() {
    let _m = fresh_machine();
    let c = loaded();
    c.mark_dirty(INO, off(2)).expect("dirty");
    assert_eq!(c.try_invalidate_range(INO, 0, 3), 3, "the other three went");
    assert!(c.holds(INO, 2), "the only copy of that write is still here");
    // And the truncate primitive beside it DOES drop it — the two are not the
    // same operation, which is the whole reason this one exists.
    c.invalidate_range(INO, off(2), off(3));
    assert!(!c.holds(INO, 2));
}

#[test]
fn a_state_walk_visits_only_pages_that_exist_and_reports_their_dirtiness() {
    let _m = fresh_machine();
    let c = loaded();
    c.mark_dirty(INO, off(1)).expect("dirty");
    // An unbounded range over a mapping holding four pages costs four entries,
    // not the index space: a sparse file is answerable at all only because of
    // this.
    let seen = c.page_states(INO, 0, u64::MAX);
    assert_eq!(seen.iter().map(|s| s.index).collect::<Vec<_>>(), vec![0, 1, 2, 3]);
    assert_eq!(seen.iter().filter(|s| s.dirty).map(|s| s.index).collect::<Vec<_>>(), vec![1]);
    assert!(seen.iter().all(|s| !s.writeback));
    // A range naming nothing resident answers empty rather than walking.
    assert!(c.page_states(INO, 100, 200).is_empty());
    assert!(c.page_states(INO, 3, 1).is_empty(), "an inverted range is not a walk");
}

#[test]
fn holding_a_page_is_answered_without_fetching_it() {
    let _m = fresh_machine();
    let c = PageCache::new();
    assert!(!c.holds(INO, 0), "an inode with no mapping holds nothing");
    c.read_page_with(INO, off(0), || Ok(page(9))).expect("fill");
    assert!(c.holds(INO, 0));
    assert!(!c.holds(INO, 1), "a query does not create the page it asks about");
    assert_eq!(PageCache::offset_of(3), off(3));
}
