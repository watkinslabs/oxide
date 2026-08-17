//! The two-list LRU and eviction (`17§4.4`).
//!
//! The test that matters here is not that a page can be evicted — it is that a
//! page carrying a write nobody has put on the medium yet CANNOT be, and that
//! cleaning it on the way out writes it exactly once.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec;

use crate::blockdev::BlockDevice;
use crate::pagecache::tests::{fresh_machine, CountingDisk};
use crate::pagecache::{nr_cached, nr_dirty, reclaimable_pages, shrink, PageCache};
use crate::types::{InodeId, PageFlags, PAGE_BYTES};

const INO: InodeId = InodeId(1);
fn page(byte: u8) -> alloc::vec::Vec<u8> { vec![byte; PAGE_BYTES] }

/// The data-loss test. A dirty page is the ONLY copy of a write; reclaim that
/// drops it silently loses it. Reclaim must write it back instead, and the
/// bytes must be readable from the medium afterwards.
#[test]
fn reclaim_never_drops_a_write_that_has_not_reached_the_medium() {
    let _m = fresh_machine();
    let disk = CountingDisk::new(16);
    let dev: Arc<dyn BlockDevice> = disk.clone();
    let pc = PageCache::new();
    for i in 0..4u64 { pc.write_page(INO, i * PAGE_BYTES as u64, &page(0xD0 + i as u8), &dev).unwrap(); }
    assert_eq!(nr_dirty(), 4);

    // Ask for far more than exists, repeatedly: nothing may make the bytes
    // unreachable.
    for _ in 0..4 { shrink(64); }

    for i in 0..4u64 {
        assert_eq!(disk.medium_page(i * PAGE_BYTES as u64), page(0xD0 + i as u8),
                   "page {i} was reclaimed without reaching the medium");
    }
    assert_eq!(nr_dirty(), 0, "reclaim cleaned every page it wanted to evict");
}

/// The mapping's own guard, reached directly. Reclaim cleans a dirty page
/// before it asks, so that path alone cannot tell whether this refusal exists
/// — and it is the last thing standing between a caller's write and a silent
/// loss if any future caller forgets to clean first.
#[test]
fn a_mapping_refuses_to_evict_a_dirty_page_even_when_asked_outright() {
    let _m = fresh_machine();
    let disk = CountingDisk::new(8);
    let dev: Arc<dyn BlockDevice> = disk.clone();
    let pc = PageCache::new();
    pc.write_page(INO, 0, &page(0x7E), &dev).unwrap();
    let map = pc.mapping(INO).unwrap();
    assert!(map.evict(0).is_none(), "a dirty page is not evictable");
    assert!(map.get(0).is_some());
    // Once it has been written, the same request succeeds.
    pc.fsync(INO, &dev).unwrap();
    assert!(map.evict(0).is_some());
}

#[test]
fn a_page_reclaim_cleaned_is_not_written_again_by_fsync() {
    let _m = fresh_machine();
    let disk = CountingDisk::new(16);
    let dev: Arc<dyn BlockDevice> = disk.clone();
    let pc = PageCache::new();
    pc.write_page(INO, 0, &page(0x11), &dev).unwrap();
    // First pass clears the reference the write left; the second reaches the
    // dirty page and cleans it.
    shrink(8);
    shrink(8);
    assert_eq!(disk.writes(), 1, "reclaim wrote it once");
    pc.fsync(INO, &dev).unwrap();
    assert_eq!(disk.writes(), 1, "and fsync has nothing left to write");
    assert_eq!(disk.medium_page(0), page(0x11));
}

#[test]
fn a_clean_unreferenced_page_is_the_one_that_gets_evicted() {
    let _m = fresh_machine();
    let pc = PageCache::new();
    for i in 0..4u64 { assert!(pc.insert_new(INO, i * PAGE_BYTES as u64, page(i as u8), 0, usize::MAX)); }
    assert_eq!(pc.cached_count(), 4);
    assert_eq!(nr_cached(), 4);
    assert_eq!(reclaimable_pages(), 4, "clean pages are reclaimable");
    let freed = shrink(4);
    assert!(freed > 0, "a clean idle page must be evictable");
    assert!(pc.cached_count() < 4);
    assert_eq!(nr_cached(), pc.cached_count());
}

#[test]
fn a_twice_referenced_page_survives_a_pass_that_evicts_a_once_referenced_one() {
    let _m = fresh_machine();
    let pc = PageCache::new();
    let cold = 0u64;
    let hot = PAGE_BYTES as u64;
    assert!(pc.insert_new(INO, cold, page(1), 0, usize::MAX));
    assert!(pc.insert_new(INO, hot, page(2), 0, usize::MAX));
    // Two references promote the hot page to the active list; the cold page
    // gets one, which only sets its reference bit.
    pc.lookup(INO, hot).unwrap();
    pc.lookup(INO, hot).unwrap();
    pc.lookup(INO, cold).unwrap();
    assert!(pc.lookup(INO, hot).unwrap().is_active());

    // First pass clears the cold page's reference bit, second evicts it.
    shrink(8);
    shrink(8);
    assert!(pc.lookup(INO, hot).is_some(), "an active page is not the first thing reclaimed");
    assert!(pc.lookup(INO, cold).is_none(), "the cold page went");
}

#[test]
fn a_referenced_page_gets_another_pass_before_it_is_evicted() {
    let _m = fresh_machine();
    let pc = PageCache::new();
    assert!(pc.insert_new(INO, 0, page(1), 0, usize::MAX));
    let p = pc.lookup(INO, 0).unwrap();
    assert!(p.flags().contains(PageFlags::REFERENCED));
    assert_eq!(shrink(4), 0, "the first pass only clears the reference");
    assert!(!p.flags().contains(PageFlags::REFERENCED));
    assert_eq!(shrink(4), 1, "the second pass evicts it");
}

#[test]
fn a_locked_page_is_never_evicted() {
    let _m = fresh_machine();
    let pc = PageCache::new();
    assert!(pc.insert_new(INO, 0, page(1), 0, usize::MAX));
    let p = pc.mapping(INO).unwrap().get(0).unwrap();
    assert!(p.trylock());
    assert_eq!(shrink(4), 0, "in-flight I/O pins the page (`17§1` invariant 3)");
    assert!(pc.mapping(INO).unwrap().get(0).is_some());
    p.unlock_page();
    assert_eq!(shrink(4), 1, "and is evictable the moment the I/O is done");
}

#[test]
fn the_machine_page_count_follows_eviction_and_invalidation() {
    let _m = fresh_machine();
    let pc = PageCache::new();
    for i in 0..3u64 { assert!(pc.insert_new(INO, i * PAGE_BYTES as u64, page(0), 0, usize::MAX)); }
    assert_eq!(nr_cached(), 3);
    pc.invalidate_range(INO, 0, PAGE_BYTES as u64);
    assert_eq!(nr_cached(), 2);
    shrink(8);
    shrink(8);
    assert_eq!(nr_cached(), pc.cached_count());
}

#[test]
fn a_dropped_cache_leaves_the_machine_count_at_zero() {
    let _m = fresh_machine();
    {
        let pc = PageCache::new();
        for i in 0..3u64 { assert!(pc.insert_new(INO, i * PAGE_BYTES as u64, page(0), 0, usize::MAX)); }
        assert_eq!(nr_cached(), 3);
    }
    assert_eq!(nr_cached(), 0, "a cache going away takes its pages with it");
    assert_eq!(shrink(8), 0, "and its stale list entries free nothing");
}
