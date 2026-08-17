//! `PG_LOCKED` and the miss path (`17§4.2` steps 3-5).
//!
//! The contract these pin: a miss publishes a locked, not-uptodate page before
//! it fetches, so N callers racing one index produce ONE fetch and N handles
//! to the same page. Without the lock bit each racer fetched its own copy and
//! the loser's bytes were thrown away — a read amplification the cache exists
//! to prevent.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::pagecache::page::CachedPage;
use crate::pagecache::tests::fresh_machine;
use crate::pagecache::PageCache;
use crate::types::{BlockError, InodeId, PageFlags, PAGE_BYTES};

const INO: InodeId = InodeId(1);

#[test]
fn a_lock_is_exclusive_and_a_second_taker_gets_it_after_the_unlock() {
    let p = CachedPage::new(INO, 0, vec![0; PAGE_BYTES]);
    assert!(p.trylock());
    assert!(!p.trylock(), "a locked page cannot be locked twice");
    assert!(p.is_locked());
    p.unlock_page();
    assert!(!p.is_locked());
    assert!(p.trylock());
}

#[test]
fn eight_racing_readers_of_one_index_cause_exactly_one_fetch() {
    let _m = fresh_machine();
    let pc: Arc<PageCache> = Arc::new(PageCache::new());
    let fetches = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let pc = Arc::clone(&pc);
        let fetches = Arc::clone(&fetches);
        handles.push(std::thread::spawn(move || {
            let page = pc.read_page_with(INO, 0, || {
                fetches.fetch_add(1, Ordering::AcqRel);
                // Long enough that every sibling reaches the tree while this
                // fetch is still in flight.
                std::thread::sleep(std::time::Duration::from_millis(40));
                Ok(vec![0xAB; PAGE_BYTES])
            }).expect("read");
            Arc::as_ptr(&page) as usize
        }));
    }
    let ptrs: Vec<usize> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(fetches.load(Ordering::Acquire), 1, "the page lock must collapse a racing miss to one fetch");
    assert!(ptrs.iter().all(|p| *p == ptrs[0]), "racers got different pages: {ptrs:?}");
    assert_eq!(pc.cached_count(), 1);
}

#[test]
fn a_page_still_being_fetched_is_not_a_lookup_hit() {
    let _m = fresh_machine();
    let pc: Arc<PageCache> = Arc::new(PageCache::new());
    let started = Arc::new(AtomicUsize::new(0));
    let reader = {
        let pc = Arc::clone(&pc);
        let started = Arc::clone(&started);
        std::thread::spawn(move || {
            let _ = pc.read_page_with(INO, 0, || {
                started.fetch_add(1, Ordering::AcqRel);
                std::thread::sleep(std::time::Duration::from_millis(60));
                Ok(vec![1; PAGE_BYTES])
            });
        })
    };
    while started.load(Ordering::Acquire) == 0 { std::thread::yield_now(); }
    assert!(pc.lookup(INO, 0).is_none(), "a not-uptodate page must not be served as a hit");
    reader.join().unwrap();
    assert!(pc.lookup(INO, 0).is_some());
}

#[test]
fn a_failed_fetch_leaves_no_page_behind() {
    let _m = fresh_machine();
    let pc = PageCache::new();
    let err = pc.read_page_with(INO, 0, || Err(BlockError::Eio)).err();
    assert_eq!(err, Some(BlockError::Eio));
    assert_eq!(pc.cached_count(), 0, "a failed fetch must not leave a placeholder");
    assert!(pc.lookup(INO, 0).is_none());
    // And the index is fetchable again afterwards.
    let page = pc.read_page_with(INO, 0, || Ok(vec![2; PAGE_BYTES])).unwrap();
    assert_eq!(*page.data.lock(), vec![2; PAGE_BYTES]);
}

#[test]
fn a_second_reference_promotes_a_page_and_the_first_only_marks_it() {
    let _m = fresh_machine();
    let pc = PageCache::new();
    let page = pc.read_page_with(INO, 0, || Ok(vec![3; PAGE_BYTES])).unwrap();
    assert!(page.flags().contains(PageFlags::REFERENCED));
    assert!(!page.is_active(), "one reference does not promote");
    pc.lookup(INO, 0).unwrap();
    assert!(page.is_active(), "the second reference promotes");
}

#[test]
fn an_unaligned_offset_is_refused_before_any_fetch() {
    let _m = fresh_machine();
    let pc = PageCache::new();
    let calls = AtomicUsize::new(0);
    let err = pc.read_page_with(INO, 1, || { calls.fetch_add(1, Ordering::AcqRel); Ok(vec![0; PAGE_BYTES]) });
    assert_eq!(err.err(), Some(BlockError::Einval));
    assert_eq!(calls.load(Ordering::Acquire), 0);
}
