//! A cached page as a machine frame, and the two eviction paths that must leave
//! a mapped one alone.
//!
//! What is at stake is not lost bytes. A page dropped from the cache while a
//! user page table still points at its frame leaves the mapper writing memory
//! the cache has stopped tracking, and the next fill of the same offset takes a
//! DIFFERENT frame — two live copies of one page, disagreeing about the file for
//! as long as both exist. Both paths that can drop a clean page have to see it:
//! the hint (`try_invalidate_range`) and reclaim (`shrink`).

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec;

use crate::blockdev::BlockDevice;
use crate::pagecache::tests::{fresh_machine, set_all_mapped, with_frames, CountingDisk};
use crate::pagecache::{nr_cached, shrink, PageCache};
use crate::types::{InodeId, PAGE_BYTES};

const INO: InodeId = InodeId(1);
fn page(byte: u8) -> alloc::vec::Vec<u8> { vec![byte; PAGE_BYTES] }

/// A resident page has no machine address until something asks to map it, and
/// the same one every time afterwards.
#[test]
fn a_page_takes_a_frame_only_when_something_asks_to_map_it() {
    let _m = fresh_machine();
    with_frames();
    set_all_mapped(false);
    let disk = CountingDisk::new(8);
    let dev: Arc<dyn BlockDevice> = disk.clone();
    let pc = PageCache::new();
    pc.read_page(INO, 0, &dev).expect("fill");

    assert_eq!(pc.frame_of(INO, 0), None, "an unmapped page stays on the heap");
    let pa = pc.ensure_frame(INO, 0).expect("a frame for a mapper");
    assert_eq!(pc.frame_of(INO, 0), Some(pa), "and keeps that address once it has one");
    assert_eq!(pc.ensure_frame(INO, 0), Some(pa), "asking twice does not move it");
}

/// The bytes survive the conversion, so a mapper sees the file rather than an
/// empty page.
#[test]
fn the_frame_a_page_moves_into_holds_the_pages_bytes() {
    let _m = fresh_machine();
    with_frames();
    set_all_mapped(false);
    let disk = CountingDisk::new(8);
    let dev: Arc<dyn BlockDevice> = disk.clone();
    let pc = PageCache::new();
    pc.write_page(INO, 0, &page(0x3C), &dev).expect("write");
    let pa = pc.ensure_frame(INO, 0).expect("frame");
    let base = crate::pagecache::tests::test_frame_ptr(pa).expect("frame pointer");
    // SAFETY: the page's own frame, read within its PAGE_BYTES span.
    let seen = unsafe { core::slice::from_raw_parts(base, PAGE_BYTES) };
    assert_eq!(seen, &page(0x3C)[..], "the mapper sees what the page held");
}

/// A page absent from the cache has no frame, and asking for one does not
/// invent it: a residency question must not fill.
#[test]
fn an_absent_page_has_no_frame_and_asking_does_not_fill_one() {
    let _m = fresh_machine();
    with_frames();
    set_all_mapped(false);
    let pc = PageCache::new();
    assert_eq!(pc.frame_of(INO, 0), None);
    assert_eq!(pc.ensure_frame(INO, 0), None, "a page the cache does not hold is not made mappable");
    assert_eq!(nr_cached(), 0, "and nothing was published to answer the question");
}

/// The HINT leaves a mapped page alone.
#[test]
fn a_hint_does_not_drop_a_page_a_user_page_table_maps() {
    let _m = fresh_machine();
    with_frames();
    let disk = CountingDisk::new(8);
    let dev: Arc<dyn BlockDevice> = disk.clone();
    let pc = PageCache::new();
    pc.read_page(INO, 0, &dev).expect("fill");
    pc.ensure_frame(INO, 0).expect("frame");

    set_all_mapped(false);
    assert!(!pc.page_user_mapped(INO, 0));
    set_all_mapped(true);
    assert!(pc.page_user_mapped(INO, 0), "the provider is what answers this, and it is installed");

    assert_eq!(pc.try_invalidate_range(INO, 0, 0), 0, "a mapped page is not a page a hint may spare");
    assert!(pc.frame_of(INO, 0).is_some(), "and it is still the cache's page");

    // Unmapped, the same hint takes it — so the refusal above is the mapping
    // rule and not an unrelated one.
    set_all_mapped(false);
    assert_eq!(pc.try_invalidate_range(INO, 0, 0), 1, "an unmapped clean page is exactly what a hint drops");
}

/// RECLAIM leaves a mapped page alone, for the same reason. Reclaim reaches a
/// clean page by a different route from the hint, so the check has to be on both.
#[test]
fn reclaim_does_not_drop_a_page_a_user_page_table_maps() {
    let _m = fresh_machine();
    with_frames();
    let disk = CountingDisk::new(8);
    let dev: Arc<dyn BlockDevice> = disk.clone();
    let pc = PageCache::new();
    pc.read_page(INO, 0, &dev).expect("fill");
    pc.ensure_frame(INO, 0).expect("frame");
    set_all_mapped(true);

    // Reclaim clears a REFERENCED page's bit and moves on, so it takes more than
    // one pass to reach the eviction decision at all.
    for _ in 0..4 { shrink(8); }
    assert!(pc.frame_of(INO, 0).is_some(), "reclaim must not take a page out from under a mapper");

    set_all_mapped(false);
    let mut freed = 0;
    for _ in 0..4 { freed += shrink(8); }
    assert_eq!(freed, 1, "an unmapped clean page is exactly what reclaim frees");
    assert_eq!(pc.frame_of(INO, 0), None);
}
