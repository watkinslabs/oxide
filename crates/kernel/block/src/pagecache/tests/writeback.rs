//! The dirty list, its thresholds, `fsync` and the flusher (`17§4.3`).

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec;

use crate::blockdev::BlockDevice;
use crate::pagecache::tests::{fresh_machine, CountingDisk};
use crate::pagecache::{
    background_threshold, dirty_action, dirty_limit, flush_pass, install_totalram_pages, nr_dirty,
    DirtyAction, PageCache, DIRTY_BACKGROUND_RATIO, DIRTY_EXPIRE_NS, DIRTY_RATIO,
};
use crate::types::{InodeId, PAGE_BYTES};

const INO: InodeId = InodeId(1);
fn page(byte: u8) -> alloc::vec::Vec<u8> { vec![byte; PAGE_BYTES] }

#[test]
fn the_thresholds_are_the_reference_percentages_of_ram() {
    let _m = fresh_machine();
    assert_eq!(DIRTY_BACKGROUND_RATIO, 10);
    assert_eq!(DIRTY_RATIO, 20);
    install_totalram_pages(1000);
    assert_eq!(background_threshold(), 100);
    assert_eq!(dirty_limit(), 200);
}

#[test]
fn the_dirty_decision_ladder_is_proceed_wake_throttle() {
    assert_eq!(dirty_action(50, 0, 1000), DirtyAction::Proceed);
    assert_eq!(dirty_action(100, 0, 1000), DirtyAction::Proceed, "at the threshold, not over it");
    assert_eq!(dirty_action(101, 0, 1000), DirtyAction::Wake);
    assert_eq!(dirty_action(150, 51, 1000), DirtyAction::Throttle);
    assert_eq!(dirty_action(0, 201, 1000), DirtyAction::Throttle, "in-flight pages count too");
    assert_eq!(dirty_action(1_000_000, 0, 0), DirtyAction::Proceed, "no RAM figure, no threshold");
}

#[test]
fn a_write_dirties_the_page_and_steps_the_machine_count() {
    let _m = fresh_machine();
    let disk = CountingDisk::new(8);
    let dev: Arc<dyn BlockDevice> = disk.clone();
    let pc = PageCache::new();
    let p = pc.write_page(INO, 0, &page(0x5A), &dev).unwrap();
    assert!(p.is_dirty());
    assert_eq!(pc.dirty_count(INO), 1, "on this inode's dirty list");
    assert_eq!(nr_dirty(), 1, "and in the machine's dirty count");
    assert_eq!(disk.writes(), 0, "a write returns before the medium sees it");
}

#[test]
fn fsync_puts_a_dirty_page_on_the_medium_exactly_once() {
    let _m = fresh_machine();
    let disk = CountingDisk::new(8);
    let dev: Arc<dyn BlockDevice> = disk.clone();
    let pc = PageCache::new();
    let p = pc.write_page(INO, 0, &page(0xC3), &dev).unwrap();
    pc.fsync(INO, &dev).unwrap();
    assert!(!p.is_dirty());
    assert_eq!(pc.dirty_count(INO), 0);
    assert_eq!(nr_dirty(), 0);
    assert_eq!(disk.medium_page(0), page(0xC3));
    assert_eq!(disk.writes(), 1);
    assert_eq!(disk.flushes(), 1, "fsync barriers the medium");
    // A second fsync has nothing to do.
    pc.fsync(INO, &dev).unwrap();
    assert_eq!(disk.writes(), 1, "a clean page is not written a second time");
}

#[test]
fn fsync_touches_only_the_named_inode() {
    let _m = fresh_machine();
    let disk = CountingDisk::new(8);
    let dev: Arc<dyn BlockDevice> = disk.clone();
    let pc = PageCache::new();
    let a = pc.write_page(INO, 0, &page(1), &dev).unwrap();
    let b = pc.write_page(InodeId(2), PAGE_BYTES as u64, &page(2), &dev).unwrap();
    pc.fsync(INO, &dev).unwrap();
    assert!(!a.is_dirty());
    assert!(b.is_dirty(), "another inode's dirty list is untouched");
    assert_eq!(nr_dirty(), 1);
}

#[test]
fn a_failed_writeback_keeps_the_bytes_and_re_dirties_the_page() {
    let _m = fresh_machine();
    let disk = CountingDisk::new(8);
    let dev: Arc<dyn BlockDevice> = disk.clone();
    let pc = PageCache::new();
    let p = pc.write_page(INO, 0, &page(0x77), &dev).unwrap();
    disk.fail_writes(1);
    assert!(pc.fsync(INO, &dev).is_err());
    assert!(p.is_dirty(), "a write that did not land leaves the page dirty");
    assert_eq!(nr_dirty(), 1);
    assert_eq!(*p.data.lock(), page(0x77), "and the only copy of the bytes is still here");
    // The retry succeeds and reaches the medium.
    pc.fsync(INO, &dev).unwrap();
    assert_eq!(disk.medium_page(0), page(0x77));
    assert_eq!(nr_dirty(), 0);
}

#[test]
fn the_flusher_writes_back_once_the_machine_is_over_its_background_threshold() {
    let _m = fresh_machine();
    let disk = CountingDisk::new(64);
    let dev: Arc<dyn BlockDevice> = disk.clone();
    let pc = PageCache::new();
    // 10% of 40 pages is 4: three dirty pages are under it, five are over.
    install_totalram_pages(40);
    for i in 0..3u64 { pc.write_page(INO, i * PAGE_BYTES as u64, &page(i as u8 + 1), &dev).unwrap(); }
    assert_eq!(flush_pass(0), 0, "under the threshold the flusher writes nothing");
    assert_eq!(nr_dirty(), 3);
    for i in 3..6u64 { pc.write_page(INO, i * PAGE_BYTES as u64, &page(i as u8 + 1), &dev).unwrap(); }
    let written = flush_pass(0);
    assert!(written > 0, "over the threshold the flusher runs");
    assert!(nr_dirty() <= background_threshold(),
            "and stops once the machine is back under it: {} dirty", nr_dirty());
    assert_eq!(disk.medium_page(0), page(1));
}

#[test]
fn the_flusher_writes_back_an_aged_mapping_even_under_the_threshold() {
    let _m = fresh_machine();
    let disk = CountingDisk::new(8);
    let dev: Arc<dyn BlockDevice> = disk.clone();
    let pc = PageCache::new();
    install_totalram_pages(1_000_000); // threshold far above anything here
    crate::pagecache::install_clock(|| 1_000);
    pc.write_page(INO, 0, &page(0x42), &dev).unwrap();
    assert_eq!(flush_pass(1_000), 0, "a freshly dirtied page waits");
    assert_eq!(flush_pass(1_000 + DIRTY_EXPIRE_NS), 1, "an expired one does not");
    assert_eq!(disk.medium_page(0), page(0x42));
    assert_eq!(nr_dirty(), 0);
}

#[test]
fn dirtying_past_the_limit_makes_the_writer_do_the_writeback() {
    let _m = fresh_machine();
    let disk = CountingDisk::new(64);
    let dev: Arc<dyn BlockDevice> = disk.clone();
    let pc = PageCache::new();
    // 20% of 10 pages is 2: the third dirty page throttles its own writer.
    install_totalram_pages(10);
    pc.write_page(INO, 0, &page(1), &dev).unwrap();
    pc.write_page(INO, PAGE_BYTES as u64, &page(2), &dev).unwrap();
    assert_eq!(disk.writes(), 0, "under the limit nothing is forced");
    pc.write_page(INO, 2 * PAGE_BYTES as u64, &page(3), &dev).unwrap();
    assert!(disk.writes() > 0, "over the limit the writer writes back before returning");
}

#[test]
fn invalidating_a_dirty_page_takes_it_off_the_machine_count() {
    let _m = fresh_machine();
    let disk = CountingDisk::new(8);
    let dev: Arc<dyn BlockDevice> = disk.clone();
    let pc = PageCache::new();
    pc.write_page(INO, 0, &page(9), &dev).unwrap();
    assert_eq!(nr_dirty(), 1);
    pc.invalidate(INO);
    assert_eq!(nr_dirty(), 0, "a dropped page cannot stay in the dirty count");
    assert_eq!(pc.cached_count(), 0);
}
