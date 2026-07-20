//! Address-space dirty-page + writeback-error tracking (`DirtyPages`, Linux
//! page-cache xarray `PAGECACHE_TAG_DIRTY` + `mapping_set_error` /
//! `filemap_check_errors`). Pure state object an inode embeds under its own
//! mapping lock; the `vfs` crate provides the primitive, `fs`/`ext4` embed it.

use vfs::mapping::{AddressSpaceOps, DirtyPages, AS_EIO, AS_ENOSPC};

#[test]
fn set_dirty_reports_state_change() {
    let mut d = DirtyPages::new();
    // First mark of a clean page reports a transition; a repeat does not.
    assert!(d.set_dirty(3));
    assert!(!d.set_dirty(3));
    assert!(d.is_dirty(3));
    assert_eq!(d.count(), 1);
    assert!(!d.is_empty());
}

#[test]
fn clear_dirty_reports_prior_state() {
    let mut d = DirtyPages::new();
    d.set_dirty(7);
    assert!(d.clear_dirty(7));      // was dirty
    assert!(!d.clear_dirty(7));     // already clean
    assert!(!d.is_dirty(7));
    assert!(d.is_empty());
}

#[test]
fn take_writeback_returns_sorted_and_clears() {
    let mut d = DirtyPages::new();
    for i in [9u64, 1, 5, 2] { d.set_dirty(i); }
    let wb = d.take_writeback();
    assert_eq!(wb, vec![1, 2, 5, 9], "writeback list is ascending page order");
    assert!(d.is_empty(), "tags cleared after collection");
    assert_eq!(d.count(), 0);
}

#[test]
fn clear_range_drops_only_in_range() {
    let mut d = DirtyPages::new();
    for i in 0..10u64 { d.set_dirty(i); }
    // Truncate-style clear of pages [3, 7): drops 3,4,5,6; keeps the rest.
    d.clear_range(3, 7);
    for i in [0u64, 1, 2, 7, 8, 9] { assert!(d.is_dirty(i), "page {i} retained"); }
    for i in 3u64..7 { assert!(!d.is_dirty(i), "page {i} dropped"); }
    assert_eq!(d.count(), 6);
}

#[test]
fn clear_range_to_eof() {
    let mut d = DirtyPages::new();
    for i in 0..5u64 { d.set_dirty(i); }
    d.clear_range(2, u64::MAX); // drop everything from page 2 to EOF
    assert!(d.is_dirty(0) && d.is_dirty(1));
    for i in 2u64..5 { assert!(!d.is_dirty(i)); }
    assert_eq!(d.count(), 2);
}

#[test]
fn take_writeback_range_collects_only_window_and_clears_only_it() {
    let mut d = DirtyPages::new();
    for i in 0..10u64 { d.set_dirty(i); }
    // sync_file_range over pages [3, 7): flush 3,4,5,6 in ascending order.
    let wb = d.take_writeback_range(3, 7);
    assert_eq!(wb, vec![3, 4, 5, 6], "only in-range dirty pages, ascending");
    // Out-of-window pages stay dirty for a later flush.
    for i in [0u64, 1, 2, 7, 8, 9] { assert!(d.is_dirty(i), "page {i} still dirty"); }
    for i in 3u64..7 { assert!(!d.is_dirty(i), "page {i} cleared after its writeback"); }
    assert_eq!(d.count(), 6);
}

#[test]
fn take_writeback_range_to_eof() {
    let mut d = DirtyPages::new();
    for i in [0u64, 4, 8, 12] { d.set_dirty(i); }
    let wb = d.take_writeback_range(4, u64::MAX);
    assert_eq!(wb, vec![4, 8, 12], "from page 4 to EOF");
    assert!(d.is_dirty(0) && d.is_empty() == false);
    assert_eq!(d.count(), 1, "only page 0 remains dirty");
}

#[test]
fn take_writeback_range_empty_window_is_noop() {
    let mut d = DirtyPages::new();
    for i in [0u64, 5] { d.set_dirty(i); }
    // A window covering no dirty page returns empty and clears nothing.
    assert_eq!(d.take_writeback_range(1, 5), Vec::<u64>::new());
    assert!(d.is_dirty(0) && d.is_dirty(5));
    assert_eq!(d.count(), 2);
}

/// The address-space `writeback_range` default forwards to `writeback()` — a
/// whole-file flush is a correct superset of any byte range. A backend with a
/// per-page dirty store overrides to flush only the in-range pages.
#[test]
fn writeback_range_default_forwards_to_writeback() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Wb { whole: AtomicUsize }
    impl AddressSpaceOps for Wb {
        fn shared_frame(&self, _off: u64) -> vfs::KResult<Option<vfs::SharedFrame>> { Ok(None) }
        fn read_at(&self, _off: u64, _dst: &mut [u8]) -> vfs::KResult<usize> { Ok(0) }
        fn size(&self) -> u64 { 0 }
        fn writeback(&self) -> Result<(), ()> { self.whole.fetch_add(1, Ordering::SeqCst); Ok(()) }
    }
    let a = Wb { whole: AtomicUsize::new(0) };
    assert!(a.writeback_range(0, 4096).is_ok());
    assert_eq!(a.whole.load(Ordering::SeqCst), 1, "default range writeback flushed the whole file once");
    assert!(a.writeback_range(0, u64::MAX).is_ok());
    assert_eq!(a.whole.load(Ordering::SeqCst), 2);
}

#[test]
fn set_error_zero_is_noop() {
    let mut d = DirtyPages::new();
    d.set_error(0);
    assert_eq!(d.check_errors(), 0);
}

#[test]
fn enospc_only_reports_enospc() {
    let mut d = DirtyPages::new();
    d.set_error(28); // ENOSPC alone
    assert_eq!(d.check_errors(), 28);
    assert_eq!(d.check_errors(), 0, "sticky flag cleared after harvest");
}

#[test]
fn eio_overrides_in_one_pass_clearing_both() {
    let mut d = DirtyPages::new();
    d.set_error(5);  // arbitrary non-ENOSPC errno -> AS_EIO
    d.set_error(28); // ENOSPC
    // Linux assigns AS_EIO last, so a single check returns EIO and clears BOTH.
    assert_eq!(d.check_errors(), 5);
    assert_eq!(d.check_errors(), 0, "both flags cleared in the one pass");
}

#[test]
fn eio_flag_value_is_distinct() {
    // Sanity on the public flag constants used by callers building masks.
    assert_ne!(AS_EIO, AS_ENOSPC);
    assert_eq!(AS_EIO & AS_ENOSPC, 0);
}
