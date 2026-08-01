// `cachestat` range decode + counter folding, against the kernel's arithmetic.

use super::{CachestatCounts, CachestatRange, PageState, CACHESTAT_FIELDS};

const SHIFT: u32 = 12;
const PG: u64 = 1 << SHIFT;

// `len == 0` is "to the end of the file", expressed as the maximum index —
// not a size lookup, so it also covers pages past `i_size`.
#[test]
fn zero_len_covers_the_whole_index_space_from_off() {
    let r = CachestatRange::from_bytes(3 * PG, 0, SHIFT);
    assert_eq!(r, CachestatRange { first: 3, last: u64::MAX });
    assert!(!r.contains(2));
    assert!(r.contains(3));
    assert!(r.contains(u64::MAX));
}

// The last index is `(off + len - 1) >> PAGE_SHIFT`: a request ending exactly
// on a page boundary must not pull in the following page.
#[test]
fn last_index_excludes_the_page_after_an_aligned_end() {
    assert_eq!(CachestatRange::from_bytes(0, PG, SHIFT), CachestatRange { first: 0, last: 0 });
    assert_eq!(CachestatRange::from_bytes(0, PG + 1, SHIFT), CachestatRange { first: 0, last: 1 });
    assert_eq!(CachestatRange::from_bytes(PG, 2 * PG, SHIFT), CachestatRange { first: 1, last: 2 });
}

// A one-byte request inside a page selects exactly that page.
#[test]
fn single_byte_selects_one_page() {
    let r = CachestatRange::from_bytes(5 * PG + 17, 1, SHIFT);
    assert_eq!(r, CachestatRange { first: 5, last: 5 });
}

// `off + len` overflowing wraps, exactly as the kernel's unsigned arithmetic
// does; the result is an inverted range that contains nothing rather than a
// silently clamped whole-file scan.
#[test]
fn overflowing_range_wraps_and_contains_nothing() {
    let r = CachestatRange::from_bytes(u64::MAX - PG, 4 * PG, SHIFT);
    assert!(r.first > r.last);
    assert!(!r.contains(0));
    assert!(!r.contains(u64::MAX >> SHIFT));
    assert_eq!(r.covered(0, 1), 0);
}

// Entries wholly outside the range contribute nothing.
#[test]
fn covered_is_zero_outside_the_range() {
    let r = CachestatRange { first: 4, last: 8 };
    assert_eq!(r.covered(0, 4), 0);
    assert_eq!(r.covered(9, 3), 0);
    assert_eq!(r.covered(3, 0), 0);
}

// A multi-page entry straddling either boundary contributes only its covered
// pages — the clipping the kernel applies to a large folio.
#[test]
fn covered_clips_a_multi_page_entry_at_both_boundaries() {
    let r = CachestatRange { first: 4, last: 8 };
    assert_eq!(r.covered(2, 4), 2);
    assert_eq!(r.covered(7, 4), 2);
    assert_eq!(r.covered(0, 64), 5);
    assert_eq!(r.covered(4, 5), 5);
    assert_eq!(r.covered(6, 1), 1);
}

// Dirty and writeback are tags ON a cache page: a dirty page counts in both
// `nr_cache` and `nr_dirty`, never instead of `nr_cache`.
#[test]
fn cache_tags_are_subsets_of_nr_cache() {
    let mut cs = CachestatCounts::default();
    cs.account(PageState::Cache { dirty: false, writeback: false }, 3);
    cs.account(PageState::Cache { dirty: true, writeback: false }, 2);
    cs.account(PageState::Cache { dirty: true, writeback: true }, 1);
    assert_eq!(cs, CachestatCounts { nr_cache: 6, nr_dirty: 3, nr_writeback: 1, nr_evicted: 0, nr_recently_evicted: 0 });
}

// Recently-evicted is a subset of evicted, and evicted pages are not cache
// pages — the two classes are disjoint.
#[test]
fn evicted_is_disjoint_from_cache_and_recent_is_a_subset() {
    let mut cs = CachestatCounts::default();
    cs.account(PageState::Evicted { recent: true }, 4);
    cs.account(PageState::Evicted { recent: false }, 5);
    assert_eq!(cs.nr_cache, 0);
    assert_eq!(cs.nr_evicted, 9);
    assert_eq!(cs.nr_recently_evicted, 4);
}

// The UAPI order is nr_cache, nr_dirty, nr_writeback, nr_evicted,
// nr_recently_evicted — the order the shim writes into user memory.
#[test]
fn uapi_field_order_matches_the_struct() {
    let cs = CachestatCounts { nr_cache: 1, nr_dirty: 2, nr_writeback: 3, nr_evicted: 4, nr_recently_evicted: 5 };
    assert_eq!(cs.as_uapi(), [1, 2, 3, 4, 5]);
    assert_eq!(CACHESTAT_FIELDS, 5);
}
