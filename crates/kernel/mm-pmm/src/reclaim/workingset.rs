// Workingset shadow-entry recency.
//
// Reclaim dropping a clean page cache page leaves a *shadow* entry at that
// index instead of nothing. The shadow records the value of the global
// nonresident-age clock at eviction. A later query measures the refault
// distance — how many pages were evicted since — and calls the page
// "recently evicted" when that distance fits inside the workingset, i.e. when
// a slightly larger cache would still have held it. This is the state
// `cachestat(2)` reports as `nr_recently_evicted`.
//
// Ungated on purpose: the decision half is a pure integer comparison and the
// cache backends that carry shadows are kernel-gated, so the arithmetic would
// otherwise never be exercised.

use core::sync::atomic::{AtomicU64, Ordering};

/// Nonresident age clock: one tick per page reclaim evicts from an LRU. The
/// shadow written at eviction stores the pre-increment value, so the first
/// refault query on it measures a distance of at least one tick.
static NONRESIDENT_AGE: AtomicU64 = AtomicU64::new(0);

/// `workingset_eviction` — advance the nonresident age and return the stamp to
/// store in the shadow entry left behind at the evicted index.
/// # C: O(1)
pub fn workingset_eviction() -> u64 { NONRESIDENT_AGE.fetch_add(1, Ordering::Relaxed) }

/// Current nonresident age (the refault-side read of the clock).
/// # C: O(1)
pub fn nonresident_age() -> u64 { NONRESIDENT_AGE.load(Ordering::Relaxed) }

/// `workingset_test_recent`'s decision, with the workingset size supplied.
/// Unsigned subtraction gives the correct distance across a clock wrap, and a
/// shadow stamped after the current age (impossible in-kernel, reachable in a
/// test) yields a huge distance rather than a spurious "recent".
/// # C: O(1)
pub fn test_recent_sized(shadow: u64, age: u64, workingset_size: u64) -> bool {
    age.wrapping_sub(shadow) <= workingset_size
}

/// File-cache workingset size: the active file LRU, plus the anonymous lists
/// that would compete with it whenever swap can absorb them. Pre-`init_page_meta`
/// there is no reclaim owner and the answer is zero, so only the newest shadow
/// counts as recent — never a fabricated population.
/// # C: O(1); # Lk: TaskList
pub fn file_workingset_size() -> u64 {
    let Some(s) = crate::setup::reclaim_snapshot() else { return 0 };
    let mut size = s.active_file;
    if crate::swap::has_writable_area() { size += s.active_anon + s.inactive_anon; }
    size
}

/// `workingset_test_recent` for a file-cache shadow: was the page at this
/// shadow evicted recently enough that the workingset would still have held it?
/// # C: O(1); # Lk: TaskList
pub fn workingset_test_recent(shadow: u64) -> bool {
    test_recent_sized(shadow, nonresident_age(), file_workingset_size())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Distance zero (a shadow stamped at the current age) is inside every
    // workingset, including an empty one.
    #[test]
    fn zero_distance_is_recent_even_with_no_workingset() {
        assert!(test_recent_sized(10, 10, 0));
    }

    // The comparison is `<=`, so a distance exactly equal to the workingset
    // size still counts — the page would have survived a cache of that size.
    #[test]
    fn distance_equal_to_workingset_is_recent_and_one_past_is_not() {
        assert!(test_recent_sized(0, 8, 8));
        assert!(!test_recent_sized(0, 9, 8));
    }

    // Unsigned wrap of the age clock must not turn an old shadow into a recent
    // one: the wrapping difference is the true tick count.
    #[test]
    fn distance_is_correct_across_clock_wrap() {
        let shadow = u64::MAX - 2;
        assert!(test_recent_sized(shadow, 1, 4));
        assert!(!test_recent_sized(shadow, 1, 3));
    }

    // A shadow "from the future" (age behind the stamp) wraps to an enormous
    // distance rather than reporting recent.
    #[test]
    fn shadow_ahead_of_clock_is_not_recent() {
        assert!(!test_recent_sized(100, 99, u64::MAX / 2));
    }

    // The clock advances once per eviction and hands out the pre-increment
    // stamp, so consecutive evictions are one tick apart.
    #[test]
    fn eviction_stamps_advance_by_one_tick() {
        let a = workingset_eviction();
        let b = workingset_eviction();
        assert_eq!(b, a + 1);
        assert!(nonresident_age() >= b + 1);
    }
}
