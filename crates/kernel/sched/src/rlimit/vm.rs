// Address-space rlimits: the `RLIMIT_AS` admission every VMA-creating path
// runs (Linux `may_expand_vm`) and the `RLIMIT_STACK` bound the fault-time
// `MAP_GROWSDOWN` extension runs (Linux `acct_stack_growth`).
//
// Pure arithmetic, no live state: the caller supplies the mm's current mapped
// size and the task's live limit, so the ordering and the truncation rules are
// hosted-testable without an address space.

use super::INFINITY;

/// Page size the limit comparison is expressed in. `RLIMIT_AS` is a byte
/// count, but Linux compares PAGE COUNTS (`rlimit(RLIMIT_AS) >> PAGE_SHIFT`),
/// so a limit that is not a whole number of pages is truncated DOWN before the
/// test — 4095 bytes is a zero-page limit, not a one-page one.
pub const PAGE_BYTES: u64 = 4096;

/// Bytes → whole pages, rounding UP: a partial page still occupies one.
/// # C: O(1)
pub const fn pages_of(bytes: u64) -> u64 { bytes.div_ceil(PAGE_BYTES) }

/// Linux `may_expand_vm`'s address-space half:
///
/// ```text
/// if (mm->total_vm + npages > rlimit(RLIMIT_AS) >> PAGE_SHIFT) return false;
/// ```
///
/// `total_vm_bytes` is the mm's current mapped size (Linux `mm->total_vm`,
/// in bytes here), `grow_bytes` is what the caller is about to add. The test
/// is strictly-greater, so a request that lands exactly ON the limit is
/// admitted.
/// # C: O(1)
pub fn may_expand_as(total_vm_bytes: u64, grow_bytes: u64, rlimit_as: u64) -> bool {
    if rlimit_as == INFINITY { return true; }
    let want = pages_of(total_vm_bytes).saturating_add(pages_of(grow_bytes));
    want <= rlimit_as / PAGE_BYTES
}

/// Bytes still addable to an mm of `total_vm_bytes` before `may_expand_as`
/// starts refusing. The caps the VMA machinery applies are computed HERE, so
/// the `RLIM_INFINITY` sentinel and the page truncation live in one place and
/// the mechanism downstream only ever compares two byte counts.
///
/// Defined for a POSITIVE growth request. An mm already over its limit — which
/// `setrlimit(2)` can produce at any moment by lowering `RLIMIT_AS` under a
/// live process — reports zero headroom, and a zero-byte "growth" against it is
/// the one case where this and [`may_expand_as`] part company: Linux refuses
/// even that, while zero is trivially within zero headroom. No caller grows by
/// nothing.
/// # C: O(1)
pub fn as_headroom_bytes(total_vm_bytes: u64, rlimit_as: u64) -> u64 {
    if rlimit_as == INFINITY { return u64::MAX; }
    let limit_pages = rlimit_as / PAGE_BYTES;
    limit_pages.saturating_sub(pages_of(total_vm_bytes)).saturating_mul(PAGE_BYTES)
}

/// Largest post-growth stack VMA `stack_growth_ok` admits. # C: O(1)
pub fn stack_size_cap(rlimit_stack: u64) -> u64 {
    if rlimit_stack == INFINITY { u64::MAX } else { rlimit_stack }
}

/// Linux `acct_stack_growth`'s stack test:
///
/// ```text
/// if (size > rlimit(RLIMIT_STACK)) return -ENOMEM;
/// ```
///
/// `size` is the WHOLE post-growth stack VMA (`vma->vm_end - address`), not
/// the increment — a stack that is already over its limit cannot grow by even
/// one page. Strictly-greater again, so a stack sized exactly at the limit is
/// still legal.
/// # C: O(1)
pub fn stack_growth_ok(new_size_bytes: u64, rlimit_stack: u64) -> bool {
    if rlimit_stack == INFINITY { return true; }
    new_size_bytes <= rlimit_stack
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infinite_as_admits_everything() {
        assert!(may_expand_as(u64::MAX / 2, u64::MAX / 2, INFINITY));
    }

    #[test]
    fn as_limit_truncates_to_whole_pages() {
        // A limit one byte short of a page is a ZERO-page limit: Linux shifts
        // the byte limit right by PAGE_SHIFT before comparing.
        assert!(!may_expand_as(0, PAGE_BYTES, PAGE_BYTES - 1));
        assert!(may_expand_as(0, PAGE_BYTES, PAGE_BYTES));
        assert!(may_expand_as(0, PAGE_BYTES, PAGE_BYTES * 2 - 1));
        assert!(!may_expand_as(0, PAGE_BYTES * 2, PAGE_BYTES * 2 - 1));
    }

    #[test]
    fn as_test_is_strictly_greater() {
        // Landing exactly ON the limit is admitted; one page past is not.
        let limit = 4 * PAGE_BYTES;
        assert!(may_expand_as(3 * PAGE_BYTES, PAGE_BYTES, limit));
        assert!(!may_expand_as(4 * PAGE_BYTES, PAGE_BYTES, limit));
    }

    #[test]
    fn as_counts_a_partial_page_as_a_whole_one() {
        assert!(!may_expand_as(PAGE_BYTES, 1, PAGE_BYTES));
        assert!(may_expand_as(PAGE_BYTES, 1, 2 * PAGE_BYTES));
    }

    #[test]
    fn as_does_not_overflow_near_infinity() {
        assert!(!may_expand_as(u64::MAX - 1, u64::MAX - 1, u64::MAX - 1));
    }

    #[test]
    fn headroom_agrees_with_the_admission_test_it_precomputes() {
        for limit_pages in 0..8u64 {
            let limit = limit_pages * PAGE_BYTES;
            for used_pages in 0..8u64 {
                let used = used_pages * PAGE_BYTES;
                let room = as_headroom_bytes(used, limit);
                for grow_pages in 1..8u64 {
                    let grow = grow_pages * PAGE_BYTES;
                    assert_eq!(grow <= room, may_expand_as(used, grow, limit),
                        "headroom {room} disagrees at limit={limit} used={used} grow={grow}");
                }
            }
        }
        assert_eq!(as_headroom_bytes(1 << 40, INFINITY), u64::MAX);
    }

    #[test]
    fn an_mm_already_over_its_limit_has_no_headroom() {
        // `setrlimit(RLIMIT_AS)` can be lowered under a live process, so this
        // state is reachable and must refuse every further mapping.
        assert_eq!(as_headroom_bytes(8 * PAGE_BYTES, PAGE_BYTES), 0);
        assert!(!may_expand_as(8 * PAGE_BYTES, PAGE_BYTES, PAGE_BYTES));
    }

    #[test]
    fn stack_size_cap_maps_infinity_onto_the_widest_span() {
        assert_eq!(stack_size_cap(INFINITY), u64::MAX);
        assert_eq!(stack_size_cap(1 << 20), 1 << 20);
    }

    #[test]
    fn stack_growth_bounds_the_whole_vma_not_the_increment() {
        let limit = 8 * 1024 * 1024;
        assert!(stack_growth_ok(limit, limit), "exactly at the limit is legal");
        assert!(!stack_growth_ok(limit + 1, limit));
        assert!(stack_growth_ok(u64::MAX, INFINITY));
    }

    #[test]
    fn a_zero_stack_limit_refuses_any_growth() {
        assert!(!stack_growth_ok(PAGE_BYTES, 0));
        assert!(stack_growth_ok(0, 0));
    }
}
