// Physical ranges this boot set aside that a LATER kernel must not reuse.
//
// A range here is memory the running kernel handed to hardware that keeps
// using it across a relocation. The interrupt controller's LPI configuration
// and pending tables are the case that exists: their addresses live in
// registers the controller keeps reading, so a kernel started by kexec finds
// the tables already live and adopts them rather than allocating its own. If
// that kernel's allocator was never told the pages are taken, it hands them
// out — and the controller then writes interrupt configuration over whatever
// landed there. The damage surfaces far away, as a poisoned pointer in the
// first driver whose data structure happened to be given the memory.
//
// One registry, two readers: the loader keeps its own segments out of these
// ranges AND carries a reservation for each into the tree the next kernel
// boots with. A second list beside this one could disagree with it at exactly
// the moment nothing can tell which is right.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

extern crate alloc;
use alloc::vec::Vec;

/// Ranges the registry can hold.
///
/// Sized for the handful of tables a machine's interrupt controller owns, not
/// for a general allocator. `add` refuses past this rather than overwriting,
/// because a dropped reservation is the failure this module exists to prevent
/// and a silent one is worse than a refused one.
pub const MAX_RANGES: usize = 16;

static COUNT: AtomicUsize = AtomicUsize::new(0);
static BASE: [AtomicU64; MAX_RANGES] = [const { AtomicU64::new(0) }; MAX_RANGES];
static LEN: [AtomicU64; MAX_RANGES] = [const { AtomicU64::new(0) }; MAX_RANGES];

/// Record `[pa, pa + len)` as memory a later kernel must not reuse.
///
/// `false` when the range is empty or the registry is full — the caller has
/// set up hardware pointing at memory that will not be described, which is
/// worth reporting rather than assuming.
/// # C: O(1)
pub fn add(pa: u64, len: u64) -> bool {
    if len == 0 { return false; }
    let i = COUNT.fetch_add(1, Ordering::AcqRel);
    if i >= MAX_RANGES {
        // Saturate rather than let the counter run away from the array.
        COUNT.store(MAX_RANGES, Ordering::Release);
        return false;
    }
    BASE[i].store(pa, Ordering::Release);
    // Published last: a reader that sees the slot counted but not yet filled
    // reads a zero length and skips it, rather than a base with no extent.
    LEN[i].store(len, Ordering::Release);
    true
}

/// Every recorded range as `(pa, len)`, in the order they were recorded.
/// # C: O(MAX_RANGES)
pub fn ranges() -> Vec<(u64, u64)> {
    let n = COUNT.load(Ordering::Acquire).min(MAX_RANGES);
    let mut v = Vec::new();
    for i in 0..n {
        let len = LEN[i].load(Ordering::Acquire);
        if len == 0 { continue; }
        v.push((BASE[i].load(Ordering::Acquire), len));
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    // One test, because the registry is process-global: split across several
    // the order would decide the result.
    #[test]
    fn a_recorded_range_is_readable_and_an_empty_one_is_refused() {
        assert!(ranges().is_empty(), "nothing recorded before the first add");

        assert!(!add(0x4000_0000, 0), "a zero-length range describes no memory");
        assert!(ranges().is_empty(), "…and is not recorded");

        assert!(add(0xbf33_8000, 0x1_0000));
        assert!(add(0xbf31_0000, 0x1_0000));
        assert_eq!(ranges(), alloc::vec![(0xbf33_8000, 0x1_0000), (0xbf31_0000, 0x1_0000)]);

        // A base of zero is a legal physical address for this registry to
        // hold; only the length decides whether a slot is published.
        assert!(add(0, 0x1000));
        assert_eq!(ranges().len(), 3);

        for i in 0..MAX_RANGES { assert_eq!(add(0x1000 * i as u64 + 0x1_0000, 0x1000), i < MAX_RANGES - 3); }
        assert_eq!(ranges().len(), MAX_RANGES, "the registry never reports more than it can hold");
    }
}
