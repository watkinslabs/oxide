// Per-devpts-instance Unix98 PTY index allocator.
//
// Each mount owns one bitmap. Allocation returns the lowest free index below
// that mount's `max=` ceiling; last-close clears the same bit so the ceiling
// bounds live PTYs rather than the number created since boot.

use alloc::vec;
use alloc::vec::Vec;

use crate::ids::MAX_PTY_PAIRS;

const WORD_BITS: usize = u64::BITS as usize;
const WORDS: usize = (MAX_PTY_PAIRS as usize + WORD_BITS - 1) / WORD_BITS;

pub(crate) struct PtsIndices { words: Vec<u64> }

impl PtsIndices {
    /// Empty per-instance allocator. # C: O(MAX_PTY_PAIRS / 64)
    pub(crate) fn new() -> Self { Self { words: vec![0; WORDS] } }

    /// Lowest free index below `max`, or `None` when the live set fills it.
    /// # C: O(max / 64)
    pub(crate) fn alloc(&mut self, max: u32) -> Option<u32> {
        let limit = max.min(MAX_PTY_PAIRS) as usize;
        if limit == 0 { return None; }
        for (wi, word) in self.words.iter_mut().enumerate().take((limit + WORD_BITS - 1) / WORD_BITS) {
            let base = wi * WORD_BITS;
            let valid = (limit - base).min(WORD_BITS);
            let mask = if valid == WORD_BITS { u64::MAX } else { (1u64 << valid) - 1 };
            let free = !*word & mask;
            if free == 0 { continue; }
            let bit = free.trailing_zeros() as usize;
            *word |= 1u64 << bit;
            return Some((base + bit) as u32);
        }
        None
    }

    /// Return one index to this instance. Duplicate release is harmless.
    /// # C: O(1)
    pub(crate) fn free(&mut self, idx: u32) {
        if idx >= MAX_PTY_PAIRS { return; }
        let i = idx as usize;
        self.words[i / WORD_BITS] &= !(1u64 << (i % WORD_BITS));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mounts_max_bounds_live_indices_and_freed_indices_are_reused() {
        let mut a = PtsIndices::new();
        assert_eq!(a.alloc(2), Some(0));
        assert_eq!(a.alloc(2), Some(1));
        assert_eq!(a.alloc(2), None);
        a.free(0);
        assert_eq!(a.alloc(2), Some(0), "the released slot, not a monotonic third index");
    }

    #[test]
    fn allocators_are_mount_local() {
        let mut a = PtsIndices::new();
        let mut b = PtsIndices::new();
        assert_eq!(a.alloc(1), Some(0));
        assert_eq!(a.alloc(1), None);
        assert_eq!(b.alloc(1), Some(0), "another mount owns another index namespace");
    }

    #[test]
    fn zero_and_the_build_ceiling_are_exact() {
        let mut a = PtsIndices::new();
        assert_eq!(a.alloc(0), None);
        for want in 0..MAX_PTY_PAIRS { assert_eq!(a.alloc(MAX_PTY_PAIRS), Some(want)); }
        assert_eq!(a.alloc(MAX_PTY_PAIRS), None);
        a.free(MAX_PTY_PAIRS - 1);
        assert_eq!(a.alloc(MAX_PTY_PAIRS), Some(MAX_PTY_PAIRS - 1));
    }
}
