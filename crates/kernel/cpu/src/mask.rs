// Fixed-capacity CPU-set representation and atomic publication storage.
//
// Linux carries CPU sets as word arrays, not a scalar machine word.  The
// kernel's first wider-than-64 CPU consumer is the online set, so this module
// owns both the value type and its monotonic boot-time publication form.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::MAX_CPUS;

/// Bits in one CPU-mask word.
pub const CPU_MASK_WORD_BITS: usize = u64::BITS as usize;
/// Number of words needed to represent every logical CPU the kernel admits.
pub const CPU_MASK_WORDS: usize = MAX_CPUS.div_ceil(CPU_MASK_WORD_BITS);

/// A set of dense logical CPU IDs.
///
/// Bits at or above `MAX_CPUS` are never set by this API.  The fixed array
/// keeps early boot and interrupt paths allocation-free while retaining the
/// same word-array shape as the scheduler-facing CPU sets.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CpuMask { words: [u64; CPU_MASK_WORDS] }

impl CpuMask {
    /// Empty set. # C: O(1)
    pub const fn empty() -> Self { Self { words: [0; CPU_MASK_WORDS] } }

    /// Set containing only `cpu`; out-of-range IDs produce the empty set.
    /// # C: O(1)
    pub const fn of(cpu: usize) -> Self {
        let mut out = Self::empty();
        if cpu < MAX_CPUS { out.words[cpu / CPU_MASK_WORD_BITS] = 1u64 << (cpu % CPU_MASK_WORD_BITS); }
        out
    }

    /// Set containing every addressable logical CPU. # C: O(words)
    pub const fn all() -> Self {
        let mut out = Self { words: [u64::MAX; CPU_MASK_WORDS] };
        let tail = MAX_CPUS % CPU_MASK_WORD_BITS;
        if tail != 0 { out.words[CPU_MASK_WORDS - 1] = (1u64 << tail) - 1; }
        out
    }

    /// True when no CPU is set. # C: O(words)
    pub const fn is_empty(&self) -> bool {
        let mut i = 0;
        while i < CPU_MASK_WORDS {
            if self.words[i] != 0 { return false; }
            i += 1;
        }
        true
    }

    /// True when `cpu` belongs to the set. # C: O(1)
    pub const fn contains(&self, cpu: usize) -> bool {
        cpu < MAX_CPUS && (self.words[cpu / CPU_MASK_WORD_BITS] & (1u64 << (cpu % CPU_MASK_WORD_BITS))) != 0
    }

    /// Insert `cpu`; returns whether the set changed. # C: O(1)
    pub fn insert(&mut self, cpu: usize) -> bool {
        if cpu >= MAX_CPUS { return false; }
        let word = &mut self.words[cpu / CPU_MASK_WORD_BITS];
        let bit = 1u64 << (cpu % CPU_MASK_WORD_BITS);
        let changed = *word & bit == 0;
        *word |= bit;
        changed
    }

    /// Remove `cpu`; returns whether the set changed. # C: O(1)
    pub fn remove(&mut self, cpu: usize) -> bool {
        if cpu >= MAX_CPUS { return false; }
        let word = &mut self.words[cpu / CPU_MASK_WORD_BITS];
        let bit = 1u64 << (cpu % CPU_MASK_WORD_BITS);
        let changed = *word & bit != 0;
        *word &= !bit;
        changed
    }

    /// Intersection of two CPU sets. # C: O(words)
    pub const fn intersect(self, rhs: Self) -> Self {
        let mut out = Self::empty();
        let mut i = 0;
        while i < CPU_MASK_WORDS {
            out.words[i] = self.words[i] & rhs.words[i];
            i += 1;
        }
        out
    }

    /// Set difference `self - rhs`. # C: O(words)
    pub const fn without(self, rhs: Self) -> Self {
        let mut out = Self::empty();
        let mut i = 0;
        while i < CPU_MASK_WORDS {
            out.words[i] = self.words[i] & !rhs.words[i];
            i += 1;
        }
        out
    }

    /// Low word for an unmigrated one-word caller. # C: O(1)
    pub const fn low_word(self) -> u64 { self.words[0] }
}

/// Atomically published CPU set.  Online CPU publication only adds bits after
/// boot, so a snapshot that races an addition is a safe subset; callers that
/// need the final set run after AP bring-up completes.
pub struct AtomicCpuMask { words: [AtomicU64; CPU_MASK_WORDS] }

impl AtomicCpuMask {
    /// Empty atomic CPU set. # C: O(1)
    pub const fn new() -> Self { Self { words: [const { AtomicU64::new(0) }; CPU_MASK_WORDS] } }

    /// Snapshot the published set. # C: O(words)
    pub fn load(&self, order: Ordering) -> CpuMask {
        let mut out = CpuMask::empty();
        let mut i = 0;
        while i < CPU_MASK_WORDS {
            out.words[i] = self.words[i].load(order);
            i += 1;
        }
        out
    }

    /// Replace the published set. # C: O(words)
    pub fn store(&self, mask: CpuMask, order: Ordering) {
        for (word, value) in self.words.iter().zip(mask.words) { word.store(value, order); }
    }

    /// Publish one CPU as present in the set. # C: O(1)
    pub fn set(&self, cpu: usize, order: Ordering) {
        if cpu < MAX_CPUS {
            self.words[cpu / CPU_MASK_WORD_BITS].fetch_or(1u64 << (cpu % CPU_MASK_WORD_BITS), order);
        }
    }

    /// Remove one CPU from the published set. # C: O(1)
    pub fn clear_cpu(&self, cpu: usize, order: Ordering) {
        if cpu < MAX_CPUS {
            self.words[cpu / CPU_MASK_WORD_BITS].fetch_and(!(1u64 << (cpu % CPU_MASK_WORD_BITS)), order);
        }
    }

    #[cfg(test)]
    pub(crate) fn clear(&self) {
        for word in &self.words { word.store(0, Ordering::Release); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_accepts_each_currently_addressable_cpu_and_rejects_the_next() {
        let mut m = CpuMask::empty();
        assert!(m.insert(0));
        assert!(m.insert(CPU_MASK_WORD_BITS - 1));
        assert!(m.contains(0));
        assert!(m.contains(CPU_MASK_WORD_BITS - 1));
        assert!(!m.contains(MAX_CPUS));
    }

    #[test]
    fn all_names_every_addressable_cpu_without_tail_bits() {
        let mask = CpuMask::all();
        assert!(mask.contains(0));
        assert!(mask.contains(MAX_CPUS - 1));
        assert!(!mask.contains(MAX_CPUS));
    }

    #[test]
    fn atomic_snapshot_observes_each_published_word() {
        let m = AtomicCpuMask::new();
        m.clear();
        m.set(0, Ordering::Release);
        m.set(MAX_CPUS - 1, Ordering::Release);
        let got = m.load(Ordering::Acquire);
        assert!(got.contains(0));
        assert!(got.contains(MAX_CPUS - 1));
    }
}
