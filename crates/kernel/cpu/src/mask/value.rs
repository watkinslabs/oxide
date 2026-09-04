// Fixed-capacity CPU-set representation and atomic publication storage.
//
// Linux carries CPU sets as word arrays, not a scalar machine word.  The
// kernel's first wider-than-64 CPU consumer is the online set, so this module
// owns both the value type and its monotonic boot-time publication form.

use core::sync::atomic::{fence as atomic_fence, AtomicBool, AtomicU64, Ordering};

use crate::MAX_CPUS;
use super::latch;

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

    /// Number of CPUs in the set. # C: O(words)
    pub const fn count_ones(&self) -> u32 {
        let mut total = 0;
        let mut i = 0;
        while i < CPU_MASK_WORDS {
            total += self.words[i].count_ones();
            i += 1;
        }
        total
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

    /// True when every CPU named by `self` is also named by `rhs`. # C: O(words)
    pub const fn is_subset_of(self, rhs: Self) -> bool { self.without(rhs).is_empty() }

    /// Low word for an unmigrated one-word caller. # C: O(1)
    pub const fn low_word(self) -> u64 { self.words[0] }

    /// Borrow the canonical word-array representation for an architecture
    /// consumer that cannot depend on the CPU crate. # C: O(1)
    pub const fn as_words(&self) -> &[u64] { &self.words }

    /// Copy a bounded external word slice into the canonical CPU-set shape.
    /// Extra words are ignored; missing words are zero. # C: O(words)
    pub fn from_words(words: &[u64]) -> Self {
        let mut out = Self::empty();
        let mut i = 0;
        while i < CPU_MASK_WORDS {
            if i < words.len() { out.words[i] = words[i]; }
            i += 1;
        }
        out.intersect(Self::all())
    }
}

/// Atomically published CPU set. Two seqcount-latch copies let IRQ-context
/// readers take one coherent generation even when a writer is interrupted.
pub struct AtomicCpuMask {
    seq: AtomicU64,
    words: [[AtomicU64; CPU_MASK_WORDS]; 2],
    writer: AtomicBool,
}

impl AtomicCpuMask {
    /// Empty atomic CPU set. # C: O(1)
    pub const fn new() -> Self {
        Self {
            seq: AtomicU64::new(0),
            words: [const { [const { AtomicU64::new(0) }; CPU_MASK_WORDS] }; 2],
            writer: AtomicBool::new(false),
        }
    }

    /// Atomic CPU set initially containing every addressable CPU. # C: O(1)
    pub const fn all() -> Self {
        Self {
            seq: AtomicU64::new(0),
            words: [const { [const { AtomicU64::new(u64::MAX) }; CPU_MASK_WORDS] }; 2],
            writer: AtomicBool::new(false),
        }
    }

    /// Snapshot the published set. # C: O(words)
    pub fn load(&self, order: Ordering) -> CpuMask {
        CpuMask { words: latch::load(self, order, &latch::NoObserve) }
    }

    /// Replace the published set. # C: O(words)
    pub fn store(&self, mask: CpuMask, order: Ordering) {
        latch::replace(self, mask.words, order, &latch::NoObserve);
    }

    /// Publish one CPU as present in the set. # C: O(1)
    pub fn set(&self, cpu: usize, order: Ordering) -> bool {
        if cpu >= MAX_CPUS { return false; }
        latch::lock(self, &latch::NoObserve);
        let mut mask = CpuMask { words: latch::active(self) };
        let changed = mask.insert(cpu);
        if changed { latch::replace_locked(self, mask.words, &latch::NoObserve); }
        latch::unlock(self, order);
        changed
    }

    /// Remove one CPU from the published set. # C: O(1)
    pub fn clear_cpu(&self, cpu: usize, order: Ordering) -> bool {
        if cpu >= MAX_CPUS { return false; }
        latch::lock(self, &latch::NoObserve);
        let mut mask = CpuMask { words: latch::active(self) };
        let changed = mask.remove(cpu);
        if changed { latch::replace_locked(self, mask.words, &latch::NoObserve); }
        latch::unlock(self, order);
        changed
    }

    #[cfg(test)]
    pub(crate) fn clear(&self) {
        self.store(CpuMask::empty(), Ordering::Release);
    }

}

impl latch::Storage<CPU_MASK_WORDS> for AtomicCpuMask {
    fn seq_load(&self, order: Ordering) -> u64 { self.seq.load(order) }
    fn seq_add(&self, value: u64, order: Ordering) { self.seq.fetch_add(value, order); }
    fn word_load(&self, copy: usize, word: usize, order: Ordering) -> u64 {
        self.words[copy][word].load(order)
    }
    fn word_store(&self, copy: usize, word: usize, value: u64, order: Ordering) {
        self.words[copy][word].store(value, order);
    }
    fn writer_lock(&self, current: bool, new: bool, success: Ordering, failure: Ordering) -> bool {
        self.writer.compare_exchange(current, new, success, failure).is_ok()
    }
    fn writer_store(&self, value: bool, order: Ordering) { self.writer.store(value, order); }
    fn fence(&self, order: Ordering) { atomic_fence(order); }
    fn relax(&self) { sync::spin_relax::relax(); }
}
