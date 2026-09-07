//! Per-message kernel-entry profile for the Win32 message pump.
//!
//! A pump that takes hundreds of milliseconds per retrieved message is either
//! waiting or working, and a console trace of every kernel entry destroys the
//! measurement it is taken for. This counts entries by ordinal into a fixed
//! slot table, with the wall time each spent inside the kernel, and reports the
//! costliest few at each retrieval: the whole instrument costs one line per
//! message. An interval whose wall time is neither user time, system time, nor
//! time inside these calls was off the CPU with the thread runnable.

use core::sync::atomic::{AtomicU64, Ordering};

/// Ordinals tracked by identity; everything past them lands in the overflow.
pub const SLOTS: usize = 24;
/// Individual entries retained by cost, whatever their ordinal. The slot table
/// is claimed by the first ordinals an interval happens to use, so the one that
/// spends the interval's time can be absent from it entirely.
pub const SLOW: usize = 8;

/// One ordinal's share of an interval.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Entry {
    /// The Win32 ordinal or Linux syscall number.
    pub ordinal: u64,
    /// Entries served in the interval.
    pub count: u64,
    /// Wall nanoseconds spent inside them.
    pub total_ns: u64,
    /// Wall nanoseconds of the single costliest one.
    pub max_ns: u64,
}

/// One retrieval interval's counts.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Interval {
    /// Kernel entries recorded in the interval.
    pub total: u64,
    /// Entries whose ordinal found no slot.
    pub other: u64,
    /// Wall nanoseconds spent inside every recorded entry, slotted or not.
    pub total_ns: u64,
    /// Occupied slots, costliest first.
    pub top: [Entry; SLOTS],
    /// The interval's costliest individual entries, `(ordinal, ns)`, costliest
    /// first, regardless of the slot table.
    pub slowest: [(u64, u64); SLOW],
}

/// Lock-free ordinal histogram, reset by whoever reports it.
pub struct PumpProfile {
    ordinals: [AtomicU64; SLOTS],
    counts: [AtomicU64; SLOTS],
    totals: [AtomicU64; SLOTS],
    maxima: [AtomicU64; SLOTS],
    total: AtomicU64,
    other: AtomicU64,
    total_ns: AtomicU64,
    slow_ordinals: [AtomicU64; SLOW],
    slow_ns: [AtomicU64; SLOW],
}

/// No ordinal occupies a slot yet. Zero is not a Win32 ordinal, so it doubles
/// as the empty marker.
const EMPTY: u64 = 0;

impl Default for PumpProfile { fn default() -> Self { Self::new() } }

impl PumpProfile {
    /// # C: O(1)
    pub const fn new() -> PumpProfile {
        PumpProfile {
            ordinals: [const { AtomicU64::new(EMPTY) }; SLOTS],
            counts: [const { AtomicU64::new(0) }; SLOTS],
            totals: [const { AtomicU64::new(0) }; SLOTS],
            maxima: [const { AtomicU64::new(0) }; SLOTS],
            total: AtomicU64::new(0),
            other: AtomicU64::new(0),
            total_ns: AtomicU64::new(0),
            slow_ordinals: [const { AtomicU64::new(EMPTY) }; SLOW],
            slow_ns: [const { AtomicU64::new(0) }; SLOW],
        }
    }

    /// # C: O(1)
    fn charge(&self, slot: usize, ns: u64) {
        self.counts[slot].fetch_add(1, Ordering::Relaxed);
        self.totals[slot].fetch_add(ns, Ordering::Relaxed);
        self.maxima[slot].fetch_max(ns, Ordering::Relaxed);
    }

    /// Retain this entry if it is costlier than the cheapest one retained.
    /// # C: O(SLOW)
    fn note_slow(&self, ordinal: u64, ns: u64) {
        let mut victim = 0;
        for slot in 1..SLOW {
            if self.slow_ns[slot].load(Ordering::Relaxed) < self.slow_ns[victim].load(Ordering::Relaxed) { victim = slot; }
        }
        if ns <= self.slow_ns[victim].load(Ordering::Relaxed) { return; }
        self.slow_ns[victim].store(ns, Ordering::Relaxed);
        self.slow_ordinals[victim].store(ordinal, Ordering::Relaxed);
    }

    /// Charge one kernel entry of `ns` wall nanoseconds to `ordinal`, claiming
    /// a free slot for an ordinal not yet seen in this interval.
    /// # C: O(SLOTS)
    pub fn record(&self, ordinal: u64, ns: u64) {
        self.total.fetch_add(1, Ordering::Relaxed);
        self.total_ns.fetch_add(ns, Ordering::Relaxed);
        self.note_slow(ordinal, ns);
        if ordinal == EMPTY { self.other.fetch_add(1, Ordering::Relaxed); return; }
        for slot in 0..SLOTS {
            let held = self.ordinals[slot].load(Ordering::Relaxed);
            if held == ordinal { return self.charge(slot, ns); }
            if held == EMPTY && self.ordinals[slot].compare_exchange(EMPTY, ordinal, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                return self.charge(slot, ns);
            }
            if self.ordinals[slot].load(Ordering::Relaxed) == ordinal { return self.charge(slot, ns); }
        }
        self.other.fetch_add(1, Ordering::Relaxed);
    }

    /// Report the interval and start the next one empty.
    /// # C: O(SLOTS log SLOTS)
    pub fn take(&self) -> Interval {
        let mut out = Interval {
            total: self.total.swap(0, Ordering::Relaxed),
            other: self.other.swap(0, Ordering::Relaxed),
            total_ns: self.total_ns.swap(0, Ordering::Relaxed),
            top: [Entry::default(); SLOTS],
            slowest: [(EMPTY, 0); SLOW],
        };
        for slot in 0..SLOW {
            out.slowest[slot] = (self.slow_ordinals[slot].swap(EMPTY, Ordering::Relaxed), self.slow_ns[slot].swap(0, Ordering::Relaxed));
        }
        out.slowest.sort_by(|a, b| b.1.cmp(&a.1));
        for slot in 0..SLOTS {
            out.top[slot] = Entry {
                ordinal: self.ordinals[slot].swap(EMPTY, Ordering::Relaxed),
                count: self.counts[slot].swap(0, Ordering::Relaxed),
                total_ns: self.totals[slot].swap(0, Ordering::Relaxed),
                max_ns: self.maxima[slot].swap(0, Ordering::Relaxed),
            };
        }
        out.top.sort_by(|a, b| b.total_ns.cmp(&a.total_ns).then(b.count.cmp(&a.count)));
        out
    }
}
