// `errseq_t`: a sticky "most recent writeback error" cell with per-subscriber
// exactly-once delivery.
//
// A single `u32` recording "the most recent error, plus a counter that lets any
// number of subscribers tell whether it changed since they last looked". This
// is the mechanism behind `fsync(2)`/`syncfs(2)` reporting a writeback error
// EXACTLY ONCE per open file description: the address_space (and the
// superblock) hold the master value, every `File` snapshots it at open, and
// `check_and_advance` reports-then-advances the snapshot.
//
// No target gate: pure value logic, unit tested here (`docs/53` — decision
// logic lives outside `#[cfg(target_os = "oxide-kernel")]` files).

use core::sync::atomic::{AtomicU32, Ordering};

/// Largest valid positive errno value the packed field can carry.
pub const MAX_ERRNO: u32 = 4095;
/// `ilog2(MAX_ERRNO) + 1` = 12, so the low 12 bits carry the errno.
const ERRSEQ_SHIFT: u32 = 12;
/// Bit 12: set once somebody has sampled the current error.
const ERRSEQ_SEEN: u32 = 1 << ERRSEQ_SHIFT;
/// Low 12 bits: the packed positive errno.
const ERRNO_MASK: u32 = ERRSEQ_SEEN - 1;
/// Lowest bit of the sequence counter, which occupies the bits above SEEN.
const ERRSEQ_CTR_INC: u32 = 1 << (ERRSEQ_SHIFT + 1);

/// A subscriber's snapshot of an [`Errseq`]. All-zero is the epoch ("no error
/// has ever been recorded"), which is why a freshly zeroed value is valid.
pub type ErrseqVal = u32;

/// The master side: an atomically-updated `errseq_t`. Lives in an
/// `address_space` (`mapping->wb_err`) and in a `super_block` (`s_wb_err`).
#[derive(Debug, Default)]
pub struct Errseq(AtomicU32);

impl Errseq {
    /// # C: O(1)
    pub const fn new() -> Self { Errseq(AtomicU32::new(0)) }

    /// Record `err` (a POSITIVE errno here; the packed field stores it directly).
    ///
    /// An error always overwrites the existing one, and the counter advances
    /// only when the previous value had been SEEN — that is what keeps a storm
    /// of identical errors from wrapping the counter, while still guaranteeing
    /// that a subscriber who already reported the old error will observe the
    /// new one.
    ///
    /// `err == 0` and `err > MAX_ERRNO` are ignored — clearing a recorded error
    /// via this path is not a thing; the previous value is kept unchanged.
    /// Returns the previous raw value, for debugging only. # C: O(1) amortised
    pub fn set(&self, err: u32) -> ErrseqVal {
        let mut old = self.0.load(Ordering::Relaxed);
        if err == 0 || err > MAX_ERRNO { return old; }
        loop {
            let mut new = (old & !(ERRNO_MASK | ERRSEQ_SEEN)) | err;
            if old & ERRSEQ_SEEN != 0 { new = new.wrapping_add(ERRSEQ_CTR_INC); }
            if new == old { return new; }
            match self.0.compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_)  => return new,
                Err(c) => old = c,
            }
        }
    }

    /// The value a new subscriber (an `open(2)`) starts from.
    ///
    /// The SEEN test is the subtle half: if the current error has NOT been seen
    /// by anybody, the sample is 0 (the epoch), so this brand-new subscriber
    /// WILL be told about it. This is deliberate — an error nobody
    /// has collected yet is still owed to someone. # C: O(1)
    pub fn sample(&self) -> ErrseqVal {
        let old = self.0.load(Ordering::Acquire);
        if old & ERRSEQ_SEEN == 0 { 0 } else { old }
    }

    /// Has anything changed since `since`, without advancing it. The lockless
    /// fast path. # C: O(1)
    pub fn check(&self, since: ErrseqVal) -> bool {
        self.0.load(Ordering::Acquire) != since
    }

    /// Report the error recorded since `*since` — as a POSITIVE errno — and
    /// advance `*since` past it so the SAME subscriber never sees it twice.
    ///
    /// Marks the master value SEEN so a subsequent `set` bumps the counter.
    /// Returns `None` when nothing changed. # C: O(1)
    pub fn check_and_advance(&self, since: &mut ErrseqVal) -> Option<u32> {
        let old = self.0.load(Ordering::Acquire);
        if old == *since { return None; }
        let new = old | ERRSEQ_SEEN;
        if new != old {
            // Outcome ignored deliberately: a lost race means another reader
            // set SEEN or a writer recorded a newer error, and either way
            // advancing `since` to `new` and reporting `new`'s errno is
            // correct for THIS subscriber.
            let _ = self.0.compare_exchange(old, new, Ordering::AcqRel, Ordering::Relaxed);
        }
        *since = new;
        let errno = new & ERRNO_MASK;
        if errno == 0 { None } else { Some(errno) }
    }

    /// Raw value — diagnostics (`/proc`, tests). # C: O(1)
    pub fn raw(&self) -> ErrseqVal { self.0.load(Ordering::Relaxed) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The all-zero epoch reports nothing, and a sample of a clean errseq is 0.
    /// # C: O(1)
    #[test]
    fn epoch_reports_nothing() {
        let e = Errseq::new();
        let mut s = e.sample();
        assert_eq!(s, 0);
        assert!(!e.check(s));
        assert_eq!(e.check_and_advance(&mut s), None);
    }

    /// The core `fsync` contract: an error is reported EXACTLY ONCE to a given
    /// subscriber. A second `fsync` on the same fd with no new error returns
    /// success.
    #[test]
    fn error_reported_exactly_once_per_subscriber() {
        let e = Errseq::new();
        let mut fd = e.sample();
        e.set(5); // EIO
        assert_eq!(e.check_and_advance(&mut fd), Some(5));
        assert_eq!(e.check_and_advance(&mut fd), None, "second fsync must not re-report");
        assert_eq!(e.check_and_advance(&mut fd), None);
    }

    /// Two fds opened before the error BOTH get told — that is the whole point
    /// of a per-subscriber snapshot rather than a single sticky flag.
    #[test]
    fn every_subscriber_gets_told_once() {
        let e = Errseq::new();
        let mut a = e.sample();
        let mut b = e.sample();
        e.set(28); // ENOSPC
        assert_eq!(e.check_and_advance(&mut a), Some(28));
        assert_eq!(e.check_and_advance(&mut b), Some(28));
        assert_eq!(e.check_and_advance(&mut a), None);
        assert_eq!(e.check_and_advance(&mut b), None);
    }

    /// Sampling returns 0 while the error is UNSEEN, so an fd opened
    /// after an uncollected error still learns about it; once collected, a
    /// later `open` starts clean.
    #[test]
    fn sample_epoch_only_while_unseen() {
        let e = Errseq::new();
        e.set(5);
        let mut late = e.sample();
        assert_eq!(late, 0, "unseen error must still be owed to a new opener");
        assert_eq!(e.check_and_advance(&mut late), Some(5));
        // Now SEEN: an fd opened from here on has nothing outstanding.
        let mut later = e.sample();
        assert_ne!(later, 0);
        assert_eq!(e.check_and_advance(&mut later), None);
    }

    /// A NEW error after one was collected is reported again to the same fd —
    /// this is what the counter increment buys.
    #[test]
    fn new_error_after_collection_is_reported_again() {
        let e = Errseq::new();
        let mut fd = e.sample();
        e.set(5);
        assert_eq!(e.check_and_advance(&mut fd), Some(5));
        e.set(5); // same errno, but the previous value was SEEN → counter moves
        assert_eq!(e.check_and_advance(&mut fd), Some(5));
        assert_eq!(e.check_and_advance(&mut fd), None);
    }

    /// Repeated errors that nobody has sampled do NOT advance the counter, so
    /// an error storm cannot wrap it.
    #[test]
    fn unseen_repeats_do_not_advance_counter() {
        let e = Errseq::new();
        let first = e.set(5);
        for _ in 0..1000 { assert_eq!(e.set(5), first, "unseen repeat must not move the counter"); }
    }

    /// A later error overwrites an earlier uncollected one — only
    /// the most recent error is ever kept.
    #[test]
    fn latest_error_wins() {
        let e = Errseq::new();
        let mut fd = e.sample();
        e.set(5);  // EIO
        e.set(28); // ENOSPC
        assert_eq!(e.check_and_advance(&mut fd), Some(28));
    }

    /// `err == 0` and anything above `MAX_ERRNO` are refused, so a bogus caller
    /// cannot clear a real error.
    #[test]
    fn zero_and_oversized_errno_ignored() {
        let e = Errseq::new();
        let mut fd = e.sample();
        e.set(5);
        e.set(0);
        e.set(MAX_ERRNO + 1);
        e.set(u32::MAX);
        assert_eq!(e.check_and_advance(&mut fd), Some(5));
    }

    /// Every errno up to `MAX_ERRNO` round-trips through the 12-bit field.
    #[test]
    fn full_errno_range_round_trips() {
        for err in 1..=MAX_ERRNO {
            let e = Errseq::new();
            let mut fd = e.sample();
            e.set(err);
            assert_eq!(e.check_and_advance(&mut fd), Some(err), "errno {err}");
        }
    }

    /// `check` is the lockless "did anything change" probe and must not
    /// advance the subscriber.
    #[test]
    fn check_does_not_advance() {
        let e = Errseq::new();
        let mut fd = e.sample();
        e.set(5);
        assert!(e.check(fd));
        assert!(e.check(fd), "check must be side-effect free for the subscriber");
        assert_eq!(e.check_and_advance(&mut fd), Some(5));
        assert!(!e.check(fd));
    }
}
