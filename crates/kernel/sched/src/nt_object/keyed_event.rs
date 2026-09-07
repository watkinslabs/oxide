//! Keyed-event rendezvous: the pairing rule and the blocking half.
//!
//! A keyed event carries no signalled state. A waiter and a releaser meet on
//! one object when they name the same key from the same process, and both
//! sides block until that meeting happens or their timeout expires. The
//! pairing is one-to-one: a releaser wakes exactly one waiter, and a key with
//! no partner leaves the caller asleep rather than succeeding.

use alloc::vec::Vec;
use sync::{Spinlock, TaskList as TaskListClass};

/// One parked side of a rendezvous.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct KeyedWaiter {
    /// Thread-group identity: pairing never crosses a process boundary.
    pub process: u32,
    /// The caller's key. Its low bit is always clear, so the value is the
    /// address the runtime handed in.
    pub key: u64,
    /// True for the wake side, false for the wait side.
    pub release: bool,
    /// Set by whichever side found this one; a matched entry never matches again.
    pub matched: bool,
    /// Identity of this entry within the object, so its owner can find it back.
    pub seq: u64,
}

/// Index of the first entry that pairs with an arriving side, or `None`.
/// The partner must be in the same process, name the same key, be the
/// opposite operation, and not already be spoken for.
/// # C: O(N_parked)
pub fn match_index(parked: &[KeyedWaiter], process: u32, key: u64, release: bool) -> Option<usize> {
    parked.iter().position(|entry|
        entry.process == process && entry.key == key && entry.release != release && !entry.matched)
}

/// A key names an address, so an odd value is never one the runtime formed.
/// # C: O(1)
pub const fn key_is_aligned(key: u64) -> bool { key & 1 == 0 }

/// Rendezvous point shared by every handle to one keyed event.
pub struct NtKeyedEvent {
    parked: Spinlock<Vec<KeyedWaiter>, TaskListClass>,
    next_seq: core::sync::atomic::AtomicU64,
    #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
    waiters: crate::live::WaitList,
}

/// How one side of a rendezvous ended.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum KeyedOutcome { Paired, TimedOut, Interrupted }

impl Default for NtKeyedEvent {
    fn default() -> Self { Self::new() }
}

impl NtKeyedEvent {
    /// Construct an empty rendezvous point. # C: O(1)
    pub const fn new() -> Self {
        Self {
            parked: Spinlock::new(Vec::new()),
            next_seq: core::sync::atomic::AtomicU64::new(1),
            #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
            waiters: crate::live::WaitList::new(),
        }
    }

    /// Parked sides, for tests and diagnostics. # C: O(N_parked)
    pub fn parked(&self) -> Vec<KeyedWaiter> { self.parked.lock().clone() }

    /// Try to pair with an already-parked opposite side without sleeping.
    /// Returns true when a partner was found and woken. # C: O(N_parked)
    pub fn try_pair(&self, process: u32, key: u64, release: bool) -> bool {
        let paired = {
            let mut parked = self.parked.lock();
            match match_index(&parked, process, key, release) {
                Some(index) => { parked[index].matched = true; true }
                None => false,
            }
        };
        #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
        if paired { self.waiters.wake_all(); }
        paired
    }

    /// Park this side until a partner claims it or the deadline passes. A
    /// deadline of zero never expires. # C: O(N_wakeups * N_parked)
    /// # SAFETY: caller is process context holding no lock a waker needs.
    #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
    pub unsafe fn rendezvous(&self, process: u32, key: u64, release: bool,
                             deadline_ns: u64, now: impl Fn() -> u64) -> KeyedOutcome {
        if self.try_pair(process, key, release) { return KeyedOutcome::Paired; }
        let seq = self.next_seq.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        self.parked.lock().push(KeyedWaiter { process, key, release, matched: false, seq });
        // SAFETY: the rendezvous point outlives this wait and the predicate
        // takes only the parked-list lock, which no waker holds across a wake.
        let outcome = unsafe {
            crate::live::wait_event_interruptible_until(&self.waiters, deadline_ns, now,
                || self.parked.lock().iter().any(|entry| entry.seq == seq && entry.matched))
        };
        let mut parked = self.parked.lock();
        let claimed = parked.iter().any(|entry| entry.seq == seq && entry.matched);
        parked.retain(|entry| entry.seq != seq);
        drop(parked);
        // A partner that claimed this entry while the wait was unwinding has
        // already consumed its half of the pairing, so the claim wins over
        // the expiry: reporting a timeout here would drop that wake.
        if claimed { return KeyedOutcome::Paired; }
        match outcome {
            crate::WaitOutcome::Ready => KeyedOutcome::Paired,
            crate::WaitOutcome::TimedOut => KeyedOutcome::TimedOut,
            crate::WaitOutcome::Interrupted => KeyedOutcome::Interrupted,
        }
    }
}

#[cfg(test)]
#[path = "keyed_event/tests.rs"]
mod tests;
