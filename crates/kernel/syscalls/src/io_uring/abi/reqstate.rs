// One in-flight request's lifetime state: who owns it, and the single gate
// that makes "a completion is posted once" true.
//
// A request can be reached at the same instant by its worker, by a
// cancellation, by its own deadline and by a readiness callback. Exactly one
// of them may report it. `claim` is the one compare-exchange all four go
// through, so precisely one wins and every later arrival sees the request
// already taken.
//
// A request that stays armed — a repeating timeout, a multishot poll, a
// receive posting one completion per delivery — goes claimed → rearmed →
// claimed again, any number of times, and finishes exactly once at the end.
// That is the sequence a use-after-free lives in, so it is here, ungated,
// where a hosted test can drive it (CLAUDE.md phantom-test rule).

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Request lifetime states.
pub mod st {
    /// Waiting: queued for a worker, armed on a clock, or armed on a poll.
    pub const ARMED: u32 = 0;
    /// A worker or a callback owns it and will report its result.
    pub const RUNNING: u32 = 1;
    /// Its completion has been posted; nothing else may post another.
    pub const DONE: u32 = 2;
}

/// The lifetime half of a request.
#[derive(Default)]
pub struct ReqState {
    state: AtomicU32,
    /// This request has been armed on its description at least once. Sticky
    /// for the request's whole life, because it answers "has the readiness
    /// wait the caller asked for already happened" — an entry that asked to
    /// be armed BEFORE any attempt must make the attempt once its poll has
    /// fired, and a flag cleared on re-issue would send it back to waiting
    /// forever without ever transferring a byte.
    polled: AtomicBool,
}

impl ReqState {
    /// # C: O(1)
    pub fn new() -> Self {
        Self { state: AtomicU32::new(st::ARMED), polled: AtomicBool::new(false) }
    }

    /// # C: O(1)
    pub fn state(&self) -> u32 { self.state.load(Ordering::Acquire) }

    /// Take ownership of a waiting request. Exactly one caller wins; every
    /// later one sees it already claimed — including one arriving after the
    /// request finished, because a finished request is never armed again.
    /// # C: O(1)
    pub fn claim(&self) -> bool {
        self.state.compare_exchange(st::ARMED, st::RUNNING, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Put a claimed request back into the waiting state. # C: O(1)
    pub fn rearm(&self) { self.state.store(st::ARMED, Ordering::Release); }

    /// Mark a claimed request finished. # C: O(1)
    pub fn finish(&self) { self.state.store(st::DONE, Ordering::Release); }

    /// # C: O(1)
    pub fn is_done(&self) -> bool { self.state() == st::DONE }

    /// # C: O(1)
    pub fn polled(&self) -> bool { self.polled.load(Ordering::Acquire) }

    /// # C: O(1)
    pub fn set_polled(&self) { self.polled.store(true, Ordering::Release); }
}

#[cfg(test)]
#[path = "reqstate/tests.rs"]
mod tests;
