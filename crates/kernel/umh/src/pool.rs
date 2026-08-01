// Sizing the pool of servicing contexts.
//
// A request that waits for its helper program to terminate (`UMH_WAIT_PROC`)
// occupies its servicing context for as long as that program runs. With a
// SINGLE servicing context every later request queues behind it, and two
// consequences follow, both reachable from an unprivileged `request_key(2)`:
//
//   * head-of-line blocking — a coredump `|pipe` or a hotplug helper waits out
//     an unrelated long-running program before it is even started;
//   * a permanent DEADLOCK — a helper that itself asks the kernel for a helper
//     (the key upcall does exactly this, which is why the construction default
//     names the ORIGINAL requester's keyring) submits a request that only the
//     context already waiting for that helper's exit could serve. Neither side
//     can advance, and the requester's wait is uninterruptible.
//
// So the servicing contexts are a POOL that grows on demand: whichever context
// takes a request makes sure an IDLE peer remains behind it, up to a cap. A
// request submitted while every earlier one blocks is picked up immediately
// instead of queueing behind them.
//
// The counting lives here, apart from the thread machinery, so the growth rule
// is decided in one place and covered without a booted kernel.

use core::sync::atomic::{AtomicU32, Ordering};

/// What a context that just took a request must do about its peers.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Grow {
    /// No idle peer is left and the cap allows another: start one. The slot is
    /// already reserved, so a failure must be reported with
    /// [`Pool::spawn_failed`].
    Spawn,
    /// An idle peer is already waiting, or the pool is at its cap.
    Enough,
}

/// Servicing-context accounting.
pub struct Pool {
    /// Contexts that exist or are reserved by a pending [`Grow::Spawn`].
    total: AtomicU32,
    /// Contexts waiting for a request rather than running one.
    idle: AtomicU32,
    cap: u32,
}

impl Pool {
    /// # C: O(1)
    pub const fn new(cap: u32) -> Self {
        Self { total: AtomicU32::new(0), idle: AtomicU32::new(0), cap }
    }

    /// Reserve a slot for a context about to be started by someone who did not
    /// take a request first — the boot path starting the first one. False when
    /// the cap is already reached, in which case nothing is started.
    /// # C: O(1)
    pub fn reserve(&self) -> bool {
        self.total.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |t| if t < self.cap { Some(t + 1) } else { None }).is_ok()
    }

    /// A reserved context reached its loop and is waiting for work.
    /// # C: O(1)
    pub fn ready(&self) { self.idle.fetch_add(1, Ordering::AcqRel); }

    /// A context took a request off the queue. Reserves a replacement when it
    /// was the last idle one, so the next request does not wait behind the work
    /// this one is about to do. # C: O(1)
    pub fn claim(&self) -> Grow {
        // Saturating: only a context that was idle can claim, so this cannot
        // legitimately underflow, and a miscount must not wrap to u32::MAX and
        // suppress every future growth.
        let idle = self.idle.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |i| Some(i.saturating_sub(1))).unwrap_or(0);
        if idle > 1 { return Grow::Enough; }
        if self.reserve() { Grow::Spawn } else { Grow::Enough }
    }

    /// A context finished its request and is waiting again. # C: O(1)
    pub fn released(&self) { self.ready(); }

    /// A reserved context could not be started; give the slot back so a later
    /// claim can try again. # C: O(1)
    pub fn spawn_failed(&self) {
        let _ = self.total.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |t| Some(t.saturating_sub(1)));
    }

    /// `(total, idle)`. # C: O(1)
    pub fn counts(&self) -> (u32, u32) {
        (self.total.load(Ordering::Acquire), self.idle.load(Ordering::Acquire))
    }

    /// Largest number of contexts this pool will start. # C: O(1)
    pub fn cap(&self) -> u32 { self.cap }
}
