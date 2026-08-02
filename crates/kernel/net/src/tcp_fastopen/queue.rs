// The fast-open state one socket's accept queue owns.
//
// It lives with the accept queue rather than beside the other socket options
// for two reasons the option-block shape cannot express: the bound may be
// written while the socket is still closed and must survive to the `listen`
// that acts on it, and a socket accepted from a listener must NOT come away
// with the listener's bound or keys — the child's accept queue is a fresh one,
// so a fast-open server does not silently turn every connection it accepts
// into another fast-open listener.
//
// A listener that named no key of its own mints from its namespace's keys
// (`super::ns`); a key set here overrides that for this listener alone, which
// is how a load-balanced pool shares one key across hosts.

use core::sync::atomic::{AtomicI32, Ordering};

use sync::{Socket as SockLockClass, Spinlock};

use super::keys::KeyCtx;

/// The bound `TCP_FASTOPEN` installs, clamped by the live `somaxconn` the same
/// way `listen`'s backlog is: a fast-open queue may not outgrow the accept
/// queue it feeds. # C: O(1)
#[inline]
pub fn clamp_qlen(backlog: i32, somaxconn: i32) -> i32 { core::cmp::min(backlog, somaxconn) }

/// Fast-open state of one accept queue.
pub struct FastOpenQueue {
    /// Outstanding fast-open requests this listener admits at once. `0`
    /// disables passive fast open on it entirely.
    max_qlen: AtomicI32,
    /// Keys this listener mints and verifies cookies with, overriding its
    /// namespace's. `None` = follow the namespace.
    ctx: Spinlock<Option<KeyCtx>, SockLockClass>,
}

impl Default for FastOpenQueue {
    /// # C: O(1)
    fn default() -> Self { Self::new() }
}

impl FastOpenQueue {
    /// # C: O(1)
    pub fn new() -> Self { Self { max_qlen: AtomicI32::new(0), ctx: Spinlock::new(None) } }

    /// # C: O(1)
    pub fn max_qlen(&self) -> i32 { self.max_qlen.load(Ordering::Acquire) }

    /// # C: O(1)
    pub fn set_max_qlen(&self, value: i32) { self.max_qlen.store(value, Ordering::Release); }

    /// # C: O(1)
    pub fn keys(&self) -> Option<KeyCtx> { *self.ctx.lock() }

    /// # C: O(1)
    pub fn set_keys(&self, ctx: KeyCtx) { *self.ctx.lock() = Some(ctx); }
}

/// What the transition into listening does to a socket's fast-open queue: a
/// namespace that enabled passive fast open without the option sizes the queue
/// to the same backlog `listen` was given. Returns whether the namespace must
/// now draw the keys the cookies will be minted from — sizing a queue is the
/// first moment a listener could need one.
///
/// A bound already named by hand is never overwritten, and neither is one a
/// previous `listen` on this socket installed: the queue outlives the listener
/// a `shutdown` took down. # C: O(1)
pub fn on_listen(bits: i32, queue: &FastOpenQueue, backlog: i32, somaxconn: i32) -> bool {
    if !super::flags::listen_enables_queue(bits, queue.max_qlen()) { return false; }
    queue.set_max_qlen(clamp_qlen(backlog, somaxconn));
    true
}

#[cfg(test)]
#[path = "queue_tests.rs"]
mod tests;
