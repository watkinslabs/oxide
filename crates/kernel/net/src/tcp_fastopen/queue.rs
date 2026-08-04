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

extern crate alloc;
use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicI32, Ordering};

use sync::{Socket as SockLockClass, Spinlock};

use super::keys::KeyCtx;

/// How long a fast-open connection that ended in a reset keeps counting
/// against the bound. A peer forging a source address cannot receive the
/// SYN-ACK, so the connection it opened dies by reset; charging those for a
/// while is what makes a flood of them turn passive fast open off on this
/// listener instead of letting it amplify.
pub const RST_PENALTY_NS: u64 = 60 * 1_000_000_000;

/// The bound `TCP_FASTOPEN` installs, clamped by the live `somaxconn` the same
/// way `listen`'s backlog is: a fast-open queue may not outgrow the accept
/// queue it feeds. # C: O(1)
#[inline]
pub fn clamp_qlen(backlog: i32, somaxconn: i32) -> i32 { core::cmp::min(backlog, somaxconn) }

/// Outstanding fast-open requests, and the reset penalties still charged.
#[derive(Default)]
struct Outstanding {
    /// Fast-open connections whose handshake has not finished, plus every
    /// penalty below.
    qlen: i32,
    /// When each charged reset stops counting, oldest first. A penalty is only
    /// ever reclaimed by an admission that needs the slot, so this is
    /// FIFO-ordered by expiry without being sorted.
    penalties: VecDeque<u64>,
}

/// Fast-open state of one accept queue.
pub struct FastOpenQueue {
    /// Outstanding fast-open requests this listener admits at once. `0`
    /// disables passive fast open on it entirely.
    max_qlen: AtomicI32,
    /// Keys this listener mints and verifies cookies with, overriding its
    /// namespace's. `None` = follow the namespace.
    ctx: Spinlock<Option<KeyCtx>, SockLockClass>,
    /// The bound's live occupancy.
    out: Spinlock<Outstanding, SockLockClass>,
}

/// The queue-bound result the fast-open policy needs to account for.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Admission { Disabled, Full, Admitted }

impl Default for FastOpenQueue {
    /// # C: O(1)
    fn default() -> Self { Self::new() }
}

impl FastOpenQueue {
    /// # C: O(1)
    pub fn new() -> Self {
        Self { max_qlen: AtomicI32::new(0), ctx: Spinlock::new(None),
               out: Spinlock::new(Outstanding::default()) }
    }

    /// # C: O(1)
    pub fn max_qlen(&self) -> i32 { self.max_qlen.load(Ordering::Acquire) }

    /// # C: O(1)
    pub fn set_max_qlen(&self, value: i32) { self.max_qlen.store(value, Ordering::Release); }

    /// # C: O(1)
    pub fn keys(&self) -> Option<KeyCtx> { *self.ctx.lock() }

    /// # C: O(1)
    pub fn set_keys(&self, ctx: KeyCtx) { *self.ctx.lock() = Some(ctx); }

    /// Outstanding fast-open requests, reset penalties included. # C: O(1)
    pub fn qlen(&self) -> i32 { self.out.lock().qlen }

    /// Whether the bound has room for one more fast-open request, reclaiming
    /// the oldest reset penalty first if it has run out.
    ///
    /// It is asked before the cookie is looked at, so a listener that is full
    /// declines without spending the hash — and a client cannot tell a full
    /// queue from a server that does not do fast open at all, because both
    /// answer with a plain handshake. # C: O(1)
    pub fn admit(&self, now_ns: u64) -> Admission {
        let max = self.max_qlen();
        if max == 0 { return Admission::Disabled; }
        let mut out = self.out.lock();
        if out.qlen < max { return Admission::Admitted; }
        match out.penalties.front() {
            Some(expiry) if now_ns >= *expiry => {
                out.penalties.pop_front(); out.qlen -= 1; Admission::Admitted
            }
            _ => Admission::Full,
        }
    }

    /// Charge one admitted fast-open request against the bound. # C: O(1)
    pub fn hold(&self) { self.out.lock().qlen += 1; }

    /// Give the charge back once the handshake has finished or been abandoned.
    ///
    /// A connection the peer reset keeps its charge for [`RST_PENALTY_NS`]
    /// instead, but only once the program has taken it: an unaccepted request
    /// costs the listener nothing extra, while one a program was already
    /// handed and then lost is the shape a forged source address produces. A
    /// listener that has stopped listening charges nothing — the bound it
    /// would protect is gone. # C: O(1)
    pub fn release(&self, now_ns: u64, reset: bool, accepted: bool, listening: bool) {
        let mut out = self.out.lock();
        if out.qlen > 0 { out.qlen -= 1; }
        if reset && accepted && listening {
            out.qlen += 1;
            out.penalties.push_back(now_ns.saturating_add(RST_PENALTY_NS));
        }
    }
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
