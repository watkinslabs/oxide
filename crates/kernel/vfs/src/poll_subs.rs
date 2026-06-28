// F181: per-Inode poll-subscriber list. An epoll instance that
// adds an fd via `epoll_ctl(EPOLL_CTL_ADD)` registers itself
// here (as `Weak<dyn EpollNotify>`); the inode's event sites
// (socket recv, peer FIN, etc.) call `notify()` which wakes only
// the subscribed epolls — not every epoll on the system. This
// lives in `vfs` rather than `sched` because `Inode` (the trait
// whose impls hold the list) lives here and vfs is below sched
// in the dep graph (cycle-free).
//
// Trait-object indirection: vfs doesn't know about WaitList; the
// `EpollNotify` callback hides it. fs::epoll's EpollInode impls
// EpollNotify by calling `self.waiters.wake_all()` internally.

extern crate alloc;
use alloc::sync::Weak;
use alloc::vec::Vec;
use sync::{Spinlock, TaskList as PollLockClass};

/// Wake callback published by an epoll instance (fs::EpollInode).
/// vfs holds `Weak<dyn EpollNotify>` so it doesn't pin the epoll
/// alive past its fd's close.
pub trait EpollNotify: Send + Sync {
    fn notify(&self);
}

/// One subscriber entry: epoll instance id + wake callback ref +
/// interest mask. `id` lets epoll_ctl(DEL) find + drop the right
/// entry without pointer comparisons on the trait object. `mask`
/// is the subscriber's interest (epitem `event.events`, Linux
/// fs/eventpoll.c) — `notify_mask` skips a subscriber whose
/// interest does not intersect the fired event, matching
/// `ep_poll_callback`'s key check. `!0` = interested in every
/// event (the plain `subscribe` default → preserves wake-all).
pub struct Subscription {
    pub id:    u32,
    pub wake:  Weak<dyn EpollNotify>,
    pub mask:  u32,
}

/// Events that wake an epoll subscriber unconditionally, regardless
/// of its requested interest mask: `EPOLLERR | EPOLLHUP` are always
/// reported (Linux fs/eventpoll.c `ep_item_poll` OR-s them into the
/// effective mask; `poll(2)` likewise always returns them). An event
/// site that emits one of these wakes every subscriber even if none
/// asked for it.
const ALWAYS_WAKE: u32 = crate::inode::POLL_ERR | crate::inode::POLL_HUP;

/// Per-Inode subscriber list. Held in Spinlock so concurrent
/// epoll_ctl + event-emit can race safely (UP single-CPU today;
/// SMP-ready when SMP lands).
pub struct PollSubscribers {
    subs: Spinlock<Vec<Subscription>, PollLockClass>,
}

impl PollSubscribers {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { subs: Spinlock::new(Vec::new()) }
    }

    /// Add a subscriber keyed by `id` (epoll instance id), interested
    /// in every event (`mask = !0`). Idempotent: a re-add with the same
    /// id replaces the prior Weak and resets interest to all-events.
    /// # C: O(N)
    pub fn subscribe(&self, id: u32, wake: Weak<dyn EpollNotify>) {
        self.subscribe_mask(id, wake, !0);
    }

    /// Add a subscriber keyed by `id` with an explicit interest `mask`
    /// (the epitem `event.events`, Linux fs/eventpoll.c). `notify_mask`
    /// wakes this subscriber only when a fired event intersects `mask`
    /// (plus the always-reported `EPOLLERR|EPOLLHUP`). Idempotent: a
    /// re-add with the same id replaces both the Weak and the mask,
    /// mirroring `epoll_ctl(EPOLL_CTL_MOD)`.
    /// # C: O(N)
    pub fn subscribe_mask(&self, id: u32, wake: Weak<dyn EpollNotify>, mask: u32) {
        let mut g = self.subs.lock();
        for s in g.iter_mut() {
            if s.id == id { s.wake = wake; s.mask = mask; return; }
        }
        g.push(Subscription { id, wake, mask });
    }

    /// Drop the subscription identified by `id`.
    /// # C: O(N)
    pub fn unsubscribe(&self, id: u32) {
        self.subs.lock().retain(|s| s.id != id);
    }

    /// Wake every live subscriber regardless of interest. GC-prune dead
    /// Weak refs. Equivalent to `notify_mask(!0)` for subscribers added
    /// via `subscribe`; event sites that cannot name the exact readiness
    /// transition (or want the legacy broadcast) call this.
    /// # C: O(N)
    pub fn notify(&self) {
        let mut g = self.subs.lock();
        g.retain(|s| s.wake.upgrade().is_some());
        for s in g.iter() {
            if let Some(a) = s.wake.upgrade() { a.notify(); }
        }
    }

    /// Wake only subscribers whose interest intersects `events`, plus
    /// any subscriber when `events` carries `EPOLLERR|EPOLLHUP` (always
    /// reported). Mirrors Linux `ep_poll_callback`'s key check: a wake
    /// carrying the just-became-ready mask skips epitems not watching
    /// those bits, avoiding a spurious wakeup (e.g. an `EPOLLIN`-only
    /// waiter is not woken by a pure `EPOLLOUT` writability transition).
    /// GC-prune dead Weak refs. `events == 0` wakes nobody (Linux:
    /// a keyless wake passes 0 only on teardown, handled separately).
    /// # C: O(N)
    pub fn notify_mask(&self, events: u32) {
        let mut g = self.subs.lock();
        g.retain(|s| s.wake.upgrade().is_some());
        let always = events & ALWAYS_WAKE != 0;
        for s in g.iter() {
            if !always && (s.mask & events) == 0 { continue; }
            if let Some(a) = s.wake.upgrade() { a.notify(); }
        }
    }

    /// True iff at least one live subscriber is registered.
    /// # C: O(N)
    pub fn has_subscribers(&self) -> bool {
        self.subs.lock().iter().any(|s| s.wake.upgrade().is_some())
    }
}

impl Default for PollSubscribers { fn default() -> Self { Self::new() } }
