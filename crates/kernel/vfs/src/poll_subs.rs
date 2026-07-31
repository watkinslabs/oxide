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
use core::sync::atomic::{AtomicU64, Ordering};
use sync::{Spinlock, TaskList as PollLockClass};

/// Wake callback published by an epoll instance (fs::EpollInode).
/// vfs holds `Weak<dyn EpollNotify>` so it doesn't pin the epoll
/// alive past its fd's close.
pub trait EpollNotify: Send + Sync {
    fn notify(&self);
    /// Wake carrying the readiness mask that fired, the "poll key" a source
    /// passes to its wait queue. `0` means the source could not name the
    /// transition (a keyless wake); a subscriber that needs a truthful mask
    /// must re-poll the file in that case.
    ///
    /// Subscribers that only latch "something happened" (epoll marks the
    /// epitem ready and re-polls in `epoll_wait`; poll/select bump a
    /// generation) need no override. A subscriber that must PRODUCE the mask
    /// inside the wake — aio's `IOCB_CMD_POLL`, which completes the request
    /// from the wakeup itself — overrides this and avoids re-polling under the
    /// source's subscriber lock.
    /// # C: O(1)
    fn notify_events(&self, events: u32) { let _ = events; self.notify(); }
}

/// One subscriber entry: epoll instance id + wake callback ref +
/// interest mask. `id` lets epoll_ctl(DEL) find + drop the right
/// entry without pointer comparisons on the trait object. `mask`
/// is the subscriber's interest (epitem `event.events`, Linux
/// fs/eventpoll.c) — `notify_mask` skips a subscriber whose
/// interest does not intersect the fired event, matching
/// `ep_poll_callback`'s key check. `!0` = interested in every
/// event (the plain `subscribe` default → preserves wake-all).
/// `exclusive` marks an `EPOLLEXCLUSIVE` epitem (Linux
/// `add_wait_queue_exclusive`): on a readiness wake `notify_mask`
/// wakes at most ONE *interested* exclusive subscriber, leaving the
/// rest asleep — the thundering-herd avoidance an `accept(2)` load
/// balancer relies on. Non-exclusive subscribers are always all woken.
pub struct Subscription {
    pub id:        u32,
    pub wake:      Weak<dyn EpollNotify>,
    pub mask:      u32,
    pub exclusive: bool,
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
    /// Monotonic notification counter for diagnostics and source-level tests.
    /// Epoll edge delivery does not consult this counter: the registered
    /// per-epitem callback itself is the edge identity.
    gen: AtomicU64,
}

impl PollSubscribers {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { subs: Spinlock::new(Vec::new()), gen: AtomicU64::new(0) }
    }

    /// Current source-notification generation. # C: O(1)
    pub fn generation(&self) -> u64 { self.gen.load(Ordering::Acquire) }

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
        self.subscribe_flags(id, wake, mask, false);
    }

    /// Add an `EPOLLEXCLUSIVE` subscriber (Linux `add_wait_queue_exclusive`):
    /// `notify_mask` wakes at most ONE interested exclusive subscriber per
    /// readiness event (plus every interested non-exclusive one), so N epolls
    /// each `accept(2)`-ing the same listening socket don't all wake on one
    /// incoming connection. Idempotent on `id` like `subscribe_mask`.
    /// # C: O(N)
    pub fn subscribe_exclusive(&self, id: u32, wake: Weak<dyn EpollNotify>, mask: u32) {
        self.subscribe_flags(id, wake, mask, true);
    }

    /// Shared insert/replace for `subscribe_mask`/`subscribe_exclusive`. A
    /// re-add with the same `id` replaces the Weak, mask AND exclusive flag,
    /// mirroring `epoll_ctl(EPOLL_CTL_MOD)`.
    /// # C: O(N)
    fn subscribe_flags(&self, id: u32, wake: Weak<dyn EpollNotify>, mask: u32, exclusive: bool) {
        let mut g = self.subs.lock();
        for s in g.iter_mut() {
            if s.id == id { s.wake = wake; s.mask = mask; s.exclusive = exclusive; return; }
        }
        g.push(Subscription { id, wake, mask, exclusive });
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
        self.gen.fetch_add(1, Ordering::AcqRel);
        let mut g = self.subs.lock();
        g.retain(|s| s.wake.upgrade().is_some());
        for s in g.iter() {
            if let Some(a) = s.wake.upgrade() { a.notify_events(0); }
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
    ///
    /// `EPOLLEXCLUSIVE` subscribers (see [`subscribe_exclusive`]) are limited
    /// to ONE wake per event: every interested non-exclusive subscriber is
    /// woken, but only the first interested exclusive one — matching Linux
    /// `__wake_up_common`'s `nr_exclusive == 1` walk where an exclusive waiter
    /// that fails the key check is skipped (not counted) so the next interested
    /// exclusive waiter still gets the wake.
    ///
    /// [`subscribe_exclusive`]: Self::subscribe_exclusive
    /// # C: O(N)
    pub fn notify_mask(&self, events: u32) {
        self.gen.fetch_add(1, Ordering::AcqRel);
        let mut g = self.subs.lock();
        g.retain(|s| s.wake.upgrade().is_some());
        let always = events & ALWAYS_WAKE != 0;
        let mut woke_exclusive = false;
        for s in g.iter() {
            if !always && (s.mask & events) == 0 { continue; }
            if s.exclusive {
                if woke_exclusive { continue; }
                woke_exclusive = true;
            }
            if let Some(a) = s.wake.upgrade() { a.notify_events(events); }
        }
    }

    /// True iff at least one live subscriber is registered.
    /// # C: O(N)
    pub fn has_subscribers(&self) -> bool {
        self.subs.lock().iter().any(|s| s.wake.upgrade().is_some())
    }
}

impl Default for PollSubscribers { fn default() -> Self { Self::new() } }

/// Whether an on-disk inode of `ft` needs its own poll wait queue, independent
/// of which filesystem stores it.
///
/// Linux `init_special_inode` gives an `S_IFIFO` node `pipefifo_fops`, and
/// `fifo_open` (`fs/pipe.c:1219`) attaches an `i_pipe` whose `rd_wait`/
/// `wr_wait` ARE the queues `pipe_poll` registers on — the backing filesystem
/// never enters into it. Every `S_IFIFO` constructor must therefore attach a
/// subscriber list; `fs::pipe`'s notify sites read it back through
/// `inode.poll_subscribers()` and silently do nothing when it is `None`.
///
/// Character/block nodes get their queue from the driver, sockets from the
/// socket object, so neither takes one here.
/// # C: O(1)
pub fn special_inode_needs_poll_subs(ft: crate::FileType) -> bool {
    matches!(ft, crate::FileType::Fifo)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FileType;

    #[test]
    fn fifo_nodes_take_a_wait_queue() {
        assert!(special_inode_needs_poll_subs(FileType::Fifo));
    }

    #[test]
    fn other_special_nodes_do_not() {
        for ft in [FileType::Regular, FileType::Directory, FileType::Symlink,
                   FileType::CharDev, FileType::BlockDev, FileType::Socket] {
            assert!(!special_inode_needs_poll_subs(ft), "{ft:?} must not take one");
        }
    }
}
