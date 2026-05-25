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

/// One subscriber entry: epoll instance id + wake callback ref.
/// `id` lets epoll_ctl(DEL) find + drop the right entry without
/// pointer comparisons on the trait object.
pub struct Subscription {
    pub id:    u32,
    pub wake:  Weak<dyn EpollNotify>,
}

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

    /// Add a subscriber keyed by `id` (epoll instance id). Idempotent:
    /// a re-add with the same id replaces the prior Weak.
    /// # C: O(N)
    pub fn subscribe(&self, id: u32, wake: Weak<dyn EpollNotify>) {
        let mut g = self.subs.lock();
        for s in g.iter_mut() {
            if s.id == id { s.wake = wake; return; }
        }
        g.push(Subscription { id, wake });
    }

    /// Drop the subscription identified by `id`.
    /// # C: O(N)
    pub fn unsubscribe(&self, id: u32) {
        self.subs.lock().retain(|s| s.id != id);
    }

    /// Wake every live subscriber. GC-prune dead Weak refs.
    /// # C: O(N)
    pub fn notify(&self) {
        let mut g = self.subs.lock();
        g.retain(|s| s.wake.upgrade().is_some());
        for s in g.iter() {
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
