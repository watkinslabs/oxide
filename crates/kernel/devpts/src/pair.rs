// The pty pair object both endpoint inodes share, and the index → pair table.
//
// Locking: each pair lives behind a single Spinlock<tty::Pair>. v1 doesn't
// split per-direction locks (master and slave I/O can stall briefly across the
// pair); per-ring locks ride a follow-up once we measure contention.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use sync::{Spinlock, TaskList, Tty as TtyClass};
use tty::Pair as TtyPair;
use vfs::{Ino, KResult, VfsError};

use crate::ids;

/// Spinlock-wrapped pair shared between the master and slave inodes.
pub struct LockedPair {
    pub(crate) inner: Spinlock<TtyPair, TtyClass>,
    ino_master: Ino,
    ino_slave:  Ino,
    /// `TIOCSPTLCK` slave lock (Linux `TTY_PTY_LOCK`). Allocated LOCKED:
    /// glibc/musl `unlockpt(master)` (= `TIOCSPTLCK` with 0) must clear it
    /// before the slave can be opened, matching `pts_unix98_lookup`'s
    /// `-EIO` on a locked slave. POSIX requires `unlockpt` pre-slave-open.
    locked: AtomicBool,
    master_exclusive: AtomicBool,
    slave_exclusive: AtomicBool,
    master_opens: AtomicU32,
    slave_opens: AtomicU32,
    /// Linux `tty->read_wait`/`tty->write_wait` for the MASTER half — the
    /// queues `n_tty_poll` registers on. Each pty half is its OWN
    /// `tty_struct` with its own queues, so master and slave get separate
    /// subscriber lists; the master inode publishes this one through
    /// `InodeBuilder::poll_subs_arc`.
    master_subs: Arc<vfs::PollSubscribers>,
    /// Same for the SLAVE half (`/dev/pts/<n>`).
    slave_subs: Arc<vfs::PollSubscribers>,
}

impl LockedPair {
    /// Build the pair backing pty `pts_num`. # C: O(1)
    pub(crate) fn new(pts_num: u32) -> Arc<Self> {
        Arc::new(Self {
            inner: Spinlock::new(TtyPair::new(pts_num)),
            ino_master: ids::master_ino(pts_num),
            ino_slave:  ids::slave_ino(pts_num),
            locked: AtomicBool::new(true),
            master_exclusive: AtomicBool::new(false),
            slave_exclusive: AtomicBool::new(false),
            master_opens: AtomicU32::new(0),
            slave_opens: AtomicU32::new(0),
            master_subs: Arc::new(vfs::PollSubscribers::new()),
            slave_subs: Arc::new(vfs::PollSubscribers::new()),
        })
    }

    /// `st_ino` of the master half. # C: O(1)
    pub fn ino_master(&self) -> Ino { self.ino_master }
    /// `st_ino` of the slave half. # C: O(1)
    pub fn ino_slave(&self) -> Ino { self.ino_slave }

    /// The MASTER half's poll/select/epoll wait queue. # C: O(1)
    pub fn master_subs(&self) -> &Arc<vfs::PollSubscribers> { &self.master_subs }
    /// The SLAVE half's poll/select/epoll wait queue. # C: O(1)
    pub fn slave_subs(&self) -> &Arc<vfs::PollSubscribers> { &self.slave_subs }

    /// Publish a readiness transition on one half (Linux
    /// `wake_up_interruptible_poll(&tty->read_wait, EPOLLIN)` and friends).
    /// `master` selects which half's waiters see it. # C: O(N_subs)
    pub fn wake_subs(&self, master: bool, events: u32) {
        if master { self.master_subs.notify_mask(events); } else { self.slave_subs.notify_mask(events); }
    }

    /// Publish a transition on BOTH halves — the `pty_close` shape, which
    /// wakes the closing side's queues AND the link's. # C: O(N_subs)
    pub fn wake_both_subs(&self, events: u32) {
        self.master_subs.notify_mask(events);
        self.slave_subs.notify_mask(events);
    }

    /// # C: O(1)
    pub fn pts_num(&self) -> u32 { self.inner.lock().pts_num }

    /// `TIOCGPTLCK` read-back: 1 = locked, 0 = unlocked. # C: O(1)
    pub fn is_locked(&self) -> bool { self.locked.load(Ordering::Acquire) }
    /// `TIOCSPTLCK` setter: non-zero arg locks, zero unlocks. # C: O(1)
    pub fn set_locked(&self, v: bool) { self.locked.store(v, Ordering::Release); }

    /// TIOCEXCL/TIOCNXCL setter for one pty endpoint. # C: O(1)
    pub fn set_exclusive(&self, master: bool, v: bool) {
        if master { &self.master_exclusive } else { &self.slave_exclusive }.store(v, Ordering::Release);
    }
    /// TIOCGEXCL readback for one pty endpoint. # C: O(1)
    pub fn exclusive(&self, master: bool) -> bool {
        if master { &self.master_exclusive } else { &self.slave_exclusive }.load(Ordering::Acquire)
    }

    /// Linux `tty_reopen` TTY_EXCLUSIVE admission for one pty endpoint. # C: O(1)
    pub fn open_endpoint(&self, master: bool, cap_sys_admin: bool) -> KResult<()> {
        let excl = if master { &self.master_exclusive } else { &self.slave_exclusive };
        let opens = if master { &self.master_opens } else { &self.slave_opens };
        if excl.load(Ordering::Acquire) && opens.load(Ordering::Acquire) != 0 && !cap_sys_admin {
            return Err(VfsError::Ebusy);
        }
        opens.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    /// Whether the master half still has an open fd. `pty_close` on the last
    /// master fd is a permanent carrier loss; anything else is recoverable by
    /// a fresh open. # C: O(1)
    pub fn master_is_open(&self) -> bool {
        self.master_opens.load(Ordering::Acquire) != 0
    }

    /// Last-close release for one pty endpoint. # C: O(1)
    pub fn close_endpoint(&self, master: bool) {
        let opens = if master { &self.master_opens } else { &self.slave_opens };
        let prev = opens.load(Ordering::Acquire);
        if prev != 0 { opens.fetch_sub(1, Ordering::AcqRel); }
    }

    /// Run `f` against the locked pair. # C: O(closure)
    pub fn with_pair<R>(&self, f: impl FnOnce(&mut tty::Pair) -> R) -> R {
        let mut g = self.inner.lock();
        f(&mut *g)
    }
}

/// pts index → pair table, so a handler holding only an index (`TIOCGPTPEER`
/// on a freshly allocated pair, the boot smoke) can reach the pair. Indexed by
/// pts_num, kept small + dense by [`next_index`].
static PAIRS: Spinlock<Vec<Arc<LockedPair>>, TaskList> = Spinlock::new(Vec::new());

/// Monotonic pts index source. # C: O(1)
static NEXT_PTS: AtomicU32 = AtomicU32::new(0);

/// Claim the next pts index. # C: O(1)
pub(crate) fn next_index() -> u32 { NEXT_PTS.fetch_add(1, Ordering::Relaxed) }

/// Publish `pair` at its index. # C: O(1) amortized
pub(crate) fn publish(idx: u32, pair: &Arc<LockedPair>) {
    let mut g = PAIRS.lock();
    if g.len() <= idx as usize { g.resize_with(idx as usize + 1, || Arc::clone(pair)); }
    else { g[idx as usize] = Arc::clone(pair); }
}

/// Resolve a pts index to its locked pair. # C: O(1)
pub fn pair_for(pts_num: u32) -> Option<Arc<LockedPair>> {
    let g = PAIRS.lock();
    g.get(pts_num as usize).cloned()
}
