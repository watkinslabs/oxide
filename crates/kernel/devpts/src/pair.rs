// The pty pair object both endpoint inodes share.
//
// Locking: each pair lives behind a single Spinlock<tty::Pair>. v1 doesn't
// split per-direction locks (master and slave I/O can stall briefly across the
// pair); per-ring locks ride a follow-up once we measure contention.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use sync::{Spinlock, TaskList, Tty as TtyClass};
use tty::Pair as TtyPair;
use vfs::{Ino, KResult, VfsError};

use crate::ids;

struct PairLifetime {
    master_opens: u32,
    slave_opens: u32,
    released: bool,
}

/// Spinlock-wrapped pair shared between the master and slave inodes.
pub struct LockedPair {
    pub(crate) inner: Spinlock<TtyPair, TtyClass>,
    ino_master: Ino,
    ino_slave:  Ino,
    pts_num: u32,
    instance: Arc<crate::DevptsFs>,
    devpts_mnt_id: u64,
    lifetime: Spinlock<PairLifetime, TaskList>,
    /// `TIOCSPTLCK` slave lock (Linux `TTY_PTY_LOCK`). Allocated LOCKED:
    /// glibc/musl `unlockpt(master)` (= `TIOCSPTLCK` with 0) must clear it
    /// before the slave can be opened, matching `pts_unix98_lookup`'s
    /// `-EIO` on a locked slave. POSIX requires `unlockpt` pre-slave-open.
    locked: AtomicBool,
    master_exclusive: AtomicBool,
    slave_exclusive: AtomicBool,
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
    pub(crate) fn new(pts_num: u32, instance: Arc<crate::DevptsFs>, devpts_mnt_id: u64) -> Arc<Self> {
        Arc::new(Self {
            inner: Spinlock::new(TtyPair::new(pts_num)),
            ino_master: ids::master_ino(pts_num),
            ino_slave:  ids::slave_ino(pts_num),
            pts_num,
            instance,
            devpts_mnt_id,
            lifetime: Spinlock::new(PairLifetime {
                master_opens: 0, slave_opens: 0, released: false,
            }),
            locked: AtomicBool::new(true),
            master_exclusive: AtomicBool::new(false),
            slave_exclusive: AtomicBool::new(false),
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
    pub fn pts_num(&self) -> u32 { self.pts_num }

    /// The slave node created with this pair, from its owning instance.
    /// # C: O(log N)
    pub fn slave_inode(&self) -> Option<vfs::InodeRef> { self.instance.slave_inode(self.pts_num) }

    /// Mount identity the pair's ptmx open selected. # C: O(1)
    pub fn devpts_mnt_id(&self) -> u64 { self.devpts_mnt_id }

    /// Existing slave path in the selected devpts mount. # C: O(log N)
    pub fn slave_path(&self) -> Option<(vfs::InodeRef, Arc<vfs::Dentry>, u64)> {
        use alloc::string::ToString;
        let m = vfs::mount::mount_by_id(self.devpts_mnt_id)?;
        let root = m.mnt_root()?;
        let inode = self.slave_inode()?;
        let name = self.pts_num.to_string();
        let dentry = vfs::dcache::d_lookup(&root, &name)
            .unwrap_or_else(|| vfs::dcache::d_add(&root, &name, Arc::clone(&inode)));
        Some((inode, dentry, self.devpts_mnt_id))
    }

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
        let mut life = self.lifetime.lock();
        if life.released { return Err(VfsError::Eio); }
        let opens = if master { life.master_opens } else { life.slave_opens };
        if excl.load(Ordering::Acquire) && opens != 0 && !cap_sys_admin {
            return Err(VfsError::Ebusy);
        }
        if master { life.master_opens += 1; } else { life.slave_opens += 1; }
        Ok(())
    }

    /// Whether the master half still has an open fd. `pty_close` on the last
    /// master fd is a permanent carrier loss; anything else is recoverable by
    /// a fresh open. # C: O(1)
    pub fn master_is_open(&self) -> bool {
        self.lifetime.lock().master_opens != 0
    }

    /// Decrement one endpoint's open-description count. Returns whether this
    /// was that endpoint's last close. # C: O(1)
    pub fn close_endpoint(&self, master: bool) -> bool {
        let mut life = self.lifetime.lock();
        let opens = if master { &mut life.master_opens } else { &mut life.slave_opens };
        if *opens == 0 { return false; }
        *opens -= 1;
        *opens == 0
    }

    /// Remove the slave and free the index once neither endpoint is open.
    /// # C: O(log N)
    pub fn release_if_unused(&self) {
        let mut life = self.lifetime.lock();
        if life.master_opens != 0 || life.slave_opens != 0 || life.released { return; }
        life.released = true;
        drop(life);
        self.instance.release_pair(self.pts_num);
    }

    /// Roll back an allocation that never became an open file. # C: O(log N)
    pub(crate) fn release_now(&self) {
        let mut life = self.lifetime.lock();
        if life.released { return; }
        life.released = true;
        drop(life);
        self.instance.release_pair(self.pts_num);
    }

    /// Run `f` against the locked pair. # C: O(closure)
    pub fn with_pair<R>(&self, f: impl FnOnce(&mut tty::Pair) -> R) -> R {
        let mut g = self.inner.lock();
        f(&mut *g)
    }
}
