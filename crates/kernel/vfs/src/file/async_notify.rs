extern crate alloc;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use core::sync::atomic::{AtomicU64, Ordering};

use sync::Spinlock;

use crate::inode::InodeRef;

use crate::namei::Cred;

use super::File;

/// SIGIO delivery hook (Linux `send_sigio`/`kill_pid_info`): installed at boot
/// by the sched signal module so the VFS fasync path can post a signal to a
/// pid/pgrp without `vfs` depending on `sched`. Args: `(owner, sig, uid,
/// euid)` — `owner` is the `F_SETOWN` target (`>0` task, `<0` `-pgrp`), `sig`
/// the resolved signal (`F_SETSIG` value or default SIGIO/SIGURG), `uid`/`euid`
/// the `F_SETOWN`-time credential snapshot for the delivery permission check.
/// `0` = not installed (host tests, early boot). # C: O(1)
pub(crate) static SIGIO_HOOK: AtomicU64 = AtomicU64::new(0);

/// Install the SIGIO delivery hook used by fasync (`O_ASYNC`). Called once at
/// kernel init by the sched signal module. # C: O(1)
pub fn set_sigio_hook(f: fn(i32, i32, u32, u32)) {
    SIGIO_HOOK.store(f as u64, Ordering::Release);
}

/// Lock class for the global fasync registry. Taken standalone (the held set
/// is snapshotted then released before any delivery hook runs), so it never
/// nests under the inode / pos / ra locks. # C: O(1)
struct FasyncLock;
impl sync::LockClass for FasyncLock { fn rank() -> u16 { 34 } fn name() -> &'static str { "FasyncLock" } }

/// `inode->i_fasync` analogue (Linux per-object `fasync_struct` list): the set
/// of open file descriptions with `O_ASYNC` enabled, awaiting SIGIO on an
/// async-ready event. Held as `Weak<File>` so a closed description drops out
/// without an explicit unregister; dead entries are pruned on every touch.
/// # C: O(N) registered fds
static FASYNC: Spinlock<Vec<Weak<File>>, FasyncLock> = Spinlock::new(Vec::new());

/// Register an open file description for fasync SIGIO delivery (Linux
/// `fasync_helper(.., on=1)` linking a `fasync_struct` onto the backend list).
/// Idempotent; prunes dead weak entries. Called when `O_ASYNC` is turned on via
/// `F_SETFL`. # C: O(N) registered fds
pub fn fasync_register(file: &Arc<File>) {
    let mut l = FASYNC.lock();
    let p = Arc::as_ptr(file);
    l.retain(|w| w.upgrade().is_some());
    if !l.iter().any(|w| w.upgrade().is_some_and(|f| Arc::as_ptr(&f) == p)) {
        l.push(Arc::downgrade(file));
    }
}

/// Unregister an open file description from fasync delivery (Linux
/// `fasync_helper(.., on=0)`). Also prunes dead entries. Called when `O_ASYNC`
/// is turned off via `F_SETFL` and from `File::drop`. # C: O(N) registered fds
pub fn fasync_unregister(file: &File) {
    let mut l = FASYNC.lock();
    let p = file as *const File;
    l.retain(|w| w.upgrade().is_some_and(|f| Arc::as_ptr(&f) != p));
}

/// Count of live fasync-registered descriptions (prunes dead entries).
/// Test/observability accessor. # C: O(N) registered fds
pub fn fasync_registered() -> usize {
    let mut l = FASYNC.lock();
    l.retain(|w| w.upgrade().is_some());
    l.len()
}

/// `kill_fasync(&inode->i_fasync, sig, band)` (Linux `fs/fcntl.c`): deliver the
/// async-ready signal to every `O_ASYNC` fd open on `inode`. A backend
/// (pipe/socket/tty) calls this when its buffer becomes readable/writable or an
/// OOB byte arrives. `dfl` is the default signal — `SIGIO` for data-ready,
/// `SIGURG` for out-of-band — overridden per-fd by `F_SETSIG`. Snapshots the
/// matching set under the registry lock, then delivers with the lock dropped so
/// the signal hook may take sched locks. # C: O(N) registered fds
pub fn kill_fasync(inode: &InodeRef, dfl: i32) {
    let snapshot: Vec<Arc<File>> = {
        let mut l = FASYNC.lock();
        l.retain(|w| w.upgrade().is_some());
        l.iter()
            .filter_map(|w| w.upgrade())
            .filter(|f| Arc::ptr_eq(&f.inode, inode))
            .collect()
    };
    for f in snapshot { f.kill_fasync(dfl); }
}

impl File {
    /// `F_SETOWN` (Linux `f_setown`): set the SIGIO/SIGURG delivery target
    /// (`>0` a task, `<0` a `-pgrp`, `0` clears) AND snapshot the requesting
    /// credentials for the later delivery permission check. Stores the bare id
    /// in `owner` (what `F_GETOWN` returns) and the packed uid/euid in
    /// `owner_creds`. # C: O(1)
    pub fn f_setown(&self, id: i32, cred: &Cred) {
        self.owner.store(id, Ordering::Release);
        self.owner_creds.store(((cred.uid as u64) << 32) | cred.uid as u64, Ordering::Release);
    }

    /// `F_GETOWN` (Linux `f_getown`): the delivery target id. # C: O(1)
    pub fn f_getown(&self) -> i32 { self.owner.load(Ordering::Acquire) }

    /// `f_owner` credential snapshot `(uid, euid)` from the last `F_SETOWN`
    /// (Linux `struct fown_struct.uid/.euid`). # C: O(1)
    pub fn f_owner_creds(&self) -> (u32, u32) {
        let v = self.owner_creds.load(Ordering::Acquire);
        ((v >> 32) as u32, v as u32)
    }

    /// `F_SETSIG` (Linux): choose the signal delivered on async-I/O readiness;
    /// `0` restores the default (SIGIO for data, SIGURG for OOB). # C: O(1)
    pub fn set_sig(&self, sig: i32) { self.f_sig.store(sig, Ordering::Release); }

    /// `F_GETSIG` (Linux). # C: O(1)
    pub fn sig(&self) -> i32 { self.f_sig.load(Ordering::Acquire) }

    /// Resolve the signal to actually deliver for an async-I/O event: the
    /// `F_SETSIG` value if set, else `dfl` (the default `SIGIO`/`SIGURG`).
    /// Linux `send_sigio_to_task`: `signum ? signum : SIGIO`. # C: O(1)
    pub fn fasync_signal(&self, dfl: i32) -> i32 {
        let s = self.f_sig.load(Ordering::Acquire);
        if s != 0 { s } else { dfl }
    }

    /// `O_ASYNC` enabled on this description (Linux `FASYNC` in `f_flags`).
    /// # C: O(1)
    pub fn is_async(&self) -> bool {
        (self.flags().bits() & super::O_ASYNC) != 0
    }

    /// `kill_fasync` per-fd core (Linux `kill_fasync_rcu` -> `send_sigio`):
    /// deliver the async-ready signal to THIS description's `f_owner` via the
    /// installed SIGIO hook. `dfl` = default signal (SIGIO data / SIGURG OOB),
    /// overridden by `F_SETSIG`. No-op unless `O_ASYNC` is set, an owner is
    /// recorded, and a hook is installed. The owner credentials snapshot is
    /// forwarded for the hook's delivery permission check. # C: O(1)
    pub fn kill_fasync(&self, dfl: i32) {
        if !self.is_async() { return; }
        let owner = self.owner.load(Ordering::Acquire);
        if owner == 0 { return; }
        let h = SIGIO_HOOK.load(Ordering::Acquire);
        if h == 0 { return; }
        let sig = self.fasync_signal(dfl);
        let (uid, euid) = self.f_owner_creds();
        // SAFETY: h installed by `set_sigio_hook` with the documented
        // fn(i32,i32,u32,u32) signature; the cast round-trips that exact type.
        let f: fn(i32, i32, u32, u32) = unsafe { core::mem::transmute(h) };
        f(owner, sig, uid, euid);
    }
}
