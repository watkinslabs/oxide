extern crate alloc;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use core::sync::atomic::{AtomicUsize, Ordering};

use sync::Spinlock;

use crate::inode::InodeRef;

use super::{File, SIGIO_HOOK};

/// Default `SIGIO`/`SIGPOLL` number (asm-generic, both arches) — the signal a
/// lease break or dnotify event delivers when the holder set no `F_SETSIG`.
pub(crate) const SIGIO_DFL: i32 = 29;

pub(crate) use super::lease_policy::F_UNLCK;
use super::lease_policy as policy;

/// dnotify `DN_*` event bits (Linux fcntl UAPI) + the `DN_MULTISHOT` one-shot
/// toggle. Re-exported for the dir-mutation emit call sites.
pub const DN_ACCESS: u32 = 0x0000_0001;
pub const DN_MODIFY: u32 = 0x0000_0002;
pub const DN_CREATE: u32 = 0x0000_0004;
pub const DN_DELETE: u32 = 0x0000_0008;
pub const DN_RENAME: u32 = 0x0000_0010;
pub const DN_ATTRIB: u32 = 0x0000_0020;
const DN_MULTISHOT: u32 = 0x8000_0000;

/// `lease_break_time` (Linux `/proc/sys/fs/lease-break-time`, default 45 s): the
/// conflicting opener blocks this long for the holder to downgrade/release
/// before the kernel force-breaks the lease and lets the open proceed.
pub const LEASE_BREAK_NS: u64 = 45_000_000_000;

/// Lock class for the global lease / dnotify registries. Standalone like the
/// fasync registry — snapshot under the lock, deliver with it dropped. # C: O(1)
struct NotifyReg;
impl sync::LockClass for NotifyReg { fn rank() -> u16 { 34 } fn name() -> &'static str { "NotifyReg" } }

/// Fast-path gate: number of open descriptions that currently hold a lease
/// (Linux per-inode `i_flctx` presence). The conflicting-open break path reads
/// this FIRST and early-outs at zero, so the common no-lease open is a single
/// relaxed load with no registry lock. # C: O(1)
static LEASE_COUNT: AtomicUsize = AtomicUsize::new(0);
/// Descriptions holding an active lease (`Weak` so close self-prunes), the
/// `i_op->lease` analogue of the per-inode lease list. # C: O(N) leased fds
static LEASE_HOLDERS: Spinlock<Vec<Weak<File>>, NotifyReg> = Spinlock::new(Vec::new());

/// Fast-path gate: number of directory fds with an armed `F_NOTIFY` watch.
/// Dir-mutation emit early-outs at zero. # C: O(1)
static DNOTIFY_COUNT: AtomicUsize = AtomicUsize::new(0);
/// Directory fds with an `F_NOTIFY` watch (Linux per-inode `i_dnotify` list).
/// # C: O(N) watched dirs
static DNOTIFY_WATCHERS: Spinlock<Vec<Weak<File>>, NotifyReg> = Spinlock::new(Vec::new());

/// Register an open description as a lease holder (Linux `generic_add_lease`
/// linking the `file_lock` onto `i_flctx`). Idempotent; called from
/// `F_SETLEASE` after `File::set_lease` records a non-`F_UNLCK` type. # C: O(N)
pub fn lease_register(file: &Arc<File>) {
    let mut l = LEASE_HOLDERS.lock();
    let p = Arc::as_ptr(file);
    l.retain(|w| w.upgrade().is_some());
    if !l.iter().any(|w| w.upgrade().is_some_and(|f| Arc::as_ptr(&f) == p)) {
        l.push(Arc::downgrade(file));
    }
    LEASE_COUNT.store(l.len(), Ordering::Release);
}

/// Drop an open description from the lease registry (Linux `lease_modify` to
/// `F_UNLCK`). Called from `F_SETLEASE F_UNLCK`, the force-break path, and
/// `File::drop`. # C: O(N) leased fds
pub fn lease_unregister(file: &File) {
    let mut l = LEASE_HOLDERS.lock();
    let p = file as *const File;
    l.retain(|w| w.upgrade().is_some_and(|f| Arc::as_ptr(&f) != p));
    LEASE_COUNT.store(l.len(), Ordering::Release);
}

/// Count of live lease-holding descriptions (prunes dead weaks). Test accessor.
/// # C: O(N) leased fds
pub fn lease_registered() -> usize {
    let mut l = LEASE_HOLDERS.lock();
    l.retain(|w| w.upgrade().is_some());
    LEASE_COUNT.store(l.len(), Ordering::Release);
    l.len()
}

/// True iff some description holds a lease on `inode` that a breaker of
/// `breaker_flavour` (a lease break from a conflicting open, or a delegation
/// break from a mutation) must clear. `breaker_writes` says the breaker wants
/// the file gone from the holder entirely rather than downgraded.
///
/// Reads the fast-path counter first — zero leases anywhere ⇒ instant `false`,
/// the boot/no-lease cost. # C: O(1) common, O(N) when a lease exists
pub fn lease_conflict(inode: &InodeRef, breaker_flavour: i32, breaker_writes: bool) -> bool {
    if LEASE_COUNT.load(Ordering::Acquire) == 0 { return false; }
    let l = LEASE_HOLDERS.lock();
    l.iter().filter_map(|w| w.upgrade())
        .any(|f| Arc::ptr_eq(&f.inode, inode)
                 && policy::conflicts(f.lease_word(), breaker_flavour, breaker_writes))
}

/// Would adding a lease of `ty` on `file` collide with another description's
/// lease on the same file? An exclusive lease demands sole tenancy, and no
/// lease may be added while a break is outstanding. # C: O(N) leased fds
pub fn add_lease_conflict(file: &Arc<File>, ty: i32) -> bool {
    if LEASE_COUNT.load(Ordering::Acquire) == 0 { return false; }
    let p = Arc::as_ptr(file);
    let l = LEASE_HOLDERS.lock();
    l.iter().filter_map(|w| w.upgrade())
        .filter(|f| Arc::as_ptr(f) != p && Arc::ptr_eq(&f.inode, &file.inode))
        .any(|f| policy::add_lease_conflicts_with_holder(ty, f.lease_word()))
}

/// Signal every conflicting lease holder on `inode`: the holder gets its
/// `F_SETSIG` signal or the default `SIGIO`, routed to its `f_owner` via the
/// installed SIGIO hook. Marks each holder's lease as breaking FIRST, so a
/// holder is told once per break rather than once per conflicting event — a
/// stream of mutations against one delegation delivers one signal, not one per
/// mutation. Snapshots under the lock, delivers with it dropped.
/// # C: O(N) leased fds
pub fn lease_break_signal(inode: &InodeRef, breaker_flavour: i32, breaker_writes: bool) {
    if LEASE_COUNT.load(Ordering::Acquire) == 0 { return; }
    let snapshot: Vec<Arc<File>> = {
        let l = LEASE_HOLDERS.lock();
        l.iter().filter_map(|w| w.upgrade())
            .filter(|f| Arc::ptr_eq(&f.inode, inode)
                        && policy::conflicts(f.lease_word(), breaker_flavour, breaker_writes))
            .filter(|f| match policy::mark_breaking(f.lease_word(), breaker_writes) {
                Some(w) => { f.set_lease_word(w); true }
                None    => false,
            })
            .collect()
    };
    for f in snapshot { f.notify_lease_break(); }
}

/// Force-break once the break time has elapsed: drop every conflicting lease on
/// `inode` and unregister it, so a holder that never voluntarily released no
/// longer blocks the breaker. # C: O(N) leased fds
pub fn lease_force_break(inode: &InodeRef, breaker_flavour: i32, breaker_writes: bool) {
    if LEASE_COUNT.load(Ordering::Acquire) == 0 { return; }
    let mut l = LEASE_HOLDERS.lock();
    for w in l.iter() {
        if let Some(f) = w.upgrade() {
            if Arc::ptr_eq(&f.inode, inode)
                && policy::conflicts(f.lease_word(), breaker_flavour, breaker_writes) {
                f.set_lease_word(policy::unleased());
            }
        }
    }
    l.retain(|w| w.upgrade().is_some_and(|f| policy::held(f.lease_word())));
    LEASE_COUNT.store(l.len(), Ordering::Release);
}

/// Register a directory fd's `F_NOTIFY` watch (Linux `fcntl_dirnotify` →
/// `dnotify_struct`). Idempotent; called when a non-zero mask is armed. # C: O(N)
pub fn dnotify_register(file: &Arc<File>) {
    let mut l = DNOTIFY_WATCHERS.lock();
    let p = Arc::as_ptr(file);
    l.retain(|w| w.upgrade().is_some());
    if !l.iter().any(|w| w.upgrade().is_some_and(|f| Arc::as_ptr(&f) == p)) {
        l.push(Arc::downgrade(file));
    }
    DNOTIFY_COUNT.store(l.len(), Ordering::Release);
}

/// Drop a directory fd from the dnotify registry (mask cleared / one-shot fired
/// / `File::drop`). # C: O(N) watched dirs
pub fn dnotify_unregister(file: &File) {
    let mut l = DNOTIFY_WATCHERS.lock();
    let p = file as *const File;
    l.retain(|w| w.upgrade().is_some_and(|f| Arc::as_ptr(&f) != p));
    DNOTIFY_COUNT.store(l.len(), Ordering::Release);
}

/// Count of live dnotify watches (prunes dead weaks). Test accessor.
/// # C: O(N) watched dirs
pub fn dnotify_registered() -> usize {
    let mut l = DNOTIFY_WATCHERS.lock();
    l.retain(|w| w.upgrade().is_some());
    DNOTIFY_COUNT.store(l.len(), Ordering::Release);
    l.len()
}

/// Emit a directory-mutation notification (Linux `dnotify_parent` →
/// `__fsnotify_parent`): for each `F_NOTIFY` watch on `dir_inode` whose mask
/// intersects `events` (`DN_CREATE`/`DELETE`/`RENAME`/`MODIFY`/`ATTRIB`/…),
/// signal the watcher (its `F_SETSIG` or default `SIGIO`). A watch without
/// `DN_MULTISHOT` is one-shot — cleared after it fires (Linux default). Reads
/// the fast-path counter first: no watch anywhere ⇒ instant return, the cost on
/// every create/unlink/rename in the no-watch (boot) case.
/// # C: O(1) common, O(N) when a watch exists
pub fn dnotify_emit(dir_inode: &InodeRef, events: u32) {
    if DNOTIFY_COUNT.load(Ordering::Acquire) == 0 { return; }
    let snapshot: Vec<Arc<File>> = {
        let l = DNOTIFY_WATCHERS.lock();
        l.iter().filter_map(|w| w.upgrade())
            .filter(|f| Arc::ptr_eq(&f.inode, dir_inode) && (f.dnotify() & events) != 0)
            .collect()
    };
    for f in snapshot {
        f.notify_lease_break(); // same fown→SIGIO delivery path
        if (f.dnotify() & DN_MULTISHOT) == 0 {
            f.set_dnotify(0);
            dnotify_unregister(&f);
        }
    }
}

impl File {
    /// Record a lease of `flavour` and type `ty` on this description —
    /// `F_RDLCK`(0) / `F_WRLCK`(1), or `F_UNLCK`(2) to drop it. Clears any
    /// pending break state, because a holder that answers the break is no
    /// longer being broken. # C: O(1)
    pub fn set_lease_of(&self, flavour: i32, ty: i32) {
        self.set_lease_word(policy::pack(flavour, ty));
    }

    /// The whole packed lease word: flavour, type and pending-break state.
    /// # C: O(1)
    pub fn lease_word(&self) -> i32 { self.lease.load(Ordering::Acquire) }

    /// Install a whole packed lease word. # C: O(1)
    pub fn set_lease_word(&self, word: i32) { self.lease.store(word, Ordering::Release); }

    /// The lease type a get-lease query of `query_flavour` reports: `F_RDLCK` /
    /// `F_WRLCK` for a matching held lease (or what an outstanding break is
    /// turning it into), `F_UNLCK` when this description holds no lease of that
    /// flavour. A delegation is invisible to a plain-lease query and vice
    /// versa. # C: O(1)
    pub fn lease_of(&self, query_flavour: i32) -> i32 {
        policy::getlease_report(self.lease_word(), query_flavour)
    }

    /// True while this description holds a lease of any flavour. # C: O(1)
    pub fn lease_held(&self) -> bool { policy::held(self.lease_word()) }

    /// `F_NOTIFY` (Linux `fcntl_dirnotify`): set the dnotify `DN_*` watch mask
    /// on this directory fd (`0` clears). Storage only; the dir-mutation event
    /// delivery is the dnotify follow-up. # C: O(1)
    pub fn set_dnotify(&self, mask: u32) { self.dnotify_mask.store(mask, Ordering::Release); }

    /// The dnotify `DN_*` watch mask on this fd (`0` = no watch). # C: O(1)
    pub fn dnotify(&self) -> u32 { self.dnotify_mask.load(Ordering::Acquire) }

    /// Deliver a lease-break / dnotify signal to this description's `f_owner`
    /// (Linux `lease->fl_lmops->lm_break` → `kill_fasync(.., SIGIO, POLL_MSG)`
    /// and dnotify's `send_sigio(fown, dn->dn_fd, POLL_MSG)`). Both name
    /// `POLL_MSG` as the reason, so the `_sigpoll` record an `F_SETSIG` handler
    /// reads carries that band and the watched descriptor.
    ///
    /// Unlike `kill_fasync`, a lease/dnotify holder need NOT be `O_ASYNC` — the
    /// `F_SETLEASE`/`F_NOTIFY` arm IS the delivery registration. Sends the
    /// `F_SETSIG` signal or the default `SIGIO`, with the captured owner creds,
    /// via the installed hook. No-op without an owner or hook. # C: O(1)
    pub fn notify_lease_break(&self) {
        use super::async_notify::{band_for, reason, sicode_for, AsyncSignal};
        let owner = self.owner.load(Ordering::Acquire);
        if owner == 0 { return; }
        let h = SIGIO_HOOK.load(Ordering::Acquire);
        if h == 0 { return; }
        let chosen = self.sig();
        let sig = self.fasync_signal(SIGIO_DFL);
        let (uid, euid) = self.f_owner_creds();
        // SAFETY: h installed by `set_sigio_hook` with the documented
        // fn(AsyncSignal) signature; the cast round-trips that exact type.
        let f: fn(AsyncSignal) = unsafe { core::mem::transmute(h) };
        f(AsyncSignal {
            owner, sig, uid, euid,
            code: sicode_for(sig, reason::POLL_MSG),
            band: band_for(reason::POLL_MSG),
            ty:   self.f_owner_type(),
            fd:   self.fasync_fd(),
            queued: chosen != 0,
        });
    }
}
