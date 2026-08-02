//! Mount namespaces, the `struct mountpoint` registry, the mount-generation
//! notify counter, and the `pivot_root` chroot-refs hook (`docs/16§6`,
//! structured like Linux `fs/mount.h` + `fs/namespace.c`).
//!
//! Split out of `mount.rs` (file-length cap, `08§7`). `mount.rs` owns the
//! `struct mount` tree (parent/child links, the `(ns,parent,dptr)` hash, the
//! dentry crossing links); this module owns the OBJECTS those links point at:
//!   - `MntNamespace` — Linux `struct mnt_namespace` (stable identity + owner
//!     user-ns placeholder + root mount id + per-ns change seq +
//!     `nr_mounts`/`pending_mounts` cap state), replacing the bare `ROOTS` id
//!     map. `Arc<MntNamespace>` is the lifetime authority; the registry is a
//!     weak live-object index except for its immortal initial-namespace pin.
//!   - `count_mounts`/`sysctl_mount_max` — the per-ns mount ceiling that bounds
//!     a single `mount(2)` propagation/rbind fan-out (Linux `count_mounts`).
//!   - `Mountpoint` — Linux `struct mountpoint` (dentry → mount refcount),
//!     keyed by dentry identity so "is this dentry a mountpoint" + the
//!     m_count drive umount/overmount accounting.
//!   - `MOUNT_GEN` — a monotonic generation bumped on every tree mutation;
//!     `/proc/.../mountinfo` `poll` returns `POLLPRI` when it advances
//!     (libmount's mount-change wakeup).

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use sync::{MountTable as MountClass, Spinlock};

use crate::dentry::Dentry;
use crate::fs::KResult;
use crate::inode::{POLL_ERR, POLL_IN, POLL_PRI};
use crate::poll_subs::PollSubscribers;
use crate::types::VfsError;

#[path = "mntns/current.rs"]
mod current;
pub use current::{current_namespace, current_ns, current_ns_owner, set_current_ns_provider, NsProvider};
#[path = "mntns/reservation.rs"]
mod reservation;
pub use reservation::MountReservation;

// ---------------------------------------------------------------------------
// Mount-generation notify counter (Linux `mnt_namespace->event` / the global
// mount seq). Bumped on attach / detach / move / pivot / remount /
// set_propagation / propagation. `/proc/.../mountinfo` poll signals POLLPRI
// when it advances since the reader's last-seen value (libmount blocks on
// `POLLPRI|POLLERR` on `/proc/self/mountinfo` to wait for mount changes).
// ---------------------------------------------------------------------------

static MOUNT_GEN: AtomicU64 = AtomicU64::new(1);
static MOUNTINFO_SUBS: Spinlock<Vec<Weak<PollSubscribers>>, MountClass> = Spinlock::new(Vec::new());

/// Current mount-table generation (advances on every tree mutation). # C: O(1)
pub fn mount_generation() -> u64 { MOUNT_GEN.load(Ordering::Acquire) }

/// Bump the mount generation + the per-ns change seq. Called by every
/// `mount.rs` tree mutation. # C: O(log N)
pub fn bump_gen(ns: u64) -> u64 {
    if let Some(n) = ns_by_id(ns) { n.seq.fetch_add(1, Ordering::AcqRel); }
    let next = MOUNT_GEN.fetch_add(1, Ordering::AcqRel) + 1;
    let wake = {
        let mut g = MOUNTINFO_SUBS.lock();
        g.retain(|w| w.upgrade().is_some());
        g.iter().filter_map(|w| w.upgrade()).collect::<Vec<_>>()
    };
    for subs in wake { subs.notify_mask(POLL_PRI | POLL_ERR); }
    next
}

/// Register one `/proc/.../mountinfo` inode's poll wait queue. # C: O(N_watchers)
pub fn attach_mountinfo_poll(subs: Arc<PollSubscribers>) {
    let weak = Arc::downgrade(&subs);
    let mut g = MOUNTINFO_SUBS.lock();
    g.retain(|w| w.upgrade().is_some());
    g.push(weak);
}

/// `/proc/.../mountinfo` poll mask given a reader's last-seen generation cell.
/// Always readable (`POLLIN`); additionally `POLLPRI|POLLERR` (libmount's
/// mount-change wakeup) when the generation advanced past `last_seen`, which
/// is then updated to the current value (edge-triggered per reader). # C: O(1)
pub fn mountinfo_poll_mask(last_seen: &AtomicU64) -> u32 {
    let cur = mount_generation();
    let prev = last_seen.swap(cur, Ordering::AcqRel);
    if cur != prev { POLL_IN | POLL_PRI | POLL_ERR } else { POLL_IN }
}

/// Per-NAMESPACE `/proc/.../mountinfo` poll mask (Linux `mounts_poll`, which
/// compares the reader's saved `m_seq` against `p->ns->event`, NOT a global
/// counter). Wakes (`POLLPRI|POLLERR`) only when THIS namespace's change seq
/// advanced past `last_seen`; a mount change confined to a FOREIGN namespace
/// does NOT spuriously wake this reader — unlike `mountinfo_poll_mask`, which
/// signals on any namespace's mutation via the global generation. Always
/// `POLLIN` (mountinfo always readable). `last_seen` is updated to the ns seq
/// (edge-triggered per reader) and should be seeded from `ns_seq(ns)` at open.
/// # C: O(log N)
pub fn mountinfo_poll_mask_ns(ns: u64, last_seen: &AtomicU64) -> u32 {
    let cur = ns_seq(ns);
    let prev = last_seen.swap(cur, Ordering::AcqRel);
    if cur != prev { POLL_IN | POLL_PRI | POLL_ERR } else { POLL_IN }
}

// ---------------------------------------------------------------------------
// MntNamespace — Linux `struct mnt_namespace`.
// ---------------------------------------------------------------------------

/// Owning reference to one canonical mount namespace.
pub type MntNamespaceRef = Arc<MntNamespace>;
pub type MntNamespaceFinalizer = fn(u64);

/// One mount namespace (Linux `struct mnt_namespace`). Holds immutable
/// identity, its owning user namespace, root mount id, and mount state. The
/// set of mounts in the ns is the global `MOUNTS` map filtered by mount namespace key —
/// no second owning copy to drift.
pub struct MntNamespace {
    identity: namespace_identity::NamespacePin,
    active: Spinlock<Option<namespace_identity::NamespaceRef>, MountClass>,
    finalizers: Spinlock<Vec<MntNamespaceFinalizer>, MountClass>,
    /// Root mount id (Linux `mnt_ns->root->mnt_id`). 0 = unset.
    pub root: AtomicU64,
    /// Per-ns mount-change seq (mountinfo).
    pub seq: AtomicU64,
    /// Live mounts committed into this ns (Linux `mnt_ns->nr_mounts`). Bounded
    /// by `sysctl_mount_max`; the umount path decrements it.
    pub nr_mounts: AtomicU64,
    /// Mounts admitted but not yet committed in an in-flight graft (Linux
    /// `mnt_ns->pending_mounts`): `count_mounts` reserves here so concurrent /
    /// propagation-expanded grafts cannot each pass the limit then collectively
    /// blow past `sysctl_mount_max`. `commit_mounts` rolls it into `nr_mounts`;
    /// `abort_mounts` releases it on the failure unwind.
    pub pending_mounts: AtomicU64,
    /// Linux `mnt_ns->is_anon`. An ANONYMOUS namespace holds a mount that no
    /// task can see: `fsmount(2)` puts its new mount in one so the mount is
    /// real — real id, real superblock, real root — while belonging to nobody's
    /// tree until `move_mount(2)` grafts it. It is not a task's namespace and
    /// never becomes one; when its root mount is dissolved the namespace goes
    /// with it.
    is_anon: bool,
}

impl MntNamespace {
    fn new(identity: namespace_identity::NamespacePin) -> MntNamespaceRef {
        Self::new_flagged(identity, false)
    }

    fn new_flagged(identity: namespace_identity::NamespacePin, is_anon: bool) -> MntNamespaceRef
    {
        Arc::new(Self {
            identity, active: Spinlock::new(None), finalizers: Spinlock::new(Vec::new()),
            root: AtomicU64::new(0), seq: AtomicU64::new(0),
            nr_mounts: AtomicU64::new(0), pending_mounts: AtomicU64::new(0), is_anon,
        })
    }

    /// Linux `is_anon_ns()`. # C: O(1)
    pub fn is_anon(&self) -> bool { self.is_anon }

    /// Stable numeric key used by mount-table state. # C: O(1)
    pub fn id(&self) -> u64 { self.identity.id().as_u64() }

    /// Linux global namespace-tree ID. # C: O(1)
    pub fn ns_id(&self) -> u64 { self.identity.ns_id().as_u64() }

    /// Stable globally unique nsfs inode. # C: O(1)
    pub fn nsfs_ino(&self) -> u64 { self.identity.nsfs_ino() }

    /// Retain the exact user namespace owning this mount namespace.
    /// # C: O(1)
    pub fn owner_user_namespace(&self) -> namespace_identity::NamespacePin {
        self.identity.owner_user_namespace()
    }

    /// Pin the canonical mount namespace identity without extending activity. # C: O(1)
    pub fn namespace_identity(&self) -> namespace_identity::NamespacePin {
        self.identity.clone()
    }

    fn activate(&self) { *self.active.lock() = Some(self.identity.activate()); }

    fn deactivate(&self) {
        let active = self.active.lock().take();
        drop(active);
    }

    /// Attach subsystem teardown to this exact owner. Duplicate registration
    /// is idempotent. # C: O(N_finalizers)
    pub fn register_finalizer(&self, finalizer: MntNamespaceFinalizer) {
        let mut finalizers = self.finalizers.lock();
        if !finalizers.iter().any(|registered| *registered as usize == finalizer as usize) {
            finalizers.push(finalizer);
        }
    }
}

struct NamespaceRegistry {
    init: Option<MntNamespaceRef>,
    by_id: BTreeMap<u64, Weak<MntNamespace>>,
}

static NAMESPACES: Spinlock<NamespaceRegistry, MountClass> = Spinlock::new(NamespaceRegistry {
    init: None,
    by_id: BTreeMap::new(),
});

impl Drop for MntNamespace {
    fn drop(&mut self) {
        self.deactivate();
        let claimed = {
            let mut registry = NAMESPACES.lock();
            let same = registry.by_id.get(&self.id())
                .is_some_and(|owner| core::ptr::eq(owner.as_ptr(), self as *const Self));
            if same { registry.by_id.remove(&self.id()); }
            same
        };
        if claimed && self.id() != 0 {
            let finalizers = core::mem::take(&mut *self.finalizers.lock());
            for finalizer in finalizers { finalizer(self.id()); }
            crate::mount::reap_ns(self.id());
        }
    }
}

/// Pin the live namespace object for `id` without reconstructing a dead ID.
/// # C: O(log N)
pub fn ns_by_id(id: u64) -> Option<MntNamespaceRef> {
    NAMESPACES.lock().by_id.get(&id).and_then(Weak::upgrade)
}

/// Return the immortal initial mount namespace. # C: O(log N)
pub fn initial() -> MntNamespaceRef {
    let mut registry = NAMESPACES.lock();
    if let Some(namespace) = registry.init.as_ref() { return Arc::clone(namespace); }
    let namespace = MntNamespace::new(namespace_identity::initial(
        namespace_identity::NamespaceKind::Mnt).pin());
    registry.by_id.insert(0, Arc::downgrade(&namespace));
    registry.init = Some(Arc::clone(&namespace));
    drop(registry);
    namespace.activate();
    namespace
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MntNamespaceAllocError { IdExhausted, OwnerNotUserNamespace }

/// Allocate and publish a fresh ANONYMOUS namespace (Linux `alloc_mnt_ns(..,
/// anon=true)`), the holder for a mount that exists but is in nobody's tree.
/// # C: O(log N)
pub fn allocate_anon<H: namespace_identity::NamespaceHandle>(owner_user_namespace: H)
    -> Result<MntNamespaceRef, MntNamespaceAllocError>
{
    allocate_flagged(owner_user_namespace, true)
}

/// Allocate and publish a fresh namespace owned by `owner_user_namespace`.
/// # C: O(log N)
pub fn allocate<H: namespace_identity::NamespaceHandle>(owner_user_namespace: H)
    -> Result<MntNamespaceRef, MntNamespaceAllocError>
{
    allocate_flagged(owner_user_namespace, false)
}

fn allocate_flagged<H: namespace_identity::NamespaceHandle>(owner_user_namespace: H, is_anon: bool)
    -> Result<MntNamespaceRef, MntNamespaceAllocError>
{
    let owner = owner_user_namespace.get_active_ref()
        .ok_or(MntNamespaceAllocError::OwnerNotUserNamespace)?;
    let identity = namespace_identity::allocate_inactive(namespace_identity::NamespaceKind::Mnt,
        owner, None).map_err(|error| match error {
            namespace_identity::AllocError::IdExhausted => MntNamespaceAllocError::IdExhausted,
            namespace_identity::AllocError::OwnerNotUserNamespace
            | namespace_identity::AllocError::ParentKindMismatch =>
                MntNamespaceAllocError::OwnerNotUserNamespace,
        })?;
    let namespace = MntNamespace::new_flagged(identity, is_anon);
    NAMESPACES.lock().by_id.insert(namespace.id(), Arc::downgrade(&namespace));
    namespace.activate();
    Ok(namespace)
}

/// Record `mnt_id` as namespace `ns`'s root mount (Linux `mnt_ns->root`).
/// # C: O(log N)
pub fn ns_set_root(ns: u64, mnt_id: u64) {
    if let Some(n) = ns_by_id(ns) { n.root.store(mnt_id, Ordering::Release); }
}

/// Root mount id for namespace `ns` (Linux `mnt_ns->root`). # C: O(log N)
pub fn ns_root_id(ns: u64) -> Option<u64> {
    ns_by_id(ns).map(|n| n.root.load(Ordering::Acquire)).filter(|&r| r != 0)
}

/// Current mount-change seq for namespace `ns` (Linux `mnt_ns->event`), bumped
/// by `bump_gen`. 0 when the ns has no object yet. Seed for a mountinfo
/// reader's `last_seen` cell (see `mountinfo_poll_mask_ns`). # C: O(log N)
pub fn ns_seq(ns: u64) -> u64 {
    ns_by_id(ns).map(|n| n.seq.load(Ordering::Acquire)).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Per-ns mount cap (Linux `sysctl_mount_max` + `mnt_ns->nr_mounts`). Without
// it, MS_SHARED propagation across a deep peer group, or a malicious
// rbind/move loop, can fan a single `mount(2)` into an unbounded number of
// `struct mount`s — Linux added `count_mounts` (commit d29216842a85) precisely
// to bound this. Mirrors `fs/namespace.c::count_mounts`: admit `num` mounts
// into `ns` iff `nr_mounts + pending_mounts + num <= sysctl_mount_max`,
// reserving in `pending_mounts`; commit rolls the reservation into `nr_mounts`.
// ---------------------------------------------------------------------------

/// Default per-namespace mount ceiling (Linux `sysctl_mount_max`, kernel
/// `fs/namespace.c` `#define DEFAULT_MOUNT_MAX 100000`).
pub const DEFAULT_MOUNT_MAX: u64 = 100_000;

static SYSCTL_MOUNT_MAX: AtomicU64 = AtomicU64::new(DEFAULT_MOUNT_MAX);

/// Current per-ns mount ceiling (`/proc/sys/fs/mount-max`). # C: O(1)
pub fn sysctl_mount_max() -> u64 { SYSCTL_MOUNT_MAX.load(Ordering::Acquire) }

/// Set the per-ns mount ceiling (`/proc/sys/fs/mount-max` write). Linux floors
/// the sysctl at 0; a value below current `nr_mounts` simply blocks further
/// grafts (existing mounts are not torn down). # C: O(1)
pub fn set_sysctl_mount_max(v: u64) { SYSCTL_MOUNT_MAX.store(v, Ordering::Release); }

/// Live committed mount count for namespace `ns` (Linux `mnt_ns->nr_mounts`).
/// 0 when the ns has no object yet. # C: O(log N)
pub fn ns_nr_mounts(ns: u64) -> u64 {
    ns_by_id(ns).map(|n| n.nr_mounts.load(Ordering::Acquire)).unwrap_or(0)
}

/// In-flight (admitted, uncommitted) mount reservation for `ns`
/// (Linux `mnt_ns->pending_mounts`). # C: O(log N)
pub fn ns_pending_mounts(ns: u64) -> u64 {
    ns_by_id(ns).map(|n| n.pending_mounts.load(Ordering::Acquire)).unwrap_or(0)
}

/// Admit `num` mounts into namespace `ns` (Linux `count_mounts`): reserve them
/// in `pending_mounts` iff `nr_mounts + pending_mounts + num` stays within
/// `sysctl_mount_max`, else `ENOSPC` with NO reservation. The reservation is a
/// CAS so two concurrent grafts cannot both pass the test against a stale
/// total. `num == 0` is a no-op (Linux admits an empty subtree). On success the
/// caller MUST follow with exactly one `commit_mounts(ns, num)` (graft wired)
/// or `abort_mounts(ns, num)` (graft unwound). # C: O(log N)
pub fn count_mounts(ns: u64, num: u64) -> KResult<()> {
    if num == 0 { return Ok(()); }
    let n = ns_by_id(ns).ok_or(VfsError::Enoent)?;
    let max = sysctl_mount_max();
    loop {
        let pend = n.pending_mounts.load(Ordering::Acquire);
        let live = n.nr_mounts.load(Ordering::Acquire);
        // Saturating add: a `num`/`live` near u64::MAX must read as "over cap",
        // never wrap to a small total that spuriously passes.
        let total = live.saturating_add(pend).saturating_add(num);
        if total > max { return Err(VfsError::Enospc); }
        if n.pending_mounts
            .compare_exchange(pend, pend + num, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        { return Ok(()); }
        // Lost the race; another graft moved pending_mounts — retry the test.
    }
}

/// Commit a prior `count_mounts(ns, num)` reservation (Linux `commit_tree`:
/// `n->nr_mounts += n->pending_mounts`): move `num` from `pending_mounts` into
/// the live `nr_mounts`. # C: O(log N)
pub fn commit_mounts(ns: u64, num: u64) {
    if num == 0 { return; }
    if let Some(n) = ns_by_id(ns) {
        let pend = n.pending_mounts.load(Ordering::Acquire);
        n.pending_mounts.store(pend.saturating_sub(num), Ordering::Release);
        n.nr_mounts.fetch_add(num, Ordering::AcqRel);
    }
}

/// Release a `count_mounts(ns, num)` reservation on the graft failure unwind
/// (Linux clears `pending_mounts` on the `attach_recursive_mnt` error path):
/// give the `num` reserved slots back without committing them. # C: O(log N)
pub fn abort_mounts(ns: u64, num: u64) {
    if num == 0 { return; }
    if let Some(n) = ns_by_id(ns) {
        let pend = n.pending_mounts.load(Ordering::Acquire);
        n.pending_mounts.store(pend.saturating_sub(num), Ordering::Release);
    }
}

/// Drop `num` live mounts from namespace `ns` on umount/detach (Linux
/// `umount_tree`: `mnt->mnt_ns = NULL; ns->nr_mounts--`). Saturates at 0 so a
/// double-detach cannot underflow the count. # C: O(log N)
pub fn dec_mounts(ns: u64, num: u64) {
    if num == 0 { return; }
    if let Some(n) = ns_by_id(ns) {
        let cur = n.nr_mounts.load(Ordering::Acquire);
        n.nr_mounts.store(cur.saturating_sub(num), Ordering::Release);
    }
}

// ---------------------------------------------------------------------------
// Mountpoint — Linux `struct mountpoint`: dentry → set-of-mounts refcount.
// ---------------------------------------------------------------------------

/// A dentry that has ≥1 mount attached on it (Linux `struct mountpoint`).
/// `m_count` is the number of mounts using this dentry as their mountpoint
/// (across all namespaces); the object is dropped when it reaches 0.
pub struct Mountpoint {
    pub m_dentry: Arc<Dentry>,
    pub m_count: AtomicU32,
}

/// dentry-identity → `Mountpoint` (Linux `mountpoint_hashtable`).
static MOUNTPOINTS: Spinlock<BTreeMap<usize, Arc<Mountpoint>>, MountClass> =
    Spinlock::new(BTreeMap::new());

fn dptr(d: &Arc<Dentry>) -> usize { Arc::as_ptr(d) as *const () as usize }

/// Get-or-create the `Mountpoint` for dentry `d`, bumping `m_count` (Linux
/// `get_mountpoint`). # C: O(log N)
pub fn get_mountpoint(d: &Arc<Dentry>) -> Arc<Mountpoint> {
    let mut g = MOUNTPOINTS.lock();
    let mp = g.entry(dptr(d)).or_insert_with(|| Arc::new(Mountpoint {
        m_dentry: d.clone(), m_count: AtomicU32::new(0),
    })).clone();
    // `m_count` 0→1 is the CREATE path: stamp the `D_MOUNTED` hint bit on the
    // dentry (Linux `d_set_mounted`). Refcounted + ns-agnostic, so a second
    // mount (overmount / cross-ns clone) on the same dentry only bumps the
    // count and leaves the bit set.
    let prev = mp.m_count.fetch_add(1, Ordering::AcqRel);
    if prev == 0 {
        // Pin the dentry's `d_count` lockref for the life of the mount (Linux
        // `mp->m_dentry = dget(dentry)`): a mounted dentry must NEVER reach
        // `dput` count 0, else `dentry_kill` stamps `LOCKREF_DEAD` and then
        // `d_drop`'s `is_mounted()` guard refuses to unhash it, leaving a
        // DEAD-but-HASHED mountpoint that every later `open()` re-finds and
        // pins (get/put-on-dead) until its `Arc` frees underneath the hash →
        // dangling entry → heap corruption. The `Arc` clone in `m_dentry`
        // alone pins memory but NOT `d_count`; this `inc_count` supplies the
        // missing VFS pin. Released in `put_mountpoint` on the last unmount.
        d.inc_count();
        d.set_mounted();
    }
    mp
}

/// Drop a mount's hold on `mp`, removing the `Mountpoint` at `m_count == 0`
/// (Linux `put_mountpoint`). # C: O(log N)
pub fn put_mountpoint(mp: &Arc<Mountpoint>) {
    let prev = mp.m_count.fetch_sub(1, Ordering::AcqRel);
    // Last drop (1→0): clear the `D_MOUNTED` hint (Linux `__put_mountpoint`)
    // and remove the registry entry.
    if prev <= 1 {
        // Clear the hint FIRST so `is_mounted()` reads false, then release the
        // `d_count` pin taken in `get_mountpoint` through a real `dput`: now
        // that the dentry is no longer mounted, `dput` correctly retains it on
        // the LRU or kills+unhashes it (the `d_drop` guard no longer blocks).
        mp.m_dentry.clear_mounted();
        MOUNTPOINTS.lock().remove(&dptr(&mp.m_dentry));
        crate::dcache::dput(mp.m_dentry.clone());
    }
}

/// True iff dentry `d` is a registered mountpoint (Linux `d_mountpoint`).
/// # C: O(log N)
pub fn is_registered_mountpoint(d: &Arc<Dentry>) -> bool {
    MOUNTPOINTS.lock().contains_key(&dptr(d))
}

// ---------------------------------------------------------------------------
// pivot_root chroot-refs hook (Linux `chroot_fs_refs`). vfs cannot walk the
// task table (sched owns it), so pivot_root calls this installed hook with
// (old_root_mnt_id, new_root_mnt_id); the sched-side implementation re-points
// every task whose root/cwd was on the old root mount to the new root.
// ---------------------------------------------------------------------------

// Typed, compiler-checked storage (sched owns the task table, which vfs cannot
// walk without a `vfs→sched` cycle — see `CURRENT_NS_PROVIDER`). The previous
// `AtomicPtr<()>` + `core::mem::transmute` is gone; install + fire are now
// type-checked with no `unsafe`. Pivot-only (cold) path.
static CHROOT_HOOK: Spinlock<Option<ChrootRefsHook>, MountClass> = Spinlock::new(None);

/// Signature of the chroot-refs hook: `(old_root_mnt_id, new_root_mnt_id)`.
pub type ChrootRefsHook = fn(u64, u64);

/// Install the chroot-refs hook (kernel boot / test). # C: O(1)
pub fn set_chroot_refs_hook(f: ChrootRefsHook) {
    *CHROOT_HOOK.lock() = Some(f);
}

/// Invoke the chroot-refs hook after a pivot_root commit (no-op if unset).
/// # C: O(1) + hook cost
pub fn chroot_fs_refs(old_root: u64, new_root: u64) {
    // Copy the fn ptr out and drop the lock before calling into sched.
    let f = *CHROOT_HOOK.lock();
    if let Some(f) = f { f(old_root, new_root); }
}
