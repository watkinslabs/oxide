//! Mount namespaces, the `struct mountpoint` registry, the mount-generation
//! notify counter, and the `pivot_root` chroot-refs hook (`docs/16§6`,
//! structured like Linux `fs/mount.h` + `fs/namespace.c`).
//!
//! Split out of `mount.rs` (file-length cap, `08§7`). `mount.rs` owns the
//! `struct mount` tree (parent/child links, the `(ns,parent,dptr)` hash, the
//! dentry crossing links); this module owns the OBJECTS those links point at:
//!   - `MntNamespace` — Linux `struct mnt_namespace` (root mount id + task
//!     refcount + per-ns change seq + `nr_mounts`/`pending_mounts` cap state),
//!     replacing the bare `ROOTS` id map.
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
use alloc::sync::Arc;
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering};
use sync::{MountTable as MountClass, Spinlock};

use crate::dentry::Dentry;
use crate::fs::KResult;
use crate::inode::{POLL_ERR, POLL_IN, POLL_PRI};
use crate::types::VfsError;

// ---------------------------------------------------------------------------
// Mount-generation notify counter (Linux `mnt_namespace->event` / the global
// mount seq). Bumped on attach / detach / move / pivot / remount /
// set_propagation / propagation. `/proc/.../mountinfo` poll signals POLLPRI
// when it advances since the reader's last-seen value (libmount blocks on
// `POLLPRI|POLLERR` on `/proc/self/mountinfo` to wait for mount changes).
// ---------------------------------------------------------------------------

static MOUNT_GEN: AtomicU64 = AtomicU64::new(1);

/// Current mount-table generation (advances on every tree mutation). # C: O(1)
pub fn mount_generation() -> u64 { MOUNT_GEN.load(Ordering::Acquire) }

/// Bump the mount generation + the per-ns change seq. Called by every
/// `mount.rs` tree mutation. # C: O(log N)
pub fn bump_gen(ns: u64) -> u64 {
    if let Some(n) = ns_by_id(ns) { n.seq.fetch_add(1, Ordering::AcqRel); }
    MOUNT_GEN.fetch_add(1, Ordering::AcqRel) + 1
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

/// One mount namespace (Linux `struct mnt_namespace`). Holds the root mount
/// id (the only self-parent), a task refcount (reap when it hits 0), and a
/// per-ns change seq (mountinfo). The set of mounts in the ns is the global
/// `MOUNTS` map filtered by `Mount.ns` — no second owning copy to drift.
pub struct MntNamespace {
    pub id: u64,
    /// Root mount id (Linux `mnt_ns->root->mnt_id`). 0 = unset.
    pub root: AtomicU64,
    /// Number of tasks whose `mount_ns == id` (Linux `mnt_ns->nr_tasks`).
    pub nr_tasks: AtomicU64,
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
}

impl MntNamespace {
    fn new(id: u64) -> Arc<Self> {
        Arc::new(MntNamespace {
            id, root: AtomicU64::new(0), nr_tasks: AtomicU64::new(0), seq: AtomicU64::new(0),
            nr_mounts: AtomicU64::new(0), pending_mounts: AtomicU64::new(0),
        })
    }
}

static NAMESPACES: Spinlock<BTreeMap<u64, Arc<MntNamespace>>, MountClass> =
    Spinlock::new(BTreeMap::new());

/// Get the namespace object for `id`, if it exists. # C: O(log N)
pub fn ns_by_id(id: u64) -> Option<Arc<MntNamespace>> {
    NAMESPACES.lock().get(&id).cloned()
}

/// Get-or-create the namespace object for `id`. # C: O(log N)
pub fn ns_get_or_create(id: u64) -> Arc<MntNamespace> {
    let mut g = NAMESPACES.lock();
    g.entry(id).or_insert_with(|| MntNamespace::new(id)).clone()
}

// Monotonic mount-namespace id source (Linux `fs/namespace.c` `mnt_ns_seq`,
// bumped by `atomic64_add_return(1, &mnt_ns_seq)` in `alloc_mnt_ns`). Strictly
// increasing and NEVER reused: even after a namespace is reaped (`ns_forget`)
// the counter keeps climbing, so a freshly allocated id can never alias the
// init namespace (id 0) nor a since-freed sibling whose id might still be
// cached in a stale `task.mount_ns` / `/proc/PID/ns/mnt` link.
static NEXT_NS_ID: AtomicU64 = AtomicU64::new(1);

/// Allocate a fresh, globally-unique, never-reused mount-namespace id and
/// register its `MntNamespace` object (Linux `alloc_mnt_ns`: `mnt_ns_seq` bump
/// + `ns_alloc_inum`). The counter starts at 1, so the result never collides
/// with the init mount namespace (id 0) every task starts in. The returned ns
/// is empty (zero tasks/mounts/seq); the caller adopts it via `task.mount_ns`
/// and pins it against reap with `mnt_ns_enter`. Single canonical allocator for
/// `clone(CLONE_NEWNS)` / `unshare(CLONE_NEWNS)` — the work-fn layer owns the
/// id source, never the syscall shim (`docs/53`). # C: O(log N)
pub fn alloc_ns_id() -> u64 {
    let id = NEXT_NS_ID.fetch_add(1, Ordering::AcqRel);
    ns_get_or_create(id);
    id
}

/// Record `mnt_id` as namespace `ns`'s root mount (Linux `mnt_ns->root`).
/// # C: O(log N)
pub fn ns_set_root(ns: u64, mnt_id: u64) {
    ns_get_or_create(ns).root.store(mnt_id, Ordering::Release);
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

/// Remove the namespace object for `id` (final reap). # C: O(log N)
pub fn ns_forget(id: u64) { NAMESPACES.lock().remove(&id); }

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
    let n = ns_get_or_create(ns);
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

/// A task entered mount-namespace `ns` (clone/unshare into it). Pins the ns
/// alive against reap. # C: O(log N)
pub fn mnt_ns_enter(ns: u64) {
    ns_get_or_create(ns).nr_tasks.fetch_add(1, Ordering::AcqRel);
}

/// A task left mount-namespace `ns` (exit). At zero tasks the ns is reaped:
/// every per-ns mount is detached + the ns object dropped (Linux
/// `free_mnt_ns` via `put_mnt_ns`). Returns true iff the ns was reaped.
/// # C: O(N_ns_mounts)
pub fn mnt_ns_exit(ns: u64) -> bool {
    let Some(n) = ns_by_id(ns) else { return false; };
    let prev = n.nr_tasks.fetch_sub(1, Ordering::AcqRel);
    if prev <= 1 {
        crate::mount::reap_ns(ns);
        ns_forget(ns);
        true
    } else { false }
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
    if prev == 0 { d.set_mounted(); }
    mp
}

/// Drop a mount's hold on `mp`, removing the `Mountpoint` at `m_count == 0`
/// (Linux `put_mountpoint`). # C: O(log N)
pub fn put_mountpoint(mp: &Arc<Mountpoint>) {
    let prev = mp.m_count.fetch_sub(1, Ordering::AcqRel);
    // Last drop (1→0): clear the `D_MOUNTED` hint (Linux `__put_mountpoint`)
    // and remove the registry entry.
    if prev <= 1 {
        mp.m_dentry.clear_mounted();
        MOUNTPOINTS.lock().remove(&dptr(&mp.m_dentry));
    }
}

/// True iff dentry `d` is a registered mountpoint (Linux `d_mountpoint`).
/// # C: O(log N)
pub fn is_registered_mountpoint(d: &Arc<Dentry>) -> bool {
    MOUNTPOINTS.lock().contains_key(&dptr(d))
}

// ---------------------------------------------------------------------------
// Mount-namespace provider (the calling task's mount_ns id).
// ---------------------------------------------------------------------------

static CURRENT_NS_PROVIDER: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Signature of the mount-ns provider.
pub type NsProvider = fn() -> u64;

/// Install the mount-ns provider (kernel boot). Idempotent. # C: O(1)
pub fn set_current_ns_provider(f: NsProvider) {
    CURRENT_NS_PROVIDER.store(f as *mut (), Ordering::Release);
}

/// The calling task's mount-namespace id, or 0 if no provider. # C: O(1)
pub fn current_ns() -> u64 {
    let p = CURRENT_NS_PROVIDER.load(Ordering::Acquire);
    if p.is_null() { return 0; }
    // SAFETY: CURRENT_NS_PROVIDER only ever holds an `NsProvider` fn pointer
    // stored by set_current_ns_provider; the null check guards un-installed.
    let f: NsProvider = unsafe { core::mem::transmute::<*mut (), NsProvider>(p) };
    f()
}

// ---------------------------------------------------------------------------
// pivot_root chroot-refs hook (Linux `chroot_fs_refs`). vfs cannot walk the
// task table (sched owns it), so pivot_root calls this installed hook with
// (old_root_mnt_id, new_root_mnt_id); the sched-side implementation re-points
// every task whose root/cwd was on the old root mount to the new root.
// ---------------------------------------------------------------------------

static CHROOT_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Signature of the chroot-refs hook: `(old_root_mnt_id, new_root_mnt_id)`.
pub type ChrootRefsHook = fn(u64, u64);

/// Install the chroot-refs hook (kernel boot / test). # C: O(1)
pub fn set_chroot_refs_hook(f: ChrootRefsHook) {
    CHROOT_HOOK.store(f as *mut (), Ordering::Release);
}

/// Invoke the chroot-refs hook after a pivot_root commit (no-op if unset).
/// # C: O(1) + hook cost
pub fn chroot_fs_refs(old_root: u64, new_root: u64) {
    let p = CHROOT_HOOK.load(Ordering::Acquire);
    if p.is_null() { return; }
    // SAFETY: CHROOT_HOOK only ever holds a ChrootRefsHook fn pointer stored
    // by set_chroot_refs_hook; the null check guards the un-installed case.
    let f: ChrootRefsHook = unsafe { core::mem::transmute::<*mut (), ChrootRefsHook>(p) };
    f(old_root, new_root);
}
