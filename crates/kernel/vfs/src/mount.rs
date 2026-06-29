//! Mount tree per `docs/16§6`, structured like Linux's `struct mount`.
//!
//! Each `Mount` is an INTRUSIVE tree node (Linux `struct mount`): it records
//! its parent mount (`mnt_parent` Weak link + `parent_id` scalar), its child
//! mounts (`mnt_mounts`), the `struct mountpoint` it is attached on
//! (`mnt_mp`, keyed by dentry identity), its root dentry (`mnt_root`), and —
//! for propagation — its master/slave links. Tree decisions ("children of M",
//! "the mount exactly here", parent/child/containment) walk these links, NOT
//! a linear table scan and NOT a string-prefix match. Mountpoint identity is
//! a global `(ns, parent_mnt_id, mountpoint_dentry_ptr) -> mnt_id stack` hash
//! (Linux `__lookup_mnt`).
//!
//! `rendered_path` is WRITE-ONLY tree-wise: set at attach/move, read ONLY by
//! /proc mountinfo, /proc mounts, statmount. It never feeds a routing decision.
//!
//! Namespaces, the `struct mountpoint` registry, the mount-generation notify
//! counter and the pivot_root chroot-refs hook live in `crate::mntns`.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU32, AtomicU64, Ordering};
use sync::{MountTable as MountClass, Spinlock};

use crate::dentry::Dentry;
use crate::fs::{FileSystem, KResult};
use crate::inode::InodeRef;
use crate::mntns::{self, get_mountpoint, put_mountpoint, Mountpoint};
use crate::superblock::{next_anon_dev, sget, SuperBlock};
use crate::types::VfsError;

// Re-export the namespace / notify / hook surface so callers keep using
// `vfs::mount::*` (provider install, generation poll, chroot hook, reap).
pub use crate::mntns::{
    chroot_fs_refs, current_ns, mnt_ns_enter, mnt_ns_exit, mount_generation,
    mountinfo_poll_mask, set_chroot_refs_hook, set_current_ns_provider,
    ChrootRefsHook, MntNamespace, Mountpoint as MountpointObj, NsProvider,
};

// Mount-propagation engine (peer/slave fan-out) lives in a submodule to hold
// the line cap; its public surface stays `vfs::mount::*` verbatim.
mod propagation;
pub use propagation::{join_peer_group, peer_group_of, propagate_mount, set_propagation};

// Umount / detach tear-down (umount(2), d_invalidate detach, propagate_umount)
// lives in a submodule to hold the line cap; public surface stays `vfs::mount::*`.
mod detach;
pub use detach::{unregister, unregister_top};
pub(crate) use detach::detach_mounts_on;

// mnt_flags model: the kernel-internal `mnt_flags` bit set (MNT_LOCKED /
// MNT_INTERNAL / MNT_DOOMED / …, Linux `include/linux/mount.h`) distinct from
// the MS_*-valued option mask, plus typed option-mask + atime-policy readback.
mod mnt_flags;
pub use mnt_flags::{
    AtimePolicy, MNT_DOOMED, MNT_EXPIRE_MARK, MNT_INTERNAL, MNT_LOCKED, MNT_MARKED, MNT_UMOUNT,
};

// Mount expiry list (Linux `mark_mounts_for_expiry`, autofs/NFS auto-umount):
// a two-sweep grace where an unused, unmarked mount is marked on one pass and
// reaped on the next if still idle.
mod expiry;
pub use expiry::{
    expire_list_create, mark_mounts_for_expiry, mnt_expire_add, mnt_expire_remove,
    sweep_expired_mounts,
};

// --- [D10] Per-mount mnt_flags OPTION bits — the REAL Linux kernel-internal
// `mnt->mnt_flags` values (`include/linux/mount.h`), a DISJOINT space from the
// MS_* mount(2) request flags below. `ms_to_mnt` maps a request mask into this
// space at mount/remount time. `/proc/mounts` + statvfs `ST_*` read these by
// NAME, so the value change is transparent to those renderers. ---
pub const MNT_NOSUID: u64 = 0x01;
pub const MNT_NODEV: u64 = 0x02;
pub const MNT_NOEXEC: u64 = 0x04;
pub const MNT_NOATIME: u64 = 0x08;
pub const MNT_NODIRATIME: u64 = 0x10;
pub const MNT_RELATIME: u64 = 0x20;
/// Linux `MNT_READONLY` (the per-mount RO bit, distinct from `SB_RDONLY`).
pub const MNT_RDONLY: u64 = 0x40;
/// Linux `MNT_NOSYMFOLLOW` (symlinks on this mount are not followed).
pub const MNT_NOSYMFOLLOW: u64 = 0x80;
/// Synthetic strictatime marker. Linux has NO per-mount strictatime bit —
/// strictatime is the ABSENCE of NOATIME+RELATIME — but `atime_policy` and
/// `inode_times` model it as one disjoint bit so an explicit MS_STRICTATIME
/// request stays representable and the policy resolver stays branch-simple.
/// Above the real `u32` mnt_flags range, disjoint from every Linux value.
pub const MNT_STRICTATIME: u64 = 1 << 33;
pub const MNT_OPTION_MASK: u64 = MNT_RDONLY | MNT_NOSUID | MNT_NODEV | MNT_NOEXEC
    | MNT_NOATIME | MNT_NODIRATIME | MNT_RELATIME | MNT_NOSYMFOLLOW | MNT_STRICTATIME;

// --- [D10] mount(2) MS_* OPTION request flags (`linux/mount.h`) — the
// USER-FACING request space the syscall passes in, mapped to MNT_* by
// `ms_to_mnt`. SYNCHRONOUS/MANDLOCK/DIRSYNC/LAZYTIME are SUPERBLOCK (`SB_*`)
// flags, not per-mount, and are NOT represented in the mnt_flags space. ---
pub const MS_RDONLY: u64 = 0x1;
pub const MS_NOSUID: u64 = 0x2;
pub const MS_NODEV: u64 = 0x4;
pub const MS_NOEXEC: u64 = 0x8;
pub const MS_NOATIME: u64 = 0x400;
pub const MS_NODIRATIME: u64 = 0x800;
pub const MS_RELATIME: u64 = 1 << 21;
pub const MS_STRICTATIME: u64 = 1 << 24;

/// Map a mount(2) MS_* OPTION request mask to the per-mount MNT_* flag space
/// (Linux `do_mount`/`reconfigure`: derive `mnt_flags` from the request). The
/// atime policy follows Linux precedence — NOATIME wins, then explicit
/// STRICTATIME, else RELATIME (the kernel default since 2.6.30 when neither
/// STRICTATIME nor NOATIME is asked for). SB-level options
/// (SYNCHRONOUS/MANDLOCK/DIRSYNC/LAZYTIME) live on the superblock and are
/// dropped here. # C: O(1)
pub fn ms_to_mnt(ms: u64) -> u64 {
    let mut f = 0u64;
    if ms & MS_RDONLY     != 0 { f |= MNT_RDONLY; }
    if ms & MS_NOSUID     != 0 { f |= MNT_NOSUID; }
    if ms & MS_NODEV      != 0 { f |= MNT_NODEV; }
    if ms & MS_NOEXEC     != 0 { f |= MNT_NOEXEC; }
    if ms & MS_NODIRATIME != 0 { f |= MNT_NODIRATIME; }
    if ms & MS_NOATIME != 0 { f |= MNT_NOATIME; }
    else if ms & MS_STRICTATIME != 0 { f |= MNT_STRICTATIME; }
    else { f |= MNT_RELATIME; }
    f
}

/// A dentry's identity key (stable address of the `Arc<Dentry>` allocation).
/// # C: O(1)
fn dptr(d: &Arc<Dentry>) -> usize { Arc::as_ptr(d) as *const () as usize }

/// True iff `d` is the global namespace-root dentry. # C: O(1)
fn is_global_root(d: &Arc<Dentry>) -> bool {
    d.parent().is_none() && d.name().is_empty()
}

/// The mount in `ns` whose superblock root DENTRY is `d`, by `s_root`
/// IDENTITY (cross-ns scanner over the global map). # C: O(N_mounts)
fn mount_with_root_dentry(ns: u64, d: &Arc<Dentry>) -> Option<Arc<Mount>> {
    let dp = dptr(d);
    MOUNTS.lock().values()
        .find(|m| m.ns == ns && m.sb.s_root().map(|r| dptr(&r) == dp).unwrap_or(false))
        .cloned()
}

/// The VISIBLE mount in `ns` whose `s_root` dentry is `d`, disambiguating the
/// codebase's shared-`s_root` pseudo-filesystems (procfs/sysfs use a SINGLETON
/// root dentry, so several mounts in ONE ns can share it — see
/// `tests/sandbox_ns_crossing.rs`). The bare `s_root`-identity `.find()` returns
/// an ARBITRARY one of those duplicates; the `(parent_mnt_id, dentry)` mount
/// hash instead needs the one the path walk actually CROSSES INTO, so this picks
/// (a) the ns ROOT mount when `d` is the ns-root `s_root`, else (b) the duplicate
/// that is the current TOP at its own mountpoint (`mp.mounted_mount == self`),
/// else (c) the first candidate. Keeps `parent_by_dentry` agreeing with the
/// walk's crossing chain so `__lookup_mnt(cur_mnt, child)` resolves the child
/// mount even under shadowed singleton-fs duplicates. # C: O(N_mounts)
fn visible_mnt_id_of_root_dentry(ns: u64, d: &Arc<Dentry>) -> Option<u64> {
    let dp = dptr(d);
    let cands: Vec<Arc<Mount>> = MOUNTS.lock().values()
        .filter(|m| m.ns == ns && m.sb.s_root().map(|r| dptr(&r) == dp).unwrap_or(false))
        .cloned().collect();
    if cands.is_empty() { return None; }
    // (a) ns root mount (mountpoint None) ⇒ the canonical ns-root id.
    if cands.iter().any(|m| m.mountpoint().is_none()) { return root_mount_id(ns); }
    // (b) the duplicate currently visible (top of its own mountpoint crossing).
    for m in cands.iter() {
        if let Some(mp) = m.mountpoint() {
            if mp.mounted_mount(ns) == Some(m.mnt_id) { return Some(m.mnt_id); }
        }
    }
    // (c) deterministic fallback.
    cands.first().map(|m| m.mnt_id)
}

/// One ancestor step in a CROSSING-AWARE parent walk (Linux `follow_dotdot`).
/// # C: O(N_mounts) at a mount root, else O(1)
fn cross_up(ns: u64, d: &Arc<Dentry>) -> Option<Arc<Dentry>> {
    if let Some(p) = d.parent() { return Some(p.clone()); }
    if d.is_root() { return mount_with_root_dentry(ns, d).and_then(|m| m.mountpoint()); }
    None
}

/// Absolute path rendered from a dentry's parent chain (Linux `d_path`) — the
/// WRITE-ONLY rendered path. # C: O(depth)
fn abs_string(d: &Arc<Dentry>) -> String {
    String::from_utf8(d.absolute_path()).unwrap_or_else(|_| String::from("/"))
}

/// Materialise the dentry at `rel` beneath `base` by a dentry→dentry descent
/// that CROSSES MOUNTS at each component exactly as namei does — the
/// engine-internal resolver for SYNTHESIZED mount positions (propagation
/// mirrors, MS_MOVE / pivot_root relocations). NEVER a global path-string
/// resolve. `rel` empty ⇒ `base` itself. # C: O(components)
pub(super) fn descend(base: &Arc<Dentry>, rel: &str) -> Option<Arc<Dentry>> {
    let ns = current_ns();
    let mut cur = base.clone();
    let mut cur_inode: Option<crate::inode::InodeRef> = None;
    for comp in rel.split('/').filter(|c| !c.is_empty()) {
        let parent_inode = match cur_inode.take() { Some(i) => i, None => cur.inode()? };
        let child = match crate::dcache::d_lookup(&cur, comp) {
            Some(d) if !d.is_negative() => d,
            _ => {
                let ci = parent_inode.lookup(comp).ok()?;
                crate::dcache::d_add(&cur, comp, ci)
            }
        };
        let mut child = child;
        while let Some(mnt_id) = child.mounted_mount(ns) {
            match root_dentry_for_mount_id(mnt_id) { Some(sr) => child = sr, None => break }
        }
        cur_inode = Some(child.inode()?);
        cur = child;
    }
    Some(cur)
}

/// The global namespace-root dentry. # C: O(1)
pub(super) fn global_root() -> Option<Arc<Dentry>> { crate::namei::root_dentry() }

// ---------------------------------------------------------------------------
// (parent_mnt_id, mountpoint_dentry_ptr) -> mnt_id stack — Linux
// `__lookup_mnt`. Top of stack = last attached (overmounts). The `ns` is NOT
// part of the key: `parent_mnt_id` is already ns-PRIVATE (every namespace mints
// fresh, never-recycled `mnt_id`s, and `copy_mnt_ns` re-stamps each clone), so
// a `(parent, dentry)` pair belongs to exactly one namespace — exactly Linux's
// `mount_hashtable` keyed on `(mnt_parent, mnt_mountpoint)`.
// ---------------------------------------------------------------------------
static MOUNT_HASH: Spinlock<BTreeMap<(u64, usize), Vec<u64>>, MountClass> =
    Spinlock::new(BTreeMap::new());

fn hash_insert(parent: u64, d: usize, mnt_id: u64) {
    MOUNT_HASH.lock().entry((parent, d)).or_default().push(mnt_id);
}
fn hash_remove(parent: u64, d: usize, mnt_id: u64) {
    let mut h = MOUNT_HASH.lock();
    if let Some(stack) = h.get_mut(&(parent, d)) {
        stack.retain(|&id| id != mnt_id);
        if stack.is_empty() { h.remove(&(parent, d)); }
    }
}
fn hash_top(parent: u64, d: usize) -> Option<u64> {
    MOUNT_HASH.lock().get(&(parent, d)).and_then(|s| s.last().copied())
}
/// Drop every hash entry naming one of `ids` (the ns-private `mnt_id`s of a
/// namespace being rebuilt / reaped). Replaces the old `ns`-keyed bulk drop now
/// that the key carries no `ns`. # C: O(N_hash × N_ids)
fn hash_drop_ids(ids: &[u64]) {
    let mut h = MOUNT_HASH.lock();
    h.retain(|_, stack| { stack.retain(|id| !ids.contains(id)); !stack.is_empty() });
}

/// `__lookup_mnt` (Linux `fs/namespace.c`): the (top) mount attached on
/// mountpoint dentry `d` whose PARENT mount is `parent_mnt_id`, by the
/// `(parent, dentry)` hash. The new crossing primitive — NOT wired into the
/// path walk this sub-round (the walk still reads the legacy per-ns
/// `dentry.mounted_mounts` map); a debug-assert at the crossing site proves the
/// two agree before 2b flips the hot path. # C: O(log N)
pub fn __lookup_mnt(parent_mnt_id: u64, d: &Arc<Dentry>) -> Option<Arc<Mount>> {
    hash_top(parent_mnt_id, dptr(d)).and_then(mount_by_id)
}

/// Parent mount id for a mount whose mountpoint dentry is `mp_d`, by DENTRY
/// IDENTITY (Linux `mnt_parent`). # C: O(depth)
fn parent_by_dentry(ns: u64, mp_d: &Arc<Dentry>) -> u64 {
    // [D9] OVERMOUNT parent: when `mp_d` is ITSELF the root dentry of a mount X,
    // a mount attached here is stacked ON X (Linux resolves the mount target
    // THROUGH the existing mount, landing on its `mnt_root`), so its parent is X
    // — the underlay top mount — NOT X's own parent. The legacy loop started at
    // `mp_d.parent()` (None for a root dentry) and fell through to the ns-root
    // mount, mis-parenting every overmount; that broke a per-`(parent,dentry)`
    // hash lookup (`__lookup_mnt(X, X_root)` could not find the overmount). The
    // pre-loop root check makes the new hash resolve the overmount top
    // deterministically by tree position instead of Vec-stack order.
    if mp_d.is_root() {
        if let Some(id) = visible_mnt_id_of_root_dentry(ns, mp_d) { return id; }
    }
    let mut cur = mp_d.parent().cloned();
    while let Some(a) = cur {
        if let Some(id) = a.mounted_mount(ns) { return id; }
        if a.is_root() {
            if let Some(id) = visible_mnt_id_of_root_dentry(ns, &a) { return id; }
            match cross_up(ns, &a) { Some(p) => { cur = Some(p); continue; } None => break }
        }
        cur = a.parent().cloned();
    }
    root_mount_id(ns).unwrap_or(0)
}

/// Relative path of `mp` beneath `stop` (exclusive), identity-bounded.
/// # C: O(depth)
pub(super) fn rel_under(mp: &Arc<Dentry>, stop: Option<&Arc<Dentry>>) -> Option<String> {
    let ns = current_ns();
    let mut names: Vec<String> = Vec::new();
    let mut cur = Some(mp.clone());
    while let Some(d) = cur {
        if let Some(s) = stop {
            if Arc::ptr_eq(&d, s) { return Some(join_names(&names)); }
        }
        match cross_up(ns, &d) {
            None => return if stop.is_none() { Some(join_names(&names)) } else { None },
            Some(p) => { if !d.name().is_empty() { names.push(d.name().to_string()); } cur = Some(p); }
        }
    }
    None
}

fn join_names(names: &[String]) -> String {
    let mut out = String::new();
    for n in names.iter().rev() { out.push('/'); out.push_str(n); }
    out
}

/// Relative path of `mp` beneath `stop` via PLAIN parent links only (NO mount
/// crossing). Distinguishes an UNDERLAY child (mounted on a dentry beneath
/// `stop` in the SAME fs — an MS_MOVE of `stop` relocates it) from an IN-FS
/// child (mounted on a dentry INSIDE the moved fs, reached only by crossing
/// `stop`; Linux `copy_tree` keeps it in place). `None` ⇒ not a plain-parent
/// descendant of `stop`. # C: O(depth)
fn plain_rel_under(mp: &Arc<Dentry>, stop: &Arc<Dentry>) -> Option<String> {
    let mut names: Vec<String> = Vec::new();
    let mut cur = Some(mp.clone());
    while let Some(d) = cur {
        if Arc::ptr_eq(&d, stop) { return Some(join_names(&names)); }
        if !d.name().is_empty() { names.push(d.name().to_string()); }
        cur = d.parent().cloned();
    }
    None
}

/// Mark `mp_d`'s dentry covered by `mnt_id` in `ns` (mount crossing). # C: O(1)
fn wire_crossing(ns: u64, mp_d: &Arc<Dentry>, mnt_id: u64) {
    mp_d.set_mounted_mount(ns, Some(mnt_id));
}

/// All mounts in `ns`, sorted by `mnt_id` ascending (= attach order, the
/// overmount stack order). # C: O(N_mounts)
pub(super) fn mounts_in_ns(ns: u64) -> Vec<Arc<Mount>> {
    MOUNTS.lock().values().filter(|m| m.ns == ns).cloned().collect()
}

/// Rebuild the POSITIONAL links for namespace `ns` from each mount's recorded
/// mountpoint dentry (identity only): crossings + `parent_id` + `mnt_parent`
/// + `mnt_mounts` child lists + hash. Propagation links (master/slave) are
/// position-independent and untouched. The single funnel for bulk paths
/// (move / pivot / copy_mnt_ns). # C: O(N×depth)
fn rebuild_ns_index(ns: u64) {
    let mounts = mounts_in_ns(ns);
    let ids: Vec<u64> = mounts.iter().map(|m| m.mnt_id).collect();
    hash_drop_ids(&ids);
    // Clear crossings + parent/child links + RELEASE each mount's current
    // `struct mountpoint` hold first. Releasing then re-acquiring keeps the
    // `m_count` (and the `D_MOUNTED` flag it gates) exactly balanced regardless
    // of the caller's prior state: a `copy_mnt_ns` clone arrives with NO hold
    // (`mnt_mp == None`), a `commit_retree` mount arrives with one already set
    // by `set_mountpoint_dentry` — both end with exactly one hold per crossing.
    for m in mounts.iter() {
        if let Some(d) = m.mountpoint() { d.set_mounted_mount(ns, None); }
        if let Some(o) = m.mnt_mp.lock().take() { put_mountpoint(&o); }
        m.mnt_mounts.lock().clear();
        *m.mnt_parent.lock() = Weak::new();
    }
    // Re-wire crossings (top wins by ascending mnt_id = stack order) + RE-ACQUIRE
    // the `struct mountpoint` hold so the `D_MOUNTED` refcount tracks this ns's
    // crossings (Linux `get_mountpoint` per attached child after a tree rebuild).
    for m in mounts.iter() {
        if let Some(d) = m.mountpoint() {
            wire_crossing(ns, &d, m.mnt_id);
            *m.mnt_mp.lock() = Some(get_mountpoint(&d));
        }
    }
    // Parent + child links + hash from the wired crossings.
    for m in mounts.iter() {
        match m.mountpoint() {
            None => { m.parent_id.store(m.mnt_id, Ordering::Release); }
            Some(d) => {
                let parent = parent_by_dentry(ns, &d);
                m.parent_id.store(parent, Ordering::Release);
                if let Some(p) = mount_by_id(parent) {
                    *m.mnt_parent.lock() = Arc::downgrade(&p);
                    p.mnt_mounts.lock().push(m.clone());
                }
                hash_insert(parent, dptr(&d), m.mnt_id);
            }
        }
    }
}

/// Mount propagation type per `docs/16§6` (`mount_namespaces(7)`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Propagation { Private = 0, Shared = 1, Slave = 2, Unbindable = 3 }

impl Propagation {
    /// # C: O(1)
    pub fn from_u8(v: u8) -> Self {
        match v { 1 => Self::Shared, 2 => Self::Slave, 3 => Self::Unbindable, _ => Self::Private }
    }
}

/// Reserved "no mount" mnt_id sentinel. `NEXT_MNT_ID` starts at 1, so `0` is
/// never assigned to a real `Mount` and can stand for "no covering mount" (the
/// namei base fallback before any root mount exists). # C: const
pub const MNT_ID_NONE: u64 = 0;
/// Monotonic mount-id source (mountinfo field 1). Starts at 1 (`MNT_ID_NONE`+1).
///
/// [D29] Strictly increasing and NEVER recycled — deliberately, NOT a leak.
/// Linux recycles `mnt_id` via an IDR only because its id is a 32-bit `int`;
/// our id is a 64-bit counter that cannot be exhausted in any realistic uptime
/// (2^64 mounts at, say, 10^9 mounts/s ≈ 585 years), so recycling buys nothing
/// and a free-list would only add ABA hazard: a freed-then-reused `mnt_id`
/// could alias a stale handle (an open file's `f_path.mnt`, an in-flight
/// `statmount`/`open_tree` fd, a `/proc/.../mountinfo` row a reader cached).
/// Same safety argument as `NEXT_NS_ID` in `mntns`. Detach drops the `MOUNTS`
/// entry; the id is simply never minted again.
static NEXT_MNT_ID: AtomicU64 = AtomicU64::new(1);
/// Monotonic peer-group id source. Starts at 1 (0 = none).
///
/// [D29] Monotonic-never-recycled for the same reason as `NEXT_MNT_ID`: a
/// 64-bit space never exhausts, and reusing a `peer_group` id could conflate a
/// demoted-then-reborn group with a stale `master:<pg>` / `shared:<pg>` field
/// still rendered in another reader's mountinfo snapshot.
static NEXT_PEER_GROUP: AtomicU64 = AtomicU64::new(1);

/// One mount instance (Linux `struct mount`). An intrusive tree node.
pub struct Mount {
    /// The mounted-instance superblock (Linux `mnt_sb`).
    pub sb: Arc<SuperBlock>,
    /// Rendered mount path — WRITE at attach/move, READ only by /proc. Behind
    /// a lock so MS_MOVE / pivot_root mutate it in place (no Arc rebuild,
    /// which would invalidate the intrusive links).
    rendered_path: Spinlock<String, MountClass>,
    /// Dentry this mount is attached on (Linux `mnt_mountpoint`). `None` only
    /// for a namespace root mount. Interior-mutable for MS_MOVE / pivot_root.
    mountpoint: Spinlock<Option<Arc<Dentry>>, MountClass>,
    /// Parent mount id (Linux `mnt_parent`), recorded at attach. Root → self.
    pub parent_id: AtomicU64,
    /// Stable unique id; /proc mountinfo field 1.
    pub mnt_id: u64,
    /// Propagation type discriminant. Default Private.
    pub propagation: AtomicU8,
    /// Peer-group id (`docs/16§6`); 0 = none.
    pub peer_group: AtomicU64,
    /// Per-mount MNT_* option bits.
    pub flags: AtomicU64,
    /// Mount-namespace id that created this mount.
    pub ns: u64,
    /// Root DENTRY of the mounted fs (Linux `mnt_root` = `mnt_sb->s_root`).
    mnt_root: Spinlock<Option<Arc<Dentry>>, MountClass>,
    /// Parent mount LINK (Linux `mnt_parent`). Weak: parent owns children via
    /// `mnt_mounts`; self/empty for a root mount.
    mnt_parent: Spinlock<Weak<Mount>, MountClass>,
    /// Child mounts (Linux `mnt_mounts`/`mnt_child`). Strong: parent owns them.
    mnt_mounts: Spinlock<Vec<Arc<Mount>>, MountClass>,
    /// The `struct mountpoint` this mount is attached on (Linux `mnt_mp`).
    mnt_mp: Spinlock<Option<Arc<Mountpoint>>, MountClass>,
    /// Slave → master link (Linux `mnt_master`). Set when this becomes a slave.
    mnt_master: Spinlock<Weak<Mount>, MountClass>,
    /// Master → slaves list (Linux `mnt_slave_list`).
    pub(super) mnt_slave_list: Spinlock<Vec<Weak<Mount>>, MountClass>,
    /// Active writer count (Linux `mnt_writers`); blocks remount-RO.
    mnt_writers: AtomicI32,
    /// Long-lived reference count (Linux `mnt_count`): external pins held BEYOND
    /// the mount's presence in the namespace tree — an open file's `f_path.mnt`,
    /// an in-flight path walk, an fd-based mount handle. `0` ⇒ no external
    /// holder. A lazy (`MNT_DETACH`) umount unlinks the mount from the tree at
    /// once but DEFERS the superblock teardown until this drops to `0`.
    mnt_count: AtomicI32,
    /// `MNT_DETACHED` (Linux `mnt->mnt_flags & MNT_DETACHED`): set once the mount
    /// has been unlinked from its namespace tree by an umount. While set, the
    /// final [`mntput`] (`mnt_count` 1 → 0) runs the deferred `deactivate_super`.
    detached: AtomicBool,
    /// Kernel-internal `mnt_flags` (Linux `include/linux/mount.h`): MNT_LOCKED,
    /// MNT_INTERNAL, MNT_DOOMED, MNT_MARKED, MNT_UMOUNT, plus the synthetic
    /// MNT_EXPIRE_MARK standing in for Linux's separate `mnt_expiry_mark` int.
    /// SEPARATE namespace from the MS_*-valued option mask in `flags` — see
    /// [`mnt_flags`]. Accessed via per-bit atomic fetch_or/and (xchg semantics).
    pub(super) mnt_internal_flags: AtomicU32,
    /// Per-mount id mapping (Linux `mnt_idmap`). Identity by default — a
    /// non-idmapped mount maps every uid/gid to itself, so stat-out and
    /// chown/create-in are byte-identical to the non-idmapped kernel.
    /// `mount_setattr(MOUNT_ATTR_IDMAP)` would install a non-identity map.
    pub mnt_idmap: Arc<crate::idmap::Idmap>,
}

impl Mount {
    /// Rendered mount-point path — RENDER ONLY. # C: O(1)
    pub fn mount_point_str(&self) -> String { self.rendered_path.lock().clone() }

    /// The dentry this mount is attached on (Linux `mnt_mountpoint`). # C: O(1)
    pub fn mountpoint(&self) -> Option<Arc<Dentry>> { self.mountpoint.lock().clone() }

    /// The mounted fs ROOT dentry (Linux `mnt_root` = `mnt_sb->s_root`). # C: O(1)
    pub fn mnt_root(&self) -> Option<Arc<Dentry>> {
        self.mnt_root.lock().clone().or_else(|| self.sb.s_root())
    }

    /// True iff this is its namespace's root mount. # C: O(log N)
    pub fn is_root(&self) -> bool {
        root_mount_id(self.ns) == Some(self.mnt_id)
    }

    /// The mounted-instance superblock (Linux `mnt_sb`). # C: O(1)
    pub fn sb(&self) -> &Arc<SuperBlock> { &self.sb }

    /// The backend behind this mount's superblock. # C: O(1)
    pub fn fs(&self) -> &Arc<dyn FileSystem> { self.sb.fs() }

    /// Active writer count (Linux `mnt_writers`). # C: O(1)
    pub fn writers(&self) -> i32 { self.mnt_writers.load(Ordering::Acquire) }

    /// Per-mount `MNT_*` option bits (Linux `mnt->mnt_flags`). # C: O(1)
    pub fn flags(&self) -> u64 { self.flags.load(Ordering::Acquire) }

    /// Long-lived external reference count (Linux `mnt_count`). # C: O(1)
    pub fn mnt_count(&self) -> i32 { self.mnt_count.load(Ordering::Acquire) }

    /// True once unlinked from its namespace tree by an umount (Linux
    /// `MNT_DETACHED`). The final [`mntput`] on a detached mount runs the
    /// deferred superblock teardown. # C: O(1)
    pub fn is_detached(&self) -> bool { self.detached.load(Ordering::Acquire) }

    /// Mark this mount unlinked from the tree (Linux `mnt_flags |=
    /// MNT_DETACHED`). Idempotent. # C: O(1)
    pub(super) fn mark_detached(&self) { self.detached.store(true, Ordering::Release); }
}

/// Global by-id mount map (Linux's mount arena), replacing the flat Vec.
/// `mount_by_id` is O(log N); cross-ns scanners iterate `.values()`.
static MOUNTS: Spinlock<BTreeMap<u64, Arc<Mount>>, MountClass> = Spinlock::new(BTreeMap::new());

/// Snapshot of all registered mounts. # C: O(N_mounts)
pub fn all_mounts() -> Vec<Arc<Mount>> { MOUNTS.lock().values().cloned().collect() }

/// The (top) mount attached EXACTLY at mountpoint dentry `d` in `ns`, by
/// IDENTITY. # C: O(log N)
pub(super) fn mount_exact_at(ns: u64, d: &Arc<Dentry>) -> Option<Arc<Mount>> {
    if is_global_root(d) { return root_mount_id(ns).and_then(mount_by_id); }
    let parent = parent_by_dentry(ns, d);
    let id = hash_top(parent, dptr(d))?;
    mount_by_id(id)
}

/// True iff a mount is attached exactly at mountpoint dentry `d` in `ns`.
/// # C: O(log N)
pub fn is_mount_in_ns(d: &Arc<Dentry>, ns: u64) -> bool {
    mount_exact_at(ns, d).is_some()
}

/// The mount that CONTAINS dentry `d` in `ns` — the mount the path walk is
/// positioned "in" when sitting AT `d` (before following any mount down). This
/// is Linux's `path.mnt` for a freshly-resolved base; a caller that hands the
/// walker only a bare dentry (no `vfsmount`) uses this to seed the walk's
/// `cur_mnt_id` accurately instead of defaulting to the ns-root mount (which is
/// wrong for a base that lives inside a sub-mount — e.g. a chroot/pivot staging
/// dir). For `d` that is itself a mount's root, returns that mount; otherwise
/// the deepest mount whose region contains `d`. # C: O(depth)
pub fn containing_mount_id(ns: u64, d: &Arc<Dentry>) -> u64 {
    if is_global_root(d) { return root_mount_id(ns).unwrap_or(MNT_ID_NONE); }
    // `parent_by_dentry` already maps a mount's own root dentry to that mount
    // (the [D9] overmount-parent prefix) and any other dentry to the mount whose
    // region contains it — exactly the "mount I am in at `d`" answer.
    parent_by_dentry(ns, d)
}

/// True iff the mount at dentry `d` in `ns` has child mounts (umount(2) EBUSY
/// busy-test) — read from the intrusive `mnt_mounts` child list, not a scan.
/// # C: O(1)
pub fn has_child_mounts(d: &Arc<Dentry>, ns: u64) -> bool {
    let Some(target) = mount_exact_at(ns, d) else { return false; };
    let has = !target.mnt_mounts.lock().is_empty();
    has
}

/// Find a mount by its stable `mnt_id`. # C: O(log N)
pub fn mount_by_id(id: u64) -> Option<Arc<Mount>> {
    MOUNTS.lock().get(&id).cloned()
}

/// The mount rooted EXACTLY at mountpoint dentry `d` in the caller's ns, by
/// the dentry crossing link (Linux `lookup_mnt`). # C: O(log N)
pub fn mount_at_path_exact(d: &Arc<Dentry>) -> Option<Arc<Mount>> {
    let ns = current_ns();
    if is_global_root(d) { return root_mount_id(ns).and_then(mount_by_id); }
    let id = d.mounted_mount(ns)?;
    mount_by_id(id)
}

/// Root mount id for namespace `ns` (Linux `mnt_ns->root`). # C: O(log N)
pub fn root_mount_id(ns: u64) -> Option<u64> { mntns::ns_root_id(ns) }

/// `mnt_id` of `m`'s parent mount — the value RECORDED at attach. # C: O(1)
pub fn parent_mnt_id(m: &Mount) -> u64 { m.parent_id.load(Ordering::Acquire) }

/// Build the `Mount` Arc (intrusive links empty; caller wires them). # C: O(1)
fn new_mount(sb: Arc<SuperBlock>, rendered: String, mountpoint: Option<Arc<Dentry>>,
             parent_id: u64, mnt_id: u64, ns: u64) -> Arc<Mount> {
    let mnt_root = sb.s_root();
    Arc::new(Mount {
        sb, rendered_path: Spinlock::new(rendered), mountpoint: Spinlock::new(mountpoint),
        parent_id: AtomicU64::new(parent_id), mnt_id,
        propagation: AtomicU8::new(Propagation::Private as u8),
        peer_group: AtomicU64::new(0), flags: AtomicU64::new(0), ns,
        mnt_root: Spinlock::new(mnt_root),
        mnt_parent: Spinlock::new(Weak::new()),
        mnt_mounts: Spinlock::new(Vec::new()),
        mnt_mp: Spinlock::new(None),
        mnt_master: Spinlock::new(Weak::new()),
        mnt_slave_list: Spinlock::new(Vec::new()),
        mnt_writers: AtomicI32::new(0),
        mnt_count: AtomicI32::new(0),
        detached: AtomicBool::new(false),
        mnt_internal_flags: AtomicU32::new(0),
        mnt_idmap: Arc::new(crate::idmap::Idmap::identity()),
    })
}

/// The `mnt_idmap` of mount `mnt_id`, or the identity map for an unknown /
/// anonymous (`0`) id. Threaded into `getattr` (stat-out) and `notify_change`
/// (chown/create-in); identity ⇒ no-op. # C: O(log N)
pub fn idmap_for(mnt_id: u64) -> Arc<crate::idmap::Idmap> {
    mount_by_id(mnt_id)
        .map(|m| m.mnt_idmap.clone())
        .unwrap_or_else(|| Arc::new(crate::idmap::Idmap::identity()))
}

/// [D6] Materialise (or, for a device-backed fs, FIND-OR-SHARE via [`sget`]) the
/// `SuperBlock` for a new mount. A backend that reports a stable backing-device
/// id (`fs.dev_id()`, Linux's `get_tree_bdev` bdev key) SHARES one `SuperBlock`
/// across every mount of that device: `sget` returns the live instance with one
/// extra `s_active` instead of allocating a duplicate, so two mounts of the same
/// disk agree on `s_dev`, inode cache and writeback (Linux's `s_active` sharing).
/// An anon/pseudo fs (no real device, `dev_id() == None` — tmpfs, procfs, a bind
/// marker) keeps a fresh per-mount `get_anon_bdev` instance, never shared.
/// # C: O(N_sb) on a dev-backed share, else O(1)
fn build_sb(fs: Arc<dyn FileSystem>, root_inode: Option<InodeRef>, s_id: String) -> Arc<SuperBlock> {
    match fs.dev_id() {
        Some(dev) => sget(dev, move || SuperBlock::for_backend(fs, root_inode, dev, s_id)),
        None => SuperBlock::for_backend(fs, root_inode, next_anon_dev(), s_id),
    }
}

/// Build a `Mount` and attach it on the caller-supplied mountpoint dentry
/// `mp` (Linux `mnt_set_mountpoint`/`commit_tree`). `mp == None` ⇒ the
/// namespace root mount. Acquires (or shares, via `build_sb`/`sget`) the
/// `SuperBlock`, then grafts it through the shared [`graft_realized`] tail.
/// # C: O(depth)
fn attach(mp: Option<Arc<Dentry>>, fs: Arc<dyn FileSystem>, root: Option<InodeRef>) -> KResult<()> {
    let mp = mp.filter(|d| !is_global_root(d));
    let root_inode = root.clone().or_else(|| fs.root());
    // `s_id` (the SB label) mirrors Linux's device/source id; the legacy mount
    // engine used the rendered mountpoint path here, which is not consumed
    // anywhere — keep it for an exact byte match with the prior behaviour.
    let s_id = match &mp { Some(d) => abs_string(d), None => String::from("/") };
    let sb = build_sb(fs, root_inode, s_id);
    graft_realized(mp, sb)
}

/// Graft an ALREADY-REALIZED `SuperBlock` (built by the new mount API's
/// `vfs_get_tree`/`get_tree`, which already ran `fill_super` + `d_make_root`)
/// onto mountpoint `mp` — the `move_mount` mode-(a) attach for a `fsmount`
/// object. The SB carries its own `s_root` dentry, from which the engine derives
/// the mount root inode (`mnt_root`), so the resulting mount-table state matches
/// the equivalent `register`/`register_bind` graft byte-for-byte (both resolve
/// the SAME root inode + root dentry). # C: O(depth)
pub fn attach_sb(mp: Option<Arc<Dentry>>, sb: Arc<SuperBlock>) -> KResult<()> {
    graft_realized(mp, sb)
}

/// Shared TAIL of [`attach`]/[`attach_sb`]: reserve the per-ns mount slot,
/// build the `Mount` over the realized `sb`, wire the intrusive parent/child +
/// crossing-hash links, and commit. The mount root inode is derived from
/// `sb.s_root()` (Linux `mnt_root`), not a stored copy. `mp == None` ⇒ the
/// namespace root mount. # C: O(depth)
fn graft_realized(mp: Option<Arc<Dentry>>, sb: Arc<SuperBlock>)
    -> KResult<()> {
    let ns = current_ns();
    // Per-ns mount cap (Linux `count_mounts` in `attach_recursive_mnt`): RESERVE
    // one slot in `pending_mounts` BEFORE building any mount state; over
    // `sysctl_mount_max` ⇒ ENOSPC. The reservation is rolled live by
    // `commit_mounts` once the mount is in `MOUNTS`; there is no fallible step
    // after this point, so no `abort_mounts` unwind path is reachable.
    mntns::count_mounts(ns, 1)?;
    let mnt_id = NEXT_MNT_ID.fetch_add(1, Ordering::Relaxed);
    let mp = mp.filter(|d| !is_global_root(d));
    let Some(d) = mp else {
        let m = new_mount(sb, String::from("/"), None, mnt_id, mnt_id, ns);
        // [D11] The namespace ROOT mount is a kernel-internal producer (Linux
        // marks rootfs / kern_mount mounts MNT_INTERNAL): never user-expirable.
        m.set_internal_flag(MNT_INTERNAL);
        mntns::ns_set_root(ns, mnt_id);
        MOUNTS.lock().insert(mnt_id, m);
        mntns::commit_mounts(ns, 1);
        mntns::bump_gen(ns);
        return Ok(());
    };
    let parent_id = parent_by_dentry(ns, &d);
    let rendered = abs_string(&d);
    let m = new_mount(sb, rendered, Some(d.clone()), parent_id, mnt_id, ns);
    // struct mountpoint (dentry refcount) + intrusive parent/child links.
    *m.mnt_mp.lock() = Some(get_mountpoint(&d));
    if let Some(p) = mount_by_id(parent_id) {
        *m.mnt_parent.lock() = Arc::downgrade(&p);
        p.mnt_mounts.lock().push(m.clone());
    }
    MOUNTS.lock().insert(mnt_id, m);
    wire_crossing(ns, &d, mnt_id);
    hash_insert(parent_id, dptr(&d), mnt_id);
    mntns::commit_mounts(ns, 1);
    mntns::bump_gen(ns);
    Ok(())
}

/// Register a FileSystem on mountpoint dentry `mp` (Linux `do_new_mount`).
/// # C: O(depth)
pub fn register(mp: Option<Arc<Dentry>>, fs: Arc<dyn FileSystem>) -> KResult<()> {
    attach(mp, fs, None)
}

/// Bind-as-clone (`mount(src, tgt, NULL, MS_BIND)`). # C: O(depth)
pub fn register_bind(mp: Option<Arc<Dentry>>, fs: Arc<dyn FileSystem>, root: InodeRef) -> KResult<()> {
    attach(mp, fs, Some(root))
}

// ---------------------------------------------------------------------------
// copy_tree / clone_mnt / commit_tree — Linux `fs/namespace.c` subtree clone
// (`copy_tree`/`clone_mnt`/`commit_tree`), the structural primitive shared by
// mount propagation (`propagate_mnt`) and the MS_REC recursive bind. A clone
// SHARES the source superblock (one extra `s_active`), copies its option flags
// + MNT_LOCKED, and carries the requested propagation (CL_MAKE_SHARED / CL_SLAVE
// / private). POSITION is resolved by the engine's unified crossing-aware
// resolver (`rel_under` for capture, `descend` for placement) — NOT by reusing
// the source mountpoint dentry: this engine (and every hosted fixture) positions
// nested mounts on UNDERLAY dentries reached by descent, so a peer/target lives
// at a DISTINCT dentry the same-dentry Linux shortcut cannot name. `rel_under`
// is the same in-fs/underlay-unifying resolver MS_MOVE/pivot_root retain.
// ---------------------------------------------------------------------------

/// Propagation type stamped on a [`clone_mnt`] copy (Linux `CL_*` clone flags).
#[derive(Clone, Copy)]
pub(super) enum CloneType { MakeShared, Slave, Private }

/// A node of a [`copy_tree`] result: the cloned mount plus its mountpoint
/// position RELATIVE to the copy's base mountpoint (so [`commit_tree`] can
/// `descend` it under any destination base). # C: field
pub(super) struct CloneNode { pub m: Arc<Mount>, pub rel: String }

/// Linux `clone_mnt`: build a NEW mount over `src`'s backend, copy its option
/// flags + MNT_LOCKED, and stamp the requested propagation. UNLINKED — no
/// mountpoint, parent, hash or `MOUNTS` entry yet (`commit_tree` wires those).
/// MakeShared joins peer group `pg`; Slave chains onto `master`'s slave list;
/// Private stands alone.
///
/// SB handling follows THIS engine's [`build_sb`] (not Linux's literal
/// `sb->s_active++` share): a dev-backed backend SHARES one `SuperBlock` via
/// `sget` (the Linux `s_active` share for the same device), while a pseudo /
/// anon backend gets a FRESH per-clone `SuperBlock` with a DISTINCT `s_root`.
/// Sharing one anon `s_root` across clones would re-introduce the singleton-
/// `s_root` ambiguity `rel_under`/`pivot_root` cannot disambiguate (the 203/EXEC
/// executor-pivot repro) — distinct identity per clone is what this dentry-
/// identity engine relies on, exactly as `register_bind` already does. # C: O(1)
pub(super) fn clone_mnt(src: &Arc<Mount>, ty: CloneType, pg: u64, master: &Arc<Mount>, ns: u64)
    -> Arc<Mount> {
    let new_id = NEXT_MNT_ID.fetch_add(1, Ordering::Relaxed);
    // [D5] derive the clone's root inode from the source `mnt_root` dentry (the
    // single source of truth), not a stored per-mount inode copy.
    let root_inode = src.mnt_root().and_then(|r| r.inode()).or_else(|| src.fs().root());
    let sb = build_sb(src.fs().clone(), root_inode, src.mount_point_str());
    let clone = new_mount(sb, src.mount_point_str(), None, 0, new_id, ns);
    clone.flags.store(src.flags.load(Ordering::Acquire), Ordering::Release);
    // Keep only MNT_LOCKED on the copy (Linux `clone_mnt`); drop transient marks.
    clone.mnt_internal_flags.store(
        src.mnt_internal_flags.load(Ordering::Acquire) & MNT_LOCKED, Ordering::Release);
    match ty {
        CloneType::MakeShared => {
            clone.propagation.store(Propagation::Shared as u8, Ordering::Release);
            clone.peer_group.store(pg, Ordering::Release);
        }
        CloneType::Slave => {
            clone.propagation.store(Propagation::Slave as u8, Ordering::Release);
            *clone.mnt_master.lock() = Arc::downgrade(master);
            master.mnt_slave_list.lock().push(Arc::downgrade(&clone));
        }
        CloneType::Private => {
            clone.propagation.store(Propagation::Private as u8, Ordering::Release);
        }
    }
    clone
}

/// Release a [`clone_mnt`] copy that will NOT be committed: unlink it from any
/// master's slave list and drop its `SuperBlock` active ref ([`build_sb`]
/// seeded one), so a skipped/failed clone leaves the SB active count and slave
/// links balanced. # C: O(master slaves)
fn release_clone(m: &Arc<Mount>) {
    if let Some(master) = m.mnt_master.lock().upgrade() {
        master.mnt_slave_list.lock()
            .retain(|w| w.upgrade().map(|x| x.mnt_id != m.mnt_id).unwrap_or(false));
    }
    *m.mnt_master.lock() = Weak::new();
    m.sb.deactivate_super();
}

/// Linux `copy_tree`: recursively CLONE the mount subtree at `src` — the root
/// itself when `include_root`, plus every BINDABLE submount whose mountpoint
/// lies under `base_mp` — preserving peer-group / slave relations per `ty`.
/// UNBINDABLE submounts are dropped (Linux `IS_MNT_UNBINDABLE`, D15). Each clone
/// records its position relative to `base_mp` via [`rel_under`] (the crossing
/// resolver handling both in-fs and underlay children) for later `descend`.
/// Returns the clones in PRE-ORDER (parents first), UNLINKED from the live tree.
/// # C: O(N_subtree × depth)
pub(super) fn copy_tree(src: &Arc<Mount>, base_mp: &Arc<Dentry>, ty: CloneType, pg: u64,
                        master: &Arc<Mount>, ns: u64, include_root: bool,
                        exclude: Option<&Arc<Dentry>>) -> Vec<CloneNode> {
    let mut out: Vec<CloneNode> = Vec::new();
    copy_tree_into(src, base_mp, ty, pg, master, ns, include_root, exclude, &mut out);
    out
}

fn copy_tree_into(src: &Arc<Mount>, base_mp: &Arc<Dentry>, ty: CloneType, pg: u64,
                  master: &Arc<Mount>, ns: u64, include_root: bool,
                  exclude: Option<&Arc<Dentry>>, out: &mut Vec<CloneNode>) {
    if include_root {
        let rel = src.mountpoint().and_then(|d| rel_under(&d, Some(base_mp))).unwrap_or_default();
        out.push(CloneNode { m: clone_mnt(src, ty, pg, master, ns), rel });
    }
    // Snapshot children OUT of the lock before recursing (recursion re-locks).
    let children: Vec<Arc<Mount>> = src.mnt_mounts.lock().iter().cloned().collect();
    for child in children.iter() {
        if is_unbindable(child) { continue; }                       // D15
        let Some(child_mp) = child.mountpoint() else { continue; };
        // Skip a submount that lives under `exclude` (the recursive-bind DESTINATION):
        // never clone the staging tree into itself, and prune its whole subtree.
        if let Some(ex) = exclude {
            if rel_under(&child_mp, Some(ex)).is_some() { continue; }
        }
        let Some(rel) = rel_under(&child_mp, Some(base_mp)) else { continue; };
        if rel.is_empty() { continue; }
        out.push(CloneNode { m: clone_mnt(child, ty, pg, master, ns), rel });
        copy_tree_into(child, base_mp, ty, pg, master, ns, false, exclude, out);
    }
}

/// Mark `rel`'s subtree dead so every later [`commit_tree`] node beneath a
/// failed/skipped parent is skipped too. # C: O(1)
fn mark_dead(dead: &mut Vec<String>, rel: &str) {
    let mut p = String::from(rel); p.push('/'); dead.push(p);
}

/// Linux `commit_tree`: splice a pre-built [`copy_tree`] clone subtree under the
/// destination — root at `dest_base`, each descendant at `descend(dest_base,
/// rel)` (falling back to `fallback` for a degenerate dest whose mounted root
/// cannot resolve the slot). Per node, in pre-order: RESERVE a per-ns slot
/// ([`mntns::count_mounts`]) BEFORE any visible state; take the `struct
/// mountpoint` D_MOUNTED hold ([`get_mountpoint`], EXACTLY ONE per crossing —
/// the refcount-sensitive line); wire intrusive parent/child + crossing-hash
/// links by dentry identity ([`parent_by_dentry`], as [`graft_realized`]);
/// insert into `MOUNTS`; `commit_mounts`. A node that cannot be positioned or
/// fails the cap is SKIPPED with its descendants (their clones' active SB ref +
/// slave link are released via [`release_clone`]) — never half-attached. One
/// [`mntns::bump_gen`] at the end. Returns the count committed. # C: O(N × depth)
pub(super) fn commit_tree(nodes: Vec<CloneNode>, dest_base: &Arc<Dentry>,
                          fallback: Option<&Arc<Dentry>>, ns: u64) -> usize {
    let mut committed = 0usize;
    let mut dead: Vec<String> = Vec::new();
    'node: for node in nodes.into_iter() {
        let CloneNode { m, rel } = node;
        for d in dead.iter() {
            if rel.starts_with(d.as_str()) { release_clone(&m); continue 'node; }
        }
        let mp_d = if rel.is_empty() {
            dest_base.clone()
        } else {
            let resolved = descend(dest_base, &rel).or_else(|| fallback.and_then(|f| {
                if Arc::ptr_eq(f, dest_base) { None } else { descend(f, &rel) }
            }));
            match resolved {
                Some(d) => d,
                None => { mark_dead(&mut dead, &rel); release_clone(&m); continue; }
            }
        };
        // RESERVE before any visible state (Linux `count_mounts` in
        // `attach_recursive_mnt`); over the per-ns cap ⇒ skip this node+subtree.
        if mntns::count_mounts(ns, 1).is_err() { mark_dead(&mut dead, &rel); release_clone(&m); continue; }
        let parent_id = parent_by_dentry(ns, &mp_d);
        let rendered = abs_string(&mp_d);
        *m.mountpoint.lock() = Some(mp_d.clone());
        *m.rendered_path.lock() = rendered;
        m.parent_id.store(parent_id, Ordering::Release);
        // The D_MOUNTED hold — ONE `get_mountpoint` per cloned crossing.
        *m.mnt_mp.lock() = Some(get_mountpoint(&mp_d));
        if let Some(p) = mount_by_id(parent_id) {
            *m.mnt_parent.lock() = Arc::downgrade(&p);
            p.mnt_mounts.lock().push(m.clone());
        }
        MOUNTS.lock().insert(m.mnt_id, m.clone());
        wire_crossing(ns, &mp_d, m.mnt_id);
        hash_insert(parent_id, dptr(&mp_d), m.mnt_id);
        mntns::commit_mounts(ns, 1);
        committed += 1;
    }
    if committed > 0 { mntns::bump_gen(ns); }
    committed
}

/// [D14] `attach_recursive_mnt` (Linux `fs/namespace.c`): graft a new mount on
/// `mp` AND deliver mount propagation to the destination parent's peer group as
/// ONE engine call, so there is no caller-visible window where the mount is
/// attached but its propagated mirrors are not (the prior `register*` +
/// separate `propagate_mount` sequence left the tree momentarily
/// half-replicated). `root` `Some` ⇒ bind-as-clone, `None` ⇒ fresh fs. Returns
/// the number of propagated mirror copies created (0 for a private/root graft).
/// # C: O(N_mounts × depth)
pub fn attach_recursive_mnt(mp: Option<Arc<Dentry>>, fs: Arc<dyn FileSystem>,
                            root: Option<InodeRef>) -> KResult<usize> {
    let at = mp.clone();
    attach(mp, fs, root)?;
    Ok(match at { Some(d) => propagation::propagate_mount(&d), None => 0 })
}

/// `mnt_id`s of `top` plus its transitive children via the intrusive child
/// lists (the dentry subtree), in `ns`. # C: O(N_subtree)
fn subtree_ids(_ns: u64, top: u64) -> Vec<u64> {
    let mut ids = alloc::vec![top];
    let mut frontier: Vec<Arc<Mount>> = mount_by_id(top).into_iter().collect();
    while let Some(m) = frontier.pop() {
        for c in m.mnt_mounts.lock().iter() {
            if !ids.contains(&c.mnt_id) { ids.push(c.mnt_id); frontier.push(c.clone()); }
        }
    }
    ids
}

/// True iff `m`'s propagation type is SHARED (Linux `IS_MNT_SHARED`). # C: O(1)
fn is_shared(m: &Mount) -> bool {
    Propagation::from_u8(m.propagation.load(Ordering::Acquire)) == Propagation::Shared
}

/// True iff `m`'s propagation type is UNBINDABLE (Linux `IS_MNT_UNBINDABLE`).
/// # C: O(1)
fn is_unbindable(m: &Mount) -> bool {
    Propagation::from_u8(m.propagation.load(Ordering::Acquire)) == Propagation::Unbindable
}

/// True iff the subtree rooted at mount `top` contains an UNBINDABLE mount
/// (Linux `do_move_mount` `tree_contains_unbindable`). # C: O(N_subtree)
fn tree_contains_unbindable(ns: u64, top: u64) -> bool {
    subtree_ids(ns, top).iter()
        .any(|id| mount_by_id(*id).map(|m| is_unbindable(&m)).unwrap_or(false))
}

/// In-place swap of a mount's mountpoint dentry + rendered path + `struct
/// mountpoint` (used by MS_MOVE / pivot_root so the Arc — and every intrusive
/// link to it — stays valid). # C: O(log N)
fn set_mountpoint_dentry(m: &Arc<Mount>, new_d: Option<Arc<Dentry>>, rendered: String) {
    let old = m.mnt_mp.lock().take();
    if let Some(o) = old { put_mountpoint(&o); }
    let newmp = new_d.as_ref().map(get_mountpoint);
    *m.mnt_mp.lock() = newmp;
    *m.mountpoint.lock() = new_d;
    *m.rendered_path.lock() = rendered;
}

/// `pivot_root(new_root, put_old)` (`docs/16§6`). # C: O(N_mounts × depth)
pub fn pivot_root(new_root: &Arc<Dentry>, put_old: &Arc<Dentry>) -> KResult<()> {
    let ns = current_ns();
    let nr_m = mount_exact_at(ns, new_root).ok_or(VfsError::Einval)?;
    let nr_mp = nr_m.mountpoint();
    let nr_id = nr_m.mnt_id;
    let nr_subtree = subtree_ids(ns, nr_id);
    let po_d = put_old.clone();
    let old_root_id = root_mount_id(ns);
    // [D20] Linux `pivot_root(2)` safety checks (all -EINVAL):
    //   * the new_root mount must not be MNT_LOCKED
    //     (`new_mnt->mnt.mnt_flags & MNT_LOCKED`);
    //   * none of {the mount put_old resides on, the new_root's parent, the
    //     current root's parent} may be SHARED — a shared mountpoint would
    //     corrupt its peers when the re-root mutates it
    //     (`IS_MNT_SHARED(old_mnt) || IS_MNT_SHARED(new_mnt->mnt_parent) ||
    //       IS_MNT_SHARED(root_mnt->mnt_parent)`).
    if nr_m.is_locked() { return Err(VfsError::Einval); }
    if let Some(p) = mount_by_id(nr_m.parent_id.load(Ordering::Acquire)) {
        if is_shared(&p) { return Err(VfsError::Einval); }
    }
    if let Some(rm) = old_root_id.and_then(mount_by_id) {
        if let Some(rp) = mount_by_id(rm.parent_id.load(Ordering::Acquire)) {
            if is_shared(&rp) { return Err(VfsError::Einval); }
        }
    }
    if let Some(om) = mount_by_id(parent_by_dentry(ns, &po_d)) {
        if is_shared(&om) { return Err(VfsError::Einval); }
    }
    let mounts = mounts_in_ns(ns);
    let stacking = nr_mp.as_ref().map(|d| Arc::ptr_eq(d, &po_d)).unwrap_or(false)
        || rel_under(&po_d, nr_mp.as_ref()) == Some(String::new());
    if stacking {
        let new_paths: Vec<(u64, String)> = mounts.iter().map(|m| {
            let np = if m.mnt_id == nr_id {
                String::from("/")
            } else if nr_subtree.contains(&m.mnt_id) {
                m.mountpoint().and_then(|d| rel_under(&d, nr_mp.as_ref()))
                    .unwrap_or_else(|| m.mount_point_str())
            } else {
                m.mount_point_str()
            };
            (m.mnt_id, np)
        }).collect();
        commit_retree(ns, &new_paths, Some(nr_id), &nr_subtree);
        if let Some(old) = old_root_id { mntns::chroot_fs_refs(old, nr_id); }
        return Ok(());
    }
    let old_dst = match rel_under(&po_d, nr_mp.as_ref()) {
        Some(r) if !r.is_empty() => r,
        _ if nr_mp.is_none() => rel_under(&po_d, None).unwrap_or_default(),
        _ => return Err(VfsError::Einval),
    };
    if po_d.mounted_mount(ns).is_some() { return Err(VfsError::Ebusy); }
    let new_paths: Vec<(u64, String)> = mounts.iter().map(|m| {
        let np = if m.mnt_id == nr_id {
            String::from("/")
        } else if nr_subtree.contains(&m.mnt_id) {
            m.mountpoint().and_then(|d| rel_under(&d, nr_mp.as_ref()))
                .unwrap_or_else(|| m.mount_point_str())
        } else if Some(m.mnt_id) == old_root_id {
            old_dst.clone()
        } else {
            let abs = m.mountpoint().and_then(|d| rel_under(&d, None))
                .unwrap_or_else(|| m.mount_point_str());
            alloc::format!("{}{}", old_dst, abs)
        };
        (m.mnt_id, np)
    }).collect();
    commit_retree(ns, &new_paths, Some(nr_id), &nr_subtree);
    if let Some(old) = old_root_id { mntns::chroot_fs_refs(old, nr_id); }
    Ok(())
}

/// Commit a whole-namespace path rewrite (pivot_root): re-root the ns, then
/// for each mount mutate its position in place and rebuild the ns index (links
/// + crossings + hash) by identity. Mounts listed in `preserve` (the new root's
/// own subtree) KEEP their existing mountpoint dentry — they live INSIDE the
/// moved filesystems and travel unchanged (Linux `copy_tree`); only their
/// rendered path is re-based. Re-deriving their dentry by a global-path
/// `descend` was the 203/EXEC bug: a bind/clone submount's `s_root` is a
/// DISTINCT dentry the global-root descent NEVER reaches, so the descent
/// re-seated the crossing onto the OLD tree's dentry — after the executor's
/// `pivot_root` the relocated `/usr`,`/lib64` were unreachable from the new
/// root, so `execve(/usr/lib/systemd/systemd-udevd)` ENOENT'd → status 203.
/// Mounts OUTSIDE the new-root subtree (the old root + its tree, relocated
/// under `put_old`) are still reachable from the global root, so their position
/// is materialised by `descend`. # C: O(N×depth)
fn commit_retree(ns: u64, new_paths: &[(u64, String)], new_root_id: Option<u64>, preserve: &[u64]) {
    let mounts = mounts_in_ns(ns);
    for m in mounts.iter() { if let Some(d) = m.mountpoint() { d.set_mounted_mount(ns, None); } }
    if let Some(rid) = new_root_id { mntns::ns_set_root(ns, rid); }
    let root = global_root();
    let dents: Vec<(u64, String, Option<Arc<Dentry>>)> = new_paths.iter().map(|(id, p)| {
        let is_root = Some(*id) == new_root_id;
        let d = if is_root { None }
                else if preserve.contains(id) { mount_by_id(*id).and_then(|m| m.mountpoint()) }
                else { root.as_ref().and_then(|r| descend(r, p)) };
        (*id, p.clone(), d)
    }).collect();
    for m in mounts.iter() {
        if let Some((_, p, d)) = dents.iter().find(|(id, _, _)| *id == m.mnt_id) {
            let is_root = Some(m.mnt_id) == new_root_id;
            set_mountpoint_dentry(m, if is_root { None } else { d.clone() }, p.clone());
        }
    }
    rebuild_ns_index(ns);
    mntns::bump_gen(ns);
}

/// Last-umount teardown (Linux `mntput` → `deactivate_super`): drop THIS
/// mount's active reference on `sb` via the [`SuperBlock`] `s_active` refcount
/// (D6). Each live mount holds exactly one active ref — `for_backend` seeds the
/// first (`s_active == 1`) and every SB-sharing clone (`copy_mnt_ns`, the Linux
/// `clone_mnt` path) grabs one via [`SuperBlock::grab_active`] — so the LAST
/// drop (1 → 0) runs `generic_shutdown_super` (sync_filesystem + `put_super`)
/// exactly once, and a still-mounted sibling/ns-clone keeps the shared instance
/// alive. Replaces the old O(N) `Arc::ptr_eq` mount-table scan, which could not
/// see refs held by mounts already removed from `MOUNTS`. Call AFTER the victim
/// is unlinked so the drop accounts for itself. # C: O(1) (O(tree) on last drop)
pub(super) fn put_super_if_last(sb: &Arc<SuperBlock>) {
    // deactivate_super = atomic_dec_and_test; on the 1→0 transition it runs
    // sync_fs + put_super internally (idempotent once already at 0).
    sb.deactivate_super();
}

/// `mntget` (Linux `mntget`): pin a long-lived external reference on `m` — the
/// `f_path.mnt` an open file carries, an in-flight path-walk hold, an fd-based
/// mount handle. Keeps the mount (and, while it is the last detached holder,
/// its superblock) alive across a concurrent lazy umount. Each `mntget` MUST be
/// balanced by exactly one [`mntput`]. # C: O(1)
pub fn mntget(m: &Arc<Mount>) {
    m.mnt_count.fetch_add(1, Ordering::AcqRel);
    // A fresh pin = the mount is in use again: reset its expiry grace so a
    // pending [`mark_mounts_for_expiry`] sweep does not reap it (Linux clears
    // `mnt_expiry_mark` when a mount is referenced).
    m.mnt_internal_flags.fetch_and(!MNT_EXPIRE_MARK, Ordering::AcqRel);
}

/// `mntput` (Linux `mntput_no_expire`): drop a long-lived reference taken by
/// [`mntget`]. When this is the LAST external reference (`mnt_count` 1 → 0) AND
/// the mount was already lazily detached from the tree (`MNT_DETACHED`), run the
/// deferred superblock teardown (`deactivate_super` → `put_super` on the last SB
/// user) — the busy-mount lazy-umount completion. # C: O(1) (O(tree) on last)
pub fn mntput(m: &Arc<Mount>) {
    let prev = m.mnt_count.fetch_sub(1, Ordering::AcqRel);
    hal::kassert!(prev > 0, "mntput: mnt_count underflow below zero");
    if prev == 1 && m.detached.load(Ordering::Acquire) {
        put_super_if_last(&m.sb);
    }
}

/// Unlink `id` from its parent's intrusive child list. # C: O(siblings)
fn unlink_from_parent(m: &Arc<Mount>) {
    if let Some(p) = m.mnt_parent.lock().upgrade() {
        p.mnt_mounts.lock().retain(|c| c.mnt_id != m.mnt_id);
    }
}

/// Copy-on-unshare / `copy_mnt_ns` (`docs/16§6`): clone every mount in
/// `from_ns` into `to_ns` as a fresh independent mount, then rebuild `to_ns`'s
/// index by identity. A child-ns clone of a SHARED mount is demoted to a
/// SLAVE of the source peer group (Linux `copy_mnt_ns` → `CL_SLAVE`), so a
/// later mount in the child does NOT propagate back into the parent ns. The
/// new ns is created. # C: O(N_mounts × depth)
pub fn copy_mnt_ns(from_ns: u64, to_ns: u64) {
    let src = mounts_in_ns(from_ns);
    mntns::ns_get_or_create(to_ns);
    for m in src.iter() {
        let new_id = NEXT_MNT_ID.fetch_add(1, Ordering::Relaxed);
        // Linux `clone_mnt`: the clone shares the source SB, so take an extra
        // active ref (`atomic_inc(&sb->s_active)`). The source mount is live in
        // `MOUNTS`, so its SB is active and `grab_active` always succeeds.
        let grabbed = m.sb.grab_active();
        hal::kassert!(grabbed, "copy_mnt_ns: live source SB must grab an active ref");
        let clone = new_mount(
            m.sb.clone(), m.mount_point_str(), m.mountpoint(),
            0, new_id, to_ns,
        );
        clone.flags.store(m.flags.load(Ordering::Acquire), Ordering::Release);
        // Linux `clone_mnt` keeps MNT_LOCKED on the copy so a child userns cannot
        // reveal a locked submount by unmounting it; transient marks are dropped.
        clone.mnt_internal_flags.store(
            m.mnt_internal_flags.load(Ordering::Acquire) & MNT_LOCKED, Ordering::Release);
        let prop = Propagation::from_u8(m.propagation.load(Ordering::Acquire));
        match prop {
            Propagation::Shared => {
                // The clone becomes a slave of the SOURCE shared mount: it
                // receives parent-ns events but its own mounts stay private to
                // the child ns (containment). master link + master's slave list.
                clone.propagation.store(Propagation::Slave as u8, Ordering::Release);
                clone.peer_group.store(m.peer_group.load(Ordering::Acquire), Ordering::Release);
                *clone.mnt_master.lock() = Arc::downgrade(m);
                m.mnt_slave_list.lock().push(Arc::downgrade(&clone));
            }
            _ => {
                clone.propagation.store(prop as u8, Ordering::Release);
                clone.peer_group.store(0, Ordering::Release);
            }
        }
        if m.mountpoint().is_none() { mntns::ns_set_root(to_ns, new_id); }
        MOUNTS.lock().insert(new_id, clone);
    }
    // Account the cloned mounts into the new ns (Linux `copy_mnt_ns` sums
    // `nr_mounts` over the copied tree). The ns COPY itself is not bounded by
    // `sysctl_mount_max` — only later grafts are — so roll the count straight
    // into the live `nr_mounts` (fresh ns ⇒ `pending == 0`).
    mntns::commit_mounts(to_ns, src.len() as u64);
    rebuild_ns_index(to_ns);
    mntns::bump_gen(to_ns);
}

/// Back-compat alias for the unshare(CLONE_NEWNS) call site. # C: O(N×depth)
pub fn snapshot_ns(from_ns: u64, to_ns: u64) { copy_mnt_ns(from_ns, to_ns); }

/// Reap every mount belonging to `ns` (Linux `free_mnt_ns` at last task
/// exit). Drops the per-ns crossings, the hash, the `struct mountpoint`
/// refcounts, and the global-map entries, and `mntput`s each mount's active
/// reference so a ns-private SB (no peer ns sharing it) runs `put_super` on
/// its last drop. # C: O(N_ns_mounts)
pub(crate) fn reap_ns(ns: u64) {
    let mounts = mounts_in_ns(ns);
    for m in mounts.iter() {
        if let Some(d) = m.mountpoint() { d.set_mounted_mount(ns, None); }
        if let Some(o) = m.mnt_mp.lock().take() { put_mountpoint(&o); }
        m.mnt_mounts.lock().clear();
        MOUNTS.lock().remove(&m.mnt_id);
        // free_mnt_ns → mntput → deactivate_super: drop this mount's active ref.
        put_super_if_last(&m.sb);
    }
    // free_mnt_ns: the whole ns is gone — zero its live mount count so a stale
    // `ns_nr_mounts` read after reap reports 0 (Linux `mnt_ns->nr_mounts` dies
    // with the namespace).
    mntns::dec_mounts(ns, mounts.len() as u64);
    hash_drop_ids(&mounts.iter().map(|m| m.mnt_id).collect::<Vec<_>>());
    mntns::bump_gen(ns);
}

/// MS_REC recursive bind (`docs/16§6`): mirror the SUBMOUNTS of the source tree
/// under `tgt` (the source ROOT itself is bound separately by the caller). Linux
/// `copy_tree`+`commit_tree`: each submount is CLONED (sharing its SB, copying
/// flags+MNT_LOCKED) as a PRIVATE bind, UNBINDABLE submounts dropped, the whole
/// subtree spliced under the destination in one engine pass with a single
/// D_MOUNTED hold per crossing. Mirror under the TARGET's mounted ROOT (the bind
/// already covers `tgt`, and a submount's slot lives INSIDE that clone — where
/// namei lands after crossing `tgt`); fall back to the bare `tgt` underlay for a
/// degenerate dest whose mounted root cannot resolve the slot, so a plain-dir
/// recursive bind still mirrors (the NAMESPACE-226 procfs-clone case). # C: O(N×depth)
pub fn bind_submounts_rec(src: &Arc<Dentry>, tgt: &Arc<Dentry>) -> usize {
    let ns = current_ns();
    let Some(src_m) = mount_exact_at(ns, src) else { return 0; };
    // Unbindable source root is not cloned (Linux `IS_MNT_UNBINDABLE`, D15).
    if is_unbindable(&src_m) { return 0; }
    // Base mountpoint to capture relative positions against: the source root's
    // own mountpoint, or the global root for the namespace-root source.
    let Some(base_mp) = src_m.mountpoint().or_else(global_root) else { return 0; };
    // Mirror under the TARGET's mounted ROOT, not its bare mountpoint dentry.
    let mut tgt_base = tgt.clone();
    while let Some(id) = tgt_base.mounted_mount(ns) {
        match root_dentry_for_mount_id(id) { Some(sr) => tgt_base = sr, None => break }
    }
    // Clone the source's submount SUBTREE (root EXCLUDED — already bound) as
    // private binds, then splice it under the destination base, falling back to
    // the bare `tgt` underlay when the mounted root cannot resolve a slot.
    let nodes = copy_tree(&src_m, &base_mp, CloneType::Private, 0, &src_m, ns, false, Some(tgt));
    commit_tree(nodes, &tgt_base, Some(tgt), ns)
}

/// `mount(MS_MOVE)`: relocate the mount at dentry `from` (plus its subtree) to
/// dentry `to`. Linux `do_move_mount`/`attach_recursive_mnt`: ONLY the moved
/// root's attachment (`mnt_parent`+`mnt_mountpoint`) changes; every internal
/// mount keeps its mountpoint DENTRY + parent link, since those dentries live
/// inside the moved filesystems and travel WITH them (`copy_tree`). An UNDERLAY
/// child (attached on a dentry beneath `from`'s mountpoint in the SAME fs, not
/// crossed into `from`) instead follows `from` to the mirrored spot under `to`.
/// Re-deriving every internal position via a global-PATH `descend` was the bug:
/// a child INSIDE the moved fs cannot be re-found before the root's new crossing
/// exists (and a shared/singleton `s_root` descends into the underlay), so the
/// child is orphaned and its leaf ENOENTs. # C: O(N × depth)
pub fn move_mount(from: &Arc<Dentry>, to: &Arc<Dentry>) -> KResult<()> {
    let from_m = mount_exact_at(current_ns(), from).ok_or(VfsError::Einval)?;
    move_mount_m(from_m, to)
}

/// As [`move_mount`] but identifies the SOURCE mount by the `mnt_id` the path
/// walk CROSSED INTO (Linux `do_move_mount` keys on `path->mnt`). The MS_MOVE
/// source resolves THROUGH the mount being moved, landing on its (often shared)
/// `s_root`, which `mount_exact_at` cannot map back to a mount — so systemd's
/// `mount_move_root` (`mount(".", "/", MS_MOVE)`, the final pivot of the
/// assembled sandbox root) got EINVAL at step NAMESPACE. # C: O(N × depth)
pub fn move_mount_by_id(from_id: u64, to: &Arc<Dentry>) -> KResult<()> {
    let from_m = mount_by_id(from_id).ok_or(VfsError::Einval)?;
    // [D32] Uniform cross-ns guard: `mount_by_id` is the ns-AGNOSTIC arena
    // lookup, so a by-id handle MUST pass `check_mnt` before any mutation.
    if !check_mnt(&from_m) { return Err(VfsError::Einval); }
    move_mount_m(from_m, to)
}

/// Shared MS_MOVE body for both [`move_mount`] variants. # C: O(N × depth)
fn move_mount_m(from_m: Arc<Mount>, to: &Arc<Dentry>) -> KResult<()> {
    let ns = current_ns();
    let from_id = from_m.mnt_id;
    let to_root = is_global_root(to);
    // Linux `do_move_mount` validation (all -EINVAL). NOTE: moving ONTO `/` is
    // NOT rejected here — systemd `mount_move_root` (`mount(new, "/", MS_MOVE)`
    // then `chroot(".")`) depends on it, and Linux permits overmounting the
    // root this way; only the two checks below are universal:
    //   * cannot move the namespace ROOT mount itself (`!mnt_has_parent(old)`);
    //   * cannot move a mount INTO its own subtree (`for(p=dest;...) if p==old`).
    if root_mount_id(ns) == Some(from_id) { return Err(VfsError::Einval); }
    // [D11] A MNT_LOCKED mount cannot be moved (Linux `do_move_mount`:
    // `attached && (old->mnt.mnt_flags & MNT_LOCKED)` → -EINVAL): an
    // unprivileged userns must not relocate a mount its parent pinned.
    if from_m.is_locked() { return Err(VfsError::Einval); }
    // [D21] Don't move a mount residing in a SHARED parent (Linux
    // `do_move_mount`: `attached && IS_MNT_SHARED(parent)` → -EINVAL): the
    // detach from the old position would otherwise have to propagate to the
    // parent's peer group. The source here is always attached (the ns-root case
    // returned above), so this is the unconditional parent-shared rejection.
    if let Some(p) = mount_by_id(from_m.parent_id.load(Ordering::Acquire)) {
        if is_shared(&p) { return Err(VfsError::Einval); }
    }
    // [D21] Don't move a tree containing UNBINDABLE mounts onto a SHARED
    // destination (Linux `do_move_mount`: `IS_MNT_SHARED(dest) &&
    // tree_contains_unbindable(old)` → -EINVAL): the dest's peers would receive
    // a propagated copy of a mount declared unbindable.
    if !to_root {
        if let Some(dest) = mount_by_id(parent_by_dentry(ns, to)) {
            if is_shared(&dest) && tree_contains_unbindable(ns, from_id) {
                return Err(VfsError::Einval);
            }
        }
    }
    if !to_root {
        let mut anc = Some(parent_by_dentry(ns, to));
        while let Some(a) = anc {
            if a == from_id { return Err(VfsError::Einval); }
            let Some(am) = mount_by_id(a) else { break; };
            let p = am.parent_id.load(Ordering::Acquire);
            anc = if p == a { None } else { Some(p) };
        }
    }
    if !to_root && to.mounted_mount(ns).is_some() { return Err(VfsError::Ebusy); }
    let to_abs = if to_root { String::from("/") } else { abs_string(to) };
    let old_mp = from_m.mountpoint();
    let old_parent = from_m.parent_id.load(Ordering::Acquire);
    let snap: Vec<Arc<Mount>> = subtree_ids(ns, from_id).iter()
        .filter_map(|id| mount_by_id(*id)).collect();

    // --- 1) Re-seat the moved ROOT mount (the only attachment that changes). ---
    if let Some(d) = &old_mp {
        hash_remove(old_parent, dptr(d), from_id);
        d.set_mounted_mount(ns, None);
    }
    unlink_from_parent(&from_m);
    let new_root_d = if to_root { None } else { Some(to.clone()) };
    set_mountpoint_dentry(&from_m, new_root_d.clone(), to_abs.clone());
    match &new_root_d {
        None => {
            from_m.parent_id.store(from_id, Ordering::Release);
            *from_m.mnt_parent.lock() = Weak::new();
        }
        Some(d) => {
            let new_parent = parent_by_dentry(ns, d);
            from_m.parent_id.store(new_parent, Ordering::Release);
            if let Some(p) = mount_by_id(new_parent) {
                *from_m.mnt_parent.lock() = Arc::downgrade(&p);
                p.mnt_mounts.lock().push(from_m.clone());
            }
            wire_crossing(ns, d, from_id);
            hash_insert(new_parent, dptr(d), from_id);
        }
    }

    // --- 2) Descendants: relocate UNDERLAY children (mirrored beneath `to`);
    //        keep IN-FS children in place (dentry/crossing/parent untouched).
    //        Both get their rendered (display) path re-based onto `to`. ---
    let to_base = new_root_d.clone().or_else(global_root);
    for m in snap.iter() {
        if m.mnt_id == from_id { continue; }
        let Some(child_mp) = m.mountpoint() else { continue; };
        let disp_rel = rel_under(&child_mp, old_mp.as_ref()).unwrap_or_default();
        let new_rendered = if disp_rel.is_empty() { to_abs.clone() }
                           else { alloc::format!("{}{}", to_abs, disp_rel) };
        match old_mp.as_ref().and_then(|omp| plain_rel_under(&child_mp, omp)) {
            Some(rel) => {
                // UNDERLAY child: relocate its mountpoint dentry to the mirrored
                // underlay position beneath `to`, by an underlay descent (NOT
                // crossing the moved root) from `to`.
                let m_parent = m.parent_id.load(Ordering::Acquire);
                hash_remove(m_parent, dptr(&child_mp), m.mnt_id);
                child_mp.set_mounted_mount(ns, None);
                let new_d = to_base.as_ref().and_then(|b| descend(b, rel.trim_start_matches('/')));
                set_mountpoint_dentry(m, new_d.clone(), new_rendered);
                unlink_from_parent(m);
                if let Some(d) = &new_d {
                    let np = parent_by_dentry(ns, d);
                    m.parent_id.store(np, Ordering::Release);
                    if let Some(p) = mount_by_id(np) {
                        *m.mnt_parent.lock() = Arc::downgrade(&p);
                        p.mnt_mounts.lock().push(m.clone());
                    }
                    wire_crossing(ns, d, m.mnt_id);
                    hash_insert(np, dptr(d), m.mnt_id);
                }
            }
            None => {
                // IN-FS child: its mountpoint dentry is inside a moved fs and
                // travels unchanged — only the rendered path follows the move.
                *m.rendered_path.lock() = new_rendered;
            }
        }
    }
    mntns::bump_gen(ns);
    Ok(())
}

/// Update the per-mount option bits on the mount at dentry `d` from a mount(2)
/// MS_* REQUEST mask (mapped to MNT_* via [`ms_to_mnt`], D10). Setting RDONLY
/// while writers are active fails with EBUSY (Linux `mnt_hold_writers`).
/// # C: O(log N)
pub fn remount_flags(d: &Arc<Dentry>, flags: u64) -> KResult<()> {
    let m = mount_exact_at(current_ns(), d).ok_or(VfsError::Einval)?;
    apply_remount(&m, flags)
}

/// As [`remount_flags`] but identifies the mount by the `mnt_id` the path walk
/// CROSSED INTO (Linux `do_reconfigure_mnt` keys on `path->mnt`, not a
/// re-derived dentry). The MS_REMOUNT walk follows the mount at its final
/// component, so the resolved dentry is the mounted-fs ROOT — which
/// `mount_exact_at` cannot map back to a mount (a root is not a mountpoint) and
/// a pseudo-fs `s_root` is SHARED across instances. The crossed-into `mnt_id`
/// is unambiguous: systemd's `ProtectKernelTunables=` RO-remount of the sandbox
/// `/proc/sys` bind then succeeds instead of EINVAL (step NAMESPACE status=226
/// once the procfs replication exposed the remount). # C: O(log N)
pub fn remount_flags_by_id(mnt_id: u64, flags: u64) -> KResult<()> {
    let m = mount_by_id(mnt_id).ok_or(VfsError::Einval)?;
    // [D32] Uniform cross-ns guard via `check_mnt` (the ns-AGNOSTIC `mount_by_id`
    // arena lookup must be gated before mutating a by-id handle).
    if !check_mnt(&m) { return Err(VfsError::Einval); }
    apply_remount(&m, flags)
}

/// Shared option update for both [`remount_flags`] variants. `flags` is the
/// mount(2) MS_* REQUEST mask; it is mapped to the per-mount MNT_* space
/// ([`ms_to_mnt`]) before being committed (D10). # C: O(1)
fn apply_remount(m: &Arc<Mount>, flags: u64) -> KResult<()> {
    let old = m.flags.load(Ordering::Acquire);
    let new = (old & !MNT_OPTION_MASK) | (ms_to_mnt(flags) & MNT_OPTION_MASK);
    if (new & MNT_RDONLY) != 0 && (old & MNT_RDONLY) == 0 && m.mnt_writers.load(Ordering::Acquire) > 0 {
        return Err(VfsError::Ebusy);
    }
    m.flags.store(new, Ordering::Release);
    mntns::bump_gen(m.ns);
    Ok(())
}

/// `mnt_want_write` (Linux): begin a write on `m`, EROFS if read-only, else
/// bump the writer count (blocks a concurrent remount-RO). # C: O(1)
pub fn mnt_want_write(m: &Mount) -> KResult<()> {
    if (m.flags.load(Ordering::Acquire) & MNT_RDONLY) != 0 { return Err(VfsError::Erofs); }
    m.mnt_writers.fetch_add(1, Ordering::AcqRel);
    Ok(())
}

/// `mnt_drop_write` (Linux): end a write begun by `mnt_want_write`. # C: O(1)
pub fn mnt_drop_write(m: &Mount) { m.mnt_writers.fetch_sub(1, Ordering::AcqRel); }

/// `check_mnt` (Linux `fs/namespace.c`): true iff mount `m` belongs to the
/// CALLER's mount namespace. The uniform guard that keeps a by-id / by-fd /
/// resolved mount handle from operating across a namespace boundary — every
/// mount-tree op handed a mount the caller did not freshly resolve in its own
/// ns must gate on it before acting. # C: O(1)
pub fn check_mnt(m: &Mount) -> bool { m.ns == current_ns() }

/// The mount that OWNS `path`, by dentry-identity crossing (Linux
/// `path_lookup`), NOT a longest-`mount_point` string scan. A walk that lands
/// on a mount in ANOTHER namespace is rejected (Linux `check_mnt`): the caller
/// sees only its own ns's tree, so the result falls back to the caller's root
/// mount, never the foreign mount. # C: O(components)
pub fn resolve_mount(path: &str) -> Option<(Arc<Mount>, String)> {
    let ns = current_ns();
    // [D22] A failed walk (path does not resolve — e.g. before any root mount
    // exists) returns `None` (→ ENOENT), NOT a silent substitution of the ns
    // root. `walk_to_mount` already returns the deepest OWNING mount for a
    // not-yet-existing leaf, so a normal path still resolves; only a truly
    // unresolvable walk yields `None`.
    let id = crate::namei::walk_to_mount(path)?;
    let m = mount_by_id(id)?;
    // Cross-ns guard kept: a walk that lands on a FOREIGN-ns mount falls back to
    // the caller's own root mount (never leaks the foreign mount).
    if !check_mnt(&m) { return root_mount_id(ns).and_then(mount_by_id).map(|r| (r, path.to_string())); }
    Some((m, path.to_string()))
}

/// True when the mount that owns `path` is remounted read-only. # C: O(components)
pub fn is_readonly_path(path: &str) -> bool {
    resolve_mount(path)
        .map(|(m, _)| (m.flags.load(Ordering::Acquire) & MNT_RDONLY) != 0)
        .unwrap_or(false)
}

/// Whole-path → inode resolver (convenience for path-string callers). # C: O(components)
pub fn lookup(path: &str) -> KResult<InodeRef> {
    crate::namei::resolve_abs(path)
}

/// Root inode of the mount rooted EXACTLY at mountpoint dentry `d`. # C: O(log N)
pub fn mount_root_at(d: &Arc<Dentry>) -> Option<InodeRef> {
    if is_global_root(d) { return None; }
    let m = mount_at_path_exact(d)?;
    // [D5] `mnt_root` (the mounted-fs root DENTRY) is the single source of
    // truth: its inode IS the bind-root inode (`for_backend`→`d_make_root`
    // stamps it as `s_root->d_inode`), so derive instead of reading the legacy
    // `root` inode copy. `fs().root()` covers an `s_root`-less SB.
    m.mnt_root().and_then(|r| r.inode()).or_else(|| m.fs().root())
}

/// Root inode of a concrete mount id (the path walk's crossing primitive).
/// # C: O(log N)
pub fn root_for_mount_id(mnt_id: u64) -> Option<InodeRef> {
    let m = mount_by_id(mnt_id)?;
    // [D5] derive from `mnt_root` (see `mount_root_at`).
    m.mnt_root().and_then(|r| r.inode()).or_else(|| m.fs().root())
}

/// The mounted fs's ROOT DENTRY for `mnt_id` (Linux `mnt->mnt_root`). The
/// namei keystone primitive. # C: O(log N)
pub fn root_dentry_for_mount_id(mnt_id: u64) -> Option<Arc<Dentry>> {
    let m = mount_by_id(mnt_id)?;
    if let Some(r) = m.mnt_root.lock().clone() { return Some(r); }
    m.sb().s_root()
}

/// The mountpoint dentry `mnt_id` is attached on, plus its parent mount id
/// (Linux `mnt->mnt_mountpoint` + `mnt->mnt_parent`). The `..`-across-a-mount
/// primitive. `None` for a namespace root mount. # C: O(log N)
pub fn mountpoint_of(mnt_id: u64) -> Option<(Arc<Dentry>, u64)> {
    let m = mount_by_id(mnt_id)?;
    Some((m.mountpoint()?, m.parent_id.load(Ordering::Acquire)))
}

/// The mountpoint dentry of the mount whose `s_root` is the dentry at raw
/// pointer `d` (Linux `prepend_path` mount bridge). # C: O(N_mounts)
pub fn mountpoint_for_root_ptr(d: *const Dentry) -> Option<Arc<Dentry>> {
    let ns = current_ns();
    let t = MOUNTS.lock();
    let mut found: Option<Arc<Mount>> = None;
    for m in t.values() {
        if m.sb.s_root().map(|r| Arc::as_ptr(&r) == d).unwrap_or(false) {
            if m.ns == ns { found = Some(m.clone()); break; }
            if found.is_none() { found = Some(m.clone()); }
        }
    }
    drop(t);
    found.and_then(|m| m.mountpoint())
}

/// Snapshot the caller's mount-namespace view (for /proc mounts + mountinfo).
/// # C: O(N_mounts)
pub fn snapshot() -> Vec<Arc<Mount>> {
    mounts_in_ns(current_ns())
}

/// Snapshot ALL mounts regardless of namespace (kernel-internal audits).
/// # C: O(N_mounts)
pub fn snapshot_all() -> Vec<Arc<Mount>> { all_mounts() }
