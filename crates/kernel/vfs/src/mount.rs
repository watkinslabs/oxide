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
use sync::{MountTable as MountClass, MountWrite as MountWriteClass, Spinlock};

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
    MNT_ATIME_MASK, MOUNT_ATTR_IDMAP, MOUNT_ATTR_NOATIME, MOUNT_ATTR_RDONLY, MOUNT_ATTR_SETTABLE,
    MOUNT_ATTR_STRICTATIME, MOUNT_ATTR__ATIME, mount_attr_to_mnt,
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

/// TEMP (D24, `debug-mnt`): emit ONE grep-able `[MNTCREATE]` line at a mount
/// create/attach/clone/graft site, via the same raw klog sink the `[MNTDIVERGE]`
/// probe uses. Lets the boot log reconstruct the exact sequence + via-tag that
/// builds the sandbox-root mounts (mnt_id 10/11) and whether the api-mounts
/// (/proc,/sys,/dev,/run) are re-created beneath them. Prod-inert (feature-off ⇒
/// no call sites). # C: O(name len)
#[cfg(feature = "debug-mnt")]
fn mntcreate_log(via: &str, new_id: u64, parent: u64, mp: Option<&Arc<Dentry>>,
                 root: Option<&Arc<Dentry>>, sb: Option<&Arc<SuperBlock>>) {
    klog::write_raw(b"[MNTCREATE] via=");
    klog::write_raw(via.as_bytes());
    klog::write_raw(b" new_id="); klog::write_dec_u64(new_id);
    klog::write_raw(b" parent="); klog::write_dec_u64(parent);
    klog::write_raw(b" mp_dentry=ptr:0x");
    klog::write_hex_u64(mp.map(|d| dptr(d) as u64).unwrap_or(0));
    klog::write_raw(b" name:");
    klog::write_raw(mp.map(|d| d.name()).unwrap_or("<none>").as_bytes());
    klog::write_raw(b" root_dentry=ptr:0x");
    klog::write_hex_u64(root.map(|d| dptr(d) as u64).unwrap_or(0));
    klog::write_raw(b" sb=ptr:0x");
    klog::write_hex_u64(sb.map(|s| Arc::as_ptr(s) as *const () as u64).unwrap_or(0));
    klog::write_raw(b"\n");
}

/// [D24] True iff `d` is THE namespace-root dentry by IDENTITY — the single
/// `s_root` of the current ns-root mount. A purely STRUCTURAL test (parentless +
/// empty name) matches EVERY superblock root dentry (procfs/sysfs singleton roots
/// included), so a fresh-fs `mount(proc,/proc)` over an existing proc mount —
/// whose target resolves to the procfs `s_root` (parentless, empty-name) — would
/// be wrongly treated as the ns root and HIJACK it. Compare against
/// [`global_root`] by pointer identity instead; fall back to the structural test
/// ONLY when no global root is set yet (the very first rootfs mount, where
/// `global_root() == None`). This is the single ns-root predicate — used both by
/// the self-root attach filter and the reader short-circuits. # C: O(1)
fn is_ns_root_dentry(d: &Arc<Dentry>) -> bool {
    match global_root() {
        Some(r) => dptr(&r) == dptr(d),
        None => d.parent().is_none() && d.name().is_empty(),
    }
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
/// that is the current TOP at its own mountpoint (`top_mount_on(mp) == self`),
/// else (c) the first candidate. Keeps `parent_by_dentry` agreeing with the
/// walk's crossing chain so `__lookup_mnt(cur_mnt, child)` resolves the child
/// mount even under shadowed singleton-fs duplicates. # C: O(N_mounts)
fn visible_mnt_id_of_root_dentry(ns: u64, d: &Arc<Dentry>) -> Option<u64> {
    let dp = dptr(d);
    let cands: Vec<Arc<Mount>> = MOUNTS.lock().values()
        .filter(|m| m.ns == ns && m.sb.s_root().map(|r| dptr(&r) == dp).unwrap_or(false))
        .cloned().collect();
    if cands.is_empty() { return None; }
    // (a) ns root mount ⇒ the canonical ns-root id. [D25] identity by the
    // self-parent `is_root()` predicate, not the `mountpoint == None` data state.
    if cands.iter().any(|m| m.is_root()) { return root_mount_id(ns); }
    // (b) the duplicate currently visible (top of its own mountpoint crossing).
    for m in cands.iter() {
        if let Some(mp) = m.mountpoint() {
            if top_mount_on(ns, &mp) == Some(m.mnt_id) { return Some(m.mnt_id); }
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

/// MOUNT-AWARE rendered path for a mount attached at dentry `d` under `parent_id`
/// (true Linux `d_path`, which walks the MOUNT tree — mnt_parent chain — not the
/// global dentry chain). Bind mounts SHARE the source dentry, so `abs_string(d)`
/// (a pure d_parent walk) yields the SOURCE's path and drops the bind prefix — a
/// self-bind of `/run/systemd/mount-rootfs/proc/sys/kernel/domainname` rendered as
/// the real `/proc/sys/kernel/domainname`, so systemd never saw the prefix become
/// a mount and its `bind_remount_recursive` convergence loop spun to its 32-try
/// EBUSY cap (status 226). Reconstruct as `parent.rendered_path` + `d`'s suffix
/// past the parent mount's root dentry. Parents are created before children
/// (Linux `attach_recursive_mnt` top-down), so the recursion bottoms out at a
/// mount on a NON-shared dentry where `abs_string` is already correct. Falls back
/// to `abs_string(d)` at the ns root or when the suffix cannot be taken. For a
/// non-shared dentry the result equals `abs_string(d)` (the two chains agree), so
/// this is a strict refinement. # C: O(depth)
fn rendered_path_for(parent_id: u64, d: &Arc<Dentry>) -> String {
    let d_ap = d.absolute_path();
    if let Some(p) = mount_by_id(parent_id) {
        if let Some(proot) = root_dentry_for_mount_id(parent_id) {
            let root_ap = proot.absolute_path();
            if d_ap.starts_with(root_ap.as_slice()) {
                // `/` root dentry renders as "/" (len 1); stripping it would eat the
                // leading slash, so treat the fs root as a zero-length prefix.
                let strip = if root_ap.as_slice() == b"/" { 0 } else { root_ap.len() };
                let rel = core::str::from_utf8(&d_ap[strip..]).unwrap_or("");
                let prp = p.mount_point_str();
                return if prp == "/" {
                    if rel.is_empty() { String::from("/") } else { String::from(rel) }
                } else {
                    let mut s = prp;
                    s.push_str(rel);      // rel starts with '/' (or is empty ⇒ stacked at prp)
                    s
                };
            }
        }
    }
    String::from_utf8(d_ap).unwrap_or_else(|_| String::from("/"))
}

/// Materialise the dentry at `rel` beneath `base` by a dentry→dentry descent
/// that CROSSES MOUNTS at each component exactly as namei does — the
/// engine-internal resolver for SYNTHESIZED mount positions (propagation
/// mirrors, MS_MOVE / pivot_root relocations). NEVER a global path-string
/// resolve. `rel` empty ⇒ `base` itself. # C: O(components)
pub(super) fn descend(base: &Arc<Dentry>, rel: &str) -> Option<Arc<Dentry>> {
    let ns = current_ns();
    let mut cur = base.clone();
    // [D24] Track the mount the descent is currently "in" so crossings resolve via
    // the strict `(parent_mnt_id, dentry)` hash (Linux `__lookup_mnt`) instead of
    // the deleted parent-agnostic `dentry.mounted_mounts` map. Seeded from the
    // mount containing `base`.
    let mut cur_mnt = containing_mount_id(ns, base);
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
        while let Some(m) = __lookup_mnt(cur_mnt, &child) {
            match m.mnt_root() { Some(sr) => { child = sr; cur_mnt = m.mnt_id; } None => break }
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

/// [D28a] Mount-tree WRITER serialization lock (Linux `mount_lock`/`namespace_sem`
/// write side — the coarse mutator gate). Every mount-tree MUTATOR takes this
/// OUTERMOST around its multi-structure mutation so two concurrent writers cannot
/// interleave the separate `MOUNTS` / `MOUNT_HASH` / `MOUNTPOINTS` / `NAMESPACES`
/// critical sections and leave them mutually inconsistent (the confirmed torn
/// window: graft inserts `MOUNTS` then `MOUNT_HASH` in SEPARATE sections; detach
/// removes them symmetrically). LOCK ORDERING (`MountWrite` rank 58, `06§3.6`):
/// STRICT OUTERMOST of the mount locks — acquired BEFORE any `MountClass`/`MountTable`
/// (70) structure lock and BEFORE `Superblock` (60, via `grab_active`), and NEVER
/// while one of those is held. It is NEVER held across a SLEEPING call — the
/// crossing-resolver `descend`/`descend_nocross`/`descend_mountpoint` (which call
/// `inode.lookup`) and `put_super_if_last` (`deactivate_super`) run OUTSIDE the
/// region — so each mutator scopes the lock to exactly its non-sleeping structural
/// mutation. READERS do NOT take it (the D28b reader-seqlock is out of scope; a
/// lock-free mount reader does not exist — readers still take `MOUNT_HASH.lock`).
/// Non-recursive (plain `Spinlock`): a mutator under `MOUNT_WRITE` must never call
/// another that takes it — `rebuild_ns_index` therefore does NOT self-lock; its
/// callers (`copy_mnt_ns`, `commit_retree`) hold `MOUNT_WRITE` around it instead.
static MOUNT_WRITE: Spinlock<(), MountWriteClass> = Spinlock::new(());

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
/// `(parent, dentry)` hash. [D24] THE crossing primitive the path walk
/// (`follow_mount_down`) and the engine-internal `descend` now read — the legacy
/// parent-agnostic `dentry.mounted_mounts` map it replaced is deleted. # C: O(log N)
pub fn __lookup_mnt(parent_mnt_id: u64, d: &Arc<Dentry>) -> Option<Arc<Mount>> {
    hash_top(parent_mnt_id, dptr(d)).and_then(mount_by_id)
}

/// [D24] The (top) mount in `ns` whose MOUNTPOINT dentry is `d`, PARENT-AGNOSTIC
/// — the strict-hash replacement for the deleted per-ns `dentry.mounted_mounts`
/// map. A mountpoint dentry's identity plus its containing filesystem fix its
/// parent mount, so every mount stacked here shares ONE `(parent, dptr)` hash
/// key; find that parent from any candidate, then return the hash TOP (last
/// attached = the overmount visible there). `None` ⇒ nothing mounted on `d` in
/// `ns`. Used where a caller has only the mountpoint dentry (not the containing
/// mount id) — e.g. `parent_by_dentry`'s ancestor walk, the busy/exact tests.
/// # C: O(N_mounts)
fn top_mount_on(ns: u64, d: &Arc<Dentry>) -> Option<u64> {
    let dp = dptr(d);
    // The visible top mount AT `d` is the LAST-attached one whose mountpoint
    // dentry is `d` (mnt_id is monotonic = attach/stack order), read DIRECTLY
    // from the arena. This is the exact value the legacy last-write-wins map
    // held. NOTE: do NOT indirect through `hash_top(parent_of_max, d)` — a
    // hash-only D24 clone can leave a mount in the `(parent,dptr)` bucket whose
    // mountpoint is no longer `d`, so the parent-indirection reports a mount as
    // covering `d` when none does (false Ebusy on move, missed shared/unbindable
    // parent checks). The direct arena scan cannot drift from the tree.
    MOUNTS.lock().values()
        .filter(|m| m.ns == ns && m.mountpoint().map(|mp| dptr(&mp) == dp).unwrap_or(false))
        .map(|m| m.mnt_id)
        .max()
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
        if let Some(id) = top_mount_on(ns, &a) { return id; }
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

/// MOUNT-AWARE relative path of `mp` beneath `stop` (exclusive), starting in the
/// KNOWN mount `start_mnt`. Unlike [`rel_under`] (which re-derives the crossed
/// mount from the dentry alone via [`mount_with_root_dentry`] — AMBIGUOUS when an
/// SB-sharing clone shares one `s_root`, Stage 1), this carries the mount context
/// up the tree via the EXPLICIT `mnt_parent`/`mnt_mountpoint` links (Linux
/// `follow_up`): a plain dentry parent step stays in the same mount; at a mount
/// ROOT it crosses up to that mount's mountpoint dentry in its PARENT. `None` ⇒
/// `mp` is not under `stop` (when `stop` is `Some`). # C: O(depth)
fn rel_under_seeded(mp: &Arc<Dentry>, start_mnt: u64, stop: Option<&Arc<Dentry>>) -> Option<String> {
    let mut names: Vec<String> = Vec::new();
    let mut cur = mp.clone();
    let mut cur_mnt = start_mnt;
    loop {
        if let Some(s) = stop { if Arc::ptr_eq(&cur, s) { return Some(join_names(&names)); } }
        match cur.parent() {
            Some(p) => {
                // Plain parent within the current mount's filesystem.
                if !cur.name().is_empty() { names.push(cur.name().to_string()); }
                cur = p.clone();
            }
            None => {
                // At a filesystem ROOT: cross UP via the explicit mount links.
                let Some(m) = mount_by_id(cur_mnt) else {
                    return if stop.is_none() { Some(join_names(&names)) } else { None };
                };
                let parent = m.parent_id.load(Ordering::Acquire);
                match m.mountpoint() {
                    // ns-root mount (self-parent / no mountpoint): walk ends here.
                    _ if parent == cur_mnt => {
                        return if stop.is_none() { Some(join_names(&names)) } else { None };
                    }
                    Some(mp_d) => { cur = mp_d; cur_mnt = parent; }
                    None => {
                        return if stop.is_none() { Some(join_names(&names)) } else { None };
                    }
                }
            }
        }
    }
}

/// The mount in `subtree` whose `mnt_root` is the filesystem ROOT containing
/// dentry `d` (reached by PLAIN parent links) — the mount-aware seed for an
/// [`rel_under_seeded`] walk from a bare dentry whose containing mount a
/// dentry-ptr scan cannot pin down (a shared `s_root`). `pivot_root` uses it to
/// seed `put_old`, which must live inside the new-root subtree. # C: O(depth+N)
fn mount_owning_dentry_in(d: &Arc<Dentry>, subtree: &[u64]) -> Option<u64> {
    let mut r = d.clone();
    while let Some(p) = r.parent() { r = p.clone(); }
    let rp = dptr(&r);
    subtree.iter().copied()
        .filter_map(mount_by_id)
        .find(|m| m.mnt_root().map(|mr| dptr(&mr) == rp).unwrap_or(false))
        .map(|m| m.mnt_id)
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
        if let Some(o) = m.mnt_mp.lock().take() { put_mountpoint(&o); }
        m.mnt_mounts.lock().clear();
        *m.mnt_parent.lock() = Weak::new();
    }
    // RE-ACQUIRE the `struct mountpoint` hold so the `D_MOUNTED` refcount tracks
    // this ns's crossings (Linux `get_mountpoint` per attached child after a tree
    // rebuild). The crossing IDENTITY itself lives in the `(parent,dentry)` hash
    // re-inserted below — there is no longer a per-ns `mounted_mounts` map to wire.
    for m in mounts.iter() {
        if let Some(d) = m.mountpoint() {
            *m.mnt_mp.lock() = Some(get_mountpoint(&d));
        }
    }
    // Parent + child links + hash from the wired crossings. The recorded
    // `parent_id` (the explicit Linux `mnt_parent`) is left intact by the clear
    // loop above, so the parent-aware derivation below can consult it.
    for m in mounts.iter() {
        match m.mountpoint() {
            None => { m.parent_id.store(m.mnt_id, Ordering::Release); }
            Some(d) => {
                let recorded = m.parent_id.load(Ordering::Acquire);
                let derived = parent_by_dentry(ns, &d);
                // [Stage 0] PARENT-AWARE: a dentry-ptr scan cannot tell two
                // mounts that SHARE one `s_root` (an SB-sharing clone, Stage 1)
                // apart, so when `parent_by_dentry` lands on a mount sharing the
                // recorded explicit parent's superblock root, trust the recorded
                // `mnt_parent` (Linux never re-derives it). When they do NOT share
                // an `s_root`, the parent genuinely moved (a pivot relocation) and
                // the freshly derived one wins.
                let parent = if recorded != 0 && recorded != m.mnt_id
                    && same_sb_root(recorded, derived) { recorded } else { derived };
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

/// True iff mounts `a` and `b` resolve to the SAME superblock root dentry (or are
/// the same mount) — the signature of an SB-sharing clone pair that a bare
/// dentry-ptr scan cannot disambiguate. # C: O(log N)
fn same_sb_root(a: u64, b: u64) -> bool {
    if a == b { return true; }
    match (mount_by_id(a), mount_by_id(b)) {
        (Some(ma), Some(mb)) => match (ma.sb.s_root(), mb.sb.s_root()) {
            (Some(ra), Some(rb)) => dptr(&ra) == dptr(&rb),
            _ => false,
        },
        _ => false,
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

    /// True iff this is its namespace's root mount, by the Linux SELF-PARENT
    /// identity test (`mnt_parent == self`, i.e. `!mnt_has_parent`). [D25] The
    /// single root predicate — collapses the three former encodings (the
    /// `MntNamespace.root` by-id index, `mountpoint == None`, and self-parent)
    /// to one O(1) atomic read that needs no cross-structure `NAMESPACES`
    /// lookup. The encodings are all set together at every graft / re-seat (root
    /// branch of [`graft_realized`], the `None` arm of [`rebuild_ns_index`],
    /// [`move_mount_m`]'s detach-to-root), so they agree; `mountpoint == None`
    /// stays the natural DATA state of a root, just not the identity test.
    /// # C: O(1)
    pub fn is_root(&self) -> bool {
        self.parent_id.load(Ordering::Acquire) == self.mnt_id
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
    if is_ns_root_dentry(d) { return root_mount_id(ns).and_then(mount_by_id); }
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
    if is_ns_root_dentry(d) { return root_mount_id(ns).unwrap_or(MNT_ID_NONE); }
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
    if is_ns_root_dentry(d) { return root_mount_id(ns).and_then(mount_by_id); }
    let id = top_mount_on(ns, d)?;
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
    #[cfg(feature = "debug-mnt")]
    mntcreate_log("new_mount", mnt_id, parent_id, mountpoint.as_ref(), mnt_root.as_ref(), Some(&sb));
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
    let mp = mp.filter(|d| !is_ns_root_dentry(d));
    let root_inode = root.clone().or_else(|| fs.root());
    // `s_id` (the SB label) mirrors Linux's device/source id; the legacy mount
    // engine used the rendered mountpoint path here, which is not consumed
    // anywhere — keep it for an exact byte match with the prior behaviour.
    let s_id = match &mp { Some(d) => abs_string(d), None => String::from("/") };
    let sb = build_sb(fs, root_inode, s_id);
    #[cfg(feature = "debug-mnt")]
    mntcreate_log("attach", 0, 0, mp.as_ref(), sb.s_root().as_ref(), Some(&sb));
    graft_realized(mp, sb, 0)
}

/// Graft an ALREADY-REALIZED `SuperBlock` (built by the new mount API's
/// `vfs_get_tree`/`get_tree`, which already ran `fill_super` + `d_make_root`)
/// onto mountpoint `mp` — the `move_mount` mode-(a) attach for a `fsmount`
/// object. The SB carries its own `s_root` dentry, from which the engine derives
/// the mount root inode (`mnt_root`), so the resulting mount-table state matches
/// the equivalent `register`/`register_bind` graft byte-for-byte (both resolve
/// the SAME root inode + root dentry). # C: O(depth)
pub fn attach_sb(mp: Option<Arc<Dentry>>, sb: Arc<SuperBlock>) -> KResult<()> {
    #[cfg(feature = "debug-mnt")]
    mntcreate_log("attach_sb", 0, 0, mp.as_ref(), sb.s_root().as_ref(), Some(&sb));
    graft_realized(mp, sb, 0)
}

/// [D51] As [`attach_sb`] but stamps the per-mount MNT_* option bits (mapped
/// from a `fsmount(2)` MOUNT_ATTR_* request by [`mount_attr_to_mnt`]) onto the
/// new mount BEFORE it enters `MOUNTS` — so a subsequent `propagate_mount`
/// peer-copy inherits them ([`clone_mnt`] copies `src.flags`). Only
/// `MNT_OPTION_MASK` bits are honoured; internal-flag bits are ignored.
/// # C: O(depth)
pub fn attach_sb_with_flags(mp: Option<Arc<Dentry>>, sb: Arc<SuperBlock>, mnt_flags: u64)
    -> KResult<()> {
    #[cfg(feature = "debug-mnt")]
    mntcreate_log("attach_sb_with_flags", 0, 0, mp.as_ref(), sb.s_root().as_ref(), Some(&sb));
    graft_realized(mp, sb, mnt_flags & MNT_OPTION_MASK)
}

/// Shared TAIL of [`attach`]/[`attach_sb`]: reserve the per-ns mount slot,
/// build the `Mount` over the realized `sb`, wire the intrusive parent/child +
/// crossing-hash links, and commit. The mount root inode is derived from
/// `sb.s_root()` (Linux `mnt_root`), not a stored copy. `mp == None` ⇒ the
/// namespace root mount. # C: O(depth)
fn graft_realized(mp: Option<Arc<Dentry>>, sb: Arc<SuperBlock>, mnt_flags: u64)
    -> KResult<()> {
    let ns = current_ns();
    let mnt_flags = mnt_flags & MNT_OPTION_MASK;
    // Per-ns mount cap (Linux `count_mounts` in `attach_recursive_mnt`): RESERVE
    // one slot in `pending_mounts` BEFORE building any mount state; over
    // `sysctl_mount_max` ⇒ ENOSPC. The reservation is rolled live by
    // `commit_mounts` once the mount is in `MOUNTS`; there is no fallible step
    // after this point, so no `abort_mounts` unwind path is reachable.
    mntns::count_mounts(ns, 1)?;
    let mnt_id = NEXT_MNT_ID.fetch_add(1, Ordering::Relaxed);
    let mp = mp.filter(|d| !is_ns_root_dentry(d));
    let Some(d) = mp else {
        let m = new_mount(sb, String::from("/"), None, mnt_id, mnt_id, ns);
        // [D51] Stamp the requested option bits before the mount goes live.
        if mnt_flags != 0 { m.flags.store(mnt_flags, Ordering::Release); }
        // [D11] The namespace ROOT mount is a kernel-internal producer (Linux
        // marks rootfs / kern_mount mounts MNT_INTERNAL): never user-expirable.
        m.set_internal_flag(MNT_INTERNAL);
        #[cfg(feature = "debug-mnt")]
        mntcreate_log("graft", mnt_id, mnt_id, None, m.mnt_root().as_ref(), Some(&m.sb));
        // [D28a] serialize the NAMESPACES-root + MOUNTS insert as one write.
        {
            let _w = MOUNT_WRITE.lock();
            mntns::ns_set_root(ns, mnt_id);
            MOUNTS.lock().insert(mnt_id, m);
        }
        mntns::commit_mounts(ns, 1);
        mntns::bump_gen(ns);
        return Ok(());
    };
    let parent_id = parent_by_dentry(ns, &d);
    let rendered = rendered_path_for(parent_id, &d);
    let m = new_mount(sb, rendered, Some(d.clone()), parent_id, mnt_id, ns);
    // [D51] Stamp the requested option bits before the mount goes live, so a
    // following propagate_mount peer-copy inherits them via clone_mnt.
    if mnt_flags != 0 { m.flags.store(mnt_flags, Ordering::Release); }
    #[cfg(feature = "debug-mnt")]
    mntcreate_log("graft", mnt_id, parent_id, Some(&d), m.mnt_root().as_ref(), Some(&m.sb));
    // struct mountpoint (dentry refcount) + intrusive parent/child links.
    // [D28a] one writer-serialized region: MOUNTPOINTS + parent/child links +
    // MOUNTS + MOUNT_HASH mutated atomically w.r.t. other writers.
    {
        let _w = MOUNT_WRITE.lock();
        *m.mnt_mp.lock() = Some(get_mountpoint(&d));
        if let Some(p) = mount_by_id(parent_id) {
            *m.mnt_parent.lock() = Arc::downgrade(&p);
            p.mnt_mounts.lock().push(m.clone());
        }
        MOUNTS.lock().insert(mnt_id, m);
        hash_insert(parent_id, dptr(&d), mnt_id);
    }
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
    #[cfg(feature = "debug-mnt")]
    mntcreate_log("register_bind", 0, 0, mp.as_ref(), None, None);
    attach(mp, fs, Some(root))
}

/// Bind attach with an EXPLICIT parent mount id + rendered path — Linux
/// `do_add_mount` keys the target on the caller's `struct path` (`vfsmount` +
/// `dentry`), NOT the dentry alone. Required when the mountpoint dentry `mp_d` is
/// SHARED across bind locations: e.g. systemd's `bind_remount_recursive` does a
/// self-bind of a procfs leaf inside `/run/systemd/mount-rootfs/...`, but that
/// leaf's dentry is the SAME Arc as the real `/proc/...` leaf, so
/// `parent_by_dentry` (a d_parent walk) picks the REAL /proc as parent and hashes
/// the bind under it — invisible at the staging prefix. systemd then never sees
/// the prefix become a mount and its remount loop spins to the 32-try EBUSY cap
/// (status 226). Passing the RESOLVED target mount (`resolve_path(target).mnt_id`)
/// as the parent puts the bind at the right `(parent_id, dentry)` hash slot and
/// renders the correct path. # C: O(1)
pub fn register_bind_under(parent_id: u64, mp_d: Arc<Dentry>, rendered: String,
    fs: Arc<dyn FileSystem>, root: InodeRef) -> KResult<()> {
    let ns = current_ns();
    mntns::count_mounts(ns, 1)?;
    let sb = build_sb(fs, Some(root), rendered.clone());
    let mnt_id = NEXT_MNT_ID.fetch_add(1, Ordering::Relaxed);
    let m = new_mount(sb, rendered, Some(mp_d.clone()), parent_id, mnt_id, ns);
    {
        let _w = MOUNT_WRITE.lock();
        *m.mnt_mp.lock() = Some(get_mountpoint(&mp_d));
        if let Some(p) = mount_by_id(parent_id) {
            *m.mnt_parent.lock() = Arc::downgrade(&p);
            p.mnt_mounts.lock().push(m.clone());
        }
        MOUNTS.lock().insert(mnt_id, m);
        hash_insert(parent_id, dptr(&mp_d), mnt_id);
    }
    mntns::commit_mounts(ns, 1);
    mntns::bump_gen(ns);
    Ok(())
}

// ---------------------------------------------------------------------------
// copy_tree / clone_mnt / commit_tree — Linux `fs/namespace.c` subtree clone
// (`copy_tree`/`clone_mnt`/`commit_tree`), the structural primitive shared by
// mount propagation (`propagate_mnt`) and the MS_REC recursive bind. A clone
// SHARES the source superblock (one extra `s_active`), copies its option flags
// + MNT_LOCKED, and carries the requested propagation (CL_MAKE_SHARED / CL_SLAVE
// / private). POSITION: a TOP-LEVEL node's slot lives under a DISTINCT
// destination fs, resolved by the crossing-aware resolver (`rel_under` for
// capture, `descend` for placement). A NESTED submount instead lands inside its
// parent clone's fs — and since the clone SHARES the source `s_root` (Stage 1),
// the source submount's mountpoint dentry IS that slot: [D31] `commit_tree`
// adopts it directly (`CloneNode::mp`, Linux `copy_tree`'s `q->mnt_mountpoint =
// dget(p->mnt_mountpoint)`), keeping the no-cross descent only as a fallback.
// `rel_under_seeded` is the same resolver MS_MOVE/pivot_root retain for
// OUT-OF-SUBTREE relocation.
// ---------------------------------------------------------------------------

/// Propagation type stamped on a [`clone_mnt`] copy (Linux `CL_*` clone flags).
#[derive(Clone, Copy)]
pub(super) enum CloneType { MakeShared, Slave, Private }

/// A node of a [`copy_tree`] result: the cloned mount plus its mountpoint
/// position RELATIVE to the copy's base mountpoint (so [`commit_tree`] can
/// `descend` it under any destination base). # C: field
///
/// `mp` (D31): the SOURCE submount's mountpoint DENTRY. Because a `clone_mnt`
/// copy SHARES the source SB and its `s_root` (Stage 1), a NESTED submount's
/// source mountpoint dentry is a live dentry under its parent clone's `mnt_root`
/// — so [`commit_tree`] adopts it DIRECTLY (Linux `copy_tree`'s `q->mnt_mountpoint
/// = dget(p->mnt_mountpoint)` same-dentry placement) instead of re-deriving the
/// slot by a no-cross path descent (which only CONVERGES with it and can fail to
/// re-mint). `None` for a TOP-LEVEL node (its slot lives under a DISTINCT
/// destination fs reached by `descend`, not the source dentry) and degenerate
/// root-only clones.
///
/// `pub` (D24 Stage 1a): an `open_tree(OPEN_TREE_CLONE)` detaches such a node
/// list into its mount-object fd (`MountObjectInode::detached_tree`), and
/// `move_mount` later commits it ([`commit_tree_hashonly`]) or fd-close releases
/// it ([`release_clone_tree`]).
pub struct CloneNode { pub m: Arc<Mount>, pub rel: String, pub mp: Option<Arc<Dentry>> }

/// Linux `clone_mnt`: build a NEW mount over `src`'s backend, copy its option
/// flags + MNT_LOCKED, and stamp the requested propagation. UNLINKED — no
/// mountpoint, parent, hash or `MOUNTS` entry yet (`commit_tree` wires those).
/// MakeShared joins peer group `pg`; Slave chains onto `master`'s slave list;
/// Private stands alone.
///
/// SB handling is Linux's literal `clone_mnt` share (`atomic_inc(&sb->s_active)`):
/// the clone SHARES the source `SuperBlock` — and therefore its `s_root` DENTRY —
/// taking ONE extra active ref ([`SuperBlock::grab_active`]); [`release_clone`] /
/// `put_super_if_last` drop it. `new_mount` derives the clone's `mnt_root` from
/// `sb.s_root()`, so the clone presents the SAME root dentry as `src`. This is
/// identical to the proven `copy_mnt_ns` cross-ns share; the SAME-ns shared-`s_root`
/// ambiguity it introduces (the 203/EXEC executor-pivot floor) is resolved by the
/// Stage-0 PARENT-AWARE derivation in [`commit_tree`] / [`rebuild_ns_index`], not
/// by minting a distinct per-clone `s_root`. # C: O(1)
pub(super) fn clone_mnt(src: &Arc<Mount>, ty: CloneType, pg: u64, master: &Arc<Mount>, ns: u64)
    -> Arc<Mount> {
    let new_id = NEXT_MNT_ID.fetch_add(1, Ordering::Relaxed);
    // [Stage 1] SHARE the source SB (and its root dentry) with one extra active
    // ref. The source is live in `MOUNTS`, so its SB is active and `grab_active`
    // always succeeds (kassert mirrors `copy_mnt_ns`).
    let sb = src.sb.clone();
    let grabbed = sb.grab_active();
    hal::kassert!(grabbed, "clone_mnt: live source SB must grab an active ref");
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
    #[cfg(feature = "debug-mnt")]
    mntcreate_log("clone", new_id, 0, None, clone.mnt_root().as_ref(), Some(&clone.sb));
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
        // The copy ROOT is positioned at the destination base (a DISTINCT fs),
        // never via the source dentry → `mp: None` (commit_tree uses `descend`).
        let rel = src.mountpoint().and_then(|d| rel_under(&d, Some(base_mp))).unwrap_or_default();
        out.push(CloneNode { m: clone_mnt(src, ty, pg, master, ns), rel, mp: None });
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
        // [D31] Record the source submount's mountpoint dentry: it is shared into
        // every clone of its parent (Stage 1 `s_root` share), so commit_tree can
        // place this nested clone on it directly (Linux same-dentry placement).
        out.push(CloneNode { m: clone_mnt(child, ty, pg, master, ns), rel, mp: Some(child_mp.clone()) });
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
                          dest_base_mnt: u64, fallback: Option<&Arc<Dentry>>, ns: u64) -> usize {
    let mut committed = 0usize;
    let mut dead: Vec<String> = Vec::new();
    // [Stage 0] PARENT-AWARE placement (the executor-pivot floor). Track each
    // committed clone's `(rel, mnt_id, mnt_root)` so a descendant derives its
    // PARENT from the clone-tree STRUCTURE (the deepest committed `rel` that is a
    // path-prefix) and its mountpoint from a NO-CROSS descent of that parent
    // clone's own `mnt_root` — NEVER a dentry-ptr scan (`parent_by_dentry`) nor a
    // crossing `descend` seeded by `containing_mount_id`, both of which an
    // SB-sharing clone (a shared `s_root`, Stage 1) conflates with the SOURCE
    // mount that owns the same dentry. Mirrors [`commit_tree_hashonly`].
    let mut placed: Vec<(String, u64, Arc<Dentry>)> = Vec::new();
    // Parent of a TOP-LEVEL node (no committed ancestor): the mount that owns
    // `dest_base`, supplied explicitly by the caller (the `(parent,dentry)`-known
    // path). `0` ⇒ derive it by dentry scan (callers without shared-`s_root`
    // ambiguity, e.g. propagation onto a distinct peer dentry).
    let base_mnt = if dest_base_mnt != 0 { dest_base_mnt } else { parent_by_dentry(ns, dest_base) };
    'node: for node in nodes.into_iter() {
        let CloneNode { m, rel, mp } = node;
        for d in dead.iter() {
            if rel.starts_with(d.as_str()) { release_clone(&m); continue 'node; }
        }
        // Deepest already-committed ancestor clone (longest `rel` path-prefix).
        let chosen = placed.iter()
            .filter(|p| p.0.is_empty()
                || { let mut s = p.0.clone(); s.push('/'); rel.starts_with(&s) })
            .max_by_key(|p| p.0.len())
            .map(|p| (p.0.clone(), p.1, p.2.clone()));
        let (parent_id, mp_d) = match chosen {
            Some((p_rel, p_id, p_root)) => {
                // [D31] Linux `copy_tree` same-dentry placement: the parent clone
                // SHARES the source parent's SB (Stage 1), so the recorded source
                // mountpoint dentry (`mp`) IS a live slot under the parent clone's
                // `mnt_root` — adopt it directly (`q->mnt_mountpoint =
                // dget(p->mnt_mountpoint)`). Fall back to a no-cross descent of the
                // rel SUFFIX (which only CONVERGES with `mp`) for a degenerate node
                // that recorded none.
                let placed_d = mp.clone().or_else(|| {
                    let sub = rel[p_rel.len()..].trim_start_matches('/');
                    descend_nocross(&p_root, sub)
                });
                match placed_d {
                    Some(d) => (p_id, d),
                    None => { mark_dead(&mut dead, &rel); release_clone(&m); continue; }
                }
            }
            None if rel.is_empty() => (base_mnt, dest_base.clone()),
            None => {
                // Top-level node beneath `dest_base` (the mounted root at the
                // bind target), falling back to the bare `fallback` underlay when
                // the mounted root cannot resolve the slot.
                let sub = rel.trim_start_matches('/');
                let resolved = descend_nocross(dest_base, sub).or_else(|| fallback.and_then(|f| {
                    if Arc::ptr_eq(f, dest_base) { None } else { descend_nocross(f, sub) }
                }));
                match resolved {
                    Some(d) => (base_mnt, d),
                    None => { mark_dead(&mut dead, &rel); release_clone(&m); continue; }
                }
            }
        };
        // RESERVE before any visible state (Linux `count_mounts` in
        // `attach_recursive_mnt`); over the per-ns cap ⇒ skip this node+subtree.
        if mntns::count_mounts(ns, 1).is_err() { mark_dead(&mut dead, &rel); release_clone(&m); continue; }
        let rendered = rendered_path_for(parent_id, &mp_d);
        let mnt_root = m.mnt_root();
        // [D28a] one writer-serialized structural region per node (after the
        // sleeping `descend_nocross` resolved `mp_d` above): parent/child links +
        // MOUNTPOINTS + MOUNTS + MOUNT_HASH mutated atomically w.r.t. other
        // writers. The (sleeping) descent stays OUTSIDE.
        {
            let _w = MOUNT_WRITE.lock();
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
            hash_insert(parent_id, dptr(&mp_d), m.mnt_id);
        }
        // Record this node for its own descendants' parent-aware placement.
        if let Some(r) = mnt_root { placed.push((rel.clone(), m.mnt_id, r)); }
        #[cfg(feature = "debug-mnt")]
        mntcreate_log("commit", m.mnt_id, parent_id, Some(&mp_d), m.mnt_root().as_ref(), Some(&m.sb));
        mntns::commit_mounts(ns, 1);
        committed += 1;
    }
    if committed > 0 { mntns::bump_gen(ns); }
    committed
}

// ---------------------------------------------------------------------------
// D24 Stage 1a — recursive open_tree/move_mount replication.
// `open_tree(OPEN_TREE_CLONE[, AT_RECURSIVE])` detaches a clone of a mount
// subtree into an fd; `move_mount` later splices it under a target via
// [`commit_tree_hashonly`]. (Post the Stage-1b walk-flip the legacy
// `dentry.mounted_mounts` map is GONE, so the "hash-only" commit is now simply
// the same `(parent_mnt_id, dentry)` strict-hash insert every commit does — the
// distinction it once preserved no longer exists.)
// ---------------------------------------------------------------------------

/// Descend `rel` beneath `base` by PLAIN dentry lookup only — NEVER crossing a
/// mount (unlike [`descend`], which follows the strict mount hash). A hash-only commit
/// positions a cloned submount on the MOUNTPOINT dentry inside the parent
/// clone's fs, so it must NOT cross the ORIGINAL mount stacked at that dentry
/// (e.g. resolving `/proc` under the clone root must land on the `/proc`
/// mountpoint dentry, not cross into the live procfs `s_root`). `rel` empty ⇒
/// `base`. # C: O(components)
fn descend_nocross(base: &Arc<Dentry>, rel: &str) -> Option<Arc<Dentry>> {
    let mut cur = base.clone();
    for comp in rel.split('/').filter(|c| !c.is_empty()) {
        let inode = cur.inode()?;
        let child = match crate::dcache::d_lookup(&cur, comp) {
            Some(d) if !d.is_negative() => d,
            _ => { let ci = inode.lookup(comp).ok()?; crate::dcache::d_add(&cur, comp, ci) }
        };
        cur = child;
    }
    Some(cur)
}

/// `open_tree(OPEN_TREE_CLONE)`: CLONE the mount subtree rooted at `src` into a
/// DETACHED node list (UNLINKED from the live tree — no mountpoint, parent, hash
/// or `MOUNTS` entry). `recursive` (AT_RECURSIVE) ⇒ the whole bindable subtree;
/// else root-only (the surplus clones [`copy_tree`] made are released so their
/// SB active refs balance). The caller stores the result in its mount-object fd
/// and either commits it ([`commit_tree_hashonly`] at `move_mount`) or releases
/// it ([`release_clone_tree`] at fd close). # C: O(N_subtree × depth)
pub fn clone_mount_tree(src: &Arc<Mount>, recursive: bool) -> Vec<CloneNode> {
    let ns = current_ns();
    let Some(base_mp) = src.mountpoint().or_else(global_root) else {
        // No base dentry (degenerate): root-only clone with empty rel.
        return alloc::vec![CloneNode { m: clone_mnt(src, CloneType::Private, 0, src, ns), rel: String::new(), mp: None }];
    };
    let mut nodes = copy_tree(src, &base_mp, CloneType::Private, 0, src, ns, true, None);
    if !recursive && nodes.len() > 1 {
        // Root-only: drop (and release) the children copy_tree cloned.
        let extra = nodes.split_off(1);
        for n in extra.iter() { release_clone(&n.m); }
    }
    nodes
}

/// Release a DETACHED [`clone_mount_tree`] node list that will NOT be committed
/// (an `open_tree` fd closed without a `move_mount`): drop each clone's SB active
/// ref + master slave link via [`release_clone`], so the SB active count and
/// propagation links stay balanced. # C: O(N × master slaves)
pub fn release_clone_tree(nodes: &[CloneNode]) {
    for n in nodes.iter() { release_clone(&n.m); }
}

/// [`commit_tree`] variant (D24 Stage 1a): splice a [`clone_mount_tree`] node
/// list under `dest_base`, inserting each clone into the strict `(parent_mnt_id,
/// dentry)` hash + intrusive parent/child links + the `struct mountpoint`
/// (D_MOUNTED) hold. (Once carried a "skip the legacy crossing map" distinction;
/// that map is now deleted, so this is an ordinary strict-hash commit.)
/// Descendants are positioned by [`descend_nocross`]
/// from the deepest already-committed ancestor clone's `mnt_root` (NOT
/// [`descend`], which would cross the original mount), so a cloned `/proc` lands
/// on the same `/proc` mountpoint dentry as the original — giving a DISTINCT hash
/// key `(clone_root_id, /proc)` that coexists with `(ns_root_id, /proc)`. Returns
/// the count committed. # C: O(N × depth)
pub fn commit_tree_hashonly(nodes: Vec<CloneNode>, dest_base: &Arc<Dentry>) -> usize {
    let ns = current_ns();
    let mut committed = 0usize;
    let mut dead: Vec<String> = Vec::new();
    // (rel, mnt_id, mnt_root dentry) of each committed node, to resolve
    // descendants' parent + base without consulting the (un-clobbered) map.
    let mut placed: Vec<(String, u64, Arc<Dentry>)> = Vec::new();
    'node: for node in nodes.into_iter() {
        let CloneNode { m, rel, mp } = node;
        for d in dead.iter() {
            if rel.starts_with(d.as_str()) { release_clone(&m); continue 'node; }
        }
        let (parent_id, mp_d) = if rel.is_empty() {
            (parent_by_dentry(ns, dest_base), dest_base.clone())
        } else {
            // Deepest committed ancestor (longest `rel` that is a path-prefix).
            let chosen = placed.iter()
                .filter(|p| p.0.is_empty()
                    || { let mut s = p.0.clone(); s.push('/'); rel.starts_with(&s) })
                .max_by_key(|p| p.0.len())
                .map(|p| (p.0.clone(), p.1, p.2.clone()));
            let Some((p_rel, p_id, p_root)) = chosen else {
                mark_dead(&mut dead, &rel); release_clone(&m); continue;
            };
            // [D31] same-dentry placement (shared `s_root`); descend fallback.
            let placed_d = mp.clone().or_else(|| {
                let sub = rel[p_rel.len()..].trim_start_matches('/');
                descend_nocross(&p_root, sub)
            });
            match placed_d {
                Some(d) => (p_id, d),
                None => { mark_dead(&mut dead, &rel); release_clone(&m); continue; }
            }
        };
        // RESERVE before any visible state (Linux `count_mounts`).
        if mntns::count_mounts(ns, 1).is_err() { mark_dead(&mut dead, &rel); release_clone(&m); continue; }
        // [D28a] one writer-serialized structural region per node (the sleeping
        // `descend_nocross`/`parent_by_dentry` resolution ran above): MOUNTPOINTS
        // + parent/child links + MOUNTS + MOUNT_HASH mutated atomically.
        {
            let _w = MOUNT_WRITE.lock();
            *m.mountpoint.lock() = Some(mp_d.clone());
            *m.rendered_path.lock() = abs_string(&mp_d);
            m.parent_id.store(parent_id, Ordering::Release);
            // The D_MOUNTED hold — ONE `get_mountpoint` per cloned crossing.
            *m.mnt_mp.lock() = Some(get_mountpoint(&mp_d));
            if let Some(p) = mount_by_id(parent_id) {
                *m.mnt_parent.lock() = Arc::downgrade(&p);
                p.mnt_mounts.lock().push(m.clone());
            }
            MOUNTS.lock().insert(m.mnt_id, m.clone());
            // Strict (parent,dentry) crossing hash — the single crossing structure.
            hash_insert(parent_id, dptr(&mp_d), m.mnt_id);
        }
        #[cfg(feature = "debug-mnt")]
        mntcreate_log("commit_hashonly", m.mnt_id, parent_id, Some(&mp_d), m.mnt_root().as_ref(), Some(&m.sb));
        mntns::commit_mounts(ns, 1);
        let mroot = m.mnt_root().unwrap_or_else(|| mp_d.clone());
        placed.push((rel, m.mnt_id, mroot));
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
    // Mount `put_old` resides on. It must live inside the new-root subtree
    // (Linux pivot_root requirement), so seed it mount-aware from there; this
    // pins the otherwise-ambiguous containing mount when the new tree shares an
    // `s_root` with the old (Stage 1). Fall back to the dentry scan otherwise.
    let po_mnt = mount_owning_dentry_in(&po_d, &nr_subtree)
        .unwrap_or_else(|| containing_mount_id(ns, &po_d));
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
    if let Some(om) = mount_by_id(po_mnt) {
        if is_shared(&om) { return Err(VfsError::Einval); }
    }
    let mounts = mounts_in_ns(ns);
    // Position of a PRESERVE-set mount under the new root, MOUNT-AWARE: seed the
    // upward walk from the mount's own recorded parent (the fs its mountpoint
    // dentry lives in) so an SB-sharing clone's shared `s_root` does not derail
    // the crossing chain (Stage 1).
    let preserve_rel = |m: &Arc<Mount>| -> Option<String> {
        m.mountpoint().and_then(|d| rel_under_seeded(&d, m.parent_id.load(Ordering::Acquire), nr_mp.as_ref()))
    };
    let stacking = nr_mp.as_ref().map(|d| Arc::ptr_eq(d, &po_d)).unwrap_or(false)
        || rel_under_seeded(&po_d, po_mnt, nr_mp.as_ref()) == Some(String::new());
    if stacking {
        let new_paths: Vec<(u64, String)> = mounts.iter().map(|m| {
            let np = if m.mnt_id == nr_id {
                String::from("/")
            } else if nr_subtree.contains(&m.mnt_id) {
                preserve_rel(m).unwrap_or_else(|| m.mount_point_str())
            } else {
                m.mount_point_str()
            };
            (m.mnt_id, np)
        }).collect();
        commit_retree(ns, &new_paths, Some(nr_id), &nr_subtree);
        if let Some(old) = old_root_id { mntns::chroot_fs_refs(old, nr_id); }
        return Ok(());
    }
    let old_dst = match rel_under_seeded(&po_d, po_mnt, nr_mp.as_ref()) {
        Some(r) if !r.is_empty() => r,
        _ if nr_mp.is_none() => rel_under_seeded(&po_d, po_mnt, None).unwrap_or_default(),
        _ => return Err(VfsError::Einval),
    };
    if top_mount_on(ns, &po_d).is_some() { return Err(VfsError::Ebusy); }
    let new_paths: Vec<(u64, String)> = mounts.iter().map(|m| {
        let np = if m.mnt_id == nr_id {
            String::from("/")
        } else if nr_subtree.contains(&m.mnt_id) {
            preserve_rel(m).unwrap_or_else(|| m.mount_point_str())
        } else if Some(m.mnt_id) == old_root_id {
            old_dst.clone()
        } else {
            let abs = m.mountpoint()
                .and_then(|d| rel_under_seeded(&d, m.parent_id.load(Ordering::Acquire), None))
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
    // [D24] Drop this ns's strict crossing-hash entries BEFORE re-deriving the
    // relocated (non-preserve) positions: those are materialised by a plain
    // dentry `descend` from the new global root, which must NOT cross the stale
    // crossings (matches the legacy map-clear that ran here). `rebuild_ns_index`
    // re-inserts every crossing from the recorded mountpoint dentries below.
    // [D28a] FRONT structural region (before the sleeping `descend` below):
    // drop the stale crossings + re-root the ns, serialized w.r.t. other writers.
    {
        let _w = MOUNT_WRITE.lock();
        hash_drop_ids(&mounts.iter().map(|m| m.mnt_id).collect::<Vec<_>>());
        if let Some(rid) = new_root_id { mntns::ns_set_root(ns, rid); }
    }
    let root = global_root();
    // The (sleeping) `descend` materialization of relocated positions runs with
    // NO writer lock held.
    let dents: Vec<(u64, String, Option<Arc<Dentry>>)> = new_paths.iter().map(|(id, p)| {
        let is_root = Some(*id) == new_root_id;
        let d = if is_root { None }
                else if preserve.contains(id) { mount_by_id(*id).and_then(|m| m.mountpoint()) }
                else { root.as_ref().and_then(|r| descend(r, p)) };
        (*id, p.clone(), d)
    }).collect();
    // [D28a] BACK structural region: re-seat every mount + rebuild the ns index
    // (links + crossings + hash) as one writer-serialized mutation.
    // `rebuild_ns_index` does NOT self-lock — it is covered by this hold.
    {
        let _w = MOUNT_WRITE.lock();
        for m in mounts.iter() {
            if let Some((_, p, d)) = dents.iter().find(|(id, _, _)| *id == m.mnt_id) {
                let is_root = Some(m.mnt_id) == new_root_id;
                set_mountpoint_dentry(m, if is_root { None } else { d.clone() }, p.clone());
            }
        }
        rebuild_ns_index(ns);
    }
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
    // [D28a] serialize the whole ns clone (the per-clone MOUNTS inserts +
    // NAMESPACES root + the `rebuild_ns_index` link/hash wiring) as one writer
    // region. No `descend` / `put_super` runs here, so no sleep under the lock;
    // `rebuild_ns_index` does NOT self-lock — it is covered by this hold.
    let _w = MOUNT_WRITE.lock();
    for m in src.iter() {
        // [D16] Reuse the shared `clone_mnt` primitive (CL_* fidelity) instead of
        // a hand-rolled inline duplicate: it shares the source SB (one extra
        // `s_active` + kassert), copies the option flags + MNT_LOCKED, and stamps
        // the requested propagation. Per the existing copy_mnt_ns CL_SLAVE
        // demotion, a SHARED source is demoted to a SLAVE of itself (CL_SLAVE: the
        // clone receives parent-ns events but its own mounts stay private to the
        // child ns); every other source is cloned PRIVATE (CL_PRIVATE).
        let prop = Propagation::from_u8(m.propagation.load(Ordering::Acquire));
        let clone = match prop {
            Propagation::Shared => {
                let c = clone_mnt(m, CloneType::Slave, 0, m, to_ns);
                // Keep the source group id on the demoted slave (the slave knows
                // which peer group it slaves to) — the inline path's behaviour.
                c.peer_group.store(m.peer_group.load(Ordering::Acquire), Ordering::Release);
                c
            }
            _ => clone_mnt(m, CloneType::Private, 0, m, to_ns),
        };
        // Cross-ns clone is 1:1: keep the SAME mountpoint dentry (`clone_mnt`
        // leaves it UNLINKED); `rebuild_ns_index` reparents from it below. The
        // rendered path string is already set by `clone_mnt` (`mount_point_str`).
        *clone.mountpoint.lock() = m.mountpoint();
        // [D25] the clone of the SOURCE ns-root mount becomes the new ns root,
        // identified by the source's self-parent `is_root()` (the clone's own
        // self-parent is stamped later by `rebuild_ns_index`'s `None` arm).
        if m.is_root() { mntns::ns_set_root(to_ns, clone.mnt_id); }
        MOUNTS.lock().insert(clone.mnt_id, clone);
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
    let mut tgt_mnt = containing_mount_id(ns, tgt);
    while let Some(m) = __lookup_mnt(tgt_mnt, &tgt_base) {
        match m.mnt_root() { Some(sr) => { tgt_base = sr; tgt_mnt = m.mnt_id; } None => break }
    }
    // Clone the source's submount SUBTREE (root EXCLUDED — already bound) as
    // private binds, then splice it under the destination base, falling back to
    // the bare `tgt` underlay when the mounted root cannot resolve a slot.
    let nodes = copy_tree(&src_m, &base_mp, CloneType::Private, 0, &src_m, ns, false, Some(tgt));
    // `tgt_mnt` is the mount whose `mnt_root` is `tgt_base` — the explicit parent
    // of every top-level cloned submount, threaded so the parent-aware
    // `commit_tree` need not (ambiguously) re-derive it from the shared dentry.
    commit_tree(nodes, &tgt_base, tgt_mnt, Some(tgt), ns)
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
    let to_root = is_ns_root_dentry(to);
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
    if !to_root && top_mount_on(ns, to).is_some() { return Err(VfsError::Ebusy); }
    let to_abs = if to_root { String::from("/") } else { abs_string(to) };
    let old_mp = from_m.mountpoint();
    let old_parent = from_m.parent_id.load(Ordering::Acquire);
    let snap: Vec<Arc<Mount>> = subtree_ids(ns, from_id).iter()
        .filter_map(|id| mount_by_id(*id)).collect();

    // --- 1) Re-seat the moved ROOT mount (the only attachment that changes). ---
    let new_root_d = if to_root { None } else { Some(to.clone()) };
    // [D28a] writer-serialized ROOT re-seat (no `descend` here): drop the old
    // crossing, unlink, then set the new mountpoint + parent/child links +
    // MOUNT_HASH atomically w.r.t. other writers.
    {
        let _w = MOUNT_WRITE.lock();
        if let Some(d) = &old_mp {
            hash_remove(old_parent, dptr(d), from_id);
        }
        unlink_from_parent(&from_m);
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
                hash_insert(new_parent, dptr(d), from_id);
            }
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
                // crossing the moved root) from `to`. [D28a] the (sleeping)
                // `descend` runs OUTSIDE the writer lock; the two structural
                // mutations (old-crossing drop, new wiring) are each serialized.
                let m_parent = m.parent_id.load(Ordering::Acquire);
                {
                    let _w = MOUNT_WRITE.lock();
                    hash_remove(m_parent, dptr(&child_mp), m.mnt_id);
                }
                let new_d = to_base.as_ref().and_then(|b| descend(b, rel.trim_start_matches('/')));
                let _w = MOUNT_WRITE.lock();
                set_mountpoint_dentry(m, new_d.clone(), new_rendered);
                unlink_from_parent(m);
                if let Some(d) = &new_d {
                    let np = parent_by_dentry(ns, d);
                    m.parent_id.store(np, Ordering::Release);
                    if let Some(p) = mount_by_id(np) {
                        *m.mnt_parent.lock() = Arc::downgrade(&p);
                        p.mnt_mounts.lock().push(m.clone());
                    }
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

/// [D52] Commit `set_mnt`/`clr_mnt` (already in the MNT_* space) onto mount `m`:
/// `new = (old & !clr) | set`, MASKED to `MNT_OPTION_MASK` so only per-mount
/// option bits move (internal flags untouched). No writer guard — callers that
/// can set RDONLY gate first. # C: O(1)
/// Apply a `mount_setattr(2)` MNT_* option change to a DETACHED mount (an
/// `fsmount`/`open_tree` object not yet in any namespace tree). No ns/arena
/// gate (the mount is unlinked), no writer guard (a detached mount has no
/// writers). Used by `mount_setattr(fd,"",AT_EMPTY_PATH,...)` so systemd's
/// fsmount→mount_setattr→move_mount sequence attaches the subtree already
/// read-only. # C: O(1)
pub fn apply_mnt_attrs_detached(m: &Arc<Mount>, set_mnt: u64, clr_mnt: u64) {
    commit_mnt_attrs(m, set_mnt, clr_mnt);
}

fn commit_mnt_attrs(m: &Arc<Mount>, set_mnt: u64, clr_mnt: u64) {
    let old = m.flags.load(Ordering::Acquire);
    let set = set_mnt & MNT_OPTION_MASK;
    let clr = clr_mnt & MNT_OPTION_MASK;
    let new = (old & !clr) | set;
    m.flags.store(new, Ordering::Release);
    mntns::bump_gen(m.ns);
}

/// [D52] Apply a `mount_setattr(2)` option change to ONE mount: same EBUSY guard
/// as [`apply_remount`] (turning RDONLY on with active writers is Linux
/// `mnt_hold_writers` EBUSY), then commit via [`commit_mnt_attrs`]. # C: O(1)
fn apply_mnt_attrs(m: &Arc<Mount>, set_mnt: u64, clr_mnt: u64) -> KResult<()> {
    let old = m.flags.load(Ordering::Acquire);
    if (set_mnt & MNT_RDONLY) != 0 && (old & MNT_RDONLY) == 0
        && m.mnt_writers.load(Ordering::Acquire) > 0 {
        return Err(VfsError::Ebusy);
    }
    commit_mnt_attrs(m, set_mnt, clr_mnt);
    Ok(())
}

/// [D52] `mount_setattr(2)` on the mount the path walk CROSSED INTO, identified
/// by `mnt_id` (Linux `do_mount_setattr` keys on `path->mnt`, NOT a re-derived
/// dentry — same lesson as [`remount_flags_by_id`]). `set`/`clr` are MNT_*
/// masks (from [`mount_attr_to_mnt`]). ns-gated by `check_mnt`. # C: O(1)
pub fn mnt_setattr_by_id(mnt_id: u64, set: u64, clr: u64) -> KResult<()> {
    let m = mount_by_id(mnt_id).ok_or(VfsError::Einval)?;
    if !check_mnt(&m) { return Err(VfsError::Einval); }
    apply_mnt_attrs(&m, set, clr)
}

/// [D52] `mount_setattr(2)` with `AT_RECURSIVE`: apply `set`/`clr` across the
/// subtree rooted at `top_id` ([`subtree_ids`]). When turning RDONLY on, Linux
/// holds writers across the WHOLE subtree first (`mnt_hold_writers`) and fails
/// atomically — so this pre-checks every mount for active writers and returns
/// EBUSY without mutating any, then commits the tree. ns-gated by `check_mnt`.
/// # C: O(N_subtree)
pub fn mnt_setattr_tree_by_id(top_id: u64, set: u64, clr: u64) -> KResult<()> {
    let top = mount_by_id(top_id).ok_or(VfsError::Einval)?;
    if !check_mnt(&top) { return Err(VfsError::Einval); }
    let ids = subtree_ids(top.ns, top_id);
    if (set & MNT_RDONLY) != 0 {
        for id in &ids {
            if let Some(m) = mount_by_id(*id) {
                let old = m.flags.load(Ordering::Acquire);
                if (old & MNT_RDONLY) == 0 && m.mnt_writers.load(Ordering::Acquire) > 0 {
                    return Err(VfsError::Ebusy);
                }
            }
        }
    }
    for id in &ids {
        if let Some(m) = mount_by_id(*id) { commit_mnt_attrs(&m, set, clr); }
    }
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
    if is_ns_root_dentry(d) { return None; }
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
