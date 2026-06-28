//! Mount table per `docs/16§6`, structured like Linux's mount tree.
//!
//! Each `Mount` records AT ATTACH TIME its parent mount (`parent_id`) and
//! the dentry it is mounted on (`mountpoint`), exactly as Linux records
//! `mnt_parent` + `mnt_mountpoint` in `mnt_set_mountpoint`. Tree decisions
//! — "is X a mountpoint", "children of M", "the mount exactly here",
//! parent/child/containment — are made by DENTRY/MOUNT IDENTITY: a global
//! `(ns, parent_mnt_id, mountpoint_dentry_ptr) -> mnt_id stack` hash
//! (Linux `__lookup_mnt`) plus per-mount `parent_id`. No string-prefix
//! scan, no longest-`mount_point` match, no path-equality fallback.
//!
//! The rendered path (`rendered_path`) is WRITE-ONLY tree-wise: it is set
//! at attach/move and read ONLY by /proc mountinfo, /proc mounts, and
//! statmount rendering (`mount_point_str`). It never feeds a routing
//! decision — those read `mountpoint`/`parent_id`/`mnt_id`/the hash.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, AtomicU8, AtomicU64, Ordering};
use sync::{MountTable as MountClass, Spinlock};

use crate::dentry::Dentry;
use crate::fs::{FileSystem, KResult};
use crate::inode::InodeRef;
use crate::superblock::{next_anon_dev, SuperBlock};
use crate::types::VfsError;

pub const MNT_RDONLY: u64 = 1;
pub const MNT_NOSUID: u64 = 2;
pub const MNT_NODEV: u64 = 4;
pub const MNT_NOEXEC: u64 = 8;
pub const MNT_SYNCHRONOUS: u64 = 16;
pub const MNT_MANDLOCK: u64 = 64;
pub const MNT_DIRSYNC: u64 = 128;
pub const MNT_NOATIME: u64 = 1024;
pub const MNT_NODIRATIME: u64 = 2048;
pub const MNT_RELATIME: u64 = 1 << 21;
pub const MNT_STRICTATIME: u64 = 1 << 24;
pub const MNT_LAZYTIME: u64 = 1 << 25;
pub const MNT_OPTION_MASK: u64 = MNT_RDONLY | MNT_NOSUID | MNT_NODEV | MNT_NOEXEC
    | MNT_SYNCHRONOUS | MNT_MANDLOCK | MNT_DIRSYNC | MNT_NOATIME | MNT_NODIRATIME
    | MNT_RELATIME | MNT_STRICTATIME | MNT_LAZYTIME;

/// The mount engine NEVER resolves a mount-point path STRING to a dentry
/// (`docs/16§3`). Every caller-boundary entry point (`register`,
/// `register_bind`, `mount_exact_at`, `move_mount`, `pivot_root`, …) RECEIVES
/// the mountpoint `Arc<Dentry>` the caller's single namei walk already
/// produced — the Linux `user_path_at`/`kern_path` `struct path.dentry` that
/// `do_mount` hands `mnt_set_mountpoint`. The engine stores it directly and
/// makes every tree decision by dentry/mount IDENTITY.
///
/// The only residual path→dentry work is engine-INTERNAL SYNTHESIS — the
/// mirror position of a propagated mount under a peer, or the relocated
/// position of a subtree under a move/pivot target. Those positions were
/// walked by NO caller, so the engine materialises them with `descend`
/// (`docs/16§3`): a pure dentry→dentry descent from a dentry the engine
/// ALREADY holds, component-by-component via `d_lookup → i_op->lookup →
/// d_add`. It is never a global path-string decision at the syscall boundary.

/// A dentry's identity key (stable address of the `Arc<Dentry>` allocation).
/// The dcache is per-(parent,name) unique, so one dentry == one mountpoint
/// location; this is the hash's dentry half. # C: O(1)
fn dptr(d: &Arc<Dentry>) -> usize { Arc::as_ptr(d) as *const () as usize }

/// True iff `d` is the global namespace-root dentry (no parent, empty name —
/// Linux `mnt_ns->root` dentry). The only mountpoint the engine treats as a
/// namespace root. Identity test, not a string compare. # C: O(1)
fn is_global_root(d: &Arc<Dentry>) -> bool {
    d.parent().is_none() && d.name().is_empty()
}

/// Absolute path rendered from a mountpoint dentry's parent chain (Linux
/// `d_path`) — the WRITE-ONLY `rendered_path` for /proc mountinfo/mounts +
/// statmount. Derived, never a routing input. # C: O(depth)
fn abs_string(d: &Arc<Dentry>) -> String {
    String::from_utf8(d.absolute_path()).unwrap_or_else(|_| String::from("/"))
}

/// Materialise the dentry at `rel` beneath `base` by a dentry→dentry descent
/// that CROSSES MOUNTS at each component exactly as `namei::path_lookup_path`
/// does (`namei.rs` mount-crossing): each component via `d_lookup` (cache)
/// then `i_op->lookup` + `d_add` (Linux `lookup_one_len` under a held parent),
/// and after resolving a child dentry that is itself a mountpoint, lookups for
/// the REMAINING components continue in that mount's root inode — never the
/// covered underlay. The engine-internal resolver for SYNTHESIZED mount
/// positions (propagation mirrors, MS_MOVE / pivot_root relocations); still
/// NEVER a global path-string resolve. `rel` empty ⇒ `base` itself.
///
/// Crossing is REQUIRED: a relocated subtree's new mountpoint dentry, or a
/// propagation mirror under a peer, lives INSIDE the mounted fs at every
/// intermediate mount the path traverses (e.g. a staging dir under a `/run`
/// tmpfs, or a bind clone of `/` under a peer). The old pure dentry walk read
/// each mountpoint's covered underlay inode, so the synthesized dentry was NOT
/// identity-equal to the one `namei` later visits — `/proc/sys/kernel/*` then
/// ENOENT'd inside udevd's mount-ns sandbox. # C: O(components)
fn descend(base: &Arc<Dentry>, rel: &str) -> Option<Arc<Dentry>> {
    let ns = current_ns();
    let mut cur = base.clone();
    // Effective inode for the NEXT child lookup. `None` ⇒ derive from `cur`
    // (the first component looks up in `base`'s OWN inode — `base` is NOT
    // crossed, so callers basing a SYNTHESIZED position at a mountpoint dentry
    // — propagation mirror under a peer, recursive-bind mirror under the bind
    // target — place it at the dcache-tree dentry directly beneath, never
    // inside the covering mount's fs). `rel` empty ⇒ `base` itself, no inode
    // needed (preserves the pre-crossing contract).
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
        // Mount crossing by dentry identity (`docs/16§3`): if `child` is a
        // mountpoint, the REMAINING components resolve in the mount's root
        // inode, not the covered underlay — exactly as `namei.rs` crosses per
        // component. This is the udevd fix: a staging mountpoint dentry under a
        // `/run`/`/tmp` tmpfs is now materialised identity-equal to the one
        // `namei` later walks, so post-MS_MOVE / pivot_root `/proc/sys/kernel/*`
        // resolves inside the sandbox instead of ENOENTing on the underlay.
        cur_inode = Some(match child.mounted_mount(ns) {
            Some(mnt_id) => root_for_mount_id(mnt_id)?,
            None => child.inode()?,
        });
        cur = child;
    }
    Some(cur)
}

/// The global namespace-root dentry, for basing a SYNTHESIZED position whose
/// peer/target is the ns root (no mountpoint dentry). # C: O(1)
fn global_root() -> Option<Arc<Dentry>> { crate::namei::root_dentry() }

// ---------------------------------------------------------------------------
// (ns, parent_mnt_id, mountpoint_dentry_ptr) -> mnt_id stack — Linux
// `__lookup_mnt`. The Vec is a stack (top = last); overmounts on the same
// dentry stack here, last attached wins, detach re-exposes the underlay.
// ---------------------------------------------------------------------------
static MOUNT_HASH: Spinlock<BTreeMap<(u64, u64, usize), Vec<u64>>, MountClass> =
    Spinlock::new(BTreeMap::new());

/// Push `mnt_id` as the top mount at (ns, parent, dptr). # C: O(log N)
fn hash_insert(ns: u64, parent: u64, d: usize, mnt_id: u64) {
    MOUNT_HASH.lock().entry((ns, parent, d)).or_default().push(mnt_id);
}

/// Remove `mnt_id` from the stack at (ns, parent, dptr). # C: O(log N)
fn hash_remove(ns: u64, parent: u64, d: usize, mnt_id: u64) {
    let mut h = MOUNT_HASH.lock();
    if let Some(stack) = h.get_mut(&(ns, parent, d)) {
        stack.retain(|&id| id != mnt_id);
        if stack.is_empty() { h.remove(&(ns, parent, d)); }
    }
}

/// Top mount mounted on (ns, parent, dptr), or `None`. # C: O(log N)
fn hash_top(ns: u64, parent: u64, d: usize) -> Option<u64> {
    MOUNT_HASH.lock().get(&(ns, parent, d)).and_then(|s| s.last().copied())
}

/// Drop every hash entry whose key matches `ns` (used when rebuilding a
/// namespace's hash from scratch). # C: O(N)
fn hash_drop_ns(ns: u64) {
    MOUNT_HASH.lock().retain(|k, _| k.0 != ns);
}

/// Parent mount id for a mount whose mountpoint dentry is `mp_d`, by DENTRY
/// IDENTITY (Linux `mnt_parent`): walk `mp_d`'s ancestor dentries to the
/// nearest one covered by a mount in `ns` and take that covering mount; no
/// covered ancestor ⇒ the namespace root mount. Pure dentry-ancestor walk —
/// the structural primitive, not a string compare. # C: O(depth)
fn parent_by_dentry(ns: u64, mp_d: &Arc<Dentry>) -> u64 {
    let mut cur = mp_d.parent().cloned();
    while let Some(a) = cur {
        if let Some(id) = a.mounted_mount(ns) { return id; }
        cur = a.parent().cloned();
    }
    root_mount_id(ns).unwrap_or(0)
}

/// Relative path of `mp` beneath `stop` (exclusive), by walking the dentry
/// parent chain and collecting names — identity-bounded (`Arc::ptr_eq`),
/// NOT string-prefix. `stop == None` walks to the global dentry root and
/// returns `mp`'s whole absolute path. Returns `None` if `stop` is not an
/// ancestor of `mp`. # C: O(depth)
fn rel_under(mp: &Arc<Dentry>, stop: Option<&Arc<Dentry>>) -> Option<String> {
    let mut names: Vec<String> = Vec::new();
    let mut cur = Some(mp.clone());
    while let Some(d) = cur {
        if let Some(s) = stop {
            if Arc::ptr_eq(&d, s) { return Some(join_names(&names)); }
        }
        match d.parent() {
            None => return if stop.is_none() { Some(join_names(&names)) } else { None },
            Some(p) => { names.push(d.name().to_string()); cur = Some(p.clone()); }
        }
    }
    None
}

/// Join collected child→ancestor names (reversed) into "/a/b". # C: O(len)
fn join_names(names: &[String]) -> String {
    let mut out = String::new();
    for n in names.iter().rev() { out.push('/'); out.push_str(n); }
    out
}

/// Mark `mp_d`'s dentry covered by `mnt_id` in `ns` (mount crossing). The
/// mount table owns the mounted root inode; the dentry stores only identity.
/// # C: O(1)
fn wire_crossing(ns: u64, mp_d: &Arc<Dentry>, mnt_id: u64) {
    mp_d.set_mounted_mount(ns, Some(mnt_id));
}

/// Rebuild the crossing links + `parent_id` + hash for namespace `ns` from
/// each mount's recorded `mountpoint` dentry (identity only). # C: O(N×depth)
fn rebuild_ns_index(ns: u64) {
    hash_drop_ns(ns);
    let mounts: Vec<Arc<Mount>> = TABLE.lock().iter().filter(|m| m.ns == ns).cloned().collect();
    // Clear then re-wire crossings (top wins by TABLE order = stack order).
    for m in mounts.iter() {
        if let Some(d) = m.mountpoint.as_ref() { d.set_mounted_mount(ns, None); }
    }
    for m in mounts.iter() {
        if let Some(d) = m.mountpoint.as_ref() { wire_crossing(ns, d, m.mnt_id); }
    }
    // Parent + hash from the wired crossings.
    for m in mounts.iter() {
        match m.mountpoint.as_ref() {
            None => { m.parent_id.store(m.mnt_id, Ordering::Release); }
            Some(d) => {
                let parent = parent_by_dentry(ns, d);
                m.parent_id.store(parent, Ordering::Release);
                hash_insert(ns, parent, dptr(d), m.mnt_id);
            }
        }
    }
}

/// Clone `m` with a replaced `mountpoint` dentry AND rendered path (Mount
/// has no Clone; atomics copied explicitly). # C: O(1)
fn rebuild(m: &Mount, mountpoint: Option<Arc<Dentry>>, rendered: String) -> Arc<Mount> {
    Arc::new(Mount {
        sb: m.sb.clone(),
        rendered_path: rendered,
        mountpoint,
        parent_id: AtomicU64::new(m.parent_id.load(Ordering::Acquire)),
        root: m.root.clone(),
        mnt_id: m.mnt_id,
        propagation: AtomicU8::new(m.propagation.load(Ordering::Acquire)),
        peer_group: AtomicU64::new(m.peer_group.load(Ordering::Acquire)),
        flags: AtomicU64::new(m.flags.load(Ordering::Acquire)),
        ns: m.ns,
    })
}

/// Clone `m` with a replaced `mountpoint` dentry AND rendered path. # C: O(1)
fn with_mountpoint_path(m: &Mount, mountpoint: Option<Arc<Dentry>>, rendered: String) -> Arc<Mount> {
    rebuild(m, mountpoint, rendered)
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

/// Monotonic mount-id source (mountinfo field 1). Starts at 1.
static NEXT_MNT_ID: AtomicU64 = AtomicU64::new(1);

/// Per-ns root mount id (Linux `mnt_ns->root`). The ONLY self-parent. Set
/// when a mount is attached at "/" (and on pivot_root / snapshot). Decisions
/// read this instead of a `rendered_path == "/"` string test. # Lk: MountClass
static ROOTS: Spinlock<BTreeMap<u64, u64>, MountClass> = Spinlock::new(BTreeMap::new());

/// Mount-namespace provider (`docs/16§6`). `null` ⇒ ns 0.
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

/// Monotonic peer-group id source (`docs/16§6`). Starts at 1 (0 = none).
static NEXT_PEER_GROUP: AtomicU64 = AtomicU64::new(1);

/// One mount instance (Linux `struct mount`). Tree position is recorded at
/// attach: `parent_id` (= `mnt_parent`) + `mountpoint` (= `mnt_mountpoint`).
/// `rendered_path` is render-only (mountinfo/statmount), never a decision.
pub struct Mount {
    /// The mounted-instance superblock (Linux `mnt_sb`). Owns `s_root`,
    /// `s_op`, `s_dev`, `s_magic`, and reaches the backend via `sb.fs()`.
    /// Every mount carries a real `SuperBlock` (built by
    /// `SuperBlock::for_backend` in `attach`).
    pub sb: Arc<SuperBlock>,
    /// Rendered mount path — WRITE at attach/move, READ only by /proc
    /// mountinfo, /proc mounts, statmount (`mount_point_str`). NEVER a
    /// routing/parent/child input. Renamed from `mount_point` so any
    /// decision-path read fails to compile.
    pub(crate) rendered_path: String,
    /// Dentry this mount is attached to (Linux `mnt_mountpoint`). `None`
    /// ONLY for a namespace root mount.
    pub mountpoint: Option<Arc<Dentry>>,
    /// Parent mount id (Linux `mnt_parent`), recorded at attach. The root
    /// points at itself.
    pub parent_id: AtomicU64,
    /// Bind-as-clone root inode (Linux `mnt_root`); `None` = whole-fs at
    /// `fs.root()`.
    pub root: Option<InodeRef>,
    /// Stable unique id; /proc mountinfo field 1.
    pub mnt_id: u64,
    /// Propagation type discriminant (`Propagation`). Default Private.
    pub propagation: AtomicU8,
    /// Peer-group id (`docs/16§6`); 0 = none.
    pub peer_group: AtomicU64,
    /// Per-mount MNT_* option bits.
    pub flags: AtomicU64,
    /// Mount-namespace id that created this mount.
    pub ns: u64,
}

impl Mount {
    /// Rendered mount-point path — RENDER ONLY (mountinfo/statmount/diag).
    /// # C: O(1)
    pub fn mount_point_str(&self) -> &str { &self.rendered_path }

    /// True iff this is its namespace's root mount (Linux: no mountpoint
    /// dentry; tracked in `ROOTS`). Identity, no string test. # C: O(log N)
    pub fn is_root(&self) -> bool {
        ROOTS.lock().get(&self.ns) == Some(&self.mnt_id)
    }

    /// The mounted-instance superblock (Linux `mnt_sb`). # C: O(1)
    pub fn sb(&self) -> &Arc<SuperBlock> { &self.sb }

    /// The backend behind this mount's superblock (Linux `mnt_sb->s_fs`).
    /// # C: O(1)
    pub fn fs(&self) -> &Arc<dyn FileSystem> { self.sb.fs() }
}

static TABLE: Spinlock<Vec<Arc<Mount>>, MountClass> = Spinlock::new(Vec::new());

/// Snapshot of all registered mounts (cheap Arc clones). # C: O(N_mounts)
pub fn all_mounts() -> Vec<Arc<Mount>> { TABLE.lock().clone() }

/// The (top) mount attached EXACTLY at mountpoint dentry `d` in `ns`, by
/// IDENTITY: derive `d`'s parent mount by dentry ancestry, then read the
/// `(ns, parent, dptr)` hash top. The global root dentry resolves to the ns
/// root mount. No string scan, no path-equality fallback. # C: O(log N)
fn mount_exact_at(ns: u64, d: &Arc<Dentry>) -> Option<Arc<Mount>> {
    if is_global_root(d) { return root_mount_id(ns).and_then(mount_by_id); }
    let parent = parent_by_dentry(ns, d);
    let id = hash_top(ns, parent, dptr(d))?;
    mount_by_id(id)
}

/// True iff a mount is attached exactly at mountpoint dentry `d` in `ns`.
/// # C: O(log N)
pub fn is_mount_in_ns(d: &Arc<Dentry>, ns: u64) -> bool {
    mount_exact_at(ns, d).is_some()
}

/// True iff some mount in `ns` is a CHILD of the mount at dentry `d` (the
/// umount(2) EBUSY busy-test). Childhood is by `parent_id` (dentry tree).
/// # C: O(N_mounts)
pub fn has_child_mounts(d: &Arc<Dentry>, ns: u64) -> bool {
    let Some(target) = mount_exact_at(ns, d) else { return false; };
    let tid = target.mnt_id;
    TABLE.lock().iter().any(|m| {
        m.ns == ns && m.mnt_id != tid && m.parent_id.load(Ordering::Acquire) == tid
    })
}

/// Find a mount by its stable `mnt_id`. # C: O(N_mounts)
pub fn mount_by_id(id: u64) -> Option<Arc<Mount>> {
    TABLE.lock().iter().find(|m| m.mnt_id == id).cloned()
}

/// The mount rooted EXACTLY at mountpoint dentry `d` in the caller's ns, by
/// the dentry crossing link (Linux `lookup_mnt`). # C: O(N_mounts)
pub fn mount_at_path_exact(d: &Arc<Dentry>) -> Option<Arc<Mount>> {
    let ns = current_ns();
    if is_global_root(d) { return root_mount_id(ns).and_then(mount_by_id); }
    let id = d.mounted_mount(ns)?;
    mount_by_id(id)
}

/// Root mount id for namespace `ns` (Linux `mnt_ns->root`). # C: O(log N)
pub fn root_mount_id(ns: u64) -> Option<u64> {
    ROOTS.lock().get(&ns).copied()
}

/// `mnt_id` of `m`'s parent mount — the value RECORDED at attach. The root
/// reports itself. No re-derivation, no string prefix. # C: O(1)
pub fn parent_mnt_id(m: &Mount) -> u64 {
    m.parent_id.load(Ordering::Acquire)
}

/// Build a `Mount` and attach it on the caller-supplied mountpoint dentry
/// `mp` (Linux `mnt_set_mountpoint`/`commit_tree`). `mp == None` ⇒ the
/// namespace root mount (Linux `mnt_ns->root`, no mountpoint dentry). `root`
/// is the bind-clone root inode (`None` = whole-fs). The rendered path is
/// derived from the dentry's parent chain (render-only). # C: O(N_mounts)
fn attach(mp: Option<Arc<Dentry>>, fs: Arc<dyn FileSystem>, root: Option<InodeRef>) -> KResult<()> {
    let ns = current_ns();
    let mnt_id = NEXT_MNT_ID.fetch_add(1, Ordering::Relaxed);
    // The global root dentry, like `None`, attaches the namespace root.
    let mp = mp.filter(|d| !is_global_root(d));
    let Some(d) = mp else {
        // `fill_super` (Linux): allocate the mounted-instance superblock with
        // its own `s_dev` and an `s_root` dentry over the fs root inode (the
        // bind/whole-fs root). The ns root has rendered path "/".
        let root_inode = root.clone().or_else(|| fs.root());
        let sb = SuperBlock::for_backend(fs, root_inode, next_anon_dev(), String::from("/"));
        ROOTS.lock().insert(ns, mnt_id);
        TABLE.lock().push(Arc::new(Mount {
            sb, rendered_path: String::from("/"), mountpoint: None,
            parent_id: AtomicU64::new(mnt_id), root, mnt_id,
            propagation: AtomicU8::new(Propagation::Private as u8),
            peer_group: AtomicU64::new(0), flags: AtomicU64::new(0), ns,
        }));
        return Ok(());
    };
    // Parent = the covering mount of the mountpoint dentry's nearest mounted
    // ancestor — by identity.
    let parent_id = parent_by_dentry(ns, &d);
    let rendered = abs_string(&d);
    let root_inode = root.clone().or_else(|| fs.root());
    let sb = SuperBlock::for_backend(fs, root_inode, next_anon_dev(), rendered.clone());
    TABLE.lock().push(Arc::new(Mount {
        sb, rendered_path: rendered, mountpoint: Some(d.clone()),
        parent_id: AtomicU64::new(parent_id), root, mnt_id,
        propagation: AtomicU8::new(Propagation::Private as u8),
        peer_group: AtomicU64::new(0), flags: AtomicU64::new(0), ns,
    }));
    wire_crossing(ns, &d, mnt_id);
    hash_insert(ns, parent_id, dptr(&d), mnt_id);
    Ok(())
}

/// Register a FileSystem on mountpoint dentry `mp` (Linux `do_new_mount`).
/// `mp == None` ⇒ the namespace root. Stacks on any existing mount at the
/// same dentry (last attached wins). # C: O(N)
pub fn register(mp: Option<Arc<Dentry>>, fs: Arc<dyn FileSystem>) -> KResult<()> {
    attach(mp, fs, None)
}

/// Bind-as-clone (`mount(src, tgt, NULL, MS_BIND)`, `docs/16§6`): attach a
/// mount on dentry `mp` whose root is the resolved source inode `root`.
/// # C: O(N_mounts)
pub fn register_bind(mp: Option<Arc<Dentry>>, fs: Arc<dyn FileSystem>, root: InodeRef) -> KResult<()> {
    attach(mp, fs, Some(root))
}

/// Propagation event delivery (`docs/16§6`): replicate the mount just
/// created at dentry `at` to every peer of its PARENT mount. Returns the
/// count propagated. Each mirror position is the peer's mountpoint dentry
/// (or the global root) DESCENDED by the relative dentry path of `at` under
/// its parent — engine-internal synthesis (`descend`), never a string
/// resolve. # C: O(N_mounts)
pub fn propagate_mount(at: &Arc<Dentry>) -> usize {
    let ns = current_ns();
    let newm = match mount_exact_at(ns, at) { Some(m) => m, None => return 0 };
    let parent = match mount_by_id(newm.parent_id.load(Ordering::Acquire)) {
        Some(p) => p, None => return 0,
    };
    let pg = parent.peer_group.load(Ordering::Acquire);
    if pg == 0 { return 0; }
    let new_mp = match newm.mountpoint.as_ref() { Some(d) => d, None => return 0 };
    // Relative path of `at` under its parent's mount location (parent's
    // mountpoint dentry, or the global root for a root parent).
    let rel = match rel_under(new_mp, parent.mountpoint.as_ref()) {
        Some(r) if !r.is_empty() => r, _ => return 0,
    };
    let root = match newm.root.clone().or_else(|| newm.fs().root()) {
        Some(r) => r, None => return 0,
    };
    let peers: Vec<Arc<Mount>> = TABLE.lock().iter()
        .filter(|m| m.ns == ns
                 && m.peer_group.load(Ordering::Acquire) == pg
                 && m.mnt_id != parent.mnt_id)
        .cloned().collect();
    let mut n = 0;
    for peer in peers {
        // Base the mirror under the peer's mountpoint dentry, or the ns root
        // when the peer IS a root mount (no mountpoint dentry).
        let base = match peer.mountpoint.clone().or_else(global_root) {
            Some(b) => b, None => continue,
        };
        let Some(dst) = descend(&base, &rel) else { continue; };
        if register_bind(Some(dst), newm.fs().clone(), root.clone()).is_ok() { n += 1; }
    }
    n
}

/// Peer group id of the mount rooted exactly at dentry `d`, or 0.
/// # C: O(N_mounts)
pub fn peer_group_of(d: &Arc<Dentry>) -> u64 {
    mount_exact_at(current_ns(), d)
        .map(|m| m.peer_group.load(Ordering::Acquire)).unwrap_or(0)
}

/// MS_SHARED peer-group inheritance (`docs/16§6`). # C: O(N_mounts)
pub fn join_peer_group(d: &Arc<Dentry>, pg: u64) {
    if pg == 0 { return; }
    if let Some(m) = mount_exact_at(current_ns(), d) {
        m.peer_group.store(pg, Ordering::Release);
        m.propagation.store(Propagation::Shared as u8, Ordering::Release);
    }
}

/// `mnt_id`s of `top` plus its transitive children by `parent_id` (the
/// dentry subtree), in `ns`. # C: O(N_mounts²)
fn subtree_ids(ns: u64, top: u64) -> Vec<u64> {
    let mut ids = alloc::vec![top];
    let t = TABLE.lock();
    let mut frontier = alloc::vec![top];
    while let Some(pid) = frontier.pop() {
        for m in t.iter() {
            if m.ns == ns && m.mnt_id != pid
                && m.parent_id.load(Ordering::Acquire) == pid
                && !ids.contains(&m.mnt_id) {
                ids.push(m.mnt_id);
                frontier.push(m.mnt_id);
            }
        }
    }
    ids
}

/// `pivot_root(new_root, put_old)` (`docs/16§6`): make the mount at
/// `new_root` the namespace root and relocate the old tree under `put_old`.
/// Identity-checked (new_root must be a mount; put_old must lie under
/// new_root and not be a mount). After the move, the namespace index is
/// rebuilt from the re-recorded mountpoint dentries. # C: O(N_mounts × depth)
pub fn pivot_root(new_root: &Arc<Dentry>, put_old: &Arc<Dentry>) -> KResult<()> {
    let ns = current_ns();
    let nr_m = mount_exact_at(ns, new_root).ok_or(VfsError::Einval)?;
    let nr_mp = nr_m.mountpoint.clone();
    let nr_id = nr_m.mnt_id;
    let nr_subtree = subtree_ids(ns, nr_id);
    let po_d = put_old.clone();
    let root_id = root_mount_id(ns);
    let mounts: Vec<Arc<Mount>> = TABLE.lock().iter().filter(|m| m.ns == ns).cloned().collect();
    // pivot_root(".", ".") — put_old IS new_root's location: the old root
    // tree stays at its paths and stacks on top of new_root at "/", which the
    // caller drops with `umount2(".", MNT_DETACH)`. Detected by dentry
    // identity BEFORE the "put_old is a mount" check (it IS new_root's mount).
    let stacking = nr_mp.as_ref().map(|d| Arc::ptr_eq(d, &po_d)).unwrap_or(false)
        || rel_under(&po_d, nr_mp.as_ref()) == Some(String::new());
    if stacking {
        let new_paths: Vec<(u64, String)> = mounts.iter().map(|m| {
            let np = if m.mnt_id == nr_id {
                String::from("/")
            } else if nr_subtree.contains(&m.mnt_id) {
                m.mountpoint.as_ref().and_then(|d| rel_under(d, nr_mp.as_ref()))
                    .unwrap_or_else(|| m.rendered_path.clone())
            } else {
                m.rendered_path.clone()        // old tree stacks at same paths
            };
            (m.mnt_id, np)
        }).collect();
        commit_retree(ns, &new_paths, Some(nr_id));
        return Ok(());
    }
    // put_old must lie under new_root (identity-bounded relative walk) and
    // must not itself be a mount.
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
            m.mountpoint.as_ref().and_then(|d| rel_under(d, nr_mp.as_ref()))
                .unwrap_or_else(|| m.rendered_path.clone())
        } else if Some(m.mnt_id) == root_id {
            old_dst.clone()
        } else {
            let abs = m.mountpoint.as_ref().and_then(|d| rel_under(d, None))
                .unwrap_or_else(|| m.rendered_path.clone());
            alloc::format!("{}{}", old_dst, abs)
        };
        (m.mnt_id, np)
    }).collect();
    commit_retree(ns, &new_paths, Some(nr_id));
    Ok(())
}

/// Commit a whole-namespace path rewrite: clear old crossings, MATERIALISE
/// each mount's new mountpoint dentry by descending its new absolute-from-
/// new-root path from the global root (`descend` — engine-internal synthesis,
/// not a string resolver), install it + the derived rendered path, then
/// rebuild the ns index (crossings + parent + hash) by identity.
/// `new_root_id`, when given, becomes the ns root. # C: O(N×depth)
fn commit_retree(ns: u64, new_paths: &[(u64, String)], new_root_id: Option<u64>) {
    // Clear old crossings for this ns (snapshot dentries first so the dentry
    // locks aren't taken while the table lock is held).
    let old_dents: Vec<Arc<Dentry>> = TABLE.lock().iter()
        .filter(|m| m.ns == ns).filter_map(|m| m.mountpoint.clone()).collect();
    for d in old_dents.iter() { d.set_mounted_mount(ns, None); }
    if let Some(rid) = new_root_id { ROOTS.lock().insert(ns, rid); }
    // Materialise each new mountpoint dentry by descending from the ns root
    // (positions are absolute-from-new-root); the new-root mount itself has
    // no mountpoint dentry.
    let root = global_root();
    let dents: Vec<(u64, String, Option<Arc<Dentry>>)> = new_paths.iter().map(|(id, p)| {
        let is_root = Some(*id) == new_root_id;
        let d = if is_root { None } else { root.as_ref().and_then(|r| descend(r, p)) };
        (*id, p.clone(), d)
    }).collect();
    let mut t = TABLE.lock();
    for i in 0..t.len() {
        if t[i].ns != ns { continue; }
        if let Some((_, p, d)) = dents.iter().find(|(id, _, _)| *id == t[i].mnt_id) {
            let is_root = Some(t[i].mnt_id) == new_root_id;
            t[i] = with_mountpoint_path(&t[i], if is_root { None } else { d.clone() }, p.clone());
        }
    }
    drop(t);
    rebuild_ns_index(ns);
}

/// `umount`: remove the mount rooted exactly at mountpoint dentry `d` (and
/// detach its crossing). Returns the count removed. # C: O(N_mounts)
pub fn unregister(d: &Arc<Dentry>) -> usize {
    let ns = current_ns();
    let Some(target) = mount_exact_at(ns, d) else { return 0; };
    let id = target.mnt_id;
    let mp = target.mountpoint.clone();
    let parent = target.parent_id.load(Ordering::Acquire);
    {
        let mut t = TABLE.lock();
        t.retain(|m| !(m.ns == ns && m.mnt_id == id));
    }
    if let Some(d) = mp.as_ref() {
        hash_remove(ns, parent, dptr(d), id);
        rewire_crossing_top(ns, d, parent);
    }
    1
}

/// Re-point the dentry crossing link to the new hash top after a detach
/// (re-expose a stacked underlay), or clear it if none remain. # C: O(log N)
fn rewire_crossing_top(ns: u64, d: &Arc<Dentry>, parent: u64) {
    match hash_top(ns, parent, dptr(d)) {
        Some(top) => d.set_mounted_mount(ns, Some(top)),
        None => d.set_mounted_mount(ns, None),
    }
}

/// Detach the top mount at mountpoint dentry `d`; with `detach_subtree`, also
/// its transitive children by `parent_id`. Stacked overmounts at the same
/// dentry are NOT children and survive (re-exposed). # C: O(N_mounts)
pub fn unregister_top(d: &Arc<Dentry>, detach_subtree: bool) -> usize {
    let ns = current_ns();
    let Some(top) = mount_exact_at(ns, d) else { return 0; };
    let top_id = top.mnt_id;
    // Never detach the sole namespace root (there is exactly one root id per
    // ns in ROOTS, so the root is never removable here).
    if root_mount_id(ns) == Some(top_id) { return 0; }
    let remove_ids: Vec<u64> = if detach_subtree { subtree_ids(ns, top_id) } else { alloc::vec![top_id] };
    // Capture (id, parent, mountpoint) for hash/crossing cleanup.
    let victims: Vec<(u64, u64, Option<Arc<Dentry>>)> = TABLE.lock().iter()
        .filter(|m| m.ns == ns && remove_ids.contains(&m.mnt_id))
        .map(|m| (m.mnt_id, m.parent_id.load(Ordering::Acquire), m.mountpoint.clone()))
        .collect();
    {
        let mut t = TABLE.lock();
        t.retain(|m| !(m.ns == ns && remove_ids.contains(&m.mnt_id)));
    }
    let mut removed = 0;
    for (id, parent, mp) in victims.iter() {
        removed += 1;
        if let Some(d) = mp.as_ref() {
            hash_remove(ns, *parent, dptr(d), *id);
            rewire_crossing_top(ns, d, *parent);
        }
    }
    removed
}

/// Copy-on-unshare (`docs/16§6`): clone every mount in `from_ns` into
/// `to_ns` as a fresh independent mount, then rebuild `to_ns`'s index by
/// identity (per-ns crossing links + parent + hash). # C: O(N_mounts)
pub fn snapshot_ns(from_ns: u64, to_ns: u64) {
    let clones: Vec<Arc<Mount>> = {
        let t = TABLE.lock();
        t.iter().filter(|m| m.ns == from_ns).map(|m| {
            let new_id = NEXT_MNT_ID.fetch_add(1, Ordering::Relaxed);
            Arc::new(Mount {
                sb: m.sb.clone(),
                rendered_path: m.rendered_path.clone(),
                mountpoint: m.mountpoint.clone(),
                parent_id: AtomicU64::new(0),
                root: m.root.clone(),
                mnt_id: new_id,
                propagation: AtomicU8::new(m.propagation.load(Ordering::Acquire)),
                peer_group: AtomicU64::new(m.peer_group.load(Ordering::Acquire)),
                flags: AtomicU64::new(m.flags.load(Ordering::Acquire)),
                ns: to_ns,
            })
        }).collect()
    };
    // Map the from_ns root clone to be to_ns's root (identity by mountpoint
    // None — the cloned root mount).
    for c in clones.iter() {
        if c.mountpoint.is_none() { ROOTS.lock().insert(to_ns, c.mnt_id); }
    }
    TABLE.lock().extend(clones);
    rebuild_ns_index(to_ns);
}

/// MS_REC recursive bind (`docs/16§6`): after `src`→`tgt` is bound, clone
/// every mount nested under `src` to the matching path under `tgt`. Submounts
/// are found by dentry ancestry (identity), not string prefix. # C: O(N)
pub fn bind_submounts_rec(src: &Arc<Dentry>, tgt: &Arc<Dentry>) -> usize {
    let ns = current_ns();
    // src's mountpoint dentry bounds "strict submount". The ns root has none
    // (mount_exact_at returns the root mount whose `mountpoint` is None), in
    // which case every non-root mount's absolute path is its relative path.
    let src_m = mount_exact_at(ns, src);
    if src_m.is_none() && !is_global_root(src) { return 0; }
    let src_id = src_m.as_ref().map(|m| m.mnt_id);
    let src_mp = src_m.and_then(|m| m.mountpoint.clone());
    let snap: Vec<Arc<Mount>> = TABLE.lock().clone();
    let mut n = 0;
    for m in snap.iter() {
        if m.ns != ns || Some(m.mnt_id) == src_id { continue; }
        let Some(mp) = m.mountpoint.as_ref() else { continue; };
        // Skip mounts already at/under the target (don't clone onto self).
        if rel_under(mp, Some(tgt)).is_some() { continue; }
        // Strict submount: mp under src's mountpoint dentry (identity).
        let Some(rel) = rel_under(mp, src_mp.as_ref()) else { continue; };
        if rel.is_empty() { continue; }
        // Mirror position = the bind target dentry descended by `rel`
        // (engine-internal synthesis, not a string resolve).
        let Some(new_mp) = descend(tgt, &rel) else { continue; };
        let root = m.root.clone().or_else(|| m.fs().root());
        if let Some(r) = root {
            if register_bind(Some(new_mp), m.fs().clone(), r).is_ok() { n += 1; }
        }
    }
    n
}

/// `mount(MS_MOVE)`: relocate the mount at dentry `from` (plus its subtree)
/// to dentry `to`. `Einval` if no mount at `from`; `Ebusy` if `to` is already
/// covered. Each moved mount's NEW mountpoint dentry is MATERIALISED by
/// descending from the ns root (`descend` — engine-internal synthesis), and
/// the rendered path derived from it; the ns index rebuilt by identity. The
/// ns root `/` has no covering dentry, so MS_MOVE-onto-`/` is permitted.
/// # C: O(N × depth)
pub fn move_mount(from: &Arc<Dentry>, to: &Arc<Dentry>) -> KResult<()> {
    let ns = current_ns();
    let from_m = mount_exact_at(ns, from).ok_or(VfsError::Einval)?;
    let to_root = is_global_root(to);
    if !to_root && to.mounted_mount(ns).is_some() { return Err(VfsError::Ebusy); }
    let to_abs = if to_root { String::new() } else { abs_string(to) };
    let from_id = from_m.mnt_id;
    let from_mp = from_m.mountpoint.clone();
    let moved = subtree_ids(ns, from_id);
    // Build new absolute-from-root paths for the moved set: top → `to`; child
    // → `to` + child's relative dentry path under `from`'s mountpoint.
    let snap: Vec<Arc<Mount>> = TABLE.lock().iter()
        .filter(|m| m.ns == ns && moved.contains(&m.mnt_id)).cloned().collect();
    let mut new_paths: Vec<(u64, String)> = Vec::new();
    for m in snap.iter() {
        let np = if m.mnt_id == from_id {
            if to_root { String::from("/") } else { to_abs.clone() }
        } else {
            match m.mountpoint.as_ref().and_then(|d| rel_under(d, from_mp.as_ref())) {
                Some(rel) if !rel.is_empty() => alloc::format!("{}{}", to_abs, rel),
                _ => m.rendered_path.clone(),
            }
        };
        new_paths.push((m.mnt_id, np));
    }
    // Detach moved crossings + hash, materialise new dentries, re-attach.
    for m in snap.iter() {
        if let Some(d) = m.mountpoint.as_ref() {
            let parent = m.parent_id.load(Ordering::Acquire);
            hash_remove(ns, parent, dptr(d), m.mnt_id);
            d.set_mounted_mount(ns, None);
        }
    }
    let root = global_root();
    let dents: Vec<(u64, String, Option<Arc<Dentry>>)> = new_paths.iter()
        .map(|(id, p)| {
            let d = if p == "/" { None } else { root.as_ref().and_then(|r| descend(r, p)) };
            (*id, p.clone(), d)
        })
        .collect();
    {
        let mut t = TABLE.lock();
        for i in 0..t.len() {
            if t[i].ns != ns || !moved.contains(&t[i].mnt_id) { continue; }
            if let Some((_, p, d)) = dents.iter().find(|(id, _, _)| *id == t[i].mnt_id) {
                t[i] = with_mountpoint_path(&t[i], d.clone(), p.clone());
            }
        }
    }
    // Re-wire crossings + parent + hash for the moved set (identity).
    let moved_mounts: Vec<Arc<Mount>> = TABLE.lock().iter()
        .filter(|m| m.ns == ns && moved.contains(&m.mnt_id)).cloned().collect();
    for m in moved_mounts.iter() {
        if let Some(d) = m.mountpoint.as_ref() { wire_crossing(ns, d, m.mnt_id); }
    }
    for m in moved_mounts.iter() {
        if let Some(d) = m.mountpoint.as_ref() {
            let parent = parent_by_dentry(ns, d);
            m.parent_id.store(parent, Ordering::Release);
            hash_insert(ns, parent, dptr(d), m.mnt_id);
        }
    }
    Ok(())
}

/// Retune the propagation type of the mount at dentry `d`. # C: O(N)
pub fn set_propagation(d: &Arc<Dentry>, kind: Propagation) -> KResult<()> {
    let m = mount_exact_at(current_ns(), d).ok_or(VfsError::Einval)?;
    m.propagation.store(kind as u8, Ordering::Release);
    match kind {
        Propagation::Shared => {
            if m.peer_group.load(Ordering::Acquire) == 0 {
                m.peer_group.store(NEXT_PEER_GROUP.fetch_add(1, Ordering::Relaxed), Ordering::Release);
            }
        }
        Propagation::Private | Propagation::Unbindable => {
            m.peer_group.store(0, Ordering::Release);
        }
        Propagation::Slave => {}
    }
    Ok(())
}

/// Update the per-mount option bits on the mount at dentry `d`. # C: O(N_mounts)
pub fn remount_flags(d: &Arc<Dentry>, flags: u64) -> KResult<()> {
    let m = mount_exact_at(current_ns(), d).ok_or(VfsError::Einval)?;
    let old = m.flags.load(Ordering::Acquire);
    let new = (old & !MNT_OPTION_MASK) | (flags & MNT_OPTION_MASK);
    m.flags.store(new, Ordering::Release);
    Ok(())
}

/// The mount that OWNS `path` (the fs whose subtree contains it), by a
/// dentry-identity mount-identification walk (Linux `path_lookup`'s mount
/// crossing), NOT a longest-`mount_point` string scan. Returns
/// `(mount, path)` with `path` unchanged (backends key on absolute paths).
/// Resolves to the owning mount of the deepest existing ancestor when the
/// final component does not yet exist (open-create/rename/link callers).
/// # C: O(path components)
pub fn resolve_mount(path: &str) -> Option<(Arc<Mount>, String)> {
    let ns = current_ns();
    let id = crate::namei::walk_to_mount(path).or_else(|| root_mount_id(ns))?;
    let m = mount_by_id(id)?;
    if m.ns != ns { return root_mount_id(ns).and_then(mount_by_id).map(|r| (r, path.to_string())); }
    Some((m, path.to_string()))
}

/// True when the mount that owns `path` is remounted read-only. # C: O(N)
pub fn is_readonly_path(path: &str) -> bool {
    resolve_mount(path)
        .map(|(m, _)| (m.flags.load(Ordering::Acquire) & MNT_RDONLY) != 0)
        .unwrap_or(false)
}

/// Whole-path → inode resolver, now implemented PURELY per-component: walk
/// `path` from the global root dentry via `d_lookup → i_op->lookup → d_add`,
/// crossing mounts by dentry identity (`docs/16§3`). No `FileSystem::lookup`.
/// Retained only as a convenience for callers (inotify dirent hooks) that
/// hold a path string rather than a walked dentry.
/// # C: O(path components)
pub fn lookup(path: &str) -> KResult<InodeRef> {
    crate::namei::resolve_abs(path)
}

/// Root inode of the mount rooted EXACTLY at mountpoint dentry `d` in the
/// caller's ns, or `None` if nothing is mounted there (or it's the global
/// root). By dentry identity. # C: O(N_mounts)
pub fn mount_root_at(d: &Arc<Dentry>) -> Option<InodeRef> {
    if is_global_root(d) { return None; }
    let m = mount_at_path_exact(d)?;
    if let Some(r) = m.root.as_ref() { return Some(r.clone()); }
    m.fs().root()
}

/// Root inode of a concrete mount id (the path walk's crossing primitive).
/// Every mounted fs publishes its `s_root` inode via `m.root` (bind/tmpfs)
/// or `FileSystem::root()` — never a whole-path lookup.
/// # C: O(N_mounts)
pub fn root_for_mount_id(mnt_id: u64) -> Option<InodeRef> {
    let t = TABLE.lock();
    let m = t.iter().find(|m| m.mnt_id == mnt_id)?;
    m.root.clone().or_else(|| m.fs().root())
}

/// Snapshot the caller's mount-namespace view (for /proc mounts +
/// mountinfo). # C: O(N_mounts)
pub fn snapshot() -> Vec<Arc<Mount>> {
    let ns = current_ns();
    TABLE.lock().iter().filter(|m| m.ns == ns).cloned().collect()
}

/// Snapshot ALL mounts regardless of namespace (kernel-internal audits).
/// # C: O(N_mounts)
pub fn snapshot_all() -> Vec<Arc<Mount>> {
    TABLE.lock().clone()
}
