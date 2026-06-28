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
use core::sync::atomic::{AtomicI32, AtomicU8, AtomicU64, Ordering};
use sync::{MountTable as MountClass, Spinlock};

use crate::dentry::Dentry;
use crate::fs::{FileSystem, KResult};
use crate::inode::InodeRef;
use crate::mntns::{self, get_mountpoint, put_mountpoint, Mountpoint};
use crate::superblock::{next_anon_dev, SuperBlock};
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
pub use propagation::{join_peer_group, peer_group_of, propagate_mount};
use propagation::propagation_targets;

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

/// `mnt_id` of the mount in `ns` rooted at dentry `d`. # C: O(N_mounts)
fn mnt_id_of_root_dentry(ns: u64, d: &Arc<Dentry>) -> Option<u64> {
    mount_with_root_dentry(ns, d).map(|m| m.mnt_id)
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
// (ns, parent_mnt_id, mountpoint_dentry_ptr) -> mnt_id stack — Linux
// `__lookup_mnt`. Top of stack = last attached (overmounts).
// ---------------------------------------------------------------------------
static MOUNT_HASH: Spinlock<BTreeMap<(u64, u64, usize), Vec<u64>>, MountClass> =
    Spinlock::new(BTreeMap::new());

fn hash_insert(ns: u64, parent: u64, d: usize, mnt_id: u64) {
    MOUNT_HASH.lock().entry((ns, parent, d)).or_default().push(mnt_id);
}
fn hash_remove(ns: u64, parent: u64, d: usize, mnt_id: u64) {
    let mut h = MOUNT_HASH.lock();
    if let Some(stack) = h.get_mut(&(ns, parent, d)) {
        stack.retain(|&id| id != mnt_id);
        if stack.is_empty() { h.remove(&(ns, parent, d)); }
    }
}
fn hash_top(ns: u64, parent: u64, d: usize) -> Option<u64> {
    MOUNT_HASH.lock().get(&(ns, parent, d)).and_then(|s| s.last().copied())
}
fn hash_drop_ns(ns: u64) {
    MOUNT_HASH.lock().retain(|k, _| k.0 != ns);
}

/// Parent mount id for a mount whose mountpoint dentry is `mp_d`, by DENTRY
/// IDENTITY (Linux `mnt_parent`). # C: O(depth)
fn parent_by_dentry(ns: u64, mp_d: &Arc<Dentry>) -> u64 {
    let mut cur = mp_d.parent().cloned();
    while let Some(a) = cur {
        if let Some(id) = a.mounted_mount(ns) { return id; }
        if a.is_root() {
            if let Some(id) = mnt_id_of_root_dentry(ns, &a) { return id; }
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
    hash_drop_ns(ns);
    let mounts = mounts_in_ns(ns);
    // Clear crossings + parent/child links first.
    for m in mounts.iter() {
        if let Some(d) = m.mountpoint() { d.set_mounted_mount(ns, None); }
        m.mnt_mounts.lock().clear();
        *m.mnt_parent.lock() = Weak::new();
    }
    // Re-wire crossings (top wins by ascending mnt_id = stack order).
    for m in mounts.iter() {
        if let Some(d) = m.mountpoint() { wire_crossing(ns, &d, m.mnt_id); }
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
                hash_insert(ns, parent, dptr(&d), m.mnt_id);
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

/// Monotonic mount-id source (mountinfo field 1). Starts at 1.
static NEXT_MNT_ID: AtomicU64 = AtomicU64::new(1);
/// Monotonic peer-group id source. Starts at 1 (0 = none).
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
    /// Bind-as-clone root inode (Linux `mnt_root` inode); `None` = whole-fs.
    pub root: Option<InodeRef>,
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
    let id = hash_top(ns, parent, dptr(d))?;
    mount_by_id(id)
}

/// True iff a mount is attached exactly at mountpoint dentry `d` in `ns`.
/// # C: O(log N)
pub fn is_mount_in_ns(d: &Arc<Dentry>, ns: u64) -> bool {
    mount_exact_at(ns, d).is_some()
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
             parent_id: u64, root: Option<InodeRef>, mnt_id: u64, ns: u64) -> Arc<Mount> {
    let mnt_root = sb.s_root();
    Arc::new(Mount {
        sb, rendered_path: Spinlock::new(rendered), mountpoint: Spinlock::new(mountpoint),
        parent_id: AtomicU64::new(parent_id), root, mnt_id,
        propagation: AtomicU8::new(Propagation::Private as u8),
        peer_group: AtomicU64::new(0), flags: AtomicU64::new(0), ns,
        mnt_root: Spinlock::new(mnt_root),
        mnt_parent: Spinlock::new(Weak::new()),
        mnt_mounts: Spinlock::new(Vec::new()),
        mnt_mp: Spinlock::new(None),
        mnt_master: Spinlock::new(Weak::new()),
        mnt_slave_list: Spinlock::new(Vec::new()),
        mnt_writers: AtomicI32::new(0),
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

/// Build a `Mount` and attach it on the caller-supplied mountpoint dentry
/// `mp` (Linux `mnt_set_mountpoint`/`commit_tree`). `mp == None` ⇒ the
/// namespace root mount. # C: O(depth)
fn attach(mp: Option<Arc<Dentry>>, fs: Arc<dyn FileSystem>, root: Option<InodeRef>) -> KResult<()> {
    let ns = current_ns();
    let mnt_id = NEXT_MNT_ID.fetch_add(1, Ordering::Relaxed);
    let mp = mp.filter(|d| !is_global_root(d));
    let Some(d) = mp else {
        let root_inode = root.clone().or_else(|| fs.root());
        let sb = SuperBlock::for_backend(fs, root_inode, next_anon_dev(), String::from("/"));
        let m = new_mount(sb, String::from("/"), None, mnt_id, root, mnt_id, ns);
        mntns::ns_set_root(ns, mnt_id);
        MOUNTS.lock().insert(mnt_id, m);
        mntns::bump_gen(ns);
        return Ok(());
    };
    let parent_id = parent_by_dentry(ns, &d);
    let rendered = abs_string(&d);
    let root_inode = root.clone().or_else(|| fs.root());
    let sb = SuperBlock::for_backend(fs, root_inode, next_anon_dev(), rendered.clone());
    let m = new_mount(sb, rendered, Some(d.clone()), parent_id, root, mnt_id, ns);
    // struct mountpoint (dentry refcount) + intrusive parent/child links.
    *m.mnt_mp.lock() = Some(get_mountpoint(&d));
    if let Some(p) = mount_by_id(parent_id) {
        *m.mnt_parent.lock() = Arc::downgrade(&p);
        p.mnt_mounts.lock().push(m.clone());
    }
    MOUNTS.lock().insert(mnt_id, m);
    wire_crossing(ns, &d, mnt_id);
    hash_insert(ns, parent_id, dptr(&d), mnt_id);
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
        commit_retree(ns, &new_paths, Some(nr_id));
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
    commit_retree(ns, &new_paths, Some(nr_id));
    if let Some(old) = old_root_id { mntns::chroot_fs_refs(old, nr_id); }
    Ok(())
}

/// Commit a whole-namespace path rewrite: MATERIALISE each mount's new
/// mountpoint dentry by descending from the ns root, mutate it in place, then
/// rebuild the ns index (links + crossings + hash) by identity. # C: O(N×depth)
fn commit_retree(ns: u64, new_paths: &[(u64, String)], new_root_id: Option<u64>) {
    let mounts = mounts_in_ns(ns);
    for m in mounts.iter() { if let Some(d) = m.mountpoint() { d.set_mounted_mount(ns, None); } }
    if let Some(rid) = new_root_id { mntns::ns_set_root(ns, rid); }
    let root = global_root();
    let dents: Vec<(u64, String, Option<Arc<Dentry>>)> = new_paths.iter().map(|(id, p)| {
        let is_root = Some(*id) == new_root_id;
        let d = if is_root { None } else { root.as_ref().and_then(|r| descend(r, p)) };
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

/// Last-umount teardown (Linux `deactivate_super` → `put_super`): run
/// `put_super` on `sb` IFF no other live mount still references it. The O(N)
/// `Arc::ptr_eq` scan stands in for the not-yet-built `s_active` refcount (D6):
/// every mount today builds a unique SB via `for_backend`, so a victim's SB is
/// shared only by bind clones of the SAME `Arc<Mount>` (none today) — the scan
/// is exact. Call AFTER the victim is removed from `MOUNTS` so it is not
/// self-counted. # C: O(N_mounts)
fn put_super_if_last(sb: &Arc<SuperBlock>) {
    let still_used = MOUNTS.lock().values().any(|m| Arc::ptr_eq(&m.sb, sb));
    if !still_used { sb.put_super(); }
}

/// Unlink `id` from its parent's intrusive child list. # C: O(siblings)
fn unlink_from_parent(m: &Arc<Mount>) {
    if let Some(p) = m.mnt_parent.lock().upgrade() {
        p.mnt_mounts.lock().retain(|c| c.mnt_id != m.mnt_id);
    }
}

/// `umount`: remove the mount rooted exactly at mountpoint dentry `d`.
/// Returns the count removed. # C: O(log N)
pub fn unregister(d: &Arc<Dentry>) -> usize {
    let ns = current_ns();
    let Some(target) = mount_exact_at(ns, d) else { return 0; };
    let id = target.mnt_id;
    let mp = target.mountpoint();
    let parent = target.parent_id.load(Ordering::Acquire);
    let sb = target.sb.clone();
    unlink_from_parent(&target);
    if let Some(o) = target.mnt_mp.lock().take() { put_mountpoint(&o); }
    MOUNTS.lock().remove(&id);
    if let Some(d) = mp.as_ref() {
        hash_remove(ns, parent, dptr(d), id);
        rewire_crossing_top(ns, d, parent);
    }
    // Last-mount of this SB → `put_super` (flush + drop s_root + clear icache).
    put_super_if_last(&sb);
    mntns::bump_gen(ns);
    1
}

/// Re-point the dentry crossing link to the new hash top after a detach.
/// # C: O(log N)
fn rewire_crossing_top(ns: u64, d: &Arc<Dentry>, parent: u64) {
    match hash_top(ns, parent, dptr(d)) {
        Some(top) => d.set_mounted_mount(ns, Some(top)),
        None => d.set_mounted_mount(ns, None),
    }
}

/// Detach the top mount at dentry `d`; with `detach_subtree`, also its
/// transitive children. Also propagates the umount to the parent's
/// propagation targets (Linux `propagate_umount`). # C: O(N_mounts)
pub fn unregister_top(d: &Arc<Dentry>, detach_subtree: bool) -> usize {
    let ns = current_ns();
    let Some(top) = mount_exact_at(ns, d) else { return 0; };
    let top_id = top.mnt_id;
    if root_mount_id(ns) == Some(top_id) { return 0; }
    // propagate_umount: detach the mirror at every propagation target of the
    // parent before removing the primary (Linux unmounts propagated copies).
    if let Some(parent) = mount_by_id(top.parent_id.load(Ordering::Acquire)) {
        if let Some(top_mp) = top.mountpoint() {
            if let Some(rel) = rel_under(&top_mp, parent.mountpoint().as_ref()) {
                if !rel.is_empty() {
                    for peer in propagation_targets(&parent) {
                        if peer.ns != ns { continue; }
                        let base = match peer.mountpoint().or_else(global_root) { Some(b) => b, None => continue };
                        if let Some(mirror) = descend(&base, &rel) {
                            let _ = unregister(&mirror);
                        }
                    }
                }
            }
        }
    }
    let remove_ids: Vec<u64> = if detach_subtree { subtree_ids(ns, top_id) } else { alloc::vec![top_id] };
    let victims: Vec<Arc<Mount>> = remove_ids.iter().filter_map(|id| mount_by_id(*id)).collect();
    let mut removed = 0;
    for m in victims.iter() {
        let parent = m.parent_id.load(Ordering::Acquire);
        let mp = m.mountpoint();
        unlink_from_parent(m);
        if let Some(o) = m.mnt_mp.lock().take() { put_mountpoint(&o); }
        MOUNTS.lock().remove(&m.mnt_id);
        if let Some(dd) = mp.as_ref() {
            hash_remove(ns, parent, dptr(dd), m.mnt_id);
            rewire_crossing_top(ns, dd, parent);
        }
        // Last-mount of this victim's SB → `put_super`. Done per-victim AFTER
        // removal so a still-present sibling sharing the SB blocks teardown.
        put_super_if_last(&m.sb);
        removed += 1;
    }
    mntns::bump_gen(ns);
    removed
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
        let clone = new_mount(
            m.sb.clone(), m.mount_point_str(), m.mountpoint(),
            0, m.root.clone(), new_id, to_ns,
        );
        clone.flags.store(m.flags.load(Ordering::Acquire), Ordering::Release);
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
    rebuild_ns_index(to_ns);
    mntns::bump_gen(to_ns);
}

/// Back-compat alias for the unshare(CLONE_NEWNS) call site. # C: O(N×depth)
pub fn snapshot_ns(from_ns: u64, to_ns: u64) { copy_mnt_ns(from_ns, to_ns); }

/// Reap every mount belonging to `ns` (Linux `free_mnt_ns` at last task
/// exit). Drops the per-ns crossings, the hash, the `struct mountpoint`
/// refcounts, and the global-map entries. # C: O(N_ns_mounts)
pub(crate) fn reap_ns(ns: u64) {
    let mounts = mounts_in_ns(ns);
    for m in mounts.iter() {
        if let Some(d) = m.mountpoint() { d.set_mounted_mount(ns, None); }
        if let Some(o) = m.mnt_mp.lock().take() { put_mountpoint(&o); }
        m.mnt_mounts.lock().clear();
        MOUNTS.lock().remove(&m.mnt_id);
    }
    hash_drop_ns(ns);
    mntns::bump_gen(ns);
}

/// MS_REC recursive bind (`docs/16§6`). # C: O(N×depth)
pub fn bind_submounts_rec(src: &Arc<Dentry>, tgt: &Arc<Dentry>) -> usize {
    let ns = current_ns();
    let src_m = mount_exact_at(ns, src);
    if src_m.is_none() && !is_global_root(src) { return 0; }
    // Unbindable sources are not cloned (Linux `IS_MNT_UNBINDABLE`).
    if let Some(ref sm) = src_m {
        if Propagation::from_u8(sm.propagation.load(Ordering::Acquire)) == Propagation::Unbindable {
            return 0;
        }
    }
    let src_id = src_m.as_ref().map(|m| m.mnt_id);
    let src_mp = src_m.and_then(|m| m.mountpoint());
    let snap = mounts_in_ns(ns);
    let mut n = 0;
    for m in snap.iter() {
        if Some(m.mnt_id) == src_id { continue; }
        if Propagation::from_u8(m.propagation.load(Ordering::Acquire)) == Propagation::Unbindable { continue; }
        let Some(mp) = m.mountpoint() else { continue; };
        if rel_under(&mp, Some(tgt)).is_some() { continue; }
        let Some(rel) = rel_under(&mp, src_mp.as_ref()) else { continue; };
        if rel.is_empty() { continue; }
        let Some(new_mp) = descend(tgt, &rel) else { continue; };
        let root = m.root.clone().or_else(|| m.fs().root());
        if let Some(r) = root {
            if register_bind(Some(new_mp), m.fs().clone(), r).is_ok() { n += 1; }
        }
    }
    n
}

/// `mount(MS_MOVE)`: relocate the mount at dentry `from` (plus its subtree) to
/// dentry `to`. # C: O(N × depth)
pub fn move_mount(from: &Arc<Dentry>, to: &Arc<Dentry>) -> KResult<()> {
    let ns = current_ns();
    let from_m = mount_exact_at(ns, from).ok_or(VfsError::Einval)?;
    let to_root = is_global_root(to);
    if !to_root && to.mounted_mount(ns).is_some() { return Err(VfsError::Ebusy); }
    let to_abs = if to_root { String::new() } else { abs_string(to) };
    let from_id = from_m.mnt_id;
    let from_mp = from_m.mountpoint();
    let moved = subtree_ids(ns, from_id);
    let snap: Vec<Arc<Mount>> = moved.iter().filter_map(|id| mount_by_id(*id)).collect();
    let mut new_paths: Vec<(u64, String)> = Vec::new();
    for m in snap.iter() {
        let np = if m.mnt_id == from_id {
            if to_root { String::from("/") } else { to_abs.clone() }
        } else {
            match m.mountpoint().and_then(|d| rel_under(&d, from_mp.as_ref())) {
                Some(rel) if !rel.is_empty() => alloc::format!("{}{}", to_abs, rel),
                _ => m.mount_point_str(),
            }
        };
        new_paths.push((m.mnt_id, np));
    }
    // Detach moved crossings + hash, then materialise + re-seat new dentries.
    for m in snap.iter() {
        if let Some(d) = m.mountpoint() {
            let parent = m.parent_id.load(Ordering::Acquire);
            hash_remove(ns, parent, dptr(&d), m.mnt_id);
            d.set_mounted_mount(ns, None);
        }
    }
    let root = global_root();
    for (id, p) in new_paths.iter() {
        let Some(m) = mount_by_id(*id) else { continue; };
        let d = if p == "/" { None } else { root.as_ref().and_then(|r| descend(r, p)) };
        set_mountpoint_dentry(&m, d, p.clone());
    }
    // Re-wire crossings + parent/child links + hash for the moved set.
    for m in snap.iter() {
        if let Some(d) = m.mountpoint() { wire_crossing(ns, &d, m.mnt_id); }
        m.mnt_mounts.lock().clear();
    }
    for m in snap.iter() {
        if let Some(d) = m.mountpoint() {
            let parent = parent_by_dentry(ns, &d);
            m.parent_id.store(parent, Ordering::Release);
            if let Some(p) = mount_by_id(parent) {
                *m.mnt_parent.lock() = Arc::downgrade(&p);
                p.mnt_mounts.lock().push(m.clone());
            }
            hash_insert(ns, parent, dptr(&d), m.mnt_id);
        }
    }
    mntns::bump_gen(ns);
    Ok(())
}

/// Retune the propagation type of the mount at dentry `d` (`docs/16§6`).
/// MS_SLAVE on a shared mount links it as a slave of its current peer group
/// (Linux `change_mnt_propagation` → `CL_SLAVE`). # C: O(N_mounts)
pub fn set_propagation(d: &Arc<Dentry>, kind: Propagation) -> KResult<()> {
    let m = mount_exact_at(current_ns(), d).ok_or(VfsError::Einval)?;
    match kind {
        Propagation::Shared => {
            if m.peer_group.load(Ordering::Acquire) == 0 {
                m.peer_group.store(NEXT_PEER_GROUP.fetch_add(1, Ordering::Relaxed), Ordering::Release);
            }
            m.propagation.store(Propagation::Shared as u8, Ordering::Release);
        }
        Propagation::Slave => {
            // Become a slave of the current peer group: pick a master from the
            // group (another shared peer) and link master↔slave. Keep
            // peer_group for the `master:<pg>` mountinfo render.
            let pg = m.peer_group.load(Ordering::Acquire);
            if pg != 0 {
                if let Some(master) = mounts_in_ns(m.ns).into_iter().find(|p| {
                    p.mnt_id != m.mnt_id
                        && Propagation::from_u8(p.propagation.load(Ordering::Acquire)) == Propagation::Shared
                        && p.peer_group.load(Ordering::Acquire) == pg
                }) {
                    *m.mnt_master.lock() = Arc::downgrade(&master);
                    master.mnt_slave_list.lock().push(Arc::downgrade(&m));
                }
            }
            m.propagation.store(Propagation::Slave as u8, Ordering::Release);
        }
        Propagation::Private | Propagation::Unbindable => {
            m.peer_group.store(0, Ordering::Release);
            *m.mnt_master.lock() = Weak::new();
            m.propagation.store(kind as u8, Ordering::Release);
        }
    }
    mntns::bump_gen(m.ns);
    Ok(())
}

/// Update the per-mount MNT_* option bits on the mount at dentry `d`. Setting
/// MNT_RDONLY while writers are active fails with EBUSY (Linux
/// `mnt_hold_writers`). # C: O(log N)
pub fn remount_flags(d: &Arc<Dentry>, flags: u64) -> KResult<()> {
    let m = mount_exact_at(current_ns(), d).ok_or(VfsError::Einval)?;
    let old = m.flags.load(Ordering::Acquire);
    let new = (old & !MNT_OPTION_MASK) | (flags & MNT_OPTION_MASK);
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

/// The mount that OWNS `path`, by dentry-identity crossing (Linux
/// `path_lookup`), NOT a longest-`mount_point` string scan. # C: O(components)
pub fn resolve_mount(path: &str) -> Option<(Arc<Mount>, String)> {
    let ns = current_ns();
    let id = crate::namei::walk_to_mount(path).or_else(|| root_mount_id(ns))?;
    let m = mount_by_id(id)?;
    if m.ns != ns { return root_mount_id(ns).and_then(mount_by_id).map(|r| (r, path.to_string())); }
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
    if let Some(r) = m.root.as_ref() { return Some(r.clone()); }
    m.fs().root()
}

/// Root inode of a concrete mount id (the path walk's crossing primitive).
/// # C: O(log N)
pub fn root_for_mount_id(mnt_id: u64) -> Option<InodeRef> {
    let m = mount_by_id(mnt_id)?;
    m.root.clone().or_else(|| m.fs().root())
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
