//! Mount table per `docs/16` mount-point routing. Owns the
//! `(path, FileSystem)` registry that `vfs::lookup` walks by
//! longest-prefix match. Replaces the hardcoded `if devfs::lookup
//! else if tmpfs::lookup else if ext4::lookup_inode` chains
//! duplicated across syscall handlers (R67).

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, AtomicU8, AtomicU64, Ordering};
use sync::{MountTable as MountClass, Spinlock};

use crate::fs::{FileSystem, KResult};
use crate::inode::InodeRef;
use crate::types::VfsError;

/// Mount propagation type per `docs/16§6` (`mount_namespaces(7)`).
/// Stored as the u8 discriminant in `Mount.propagation` so it can be
/// retuned in place by `mount(MS_SHARED|PRIVATE|SLAVE|UNBINDABLE)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Propagation { Private = 0, Shared = 1, Slave = 2, Unbindable = 3 }

impl Propagation {
    /// # C: O(1)
    pub fn from_u8(v: u8) -> Self {
        match v { 1 => Self::Shared, 2 => Self::Slave, 3 => Self::Unbindable, _ => Self::Private }
    }
}

/// Monotonic mount-id source. Linux assigns each mount a unique
/// `mnt_id` (the first field of /proc/<pid>/mountinfo) that is stable
/// for the mount's lifetime — findmnt/systemd key the mount tree on
/// it + `parent_id`. Starts at 1 (0 means "no parent" for the root).
static NEXT_MNT_ID: AtomicU64 = AtomicU64::new(1);

/// Mount-namespace provider (`docs/16§6`): the kernel installs a fn that
/// reads the calling task's `mount_ns` id, so `register`/`register_bind`
/// can stamp each new mount with the namespace that created it without
/// every call site passing it. `null` (pre-install / hosted tests) ⇒ ns 0.
/// The per-ns *tree* (resolution scoped to the caller's ns, copy-on-unshare
/// divergence) builds on this stamp; today resolution stays global (ns 0
/// base visible to all) — see `docs/16§6` + TASKS V7 stage U2.
static CURRENT_NS_PROVIDER: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Signature of the mount-ns provider.
pub type NsProvider = fn() -> u64;

/// Install the mount-ns provider (kernel boot). Idempotent (last wins).
/// # C: O(1)
pub fn set_current_ns_provider(f: NsProvider) {
    CURRENT_NS_PROVIDER.store(f as *mut (), Ordering::Release);
}

/// The calling task's mount-namespace id, or 0 if no provider is installed
/// (early boot / hosted tests / no current task).
/// # C: O(1)
pub fn current_ns() -> u64 {
    let p = CURRENT_NS_PROVIDER.load(Ordering::Acquire);
    if p.is_null() { return 0; }
    // SAFETY: CURRENT_NS_PROVIDER only ever holds a value stored by
    // set_current_ns_provider, which takes an `NsProvider` fn pointer; a
    // null check above guards the un-installed case, so the transmute
    // targets a valid `fn() -> u64`.
    let f: NsProvider = unsafe { core::mem::transmute::<*mut (), NsProvider>(p) };
    f()
}

/// Monotonic mount peer-group id source (`docs/16§6`). Linux assigns each
/// *peer group* a unique id, distinct from `mnt_id`; mounts sharing
/// propagation events share one peer-group id, rendered `shared:<pg>`
/// (a member) / `master:<pg>` (a slave of group pg) in mountinfo. Starts
/// at 1 (0 = "not in any peer group").
static NEXT_PEER_GROUP: AtomicU64 = AtomicU64::new(1);

/// One mount instance. The mount *tree* (`docs/16§6`) is represented
/// implicitly: a mount's parent is the live mount whose `mount_point`
/// is the longest proper path-prefix of this one (see `parent_id`),
/// so MS_MOVE is a `mount_point` change and there are no Arc cycles.
pub struct Mount {
    pub fs: Arc<dyn FileSystem>,
    pub mount_point: String,
    /// Bind-as-clone root (`docs/16§6`): when `Some`, this mount's root is
    /// an arbitrary source inode (the bound subtree's dir), not the fs's
    /// own `root()`. The dentry walk crosses into it and mirrors the whole
    /// source subtree per component via `Inode::lookup` — the Linux model,
    /// replacing the old BindFs whole-path rewrite. `None` = a normal
    /// whole-filesystem mount rooted at `fs.root()`.
    pub root: Option<InodeRef>,
    /// Stable, unique per mount lifetime. /proc mountinfo field 1.
    pub mnt_id: u64,
    /// Propagation type discriminant (`Propagation`). Default Private.
    pub propagation: AtomicU8,
    /// Peer-group id (`docs/16§6`); 0 = none. Assigned on `MS_SHARED`,
    /// inherited by clones of a shared mount. Rendered `shared:<pg>` /
    /// `master:<pg>` in mountinfo. Distinct from `mnt_id`.
    pub peer_group: AtomicU64,
    /// Mount-namespace id that created this mount (`docs/16§6`). Stamped
    /// from `current_ns()` at register time (0 = the initial/boot ns).
    /// Per-ns-scoped resolution + copy-on-unshare divergence build on this
    /// (TASKS V7 stage U2); today resolution stays global.
    pub ns: u64,
}

static TABLE: Spinlock<Vec<Arc<Mount>>, MountClass> = Spinlock::new(Vec::new());

/// Register a FileSystem at `mount_point`. Idempotent: if the
/// same mount_point already has a mount, returns Ebusy.
/// # C: O(N_mounts) — linear scan + push.
pub fn register(mount_point: &str, fs: Arc<dyn FileSystem>) -> KResult<()> {
    let mut t = TABLE.lock();
    if t.iter().any(|m| m.mount_point == mount_point) {
        return Err(VfsError::Eexist);
    }
    t.push(Arc::new(Mount {
        fs,
        mount_point: mount_point.to_string(),
        root: None,
        mnt_id: NEXT_MNT_ID.fetch_add(1, Ordering::Relaxed),
        propagation: AtomicU8::new(Propagation::Private as u8),
        peer_group: AtomicU64::new(0),
        ns: current_ns(),
    }));
    Ok(())
}

/// Bind-as-clone (`mount(src, tgt, NULL, MS_BIND)`, `docs/16§6`): register
/// a mount at `mount_point` whose root is the already-resolved source
/// inode `root`. The dentry walk crosses into it (`mount_root_at`) and
/// resolves `tgt/<x>` as `root.lookup("x")...` — mirroring the source
/// subtree with NO path rewrite (vs the old BindFs). `fs` supplies only
/// statfs `magic()` + the mountinfo line. Eexist if `mount_point` taken.
/// # C: O(N_mounts)
pub fn register_bind(mount_point: &str, fs: Arc<dyn FileSystem>, root: InodeRef) -> KResult<()> {
    let mut t = TABLE.lock();
    if t.iter().any(|m| m.mount_point == mount_point) {
        return Err(VfsError::Eexist);
    }
    t.push(Arc::new(Mount {
        fs,
        mount_point: mount_point.to_string(),
        root: Some(root),
        mnt_id: NEXT_MNT_ID.fetch_add(1, Ordering::Relaxed),
        propagation: AtomicU8::new(Propagation::Private as u8),
        peer_group: AtomicU64::new(0),
        ns: current_ns(),
    }));
    Ok(())
}

/// MS_REC recursive bind (`mount(src, tgt, NULL, MS_BIND|MS_REC)`,
/// `docs/16§6`): after `src`→`tgt` is bound, clone every mount nested
/// under `src` to the matching path under `tgt` as a bind-as-clone
/// (same root inode). The caller binds the top `src`→`tgt`; this clones
/// the submounts. Returns the count cloned. A submount whose root inode
/// can't be determined (whole-path pseudo-fs without `root()`) is skipped
/// — full coverage rides the mount-table unification (tmpfs lives in the
/// devfs registry, not this TABLE).
/// # C: O(N_mounts)
pub fn bind_submounts_rec(src: &str, tgt: &str) -> usize {
    let snap: Vec<Arc<Mount>> = TABLE.lock().clone();
    let mut n = 0;
    for m in snap.iter() {
        // Strict submount: mount_point == "<src>/<...>".
        let rel = match m.mount_point.strip_prefix(src) {
            Some(r) if r.starts_with('/') => r,
            _ => continue,
        };
        let new_mp = alloc::format!("{}{}", tgt, rel);
        // bind-as-clone reuses the submount's own root; whole-fs mounts
        // fall back to fs.root().
        let root = m.root.clone().or_else(|| m.fs.root());
        if let Some(r) = root {
            if register_bind(&new_mp, m.fs.clone(), r).is_ok() { n += 1; }
        }
    }
    n
}

/// `mnt_id` of `path`'s parent mount: the live mount whose
/// `mount_point` is the longest *proper* prefix of `path`. `0` if
/// none (the root mount "/"). Drives /proc mountinfo's parent_id so
/// the tree systemd/findmnt reconstruct is real (e.g. /dev/shm's
/// parent is /dev, not "/"). `path` must be the mount's own
/// `mount_point`.
/// # C: O(N_mounts × max_mount_point_len)
pub fn parent_id_of(path: &str) -> u64 {
    let t = TABLE.lock();
    let mut best: Option<&Arc<Mount>> = None;
    for m in t.iter() {
        let mp = m.mount_point.as_str();
        // Proper prefix only: skip the mount itself and equal paths.
        if mp == path { continue; }
        let is_prefix = (mp == "/" && path != "/")
            || (path.starts_with(mp) && path.as_bytes().get(mp.len()) == Some(&b'/'));
        if !is_prefix { continue; }
        match best {
            None => best = Some(m),
            Some(cur) if mp.len() > cur.mount_point.len() => best = Some(m),
            _ => {}
        }
    }
    best.map(|m| m.mnt_id).unwrap_or(0)
}

/// `mount(MS_MOVE)`: relocate the mount rooted exactly at `from` to
/// `to`. The tree is implicit (parent = longest path-prefix mount), so a
/// move is a `mount_point` rewrite that preserves `mnt_id` + propagation
/// — the new parent_id falls out of the prefix recompute automatically
/// (`docs/16§6`). `Einval` if no mount is rooted exactly at `from`;
/// `Ebusy` if a mount already occupies `to`. Submounts (mounts whose
/// point is under `from`) are NOT re-pointed here — Linux moves the whole
/// subtree; that rides the table unification (tmpfs still lives in the
/// devfs registry). For a single real-fs mount (the pivot_root case) this
/// is the complete operation.
/// # C: O(N_mounts)
pub fn move_mount(from: &str, to: &str) -> KResult<()> {
    let mut t = TABLE.lock();
    if t.iter().any(|m| m.mount_point == to) {
        return Err(VfsError::Ebusy);
    }
    let idx = t.iter().position(|m| m.mount_point == from).ok_or(VfsError::Einval)?;
    let old = &t[idx];
    let moved = Arc::new(Mount {
        fs: old.fs.clone(),
        mount_point: to.to_string(),
        root: old.root.clone(),
        mnt_id: old.mnt_id,
        propagation: AtomicU8::new(old.propagation.load(Ordering::Acquire)),
        peer_group: AtomicU64::new(old.peer_group.load(Ordering::Acquire)),
        ns: old.ns,
    });
    t[idx] = moved;
    Ok(())
}

/// Retune the propagation type of the mount at `mount_point`.
/// `mount(MS_SHARED|PRIVATE|SLAVE|UNBINDABLE)` lands here. Returns
/// Einval if no mount is rooted exactly at `mount_point`.
/// # C: O(N_mounts)
pub fn set_propagation(mount_point: &str, kind: Propagation) -> KResult<()> {
    let t = TABLE.lock();
    let m = t.iter().find(|m| m.mount_point == mount_point).ok_or(VfsError::Einval)?;
    m.propagation.store(kind as u8, Ordering::Release);
    // Peer-group bookkeeping: making a mount shared joins it to a peer
    // group (a fresh one if it had none); making it private/unbindable
    // drops it from its group. Slave keeps its group as its master ref.
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

/// Find the mount whose mount_point is the longest prefix of
/// `path`. Returns `(mount, path)` — the second element is the
/// original `path` unchanged. v1 backends key their internal
/// tables by full absolute paths (devfs registers `/dev/console`,
/// ext4 mounts at `/`), so callers pass the unmodified path to
/// `mnt.fs.lookup/create/unlink/rename`. Once dentries land, the
/// mount-relative split becomes meaningful and this returns a
/// stripped path.
/// # C: O(N_mounts × max_mount_point_len)
pub fn resolve_mount(path: &str) -> Option<(Arc<Mount>, String)> {
    let t = TABLE.lock();
    let mut best: Option<&Arc<Mount>> = None;
    for m in t.iter() {
        let mp = m.mount_point.as_str();
        let match_full = path == mp;
        let match_pref = mp.len() == 1 && mp == "/" /* root: always */
                      || (path.starts_with(mp) && path.as_bytes().get(mp.len()) == Some(&b'/'));
        if !(match_full || match_pref) { continue; }
        match best {
            None => best = Some(m),
            Some(cur) if mp.len() > cur.mount_point.len() => best = Some(m),
            _ => {}
        }
    }
    best.map(|m| (m.clone(), path.to_string()))
}

/// Unified path lookup. Walks the mount table by longest-prefix
/// match, then calls the matching FS's `lookup`. v1 backends key
/// their internal tables by full absolute paths (devfs registers
/// `/dev/console`, ext4 mounts at `/`), so we pass the unmodified
/// `path` after we've identified the owning mount. Once dentries
/// land, the mount-relative split becomes meaningful again.
/// # C: O(N_mounts) for mount routing + O(FS-impl).
pub fn lookup(path: &str) -> KResult<InodeRef> {
    let (mnt, _rel) = resolve_mount(path).ok_or(VfsError::Enoent)?;
    mnt.fs.lookup(path).ok_or(VfsError::Enoent)
}

/// Mount-crossing hook for the dentry path-walk (`docs/16§3`): if a
/// filesystem is mounted EXACTLY at `abs`, return its root inode — the
/// inode the walk switches to on crossing. `None` if nothing is mounted
/// there (or it's the root mount `/`, which the walk already starts at).
/// Prefers `Superblock::root` (`fs.root()`); falls back to the
/// whole-path `fs.lookup(abs)` for backends that don't expose `root()`
/// yet (tmpfs/proc/sys key their tables by full path, so this returns
/// the correct per-mount root even though the fs struct is shared).
///
/// Install via `crate::namei::set_mount_resolver(mount_root_at)` at boot
/// so `path_lookup` crosses every mount uniformly — the V5 unification.
/// # C: O(N_mounts)
pub fn mount_root_at(abs: &str) -> Option<InodeRef> {
    if abs == "/" { return None; }
    let (m, _) = resolve_mount(abs)?;
    if m.mount_point != abs { return None; }
    // Bind-as-clone: the mount's root is an arbitrary source inode; the
    // walk continues into the source subtree via per-component lookup.
    if let Some(r) = m.root.as_ref() { return Some(r.clone()); }
    m.fs.root().or_else(|| m.fs.lookup(abs))
}

/// Whole-path in-mount resolver for the dentry walk's delegation path
/// (`docs/16§3`): resolve a full absolute path through its owning
/// mount's `lookup`. Used when a per-component `Inode::lookup` can't
/// descend because the filesystem there resolves whole-path (procfs).
/// # C: O(N_mounts) + O(FS-impl)
pub fn mount_whole_path(abs: &str) -> Option<InodeRef> {
    lookup(abs).ok()
}

/// Install both path-walk hooks (`mount_root_at` crossing +
/// `mount_whole_path` delegation) into `vfs::namei`. Called once at boot.
/// # C: O(1)
pub fn install_resolvers() {
    crate::namei::set_mount_resolver(mount_root_at);
    crate::namei::set_mount_whole_path(mount_whole_path);
}

/// Snapshot the mount table for `/proc/mounts`.
/// # C: O(N_mounts)
pub fn snapshot() -> Vec<Arc<Mount>> {
    TABLE.lock().clone()
}
