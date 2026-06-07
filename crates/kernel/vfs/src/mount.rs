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

use crate::dentry::Dentry;
use crate::fs::{FileSystem, KResult};
use crate::inode::InodeRef;
use crate::types::VfsError;

/// Mount-point dentry resolver (`docs/16§3`): the kernel installs a fn
/// that resolves an absolute mount-point path to its CANONICAL dentry
/// in the global dentry tree (following symlinks on the final
/// component, so a bind target of `/proc/self/fd/N` lands on the file
/// the fd points at). `register`/`register_bind` call it once at mount
/// time to mark that dentry a mount point, so the path walk can cross
/// by dentry identity rather than path-string prefix. `null`
/// (pre-install / hosted tests) ⇒ resolution unavailable, crossing
/// stays inert — those paths drive the walk with explicit dentries.
static DENTRY_RESOLVER: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Signature of the mount-point dentry resolver.
pub type DentryResolver = fn(&str) -> Option<Arc<Dentry>>;

/// Install the mount-point dentry resolver (kernel boot). Last wins.
/// # C: O(1)
pub fn set_dentry_resolver(f: DentryResolver) {
    DENTRY_RESOLVER.store(f as *mut (), Ordering::Release);
}

/// Resolve a mount-point path to its canonical dentry via the installed
/// resolver, or `None` if unavailable. # C: O(path components)
fn resolve_dentry(path: &str) -> Option<Arc<Dentry>> {
    let p = DENTRY_RESOLVER.load(Ordering::Acquire);
    if p.is_null() { return None; }
    // SAFETY: DENTRY_RESOLVER only ever holds a value stored by
    // set_dentry_resolver, which takes a `DentryResolver` fn pointer; the
    // round-trip through *mut () preserves the fn's address.
    let f: DentryResolver = unsafe { core::mem::transmute::<*mut (), DentryResolver>(p) };
    f(path)
}

/// Mark `mount_point`'s canonical dentry as a mount point carrying
/// `root` (the mounted fs's root inode), so `path_lookup` crosses into
/// it by dentry identity (`docs/16§3`). The root mount `/` is skipped
/// (the walk already starts at the root inode). No-op if the resolver
/// isn't installed or the path doesn't resolve (the mount still lives in
/// the table for `/proc/mounts`/mnt_id bookkeeping). # C: O(path)
fn wire_crossing(mount_point: &str, root: Option<InodeRef>) {
    if mount_point == "/" { return; }
    let Some(root) = root else { return; };
    if let Some(d) = resolve_dentry(mount_point) {
        d.set_mounted_root(Some(root));
    }
}

/// Clear the mount link on `mount_point`'s canonical dentry (umount).
/// # C: O(path)
fn unwire_crossing(mount_point: &str) {
    if mount_point == "/" { return; }
    if let Some(d) = resolve_dentry(mount_point) {
        d.set_mounted_root(None);
    }
}

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

/// Snapshot of all registered mounts (cheap Arc clones). Backs the
/// statmount/listmount(2) mount-introspection syscalls.
/// # C: O(N_mounts)
pub fn all_mounts() -> Vec<Arc<Mount>> { TABLE.lock().clone() }

/// Find a mount by its stable `mnt_id`.
/// # C: O(N_mounts)
pub fn mount_by_id(id: u64) -> Option<Arc<Mount>> {
    TABLE.lock().iter().find(|m| m.mnt_id == id).cloned()
}

/// `mnt_id` of the mount that is `m`'s parent — the registered mount whose
/// `mount_point` is the longest strict path-prefix of `m`'s. The root mount
/// (no strict-prefix parent) reports itself, matching Linux.
/// # C: O(N_mounts)
pub fn parent_mnt_id(m: &Mount) -> u64 {
    let mut best: Option<&Arc<Mount>> = None;
    let table = TABLE.lock();
    for cand in table.iter() {
        if cand.mnt_id == m.mnt_id { continue; }
        let cp = cand.mount_point.as_str();
        let mp = m.mount_point.as_str();
        // cp must be a path-prefix of mp ("/" prefixes everything; "/a" prefixes "/a/b").
        let is_prefix = mp == cp
            || (mp.starts_with(cp) && (cp == "/" || mp.as_bytes().get(cp.len()) == Some(&b'/')));
        if is_prefix {
            match best {
                Some(b) if b.mount_point.len() >= cp.len() => {}
                _ => best = Some(cand),
            }
        }
    }
    best.map(|b| b.mnt_id).unwrap_or(m.mnt_id)
}

/// Register a FileSystem at `mount_point`. Idempotent: if the
/// same mount_point already has a mount, returns Ebusy.
/// # C: O(N_mounts) — linear scan + push.
pub fn register(mount_point: &str, fs: Arc<dyn FileSystem>) -> KResult<()> {
    let ns = current_ns();
    // Crossing root inode: prefer `Superblock::root`, else the backend's
    // own whole-path lookup of its mount point (devfs/procfs/sysfs/tmpfs
    // expose their root dir this way — they don't override `root()`). This
    // inode is what the mount SHADOWS the underlying dir with, so the walk
    // sees the mounted fs's contents — not the ext4 dir beneath it.
    let root_inode = fs.root().or_else(|| fs.lookup(mount_point));
    {
        let mut t = TABLE.lock();
        if t.iter().any(|m| m.mount_point == mount_point && m.ns == ns) {
            return Err(VfsError::Eexist);
        }
        t.push(Arc::new(Mount {
            fs,
            mount_point: mount_point.to_string(),
            root: None,
            mnt_id: NEXT_MNT_ID.fetch_add(1, Ordering::Relaxed),
            propagation: AtomicU8::new(Propagation::Private as u8),
            peer_group: AtomicU64::new(0),
            ns,
        }));
    }
    // Wire dentry-identity crossing (`docs/16§3`) after dropping the
    // table lock — resolve_dentry runs a path walk that may re-enter
    // the table (resolve_mount), so it must not be held.
    wire_crossing(mount_point, root_inode);
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
    let ns = current_ns();
    {
        let mut t = TABLE.lock();
        if t.iter().any(|m| m.mount_point == mount_point && m.ns == ns) {
            return Err(VfsError::Eexist);
        }
        t.push(Arc::new(Mount {
            fs,
            mount_point: mount_point.to_string(),
            root: Some(root.clone()),
            mnt_id: NEXT_MNT_ID.fetch_add(1, Ordering::Relaxed),
            propagation: AtomicU8::new(Propagation::Private as u8),
            peer_group: AtomicU64::new(0),
            ns,
        }));
    }
    // Cross into the bound subtree's root inode by dentry identity. For a
    // bind onto `/proc/self/fd/N` the resolver follows that magic symlink
    // to the real target dentry (e.g. /etc/machine-id) — the Linux model.
    wire_crossing(mount_point, Some(root));
    Ok(())
}

/// Propagation event delivery (`docs/16§6`): replicate the mount just
/// created at `at` to every peer of its PARENT mount. If the parent mount
/// is in peer group P, each OTHER mount in P (same ns) receives a clone of
/// `at` at the mirrored relative path `<peer>/<rel>` — what makes a mount
/// established under a shared directory appear in all its peers (systemd
/// `PrivateTmp=`, container propagation). Returns the count propagated;
/// the clones are independent private mounts (own mnt_id). No-op when the
/// parent isn't shared.
/// # C: O(N_mounts)
pub fn propagate_mount(at: &str) -> usize {
    let ns = current_ns();
    let (fs, root, targets) = {
        let t = TABLE.lock();
        let newm = match t.iter().find(|m| m.mount_point == at && m.ns == ns) {
            Some(m) => m.clone(), None => return 0,
        };
        // Parent = longest proper-prefix mount in this ns.
        let mut parent: Option<&Arc<Mount>> = None;
        for m in t.iter() {
            if m.ns != ns { continue; }
            let mp = m.mount_point.as_str();
            if mp == at { continue; }
            let is_pre = mp == "/"
                || (at.starts_with(mp) && at.as_bytes().get(mp.len()) == Some(&b'/'));
            if !is_pre { continue; }
            match parent {
                None => parent = Some(m),
                Some(c) if mp.len() > c.mount_point.len() => parent = Some(m),
                _ => {}
            }
        }
        let parent = match parent { Some(p) => p, None => return 0 };
        let pg = parent.peer_group.load(Ordering::Acquire);
        if pg == 0 { return 0; }
        let rel = at[parent.mount_point.len()..].to_string();   // e.g. "/x"
        let root = match newm.root.clone().or_else(|| newm.fs.root()) {
            Some(r) => r, None => return 0,
        };
        let targets: Vec<String> = t.iter()
            .filter(|m| m.ns == ns
                     && m.peer_group.load(Ordering::Acquire) == pg
                     && m.mount_point != parent.mount_point)
            .map(|m| alloc::format!("{}{}", m.mount_point, rel))
            .collect();
        (newm.fs.clone(), root, targets)
    };
    let mut n = 0;
    for dst in targets {
        if register_bind(&dst, fs.clone(), root.clone()).is_ok() { n += 1; }
    }
    n
}

/// Peer group id of the mount rooted exactly at `mount_point` in the
/// caller's ns, or 0 if none / not a mount (`docs/16§6`).
/// # C: O(N_mounts)
pub fn peer_group_of(mount_point: &str) -> u64 {
    let ns = current_ns();
    let t = TABLE.lock();
    t.iter().find(|m| m.mount_point == mount_point && m.ns == ns)
        .map(|m| m.peer_group.load(Ordering::Acquire)).unwrap_or(0)
}

/// MS_SHARED peer-group inheritance (`docs/16§6`): the mount at
/// `mount_point` joins peer group `pg` and becomes Shared. Used when
/// binding a shared mount — Linux makes the new mount a peer of the
/// source's group, so it renders the same `shared:<pg>` and future
/// propagation events reach it. No-op if `mount_point` isn't a mount in
/// this ns or `pg` is 0.
/// # C: O(N_mounts)
pub fn join_peer_group(mount_point: &str, pg: u64) {
    if pg == 0 { return; }
    let ns = current_ns();
    let t = TABLE.lock();
    if let Some(m) = t.iter().find(|m| m.mount_point == mount_point && m.ns == ns) {
        m.peer_group.store(pg, Ordering::Release);
        m.propagation.store(Propagation::Shared as u8, Ordering::Release);
    }
}

/// `pivot_root(new_root, put_old)` (`docs/16§6`): make the mount at
/// `new_root` the namespace root and relocate the old root tree under
/// `put_old`. Since resolution reads the shared per-ns table, rewriting
/// mount_points here makes `/` resolve to new_root for every task in the
/// ns. Rules (Linux): `new_root` must be a mount; `put_old` must be under
/// `new_root` and not itself a mount (else its subtree would collide with
/// the relocated old root). Rewrite, all in the caller's ns:
///   - mounts at/under `new_root` → strip the `new_root` prefix (the mount
///     exactly at `new_root` becomes `/`);
///   - every other mount (the old tree, incl. old `/`) → reparent under
///     `put_old`'s post-pivot path (`put_old` with `new_root` stripped).
/// `mnt_id`/propagation/peer_group/root preserved on every moved mount.
/// # C: O(N_mounts)
pub fn pivot_root(new_root: &str, put_old: &str) -> KResult<()> {
    let ns = current_ns();
    let mut t = TABLE.lock();
    if !t.iter().any(|m| m.mount_point == new_root && m.ns == ns) {
        return Err(VfsError::Einval);                 // new_root not a mount
    }
    let under_new = put_old.strip_prefix(new_root).filter(|r| r.starts_with('/'));
    let old_dst = match under_new {
        Some(r) => r.to_string(),                     // e.g. "/old"
        None => return Err(VfsError::Einval),         // put_old not under new_root
    };
    if t.iter().any(|m| m.mount_point == put_old && m.ns == ns) {
        return Err(VfsError::Ebusy);                  // put_old is itself a mount
    }
    for i in 0..t.len() {
        let m = &t[i];
        if m.ns != ns { continue; }
        let mp = m.mount_point.as_str();
        let new_mp = if mp == new_root {
            String::from("/")
        } else if let Some(rel) = mp.strip_prefix(new_root).filter(|r| r.starts_with('/')) {
            rel.to_string()                            // new tree: drop new_root prefix
        } else if mp == "/" {
            old_dst.clone()                            // old root → put_old's new path
        } else {
            alloc::format!("{}{}", old_dst, mp)        // old tree under put_old
        };
        t[i] = Arc::new(Mount {
            fs: m.fs.clone(),
            mount_point: new_mp,
            root: m.root.clone(),
            mnt_id: m.mnt_id,
            propagation: AtomicU8::new(m.propagation.load(Ordering::Acquire)),
            peer_group: AtomicU64::new(m.peer_group.load(Ordering::Acquire)),
            ns: m.ns,
        });
    }
    Ok(())
}

/// `umount`: remove the mount rooted exactly at `mount_point` in the
/// caller's namespace (`docs/16§6`). Returns the count removed (0 if
/// none — e.g. `mount_point` isn't a mount in this ns). Bind mounts and
/// any future TABLE-resident mount detach here; before this, umount only
/// touched the devfs registry, so unmounting a bind mount was a silent
/// no-op that left it resolving forever.
/// # C: O(N_mounts)
pub fn unregister(mount_point: &str) -> usize {
    let ns = current_ns();
    let removed = {
        let mut t = TABLE.lock();
        let before = t.len();
        t.retain(|m| !(m.mount_point == mount_point && m.ns == ns));
        before - t.len()
    };
    // Detach the dentry mount link iff no mount remains at this path in
    // any ns (the dentry tree is global; another ns may still mount here).
    if removed > 0 && !TABLE.lock().iter().any(|m| m.mount_point == mount_point) {
        unwire_crossing(mount_point);
    }
    removed
}

/// Copy-on-unshare (`docs/16§6`): clone every mount in `from_ns` into
/// `to_ns` as a fresh independent mount (new `mnt_id`, same fs/root/
/// mount_point/propagation/peer_group). `sys_unshare(CLONE_NEWNS)` calls
/// this so the new namespace starts with a full private copy of the
/// parent's tree, then the two diverge independently (Linux semantics).
/// # C: O(N_mounts in from_ns)
pub fn snapshot_ns(from_ns: u64, to_ns: u64) {
    let mut t = TABLE.lock();
    let clones: Vec<Arc<Mount>> = t.iter()
        .filter(|m| m.ns == from_ns)
        .map(|m| Arc::new(Mount {
            fs: m.fs.clone(),
            mount_point: m.mount_point.clone(),
            root: m.root.clone(),
            mnt_id: NEXT_MNT_ID.fetch_add(1, Ordering::Relaxed),
            propagation: AtomicU8::new(m.propagation.load(Ordering::Acquire)),
            peer_group: AtomicU64::new(m.peer_group.load(Ordering::Acquire)),
            ns: to_ns,
        }))
        .collect();
    t.extend(clones);
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
    let ns = current_ns();
    let snap: Vec<Arc<Mount>> = TABLE.lock().clone();
    let mut n = 0;
    for m in snap.iter() {
        if m.ns != ns { continue; }
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
    let ns = current_ns();
    let t = TABLE.lock();
    let mut best: Option<&Arc<Mount>> = None;
    for m in t.iter() {
        if m.ns != ns { continue; }
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
/// `Ebusy` if a mount already occupies `to`. Submounts (mounts nested
/// under `from`) move WITH it — Linux relocates the whole subtree, so a
/// mount at `<from>/<rel>` becomes `<to>/<rel>` (U4). `mnt_id` +
/// propagation + peer_group preserved on every moved mount.
/// # C: O(N_mounts)
pub fn move_mount(from: &str, to: &str) -> KResult<()> {
    let ns = current_ns();
    let mut t = TABLE.lock();
    if t.iter().any(|m| m.mount_point == to && m.ns == ns) {
        return Err(VfsError::Ebusy);
    }
    if !t.iter().any(|m| m.mount_point == from && m.ns == ns) {
        return Err(VfsError::Einval);
    }
    // Rewrite the exact mount AND every submount nested under `from/`,
    // re-rooting the `from` prefix onto `to`.
    for i in 0..t.len() {
        let m = &t[i];
        if m.ns != ns { continue; }
        let new_mp = if m.mount_point == from {
            to.to_string()
        } else if let Some(rel) = m.mount_point.strip_prefix(from)
            .filter(|r| r.starts_with('/')) {
            alloc::format!("{}{}", to, rel)
        } else {
            continue;
        };
        t[i] = Arc::new(Mount {
            fs: m.fs.clone(),
            mount_point: new_mp,
            root: m.root.clone(),
            mnt_id: m.mnt_id,
            propagation: AtomicU8::new(m.propagation.load(Ordering::Acquire)),
            peer_group: AtomicU64::new(m.peer_group.load(Ordering::Acquire)),
            ns: m.ns,
        });
    }
    Ok(())
}

/// Retune the propagation type of the mount at `mount_point`.
/// `mount(MS_SHARED|PRIVATE|SLAVE|UNBINDABLE)` lands here. Returns
/// Einval if no mount is rooted exactly at `mount_point`.
/// # C: O(N_mounts)
pub fn set_propagation(mount_point: &str, kind: Propagation) -> KResult<()> {
    let ns = current_ns();
    let t = TABLE.lock();
    let m = t.iter().find(|m| m.mount_point == mount_point && m.ns == ns).ok_or(VfsError::Einval)?;
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
    // Per-ns (`docs/16§6`): only mounts in the caller's mount namespace are
    // visible. `unshare(CLONE_NEWNS)` copy-on-unshares the parent's set
    // (`snapshot_ns`), so a new ns starts complete then diverges.
    let ns = current_ns();
    let t = TABLE.lock();
    let mut best: Option<&Arc<Mount>> = None;
    for m in t.iter() {
        if m.ns != ns { continue; }
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

/// QUERY: root inode of the mount rooted EXACTLY at `abs` in the
/// caller's ns, or `None` if nothing is mounted there (or it's `/`).
/// This is a mount-table lookup by path — used for `/proc/mounts`
/// bookkeeping and tests, NOT the path-walk crossing mechanism (that is
/// dentry-identity-keyed via `Dentry::mounted_root`, `docs/16§3`).
/// Prefers the bind-clone `root`; falls back to `fs.root()` then the
/// whole-path `fs.lookup(abs)`. # C: O(N_mounts)
pub fn mount_root_at(abs: &str) -> Option<InodeRef> {
    if abs == "/" { return None; }
    let (m, _) = resolve_mount(abs)?;
    if m.mount_point != abs { return None; }
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

/// Install the whole-path delegation hook (`mount_whole_path`) into
/// `vfs::namei`. Mount CROSSING is now keyed by dentry identity
/// (`Dentry::mounted_root`, wired in `register`/`register_bind`), so the
/// old string `mount_root_at` crossing hook is gone — only the
/// whole-path delegate (procfs synthesising from a full path) remains.
/// Called once at boot. # C: O(1)
pub fn install_resolvers() {
    crate::namei::set_mount_whole_path(mount_whole_path);
}

/// Snapshot the caller's mount-namespace view of the table (for
/// `/proc/<pid>/mounts` + mountinfo — both per-ns, `docs/16§6`).
/// # C: O(N_mounts)
pub fn snapshot() -> Vec<Arc<Mount>> {
    let ns = current_ns();
    TABLE.lock().iter().filter(|m| m.ns == ns).cloned().collect()
}

/// Snapshot ALL mounts regardless of namespace (kernel-internal audits).
/// # C: O(N_mounts)
pub fn snapshot_all() -> Vec<Arc<Mount>> {
    TABLE.lock().clone()
}
