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
    ns: AtomicU64,
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
    /// Namespace key while its canonical owner is retained. # C: O(1)
    pub fn namespace_id(&self) -> u64 { self.ns.load(Ordering::Acquire) }

    /// Rebind an unpublished detached clone to its destination owner. # C: O(1)
    fn rebind_namespace(&self, namespace: &mntns::MntNamespaceRef) {
        self.ns.store(namespace.id(), Ordering::Release);
    }

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

/// Per-namespace secondary index (ns id -> {mnt_id -> Mount}), DERIVED from
/// `MOUNTS` — never an independent truth. Every mount a namespace owns is
/// reachable in O(log N_ns) instead of the O(N_total_system_mounts) a
/// `MOUNTS.lock().values().filter(namespace_id == ns)` scan costs, which
/// otherwise makes every `unshare(CLONE_NEWNS)` (systemd `PrivateTmp=`,
/// `ProtectSystem=`, …) and every recursive-bind/subtree-copy cost grow with
/// the WHOLE system's mount count, not the namespace being cloned (B1430).
/// Maintained ONLY by [`mounts_publish`]/[`mounts_unpublish`] — the single
/// choke point every attach/detach/move/reap path must go through so this can
/// never disagree with `MOUNTS` (mirrors the existing `MOUNT_HASH` secondary
/// index's same-shape discipline).
static NS_MOUNTS: Spinlock<BTreeMap<u64, BTreeMap<u64, Arc<Mount>>>, MountClass> =
    Spinlock::new(BTreeMap::new());

/// Publish `m` into the mount arena AND its namespace's index in one call —
/// the ONLY way a mount may enter `MOUNTS` (`docs/16§6`). `m.namespace_id()`
/// must already be its FINAL namespace ([`Mount::rebind_namespace`] runs
/// before this on every path that needs it), so the two structures are always
/// inserted under the same key. # C: O(log N)
fn mounts_publish(m: Arc<Mount>) {
    let ns = m.namespace_id();
    MOUNTS.lock().insert(m.mnt_id, m.clone());
    NS_MOUNTS.lock().entry(ns).or_default().insert(m.mnt_id, m);
}

/// Remove `id` from the mount arena AND its namespace's index — the ONLY way a
/// mount may leave `MOUNTS`. The namespace key is read back from the removed
/// arena entry itself (never a caller-supplied `ns`), so a mount can never be
/// dropped from the wrong bucket. # C: O(log N)
fn mounts_unpublish(id: u64) -> Option<Arc<Mount>> {
    let removed = MOUNTS.lock().remove(&id);
    if let Some(m) = removed.as_ref() {
        let ns = m.namespace_id();
        let mut g = NS_MOUNTS.lock();
        if let Some(bucket) = g.get_mut(&ns) {
            bucket.remove(&id);
            if bucket.is_empty() { g.remove(&ns); }
        }
    }
    removed
}

/// Every mount in `ns`, by the per-namespace index — O(N_ns), not
/// O(N_total_system_mounts). The read-side counterpart of [`mounts_publish`]/
/// [`mounts_unpublish`]. # C: O(N_ns)
fn ns_mounts_snapshot(ns: u64) -> Vec<Arc<Mount>> {
    NS_MOUNTS.lock().get(&ns).map(|b| b.values().cloned().collect()).unwrap_or_default()
}

/// Snapshot of all registered mounts, across every namespace. # C: O(N_mounts)
pub fn all_mounts() -> Vec<Arc<Mount>> { MOUNTS.lock().values().cloned().collect() }

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

/// Reverse index: mnt_id -> its CURRENT `(parent, dptr)` `MOUNT_HASH` key.
/// DERIVED from `MOUNT_HASH`, maintained ONLY by `hash_insert`/`hash_remove` (the
/// sole `MOUNT_HASH` mutators), so it can never disagree with it. Lets
/// `hash_drop_ids` find + remove a specific id's entry in O(log N) instead of a
/// `.retain()` over EVERY `(parent,dptr)` bucket in the system — that scan is
/// O(N_total_system_mount_hash_entries) regardless of how few `ids` are being
/// dropped, so a single-namespace `rebuild_ns_index` (`copy_mnt_ns` on every
/// `unshare(CLONE_NEWNS)`, `commit_retree` on every pivot_root/move) paid for
/// every OTHER namespace's hash entries too (B1430).
static HASH_KEY_OF: Spinlock<BTreeMap<u64, (u64, usize)>, MountClass> = Spinlock::new(BTreeMap::new());

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
    HASH_KEY_OF.lock().insert(mnt_id, (parent, d));
}
fn hash_remove(parent: u64, d: usize, mnt_id: u64) {
    let mut h = MOUNT_HASH.lock();
    if let Some(stack) = h.get_mut(&(parent, d)) {
        stack.retain(|&id| id != mnt_id);
        if stack.is_empty() { h.remove(&(parent, d)); }
    }
    HASH_KEY_OF.lock().remove(&mnt_id);
}
fn hash_top(parent: u64, d: usize) -> Option<u64> {
    MOUNT_HASH.lock().get(&(parent, d)).and_then(|s| s.last().copied())
}
/// Drop every hash entry naming one of `ids` (the ns-private `mnt_id`s of a
/// namespace being rebuilt / reaped) via the `HASH_KEY_OF` reverse index — O(N_ids
/// × log N), not a full-table scan (B1430). # C: O(N_ids × log N)
fn hash_drop_ids(ids: &[u64]) {
    for &id in ids {
        // Bind the lookup to a LOCAL first: `if let Some(..) = HASH_KEY_OF.lock()...`
        // extends the scrutinee guard's lifetime across the whole `if let` body
        // (Rust's temporary-lifetime-extension rule), so `hash_remove` below would
        // re-lock the SAME already-held `HASH_KEY_OF` spinlock and spin forever.
        // The `let` statement drops the guard immediately, before `hash_remove` runs.
        let key = HASH_KEY_OF.lock().get(&id).copied();
        if let Some((parent, d)) = key {
            hash_remove(parent, d, id);
        }
    }
}

/// The (top) mount attached EXACTLY at mountpoint dentry `d` in `ns`, by
/// IDENTITY. # C: O(log N)
pub(super) fn mount_exact_at(ns: u64, d: &Arc<Dentry>) -> Option<Arc<Mount>> {
    if is_ns_root_dentry(d) {
        let rootid = root_mount_id(ns)?;
        // A mount STACKED ON the ns root (Linux overmount) is the visible top at
        // the root dentry — return it, not the underlay root mount. This is the
        // old root left by `pivot_root(".", ".")`: without this, `umount2(".",
        // MNT_DETACH)` (systemd's post-pivot switch-root cleanup) can't find it
        // and EINVALs. Falls back to the root mount when nothing is stacked.
        if let Some(over) = hash_top(rootid, dptr(d)) { return mount_by_id(over); }
        return mount_by_id(rootid);
    }
    top_mount_on(ns, d).and_then(mount_by_id)
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
    let namespace = current_namespace();
    let ns = namespace.id();
    if is_ns_root_dentry(d) {
        // Prefer a mount stacked ON the ns root (overmount, e.g. `pivot_root(.,.)`
        // old root); fall back to the underlay root mount when none is stacked.
        if let Some(id) = top_mount_on(ns, d) { return mount_by_id(id); }
        return root_mount_id(ns).and_then(mount_by_id);
    }
    let id = top_mount_on(ns, d)?;
    mount_by_id(id)
}

/// The mount rooted exactly at `(parent_mnt_id, d)` in the caller's namespace.
/// This is the non-lossy form for callers that already resolved a Linux
/// `struct path` mount target; a bare dentry is ambiguous across bind clones
/// that share dentries. # C: O(log N)
pub fn mount_at_path_exact_under(parent_mnt_id: u64, d: &Arc<Dentry>) -> Option<Arc<Mount>> {
    let namespace = current_namespace();
    __lookup_mnt(parent_mnt_id, d).filter(|m| m.namespace_id() == namespace.id())
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
        peer_group: AtomicU64::new(0), flags: AtomicU64::new(0), ns: AtomicU64::new(ns),
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
