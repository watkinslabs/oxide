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
