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
fn attach(mp: Option<Arc<Dentry>>, fs: Arc<dyn FileSystem>, root: Option<InodeRef>,
    parent_hint: Option<u64>) -> KResult<()> {
    let mp = mp.filter(|d| !is_ns_root_dentry(d));
    let root_inode = root.clone().or_else(|| fs.root());
    // `s_id` (the SB label) mirrors Linux's device/source id; the legacy mount
    // engine used the rendered mountpoint path here, which is not consumed
    // anywhere — keep it for an exact byte match with the prior behaviour.
    let s_id = match &mp { Some(d) => abs_string(d), None => String::from("/") };
    let sb = build_sb(fs, root_inode, s_id);
    #[cfg(feature = "debug-mnt")]
    mntcreate_log("attach", 0, 0, mp.as_ref(), sb.s_root().as_ref(), Some(&sb));
    graft_realized(mp, sb, 0, parent_hint)
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
    graft_realized(mp, sb, 0, None)
}

/// [D51] As [`attach_sb`] but stamps the per-mount MNT_* option bits (mapped
/// from a `fsmount(2)` MOUNT_ATTR_* request by [`mount_attr_to_mnt`]) onto the
/// new mount BEFORE it enters `MOUNTS` — so a subsequent `propagate_mount`
/// peer-copy inherits them ([`clone_mnt`] copies `src.flags`). Only
/// `MNT_OPTION_MASK` bits are honoured; internal-flag bits are ignored.
/// # C: O(depth)
pub fn attach_sb_with_flags(mp: Option<Arc<Dentry>>, sb: Arc<SuperBlock>, mnt_flags: u64)
    -> KResult<()> {
    attach_sb_with_flags_at(mp, sb, mnt_flags, None)
}

/// As [`attach_sb_with_flags`] but the caller supplies the destination PARENT
/// mount id the path walk crossed into (`Some`). When `mp` sits in a bind
/// mount, its parent dentry is SHARED between the bind and its source, so
/// `parent_by_dentry(mp)` is ambiguous and can parent the new mount under a
/// peer bind — leaving it unreachable via the path the caller walked (systemd
/// creates the sandbox apivfs at /run/systemd/namespace-X AFTER rbinding / onto
/// /run/systemd/mount-rootfs, so the /run root dentry is bind-shared and the
/// new mount was born parented under mount-rootfs/run). Threading the walked
/// parent mnt_id fixes the placement. # C: O(depth)
pub fn attach_sb_with_flags_at(mp: Option<Arc<Dentry>>, sb: Arc<SuperBlock>,
    mnt_flags: u64, parent_hint: Option<u64>) -> KResult<()> {
    #[cfg(feature = "debug-mnt")]
    mntcreate_log("attach_sb_with_flags", 0, 0, mp.as_ref(), sb.s_root().as_ref(), Some(&sb));
    graft_realized(mp, sb, mnt_flags & MNT_OPTION_MASK, parent_hint)
}

/// Shared TAIL of [`attach`]/[`attach_sb`]: reserve the per-ns mount slot,
/// build the `Mount` over the realized `sb`, wire the intrusive parent/child +
/// crossing-hash links, and commit. The mount root inode is derived from
/// `sb.s_root()` (Linux `mnt_root`), not a stored copy. `mp == None` ⇒ the
/// namespace root mount. # C: O(depth)
fn graft_realized(mp: Option<Arc<Dentry>>, sb: Arc<SuperBlock>, mnt_flags: u64,
    parent_hint: Option<u64>) -> KResult<()> {
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
    let parent_id = parent_hint.unwrap_or_else(|| parent_by_dentry(ns, &d));
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
    attach(mp, fs, None, None)
}

/// As [`register`] but with the walked destination PARENT mount id (see
/// [`attach_sb_with_flags_at`] — disambiguates a mountpoint sitting in a bind
/// mount whose parent dentry is shared). # C: O(depth)
pub fn register_at(mp: Option<Arc<Dentry>>, fs: Arc<dyn FileSystem>, parent_hint: Option<u64>) -> KResult<()> {
    attach(mp, fs, None, parent_hint)
}

/// Bind-as-clone (`mount(src, tgt, NULL, MS_BIND)`). # C: O(depth)
pub fn register_bind(mp: Option<Arc<Dentry>>, fs: Arc<dyn FileSystem>, root: InodeRef) -> KResult<()> {
    register_bind_at(mp, fs, root, None)
}

/// As [`register_bind`] but with the walked destination PARENT mount id.
/// # C: O(depth)
pub fn register_bind_at(mp: Option<Arc<Dentry>>, fs: Arc<dyn FileSystem>, root: InodeRef,
    parent_hint: Option<u64>) -> KResult<()> {
    #[cfg(feature = "debug-mnt")]
    mntcreate_log("register_bind", 0, 0, mp.as_ref(), None, None);
    attach(mp, fs, Some(root), parent_hint)
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
