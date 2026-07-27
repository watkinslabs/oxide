/// Compatibility fill-super boundary for filesystems not yet converted to a
/// native `FileSystemType::mount` implementation. It returns a realized SB and
/// never crosses into namespace state with the backend object. # C: O(depth)
fn realize_compat_sb(s_type: Arc<dyn FileSystemType>, mp: Option<&Arc<Dentry>>,
    fs: Arc<dyn FileSystem>, root: Option<InodeRef>) -> KResult<Arc<SuperBlock>> {
    let s_id = match mp { Some(d) => abs_string(d), None => String::from("/") };
    superblock_from_filesystem(s_type, fs, root, s_id)
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
    let namespace = current_namespace();
    let reservation = mntns::MountReservation::reserve(&namespace, 1)?;
    let ns = reservation.namespace_id();
    let mnt_flags = mnt_flags & MNT_OPTION_MASK;
    // Per-ns mount cap (Linux `count_mounts` in `attach_recursive_mnt`): RESERVE
    // one slot in `pending_mounts` BEFORE building any mount state; over
    // `sysctl_mount_max` ⇒ ENOSPC. The reservation is rolled live by
    // `commit_mounts` once the mount is in `MOUNTS`; there is no fallible step
    // after this point, so no `abort_mounts` unwind path is reachable.
    let mnt_id = NEXT_MNT_ID.fetch_add(1, Ordering::Relaxed);
    let mp = mp.filter(|d| !is_ns_root_dentry(d));
    let Some(d) = mp else {
        let m = new_mount(sb, String::from("/"), None, mnt_id, mnt_id, ns);
        if let Some(global) = global_root() { *m.mnt_root.lock() = Some(global); }
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
            mounts_publish(m);
        }
        reservation.commit();
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
        mounts_publish(m);
        hash_insert(parent_id, dptr(&d), mnt_id);
    }
    reservation.commit();
    mntns::bump_gen(ns);
    Ok(())
}

/// Register a filesystem instance with an explicit registered type on mountpoint
/// dentry `mp` (Linux `do_new_mount` after `get_fs_type`). # C: O(depth)
pub fn register_typed(s_type: Arc<dyn FileSystemType>, mp: Option<Arc<Dentry>>,
    fs: Arc<dyn FileSystem>) -> KResult<()> {
    register_typed_at(s_type, mp, fs, None)
}

/// As [`register_typed`] but with the walked destination PARENT mount id.
/// # C: O(depth)
pub fn register_typed_at(s_type: Arc<dyn FileSystemType>, mp: Option<Arc<Dentry>>,
    fs: Arc<dyn FileSystem>, parent_hint: Option<u64>) -> KResult<()> {
    let mp = mp.filter(|d| !is_ns_root_dentry(d));
    let sb = realize_compat_sb(s_type, mp.as_ref(), fs, None)?;
    graft_realized(mp, sb, 0, parent_hint)
}

/// Register a FileSystem on mountpoint dentry `mp` by looking up its registered
/// Linux `file_system_type`. No ad hoc type is synthesized; missing registry
/// entry is `ENODEV`. # C: O(depth + N_fs)
/// # C: O(depth)
pub fn register(mp: Option<Arc<Dentry>>, fs: Arc<dyn FileSystem>) -> KResult<()> {
    let ty = crate::fs::get_fs_type(fs.name()).ok_or(VfsError::Enodev)?;
    register_typed(ty, mp, fs)
}

/// As [`register`] but with the walked destination PARENT mount id (see
/// [`attach_sb_with_flags_at`] — disambiguates a mountpoint sitting in a bind
/// mount whose parent dentry is shared). # C: O(depth)
pub fn register_at(mp: Option<Arc<Dentry>>, fs: Arc<dyn FileSystem>, parent_hint: Option<u64>) -> KResult<()> {
    let ty = crate::fs::get_fs_type(fs.name()).ok_or(VfsError::Enodev)?;
    register_typed_at(ty, mp, fs, parent_hint)
}

/// Bind-as-clone (`mount(src, tgt, NULL, MS_BIND)`). # C: O(depth)
pub fn register_bind(mp: Option<Arc<Dentry>>, fs: Arc<dyn FileSystem>, root: InodeRef) -> KResult<()> {
    register_bind_at(mp, fs, root, None)
}

/// Bind-as-clone with an explicit registered filesystem type. # C: O(depth)
pub fn register_bind_typed(s_type: Arc<dyn FileSystemType>, mp: Option<Arc<Dentry>>,
    fs: Arc<dyn FileSystem>, root: InodeRef) -> KResult<()> {
    register_bind_typed_at(s_type, mp, fs, root, None)
}

/// As [`register_bind_typed`] but with the walked destination PARENT mount id.
/// # C: O(depth)
pub fn register_bind_typed_at(s_type: Arc<dyn FileSystemType>, mp: Option<Arc<Dentry>>,
    fs: Arc<dyn FileSystem>, root: InodeRef, parent_hint: Option<u64>) -> KResult<()> {
    #[cfg(feature = "debug-mnt")]
    mntcreate_log("register_bind", 0, 0, mp.as_ref(), None, None);
    let mp = mp.filter(|d| !is_ns_root_dentry(d));
    let sb = realize_compat_sb(s_type, mp.as_ref(), fs, Some(root))?;
    graft_realized(mp, sb, 0, parent_hint)
}

/// As [`register_bind`] but with the walked destination PARENT mount id.
/// # C: O(depth)
pub fn register_bind_at(mp: Option<Arc<Dentry>>, fs: Arc<dyn FileSystem>, root: InodeRef,
    parent_hint: Option<u64>) -> KResult<()> {
    let ty = crate::fs::get_fs_type(fs.name()).ok_or(VfsError::Enodev)?;
    register_bind_typed_at(ty, mp, fs, root, parent_hint)
}

/// Bind-as-clone from a resolved source `struct path`: preserve the SOURCE
/// dentry as `mnt_root`, not just its inode. Linux bind mounts carry a full
/// `(vfsmount,dentry)` root; rebuilding from the inode mints an alias root
/// dentry, so recursive submount hash keys diverge from later namei walks.
/// # C: O(depth)
pub fn register_bind_path_at(mp: Option<Arc<Dentry>>, fs: Arc<dyn FileSystem>, root_dentry: Arc<Dentry>,
    parent_hint: Option<u64>) -> KResult<()> {
    let ty = crate::fs::get_fs_type(fs.name()).ok_or(VfsError::Enodev)?;
    register_bind_path_typed_at(ty, mp, fs, root_dentry, parent_hint)
}

/// Bind clone preserving source dentry with an explicit filesystem type.
/// # C: O(depth)
pub fn register_bind_path_typed_at(s_type: Arc<dyn FileSystemType>, mp: Option<Arc<Dentry>>,
    fs: Arc<dyn FileSystem>, root_dentry: Arc<Dentry>, parent_hint: Option<u64>) -> KResult<()> {
    let root = root_dentry.inode().ok_or(VfsError::Enoent)?;
    let namespace = current_namespace();
    let reservation = mntns::MountReservation::reserve(&namespace, 1)?;
    let ns = reservation.namespace_id();
    let mp = mp.filter(|d| !is_ns_root_dentry(d));
    let sb = realize_compat_sb(s_type, mp.as_ref(), fs, Some(root))?;
    let mnt_id = NEXT_MNT_ID.fetch_add(1, Ordering::Relaxed);
    let Some(d) = mp else {
        let m = new_mount(sb, String::from("/"), None, mnt_id, mnt_id, ns);
        *m.mnt_root.lock() = Some(root_dentry);
        m.set_internal_flag(MNT_INTERNAL);
        {
            let _w = MOUNT_WRITE.lock();
            mntns::ns_set_root(ns, mnt_id);
            mounts_publish(m);
        }
        reservation.commit();
        mntns::bump_gen(ns);
        return Ok(());
    };
    let parent_id = parent_hint.unwrap_or_else(|| parent_by_dentry(ns, &d));
    let rendered = rendered_path_for(parent_id, &d);
    graft_bind_realized(d, sb, root_dentry, parent_id, rendered, reservation)
}

/// Linux bind clone from a resolved source `struct path`: the new mount shares
/// the SOURCE mount's `mnt_sb` and uses `root_dentry` as its per-mount
/// `mnt_root`. No synthetic bind filesystem or fresh superblock is created.
/// # C: O(depth)
pub fn register_bind_clone_at(mp: Option<Arc<Dentry>>, source_mnt_id: u64,
    root_dentry: Arc<Dentry>, parent_hint: Option<u64>) -> KResult<()> {
    let src = mount_by_id(source_mnt_id).ok_or(VfsError::Einval)?;
    if !check_mnt(&src) { return Err(VfsError::Einval); }
    let namespace = current_namespace();
    let reservation = mntns::MountReservation::reserve(&namespace, 1)?;
    let ns = reservation.namespace_id();
    let grabbed = src.sb.grab_active();
    hal::kassert!(grabbed, "register_bind_clone_at: live source SB must grab active ref");
    let mp = mp.filter(|d| !is_ns_root_dentry(d));
    let sb = src.sb.clone();
    let mnt_id = NEXT_MNT_ID.fetch_add(1, Ordering::Relaxed);
    let Some(d) = mp else {
        let m = new_mount(sb, String::from("/"), None, mnt_id, mnt_id, ns);
        *m.mnt_root.lock() = Some(root_dentry);
        m.flags.store(src.flags.load(Ordering::Acquire), Ordering::Release);
        m.mnt_internal_flags.store(
            src.mnt_internal_flags.load(Ordering::Acquire) & MNT_LOCKED, Ordering::Release);
        m.set_internal_flag(MNT_INTERNAL);
        {
            let _w = MOUNT_WRITE.lock();
            mntns::ns_set_root(ns, mnt_id);
            mounts_publish(m);
        }
        reservation.commit();
        mntns::bump_gen(ns);
        return Ok(());
    };
    let parent_id = parent_hint.unwrap_or_else(|| parent_by_dentry(ns, &d));
    let rendered = rendered_path_for(parent_id, &d);
    graft_bind_realized_with_flags(d, sb, root_dentry, parent_id, rendered,
        src.flags.load(Ordering::Acquire), src.mnt_internal_flags.load(Ordering::Acquire) & MNT_LOCKED,
        reservation)
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
pub fn register_bind_under(parent_id: u64, mp_d: Arc<Dentry>, _rendered: String,
    fs: Arc<dyn FileSystem>, root: InodeRef) -> KResult<()> {
    let namespace = current_namespace();
    let reservation = mntns::MountReservation::reserve(&namespace, 1)?;
    let rendered = rendered_path_for(parent_id, &mp_d);
    let ty = crate::fs::get_fs_type(fs.name()).ok_or(VfsError::Enodev)?;
    let sb = superblock_from_filesystem(ty, fs, Some(root), rendered.clone())?;
    let root_dentry = sb.s_root().ok_or(VfsError::Enoent)?;
    graft_bind_realized(mp_d, sb, root_dentry, parent_id, rendered, reservation)
}

/// As [`register_bind_under`] but preserves the bind source dentry as `mnt_root`.
/// # C: O(1)
pub fn register_bind_path_under(parent_id: u64, mp_d: Arc<Dentry>, _rendered: String,
    fs: Arc<dyn FileSystem>, root_dentry: Arc<Dentry>) -> KResult<()> {
    let root = root_dentry.inode().ok_or(VfsError::Enoent)?;
    let namespace = current_namespace();
    let reservation = mntns::MountReservation::reserve(&namespace, 1)?;
    let rendered = rendered_path_for(parent_id, &mp_d);
    let ty = crate::fs::get_fs_type(fs.name()).ok_or(VfsError::Enodev)?;
    let sb = superblock_from_filesystem(ty, fs, Some(root), rendered.clone())?;
    graft_bind_realized(mp_d, sb, root_dentry, parent_id, rendered, reservation)
}

/// As [`register_bind_clone_at`] but the caller supplies the walked destination
/// parent mount id explicitly. # C: O(1)
pub fn register_bind_clone_under(parent_id: u64, mp_d: Arc<Dentry>,
    source_mnt_id: u64, root_dentry: Arc<Dentry>) -> KResult<()> {
    let src = mount_by_id(source_mnt_id).ok_or(VfsError::Einval)?;
    if !check_mnt(&src) { return Err(VfsError::Einval); }
    let namespace = current_namespace();
    let reservation = mntns::MountReservation::reserve(&namespace, 1)?;
    let grabbed = src.sb.grab_active();
    hal::kassert!(grabbed, "register_bind_clone_under: live source SB must grab active ref");
    let rendered = rendered_path_for(parent_id, &mp_d);
    graft_bind_realized_with_flags(mp_d, src.sb.clone(), root_dentry, parent_id, rendered,
        src.flags.load(Ordering::Acquire), src.mnt_internal_flags.load(Ordering::Acquire) & MNT_LOCKED,
        reservation)
}

fn graft_bind_realized(mp_d: Arc<Dentry>, sb: Arc<SuperBlock>, root_dentry: Arc<Dentry>,
    parent_id: u64, rendered: String, reservation: mntns::MountReservation) -> KResult<()> {
    graft_bind_realized_with_flags(mp_d, sb, root_dentry, parent_id, rendered, 0, 0, reservation)
}

fn graft_bind_realized_with_flags(mp_d: Arc<Dentry>, sb: Arc<SuperBlock>, root_dentry: Arc<Dentry>,
    parent_id: u64, rendered: String, mnt_flags: u64, internal_flags: u32,
    reservation: mntns::MountReservation) -> KResult<()> {
    let ns = reservation.namespace_id();
    let mnt_id = NEXT_MNT_ID.fetch_add(1, Ordering::Relaxed);
    let m = new_mount(sb, rendered, Some(mp_d.clone()), parent_id, mnt_id, ns);
    *m.mnt_root.lock() = Some(root_dentry);
    m.flags.store(mnt_flags & MNT_OPTION_MASK, Ordering::Release);
    m.mnt_internal_flags.store(internal_flags & MNT_LOCKED, Ordering::Release);
    {
        let _w = MOUNT_WRITE.lock();
        *m.mnt_mp.lock() = Some(get_mountpoint(&mp_d));
        if let Some(p) = mount_by_id(parent_id) {
            *m.mnt_parent.lock() = Arc::downgrade(&p);
            p.mnt_mounts.lock().push(m.clone());
        }
        mounts_publish(m);
        hash_insert(parent_id, dptr(&mp_d), mnt_id);
    }
    reservation.commit();
    mntns::bump_gen(ns);
    Ok(())
}
