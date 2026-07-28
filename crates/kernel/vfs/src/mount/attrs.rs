/// Update the per-mount option bits on the mount at dentry `d` from a mount(2)
/// MS_* REQUEST mask (mapped to MNT_* via [`ms_to_mnt`], D10). Setting RDONLY
/// while writers are active fails with EBUSY (Linux `mnt_hold_writers`).
/// # C: O(log N)
pub fn remount_flags(d: &Arc<Dentry>, flags: u64) -> KResult<()> {
    let namespace = current_namespace();
    let m = mount_exact_at(namespace.id(), d).ok_or(VfsError::Einval)?;
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

/// `mount(2) MS_REMOUNT` for a non-bind remount: update the superblock flags
/// through `SuperBlock::reconfigure_super` first, then commit the per-mount
/// `MNT_*` option bits. A backend remount failure leaves both flag sets
/// unchanged, matching Linux's fail-before commit shape. # C: O(dirty)
pub fn remount_super_flags_by_id(mnt_id: u64, flags: u64) -> KResult<()> {
    let m = mount_by_id(mnt_id).ok_or(VfsError::Einval)?;
    if !check_mnt(&m) { return Err(VfsError::Einval); }
    let (old, new) = proposed_mnt_flags(&m, flags);
    // Linux `do_remount`: the locked-flag ladder runs BEFORE the superblock is
    // reconfigured, so a refused relax leaves the SB untouched.
    if !can_change_locked_flags(&m, new) { return Err(VfsError::Eperm); }
    if (new & MNT_RDONLY) != 0 && (old & MNT_RDONLY) == 0 && m.mnt_writers.load(Ordering::Acquire) > 0 {
        return Err(VfsError::Ebusy);
    }
    let sb_set = ms_to_sb(flags);
    m.sb.reconfigure_super(sb_set, SB_REMOUNT_MASK & !sb_set)?;
    m.flags.store(new, Ordering::Release);
    mntns::bump_gen(m.namespace_id());
    Ok(())
}

/// Shared option update for both [`remount_flags`] variants. `flags` is the
/// mount(2) MS_* REQUEST mask; it is mapped to the per-mount MNT_* space
/// ([`ms_to_mnt`]) before being committed (D10). # C: O(1)
fn apply_remount(m: &Arc<Mount>, flags: u64) -> KResult<()> {
    let (old, new) = proposed_mnt_flags(m, flags);
    // Linux `do_reconfigure_mnt`: `can_change_locked_flags` → EPERM, ahead of the
    // writer (EBUSY) check. An unprivileged user-namespace holder therefore
    // cannot remount away a protection its parent namespace froze.
    if !can_change_locked_flags(m, new) { return Err(VfsError::Eperm); }
    if (new & MNT_RDONLY) != 0 && (old & MNT_RDONLY) == 0 && m.mnt_writers.load(Ordering::Acquire) > 0 {
        return Err(VfsError::Ebusy);
    }
    m.flags.store(new, Ordering::Release);
    mntns::bump_gen(m.namespace_id());
    Ok(())
}

fn proposed_mnt_flags(m: &Arc<Mount>, flags: u64) -> (u64, u64) {
    let old = m.flags.load(Ordering::Acquire);
    // MS_REMOUNT preserves the current atime mode when the request names none
    // (Linux `path_mount`, "The default atime for remount is preservation").
    let new = (old & !MNT_OPTION_MASK) | (ms_to_mnt_remount(flags, old) & MNT_OPTION_MASK);
    (old, new)
}

const SB_REMOUNT_MASK: u64 = crate::superblock::SB_RDONLY
    | crate::superblock::SB_SYNCHRONOUS
    | crate::superblock::SB_MANDLOCK
    | crate::superblock::SB_DIRSYNC
    | crate::superblock::SB_LAZYTIME;

fn ms_to_sb(flags: u64) -> u64 {
    let mut sb = 0;
    if flags & crate::mount::MS_RDONLY != 0 { sb |= crate::superblock::SB_RDONLY; }
    if flags & crate::mount::MS_SYNCHRONOUS != 0 { sb |= crate::superblock::SB_SYNCHRONOUS; }
    if flags & crate::mount::MS_MANDLOCK != 0 { sb |= crate::superblock::SB_MANDLOCK; }
    if flags & crate::mount::MS_DIRSYNC != 0 { sb |= crate::superblock::SB_DIRSYNC; }
    if flags & crate::mount::MS_LAZYTIME != 0 { sb |= crate::superblock::SB_LAZYTIME; }
    sb
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
    mntns::bump_gen(m.namespace_id());
}

/// [D52] Apply a `mount_setattr(2)` option change to ONE mount: same EBUSY guard
/// as [`apply_remount`] (turning RDONLY on with active writers is Linux
/// `mnt_hold_writers` EBUSY), then commit via [`commit_mnt_attrs`]. # C: O(1)
fn apply_mnt_attrs(m: &Arc<Mount>, set_mnt: u64, clr_mnt: u64) -> KResult<()> {
    let old = m.flags.load(Ordering::Acquire);
    if !can_change_locked_flags(m, recalc_flags(old, set_mnt, clr_mnt)) { return Err(VfsError::Eperm); }
    if (set_mnt & MNT_RDONLY) != 0 && (old & MNT_RDONLY) == 0
        && m.mnt_writers.load(Ordering::Acquire) > 0 {
        return Err(VfsError::Ebusy);
    }
    commit_mnt_attrs(m, set_mnt, clr_mnt);
    Ok(())
}

/// Linux `recalc_flags`: the MNT_* option word a `mount_setattr(2)` request
/// would install — `(current & ~attr_clr) | attr_set` — fed to
/// [`can_change_locked_flags`] before anything is committed. # C: O(1)
fn recalc_flags(old: u64, set_mnt: u64, clr_mnt: u64) -> u64 {
    (old & !(clr_mnt & MNT_OPTION_MASK)) | (set_mnt & MNT_OPTION_MASK)
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
    let ids = subtree_ids(top.namespace_id(), top_id);
    // Linux `mount_setattr` runs `can_change_locked_flags(m, recalc_flags(...))`
    // over the WHOLE subtree in its first pass and aborts with EPERM before any
    // mount is touched — one locked node vetoes the entire recursive request.
    for id in &ids {
        if let Some(m) = mount_by_id(*id) {
            let old = m.flags.load(Ordering::Acquire);
            if !can_change_locked_flags(&m, recalc_flags(old, set, clr)) { return Err(VfsError::Eperm); }
        }
    }
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

/// Linux `__mnt_is_readonly` (`fs/namespace.c`): `(mnt_flags & MNT_READONLY) ||
/// sb_rdonly(mnt_sb)`. BOTH halves matter — `mount -o ro` on a fresh mount sets
/// the per-mount bit, while a read-only superblock (a RO-mounted backing device,
/// a failed-journal ext4) makes every mount over it read-only regardless.
/// # C: O(1)
pub fn mnt_is_readonly(m: &Mount) -> bool {
    (m.flags.load(Ordering::Acquire) & MNT_RDONLY) != 0 || m.sb().is_readonly()
}

/// `mnt_want_write` (Linux): begin a write on `m`, EROFS if read-only, else
/// bump the writer count (blocks a concurrent remount-RO). # C: O(1)
pub fn mnt_want_write(m: &Mount) -> KResult<()> {
    if mnt_is_readonly(m) { return Err(VfsError::Erofs); }
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
pub fn check_mnt(m: &Mount) -> bool {
    let namespace = current_namespace();
    m.namespace_id() == namespace.id()
}

/// Root inode of the mount rooted EXACTLY at mountpoint dentry `d`. # C: O(log N)
pub fn mount_root_at(d: &Arc<Dentry>) -> Option<InodeRef> {
    if is_ns_root_dentry(d) { return None; }
    let m = mount_at_path_exact(d)?;
    // [D5] `mnt_root` (the mounted-fs root DENTRY) is the single source of
    // truth: its inode IS the bind-root inode stamped as `s_root->d_inode`.
    m.mnt_root().and_then(|r| r.inode())
}

/// Root inode of a concrete mount id (the path walk's crossing primitive).
/// # C: O(log N)
pub fn root_for_mount_id(mnt_id: u64) -> Option<InodeRef> {
    let m = mount_by_id(mnt_id)?;
    // [D5] derive from `mnt_root` (see `mount_root_at`).
    m.mnt_root().and_then(|r| r.inode())
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
    let namespace = current_namespace();
    let ns = namespace.id();
    let t = MOUNTS.lock();
    let mut found: Option<Arc<Mount>> = None;
    for m in t.values() {
        if m.sb.s_root().map(|r| Arc::as_ptr(&r) == d).unwrap_or(false) {
            if m.namespace_id() == ns { found = Some(m.clone()); break; }
            if found.is_none() { found = Some(m.clone()); }
        }
    }
    drop(t);
    found.and_then(|m| m.mountpoint())
}

/// Snapshot the caller's mount-namespace view (for /proc mounts + mountinfo).
/// # C: O(N_mounts)
pub fn snapshot() -> Vec<Arc<Mount>> {
    let namespace = current_namespace();
    mounts_in_ns(namespace.id())
}

/// Snapshot an explicit mount namespace (for `/proc/<pid>/mountinfo`). # C: O(N_mounts)
pub fn snapshot_ns_view(ns: u64) -> Vec<Arc<Mount>> {
    mounts_in_ns(ns)
}

/// Snapshot ALL mounts regardless of namespace (kernel-internal audits).
/// # C: O(N_mounts)
pub fn snapshot_all() -> Vec<Arc<Mount>> { all_mounts() }
