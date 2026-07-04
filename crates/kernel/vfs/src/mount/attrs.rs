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
