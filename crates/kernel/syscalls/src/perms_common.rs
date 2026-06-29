// Shared perms/*at path-resolution helpers + AT_* consts (docs/53 §0).
// Used by the chmod/chown family and the *xattrat / file_{get,set}attr
// families.

#![cfg(target_os = "oxide-kernel")]

extern crate alloc;
use alloc::sync::Arc;
use syscall::errno::Errno;
use vfs::{File, InodeRef};

/// Monotonic ns for the inode_times overlay (mtime/ctime stamping).
/// # C: O(1)
pub(crate) fn now_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

/// AT_FDCWD sentinel — legacy (non-*at) callers pass this so the path
/// resolves against cwd; *at callers pass the real dirfd.
pub(crate) const AT_FDCWD: i32 = -100;

/// `AT_SYMLINK_NOFOLLOW` (uapi): when set in a *at `at_flags`, operate on the
/// symlink itself rather than its target. Shared by the *at families.
pub(crate) const AT_SYMLINK_NOFOLLOW: u32 = 0x100;

/// Resolve a dirfd-relative path to its inode (shared by chmod/chown *at and
/// the *xattrat family). `follow` controls symlink-following (AT_SYMLINK_NOFOLLOW).
/// # C: O(N_path)
pub(crate) fn resolve_path_inode(dirfd: i32, path_ptr: u64, follow: bool) -> Result<InodeRef, i64> {
    if path_ptr == 0 || path_ptr >= hal::USER_VA_END {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    // SAFETY: path_ptr in user range; bounded read via existing helper.
    let bytes = unsafe { devfs::read_user_cstr(path_ptr, 256) };
    let raw = bytes.and_then(|b| if b.is_empty() { None } else { core::str::from_utf8(b).ok() })
        .ok_or(-(Errno::Einval.as_i32() as i64))?;
    // BUG D: resolve against the dirfd's directory for a real fd-relative
    // dirfd (fchmodat/fchownat); resolve_at(AT_FDCWD, raw) == resolve_cwd(raw)
    // so legacy chmod/chown are unchanged.
    let resolved = crate::pathresolve::resolve_at_result(dirfd, raw)?;
    let s = resolved.as_str();
    // THE resolver (path-walk): crosses mounts, follows symlinks unless
    // `!follow` (chmod/chown follow; AT_SYMLINK_NOFOLLOW / lchown don't).
    crate::pathresolve::resolve(s, !follow)
        .ok_or(-(Errno::Enoent.as_i32() as i64))
}

/// BUG E: resolve the `*at` target. `AT_EMPTY_PATH` (0x1000) with an empty
/// path means "operate on the dirfd itself" — i.e. fchmodat/fchownat with `""`
/// == fchmod/fchown on the open fd. systemd uses this to reset /dev/console's
/// ownership/mode; without it the empty path resolved to EINVAL. Mirrors
/// `newfstatat`'s AT_EMPTY_PATH handling.
pub(crate) const AT_EMPTY_PATH: u32 = 0x1000;

// ===========================================================================
// D4: chmod/chown ownership + EROFS enforcement. The DAC *decisions* live in
// `vfs` (pure, hosted-tested); these helpers resolve the target + mount, run
// the decision against `current_cred()`, then apply via the inode_times
// overlay (the universal owner/mode store, since no FS impl carries native
// `set_perm`/`set_owner` yet — WP9 unifies this through `notify_change`).
// ===========================================================================

/// Resolve a dirfd-relative path to `(inode, mnt_id)` so the chmod/chown
/// family can enforce EROFS on the owning mount. Preserves the path-walk errno
/// (EACCES from `may_lookup`, ENOTDIR, ELOOP …). # C: O(N_path)
pub(crate) fn resolve_path_mnt(dirfd: i32, path_ptr: u64, follow: bool) -> Result<(InodeRef, u64), i64> {
    if path_ptr == 0 || path_ptr >= hal::USER_VA_END {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    // SAFETY: path_ptr in user range; bounded read via existing helper.
    let bytes = unsafe { devfs::read_user_cstr(path_ptr, 256) };
    let raw = bytes.and_then(|b| if b.is_empty() { None } else { core::str::from_utf8(b).ok() })
        .ok_or(-(Errno::Einval.as_i32() as i64))?;
    let resolved = crate::pathresolve::resolve_at_result(dirfd, raw)?;
    let vp = crate::pathresolve::resolve_path_result(resolved.as_str(), !follow)
        .map_err(|e| -(e as i64))?;
    Ok((vp.inode, vp.mnt_id))
}

/// Resolve a `*xattrat` (Linux 6.13) target inode, honouring the at_flags
/// shared by that family: AT_SYMLINK_NOFOLLOW (operate on the symlink) and
/// AT_EMPTY_PATH (empty path → operate on the dirfd itself). Unknown flag bits
/// → EINVAL (Linux `setxattrat`/`getxattrat` reject `~(AT_SYMLINK_NOFOLLOW |
/// AT_EMPTY_PATH)`). # C: O(N_path)
pub(crate) fn resolve_xattr_at(dirfd: i32, path_ptr: u64, at_flags: u32) -> Result<InodeRef, i64> {
    if at_flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(-(Errno::Einval.as_i32() as i64));
    }
    // Centralized `*at` resolution: AT_EMPTY_PATH → LOOKUP_EMPTY (empty path
    // operates on the dirfd, ENOENT without it); FOLLOW unless AT_SYMLINK_NOFOLLOW.
    let follow = at_flags & AT_SYMLINK_NOFOLLOW == 0;
    let lf = vfs::LookupFlags {
        empty: at_flags & AT_EMPTY_PATH != 0,
        no_follow_final: !follow,
        follow,
        ..Default::default()
    };
    crate::pathresolve::resolve_at_lookup(dirfd, path_ptr, lf).map(|p| p.inode)
}

/// Resolve an open fd to its `Arc<File>` (carries `mnt_id` for EROFS). # C: O(1)
pub(crate) fn resolve_fd_file(fd: i32) -> Result<Arc<File>, i64> {
    let cur = sched::live::current().ok_or(-(Errno::Ebadf.as_i32() as i64))?;
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(-(Errno::Ebadf.as_i32() as i64))?.clone();
    fdt.get(fd).map_err(|_| -(Errno::Ebadf.as_i32() as i64))
}

/// Resolve a *at target to `(inode, mnt_id)` honouring AT_EMPTY_PATH. # C: O(N_path)
pub(crate) fn resolve_at_target_mnt(dirfd: i32, path_ptr: u64, flags: u32, follow: bool)
    -> Result<(InodeRef, u64), i64>
{
    // Centralized `*at` resolution: AT_EMPTY_PATH → LOOKUP_EMPTY (empty path
    // operates on the dirfd, ENOENT without it); FOLLOW unless AT_SYMLINK_NOFOLLOW.
    let lf = vfs::LookupFlags {
        empty: (flags & AT_EMPTY_PATH) != 0,
        no_follow_final: !follow,
        follow,
        ..Default::default()
    };
    let p = crate::pathresolve::resolve_at_lookup(dirfd, path_ptr, lf)?;
    Ok((p.inode, p.mnt_id))
}

/// EROFS when `mnt_id` names a read-only mount (Linux `mnt_want_write`). A
/// `0` id (anon/pseudo inode) has no mount to enforce. # C: O(log N)
pub(crate) fn check_rofs(mnt_id: u64) -> Result<(), i64> {
    use core::sync::atomic::Ordering;
    if mnt_id == 0 { return Ok(()); }
    if let Some(m) = vfs::mount::mount_by_id(mnt_id) {
        if (m.flags.load(Ordering::Acquire) & vfs::mount::MNT_RDONLY) != 0 {
            return Err(-(Errno::Erofs.as_i32() as i64));
        }
    }
    Ok(())
}

/// Current permission bits for the suid/sgid-kill: per-fs `perm()` first, then
/// the inode_times overlay, then the statx default. # C: O(log N)
fn effective_mode(inode: &InodeRef) -> u16 {
    if let Some(p) = inode.perm() { return p; }
    if let Some(o) = vfs::inode_times::get(inode) { if o.owner_set { return o.mode_bits; } }
    0o600
}

/// Kernel `notify_change` (Linux `fs/attr.c`): the single convergence point for
/// chmod/chown/truncate/utimes. EROFS gate on the owning mount, then the vfs
/// `setattr_prepare` DAC+idmap decision, then apply each changed attribute via
/// the inode's native op — falling back to the `inode_times` metadata overlay
/// for pseudo-fs without native storage. ATTR_SIZE truncates directly (no
/// overlay; its EROFS propagates). Owner ids in `ia` are vfs ids; `map_in_*`
/// stores them as fs ids. # C: O(N_path)
pub(crate) fn notify_change(inode: &InodeRef, mnt_id: u64, mut ia: vfs::Iattr) -> i64 {
    if let Err(rv) = check_rofs(mnt_id) { return rv; }
    let idmap = vfs::mount::idmap_for(mnt_id);
    let cred = crate::pathresolve::current_cred();
    if let Err(e) = vfs::setattr_prepare(&idmap, inode, &mut ia, &cred) { return -(e as i64); }
    let now = now_ns();
    // ATTR_SIZE — truncate; no overlay equivalent, propagate EROFS/errors.
    if ia.valid & vfs::ATTR_SIZE != 0 {
        if let Err(e) = inode.truncate(ia.size) { return -(e as i64); }
    }
    // ATTR_UID/GID — native set_owner with idmap-in ids, else overlay
    // (the overlay keeps `u32::MAX` for an unchanged field).
    if ia.valid & (vfs::ATTR_UID | vfs::ATTR_GID) != 0 {
        let uid = if ia.valid & vfs::ATTR_UID != 0 { idmap.map_in_uid(ia.uid) } else { inode.uid().unwrap_or(0) };
        let gid = if ia.valid & vfs::ATTR_GID != 0 { idmap.map_in_gid(ia.gid) } else { inode.gid().unwrap_or(0) };
        if inode.set_owner(uid, gid).is_err() {
            let ov_uid = if ia.valid & vfs::ATTR_UID != 0 { uid } else { u32::MAX };
            let ov_gid = if ia.valid & vfs::ATTR_GID != 0 { gid } else { u32::MAX };
            vfs::inode_times::set_owner(inode, ov_uid, ov_gid, now);
        }
    }
    // ATTR_MODE and/or ATTR_KILL_* — fold into one final mode.
    let mut mode = ia.mode;
    let mut set_mode = ia.valid & vfs::ATTR_MODE != 0;
    if ia.valid & (vfs::ATTR_KILL_SUID | vfs::ATTR_KILL_SGID) != 0 {
        let base = if set_mode { mode } else { effective_mode(inode) };
        mode = vfs::apply_kill_priv(ia.valid, base);
        set_mode = true;
    }
    if set_mode {
        let m = mode & 0o7777;
        if inode.set_perm(m).is_err() { vfs::inode_times::set_mode(inode, m, now); }
    }
    // ATTR_ATIME/MTIME — native set_times (ctime stamped now) else overlay.
    if ia.valid & (vfs::ATTR_ATIME | vfs::ATTR_MTIME) != 0 {
        let a  = if ia.valid & vfs::ATTR_ATIME != 0 { Some(ia.atime_ns) } else { None };
        let mt = if ia.valid & vfs::ATTR_MTIME != 0 { Some(ia.mtime_ns) } else { None };
        if inode.set_times(a, mt, now).is_err() { vfs::inode_times::set(inode, a, mt, now); }
    }
    0
}

/// `chmod` work-fn shared by chmod/fchmod/fchmodat(2): routes through
/// `notify_change` (EROFS, owner-or-FOWNER, S_ISGID strip, apply). # C: O(N_path)
///
/// A symlink inode only reaches here via fchmodat/fchmodat2 with
/// AT_SYMLINK_NOFOLLOW (an `lchmod`); no filesystem implements chmod on a
/// symlink, so Linux returns EOPNOTSUPP (D40) — there is no symlink i_op->setattr.
pub(crate) fn do_chmod(inode: &InodeRef, mnt_id: u64, mode: u16) -> i64 {
    if matches!(inode.file_type(), vfs::FileType::Symlink) {
        return -(Errno::Eopnotsupp.as_i32() as i64);
    }
    notify_change(inode, mnt_id, vfs::Iattr { valid: vfs::ATTR_MODE, mode: mode & 0o7777, ..Default::default() })
}

/// `chown` work-fn shared by chown/fchown/fchownat: routes through
/// `notify_change` (EROFS, CAP_CHOWN / owner+group rules, `(uid_t)-1` leave-
/// alone, set-uid/set-gid drop on a non-directory — set unconditionally for a
/// non-dir, matching Linux `chown_common`). # C: O(N_path)
pub(crate) fn do_chown(inode: &InodeRef, mnt_id: u64, uid_arg: u32, gid_arg: u32) -> i64 {
    let mut valid = 0u32;
    if uid_arg != u32::MAX { valid |= vfs::ATTR_UID; }
    if gid_arg != u32::MAX { valid |= vfs::ATTR_GID; }
    // Linux drops S_ISUID and (group-exec) S_ISGID on any chown of a non-dir,
    // including the no-op `chown(-1,-1)`.
    if !matches!(inode.file_type(), vfs::FileType::Directory) {
        valid |= vfs::ATTR_KILL_SUID | vfs::ATTR_KILL_SGID;
    }
    notify_change(inode, mnt_id, vfs::Iattr { valid, uid: uid_arg, gid: gid_arg, ..Default::default() })
}
