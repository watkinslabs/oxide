// Shared perms/*at path-resolution helpers + AT_* consts (docs/53 §0).
// Used by the chmod/chown family and the *xattrat / file_{get,set}attr
// families.

#![cfg(target_os = "oxide-kernel")]

extern crate alloc;
use alloc::sync::Arc;
use syscall::errno::Errno;
use vfs::{File, InodeRef};

/// Wall-clock ns for the inode_times overlay (mtime/ctime stamping) — Linux
/// `current_time` reads `ktime_get_coarse_real_ts64`, i.e.
/// CLOCK_REALTIME. This used to return the MONOTONIC counter, so every
/// `notify_change` ctime stamp was the machine's uptime rather than an
/// epoch-relative time, and `ls -l` after a chmod showed 1970 plus a few
/// seconds. `timekeeper` owns the wall clock and is the same source installed
/// as vfs's realtime provider (`crate::mount`). # C: O(1)
pub(crate) fn now_ns() -> u64 { timekeeper::realtime_ns() }

// `AT_*` numbers are owned by `syscall::at` (the ABI crate both this shim and
// the `fs` work-fn crate depend on); re-exported, never re-declared.
pub(crate) use syscall::at::{AT_FDCWD, AT_SYMLINK_NOFOLLOW};

/// BUG E: `AT_EMPTY_PATH` with an empty path means "operate on the dirfd
/// itself" — fchmodat/fchownat with `""` == fchmod/fchown on the open fd.
/// systemd uses this to reset /dev/console's ownership/mode; without it the
/// empty path resolved to EINVAL. Mirrors `newfstatat`'s handling.
pub(crate) use syscall::at::AT_EMPTY_PATH;
pub(crate) const AT_CHMOD_CHOWN_VALID: u32 = syscall::at::AT_NOFOLLOW_EMPTY;

/// Validate chmod/chown `*at` flags before lookup or mutation. # C: O(1)
pub(crate) fn validate_chmod_chown_flags(flags: u32) -> Result<(), i64> {
    if flags & !AT_CHMOD_CHOWN_VALID != 0 {
        return Err(-(Errno::Einval.as_i32() as i64));
    }
    Ok(())
}

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
    let lf = vfs::LookupFlags {
        no_follow_final: !follow,
        follow,
        ..Default::default()
    };
    let vp = crate::pathresolve::resolve_at_lookup(dirfd, path_ptr, lf)?;
    Ok((vp.inode, vp.mnt_id))
}

/// Resolve a legacy (non-`*at`) xattr target to `(inode, mnt_id)`, preserving
/// mount identity for write-side EROFS checks. The `*xattrat` slots use
/// `pathresolve::resolve_at_or_{dirfd,fd}` instead, which carry Linux's
/// `getname_maybe_null` NULL-pathname rule. # C: O(N_path)
pub(crate) fn resolve_xattr_at_mnt(dirfd: i32, path_ptr: u64, at_flags: u32) -> Result<(InodeRef, u64), i64> {
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
    crate::pathresolve::resolve_at_lookup(dirfd, path_ptr, lf).map(|p| (p.inode, p.mnt_id))
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
    validate_chmod_chown_flags(flags)?;
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

/// Linux `mnt_want_write` … `mnt_drop_write` bracket around a metadata write:
/// `EROFS` on a read-only mount, otherwise the write hold is held for the whole
/// of `f` so a concurrent remount-ro cannot land mid-operation (Linux
/// `filename_setxattr` / `file_setxattr` / `filename_removexattr`). A `0`
/// `mnt_id` (anon/pseudo inode) has no mount to hold. # C: O(log N) + C(f)
pub(crate) fn with_mnt_write(mnt_id: u64, f: impl FnOnce() -> i64) -> i64 {
    if mnt_id == 0 { return f(); }
    let Some(m) = vfs::mount::mount_by_id(mnt_id) else { return f(); };
    if let Err(e) = vfs::mount::mnt_want_write(&m) { return -(e as i64); }
    let rv = f();
    vfs::mount::mnt_drop_write(&m);
    rv
}

/// Kernel `notify_change`: the single convergence point for
/// chmod/chown/truncate/utimes. EROFS gate on the owning mount, then the vfs
/// `setattr_prepare` DAC+idmap decision, then the inode's `i_op->setattr`
/// (`simple_setattr` default for pseudo-fs; ext4 additionally journals the
/// change through to disk). ATTR_SIZE truncate, owner `map_in_*`, and the
/// suid/sgid-kill fold all live inside `setattr`; owner ids in `ia` are vfs
/// ids. # C: O(N_path)
pub(crate) fn notify_change(inode: &InodeRef, mnt_id: u64, mut ia: vfs::Iattr) -> i64 {
    let cred = crate::pathresolve::current_cred();
    match vfs::notify_change_mnt(inode, mnt_id, &mut ia, &cred, now_ns()) {
        Ok(())  => 0,
        Err(e)  => -(e as i64),
    }
}

/// `chmod` ABI shim shared by chmod/fchmod/fchmodat(2). The mode change itself
/// is `fs::chattr::chmod_common`; the symlink EOPNOTSUPP, EROFS, immutable
/// EPERM, owner-or-FOWNER and S_ISGID rules all live under `notify_change`.
/// # C: O(N_path)
pub(crate) fn do_chmod(inode: &InodeRef, mnt_id: u64, mode: u16) -> i64 {
    match ::fs::chattr::chmod_common(inode, mnt_id, mode, &crate::pathresolve::current_cred()) {
        Ok(())  => 0,
        Err(e)  => -(e as i64),
    }
}

/// `chown` ABI shim shared by chown/lchown/fchown/fchownat. Translates the two
/// uid/gid ARGUMENTS out of the caller's user namespace (Linux `chown_common`
/// opens with `make_kuid`/`make_kgid`), resolving the `(uid_t)-1` sentinel to
/// "leave alone" FIRST — `-1` is deliberately unmapped in every namespace, so
/// testing it after the translation would turn every `chown(path,-1,-1)` into
/// `EINVAL`. An id the namespace does not map is `EINVAL` (Linux
/// `setattr_vfsuid` refusing an `INVALID_UID`), reported before any mutation.
/// # C: O(N_path)
pub(crate) fn do_chown(inode: &InodeRef, mnt_id: u64, uid_arg: u32, gid_arg: u32) -> i64 {
    const LEAVE_ALONE: u32 = u32::MAX;
    let einval = -(Errno::Einval.as_i32() as i64);
    let uid = if uid_arg == LEAVE_ALONE { None } else {
        match sched::cred::make_kuid(uid_arg) { Some(k) => Some(k), None => return einval }
    };
    let gid = if gid_arg == LEAVE_ALONE { None } else {
        match sched::cred::make_kgid(gid_arg) { Some(k) => Some(k), None => return einval }
    };
    match ::fs::chattr::chown_common(inode, mnt_id, uid, gid, &crate::pathresolve::current_cred()) {
        Ok(())  => 0,
        Err(e)  => -(e as i64),
    }
}
