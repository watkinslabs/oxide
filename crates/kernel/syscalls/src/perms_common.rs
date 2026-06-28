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
    if (flags & AT_EMPTY_PATH) != 0 {
        // SAFETY: bounded 1-byte probe via the validated helper; only checks emptiness.
        let empty = unsafe { devfs::read_user_cstr(path_ptr, 1) }.map_or(true, |b| b.is_empty());
        if empty {
            let f = resolve_fd_file(dirfd)?;
            return Ok((f.inode().clone(), f.mnt_id()));
        }
    }
    resolve_path_mnt(dirfd, path_ptr, follow)
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

/// `chmod` work-fn shared by chmod/fchmod/fchmodat(2): EROFS, owner-or-FOWNER
/// check, S_ISGID strip for non-members, then apply. # C: O(N_path)
pub(crate) fn do_chmod(inode: &InodeRef, mnt_id: u64, mode: u16) -> i64 {
    if let Err(rv) = check_rofs(mnt_id) { return rv; }
    let cred = crate::pathresolve::current_cred();
    if let Err(e) = vfs::may_chmod(inode, &cred) { return -(e as i64); }
    let m = vfs::chmod_sgid_strip(mode & 0o7777, inode, &cred);
    if inode.set_perm(m).is_err() { vfs::inode_times::set_mode(inode, m, now_ns()); }
    0
}

/// `chown` work-fn shared by chown/fchown/fchownat: EROFS, CAP_CHOWN / owner+
/// group rules, then apply (`(uid_t)-1` ⇒ leave-alone) and drop set-uid/set-gid
/// on a regular file. # C: O(N_path)
pub(crate) fn do_chown(inode: &InodeRef, mnt_id: u64, uid_arg: u32, gid_arg: u32) -> i64 {
    if let Err(rv) = check_rofs(mnt_id) { return rv; }
    let new_uid = if uid_arg == u32::MAX { None } else { Some(uid_arg) };
    let new_gid = if gid_arg == u32::MAX { None } else { Some(gid_arg) };
    if new_uid.is_none() && new_gid.is_none() {
        // Pure no-op chown still drops priv bits on a non-dir (Linux chown_common).
    }
    let cred = crate::pathresolve::current_cred();
    if let Err(e) = vfs::may_chown(inode, new_uid, new_gid, &cred) { return -(e as i64); }
    // Apply. Native `set_owner` (none exist yet) gets resolved ids; the overlay
    // handles the `u32::MAX` leave-alone sentinel itself.
    let eff_uid = new_uid.unwrap_or_else(|| inode.uid().unwrap_or(0));
    let eff_gid = new_gid.unwrap_or_else(|| inode.gid().unwrap_or(0));
    if inode.set_owner(eff_uid, eff_gid).is_err() {
        vfs::inode_times::set_owner(inode, uid_arg, gid_arg, now_ns());
    }
    // Drop S_ISUID / (group-exec) S_ISGID on a regular file after the chown.
    let is_dir = matches!(inode.file_type(), vfs::FileType::Directory);
    if let Some(nm) = vfs::chown_kill_priv(effective_mode(inode), is_dir) {
        if inode.set_perm(nm).is_err() { vfs::inode_times::set_mode(inode, nm, now_ns()); }
    }
    0
}
