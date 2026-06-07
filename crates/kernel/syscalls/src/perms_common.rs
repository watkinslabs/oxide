// Shared perms/*at path-resolution helpers + AT_* consts (docs/53 §0).
// Used by the chmod/chown family and the *xattrat / file_{get,set}attr
// families.

#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;
use vfs::InodeRef;

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
    let resolved = crate::pathresolve::resolve_at(dirfd, raw)
        .unwrap_or_else(|| crate::pathresolve::resolve_cwd(raw));
    let s = resolved.as_str();
    // THE resolver (path-walk): crosses mounts, follows symlinks unless
    // `!follow` (chmod/chown follow; AT_SYMLINK_NOFOLLOW / lchown don't).
    crate::pathresolve::resolve(s, !follow)
        .ok_or(-(Errno::Enoent.as_i32() as i64))
}

/// Resolve an open fd to its inode (shared by fchmod/fchown and the
/// AT_EMPTY_PATH *at fast-path).
/// # C: O(1)
pub(crate) fn resolve_fd_inode(fd: i32) -> Result<InodeRef, i64> {
    let cur = match sched::live::current() {
        Some(c) => c, None => return Err(-(Errno::Ebadf.as_i32() as i64)),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return Err(-(Errno::Ebadf.as_i32() as i64)),
    };
    let f = match fdt.get(fd) {
        Ok(f) => f, Err(_) => return Err(-(Errno::Ebadf.as_i32() as i64)),
    };
    Ok(f.inode().clone())
}

/// BUG E: resolve the `*at` target. `AT_EMPTY_PATH` (0x1000) with an empty
/// path means "operate on the dirfd itself" — i.e. fchmodat/fchownat with `""`
/// == fchmod/fchown on the open fd. systemd uses this to reset /dev/console's
/// ownership/mode; without it the empty path resolved to EINVAL. Mirrors
/// `newfstatat`'s AT_EMPTY_PATH handling.
pub(crate) const AT_EMPTY_PATH: u32 = 0x1000;

/// Resolve a *at target honouring AT_EMPTY_PATH (dirfd-self fast path).
/// # C: O(N_path)
pub(crate) fn resolve_at_target(dirfd: i32, path_ptr: u64, flags: u32, follow: bool) -> Result<InodeRef, i64> {
    if (flags & AT_EMPTY_PATH) != 0 {
        // SAFETY: bounded 1-byte probe via the validated helper; only checks emptiness.
        let empty = unsafe { devfs::read_user_cstr(path_ptr, 1) }
            .map_or(true, |b| b.is_empty());
        if empty { return resolve_fd_inode(dirfd); }
    }
    resolve_path_inode(dirfd, path_ptr, follow)
}
