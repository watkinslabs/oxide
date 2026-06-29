// Shared helper for access(2) / faccessat(2) / faccessat2(2). Split per
// `08§7` / `53§0`. D4: a REAL permission check (R_OK/W_OK/X_OK against the
// inode), not existence-only. `access(2)`/`faccessat(2)` use the caller's REAL
// uid/gid (POSIX); `faccessat2(AT_EACCESS)` uses the effective (fs) ids.
#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;

/// `R_OK`/`W_OK`/`X_OK` (uapi `unistd.h`); `F_OK` = 0.
const R_OK: u32 = 4;
const W_OK: u32 = 2;
const X_OK: u32 = 1;
/// `AT_*` flags accepted by `faccessat2` (`AT_EACCESS` = effective-id check).
const AT_EACCESS: u32 = 0x200;
const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
const AT_EMPTY_PATH: u32 = 0x1000;

/// Permission check resolving `path_ptr` against `dirfd` (real `faccessat(2)`
/// dirfd semantics; AT_FDCWD = -100 → cwd). `mode` is the R/W/X bitmask;
/// `flags` carries `AT_EACCESS`/`AT_SYMLINK_NOFOLLOW`. Returns 0 on grant.
/// # C: O(N_path)
pub(crate) fn do_access(dirfd: i32, path_ptr: u64, mode: u32, flags: u32) -> i64 {
    // Linux `faccessat2`: reject undefined mode/flag bits with EINVAL.
    if mode & !0o7 != 0 { return -(Errno::Einval.as_i32() as i64); }
    const VALID_FLAGS: u32 = AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;
    if flags & !VALID_FLAGS != 0 { return -(Errno::Einval.as_i32() as i64); }
    let no_follow = flags & AT_SYMLINK_NOFOLLOW != 0;
    // Centralized `*at` resolution: AT_EMPTY_PATH → LOOKUP_EMPTY (empty/NULL
    // path operates on the dirfd, ENOENT without it); faccessat FOLLOWS the
    // trailing symlink (LOOKUP_FOLLOW) unless AT_SYMLINK_NOFOLLOW.
    let lf = vfs::LookupFlags {
        empty: (flags & AT_EMPTY_PATH) != 0,
        no_follow_final: no_follow,
        follow: !no_follow,
        ..Default::default()
    };
    let vp = match crate::pathresolve::resolve_at_lookup(dirfd, path_ptr, lf) {
        Ok(p) => p, Err(rv) => return rv,
    };
    // W_OK on a read-only mount → EROFS (Linux access(2)).
    if mode & W_OK != 0 && vp.mnt_id != 0 {
        use core::sync::atomic::Ordering;
        if let Some(m) = vfs::mount::mount_by_id(vp.mnt_id) {
            if (m.flags.load(Ordering::Acquire) & vfs::mount::MNT_RDONLY) != 0 {
                return -(Errno::Erofs.as_i32() as i64);
            }
        }
    }
    let mut mask = 0u32;
    if mode & R_OK != 0 { mask |= vfs::MAY_READ; }
    if mode & W_OK != 0 { mask |= vfs::MAY_WRITE; }
    if mode & X_OK != 0 { mask |= vfs::MAY_EXEC; }
    if mask == 0 { return 0; } // F_OK: existence only (already resolved).
    // access(2) uses REAL ids; faccessat2(AT_EACCESS) uses effective (fs) ids.
    let cred = if flags & AT_EACCESS != 0 {
        crate::pathresolve::current_cred()
    } else {
        crate::pathresolve::current_cred_real()
    };
    match vfs::inode_permission(&vp.inode, mask, &cred) {
        Ok(())  => 0,
        Err(e)  => -(e as i64),
    }
}
