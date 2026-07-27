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

#[cfg(feature = "debug-mount")]
fn log_runtime_access(op: &'static str, dirfd: i32, path_ptr: u64, rv: i64) {
    if let Ok(path) = crate::namei_common::read_user_path(path_ptr) {
        if path.starts_with("/run/systemd") || path.contains("systemd/journal") || path.starts_with("/sys/fs/cgroup") {
            let mut tag = alloc::string::String::from(path.as_str());
            tag.push_str(" dirfd=");
            tag.push_str(&alloc::format!("{}", dirfd));
            crate::mount_common::mnt_log(op, &tag, rv);
        }
    }
}

#[cfg(feature = "debug-mount")]
fn log_access_rofs_detail(dirfd: i32, path_ptr: u64, vp: &vfs::VfsPath, m: &vfs::mount::Mount) {
    if let Ok(path) = crate::namei_common::read_user_path(path_ptr) {
        if !path.starts_with("/sys/fs/cgroup") { return; }
        klog::write_raw(b"[ACCESS-EROFS] ns=");
        klog::write_dec_u64(sched::live::current_mount_ns());
        klog::write_raw(b" dirfd=");
        if dirfd < 0 { klog::write_raw(b"-"); klog::write_dec_u64((-dirfd) as u64); }
        else { klog::write_dec_u64(dirfd as u64); }
        klog::write_raw(b" path=");
        klog::write_raw(path.as_bytes());
        klog::write_raw(b" resolved_mnt=");
        klog::write_dec_u64(vp.mnt_id);
        klog::write_raw(b" mount_ns=");
        klog::write_dec_u64(m.namespace_id());
        klog::write_raw(b" mnt_flags=0x");
        klog::write_hex_u64(m.flags());
        klog::write_raw(b" mp=");
        let mp = m.mount_point_str();
        klog::write_raw(mp.as_bytes());
        klog::write_raw(b"\n");
    }
}

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
    // Centralized `*at` resolution: AT_EMPTY_PATH → LOOKUP_EMPTY (empty string
    // operates on the dirfd, NULL still EFAULTs); faccessat FOLLOWS the
    // trailing symlink (LOOKUP_FOLLOW) unless AT_SYMLINK_NOFOLLOW.
    let lf = vfs::LookupFlags {
        empty: (flags & AT_EMPTY_PATH) != 0,
        no_follow_final: no_follow,
        follow: !no_follow,
        ..Default::default()
    };
    // Linux `do_faccessat` overrides credentials before `filename_lookup`, so
    // intermediate directory search and final inode permission use the same
    // selected real/effective identity.
    let cred = if flags & AT_EACCESS != 0 {
        crate::pathresolve::current_cred()
    } else {
        crate::pathresolve::current_cred_real()
    };
    let vp = match crate::pathresolve::resolve_at_lookup_cred(dirfd, path_ptr, lf, cred.clone()) {
        Ok(p) => p,
        Err(rv) => {
            #[cfg(feature = "debug-mount")]
            log_runtime_access("access_resolve", dirfd, path_ptr, rv);
            return rv;
        }
    };
    if mode & X_OK != 0 && matches!(vp.inode.file_type(), vfs::FileType::Regular) {
        if let Some(m) = vfs::mount::mount_by_id(vp.mnt_id) {
            if m.is_noexec() {
                #[cfg(feature = "debug-mount")]
                log_runtime_access("access_noexec", dirfd, path_ptr, -(Errno::Eacces.as_i32() as i64));
                return -(Errno::Eacces.as_i32() as i64);
            }
        }
    }
    let mut mask = 0u32;
    if mode & R_OK != 0 { mask |= vfs::MAY_READ; }
    if mode & W_OK != 0 { mask |= vfs::MAY_WRITE; }
    if mode & X_OK != 0 { mask |= vfs::MAY_EXEC; }
    if mask == 0 {
        #[cfg(feature = "debug-mount")]
        log_runtime_access("access", dirfd, path_ptr, 0);
        return 0;
    } // F_OK: existence only (already resolved).
    match vfs::inode_permission(&vp.inode, mask, &cred) {
        Ok(())  => {
            if mode & W_OK != 0 && !access_special_file(vp.inode.file_type()) {
                if let Some(m) = vfs::mount::mount_by_id(vp.mnt_id) {
                    if m.is_readonly() {
                        #[cfg(feature = "debug-mount")]
                        {
                            log_access_rofs_detail(dirfd, path_ptr, &vp, &m);
                            log_runtime_access("access_rofs", dirfd, path_ptr, -(Errno::Erofs.as_i32() as i64));
                        }
                        return -(Errno::Erofs.as_i32() as i64);
                    }
                }
            }
            #[cfg(feature = "debug-mount")]
            log_runtime_access("access", dirfd, path_ptr, 0);
            0
        }
        Err(e)  => {
            let rv = -(e as i64);
            #[cfg(feature = "debug-mount")]
            log_runtime_access("access", dirfd, path_ptr, rv);
            rv
        }
    }
}

/// Linux `special_file`: char/block/fifo/socket skip the post-permission EROFS
/// rewrite in `faccessat*`.
/// # C: O(1)
fn access_special_file(ft: vfs::FileType) -> bool {
    matches!(ft, vfs::FileType::CharDev | vfs::FileType::BlockDev | vfs::FileType::Fifo | vfs::FileType::Socket)
}
