// 076 truncate — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `sys_truncate(path, length)` — slot 76.
/// # C: O(N_devfs_entries)
pub fn sys_truncate(args: &SyscallArgs) -> i64 {
    let path_ptr = args.a0;
    let len      = args.a1;
    // Linux do_sys_truncate: a negative length is EINVAL before any walk (D33).
    if (len as i64) < 0 { return -(Errno::Einval.as_i32() as i64); }
    // D1/D2: PATH_MAX errno contract (EFAULT/ENOENT-on-empty/ENAMETOOLONG).
    let path = match crate::namei_common::read_user_path(path_ptr) {
        Ok(s)   => s,
        Err(rv) => return rv,
    };
    let s: &str = path.as_str();
    if let Err(rv) = crate::landlock::check(s,
        ::security::landlock::access::TRUNCATE) { return rv; }
    // truncate(2) follows symlinks; resolve to the inode + owning mount.
    let vp = match crate::pathresolve::resolve_path_result(s, false) {
        Ok(p)  => p,
        Err(e) => return -(e as i64),
    };
    // EISDIR on a directory (Linux do_sys_truncate); the size/MAY_WRITE/EROFS
    // path then converges on notify_change (ATTR_SIZE).
    if matches!(vp.inode.file_type(), vfs::FileType::Directory) {
        return -(Errno::Eisdir.as_i32() as i64);
    }
    crate::perms_common::notify_change(&vp.inode, vp.mnt_id,
        vfs::Iattr { valid: vfs::ATTR_SIZE, size: len, ..Default::default() })
}
