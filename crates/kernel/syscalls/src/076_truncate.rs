// 076 truncate — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

/// `sys_truncate(path, length)` — slot 76.
/// # C: O(N_devfs_entries)
pub fn sys_truncate(args: &SyscallArgs) -> i64 {
    let path_ptr = args.a0;
    let len      = args.a1;
    // Linux do_sys_truncate: a negative length is EINVAL before any walk (D33).
    if (len as i64) < 0 { return -(Errno::Einval.as_i32() as i64); }
    if path_ptr == 0 || path_ptr >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: ptr in user range; user page mapped; bounded read.
    let path = match unsafe { devfs::read_user_cstr(path_ptr, 256) } {
        Some(p) if !p.is_empty() => p,
        _                        => return -(Errno::Einval.as_i32() as i64),
    };
    let s = match core::str::from_utf8(path) {
        Ok(s) => s, Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
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
