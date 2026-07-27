// 076 truncate — one syscall, one file (docs/53 §0). ABI shim only: the size
// change itself is `fs::truncate::vfs_truncate` (Linux `fs/open.c`).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `sys_truncate(path, length)` — slot 76.
/// # C: O(N_path)
pub fn sys_truncate(args: &SyscallArgs) -> i64 {
    let path_ptr = args.a0;
    let len      = args.a1;
    // Linux `ksys_truncate`: a negative length is EINVAL before any walk (D33).
    if (len as i64) < 0 { return -(Errno::Einval.as_i32() as i64); }
    // D1/D2: PATH_MAX errno contract (EFAULT/ENOENT-on-empty/ENAMETOOLONG).
    let path = match crate::namei_common::read_user_path(path_ptr) {
        Ok(s)   => s,
        Err(rv) => return rv,
    };
    // truncate(2) follows symlinks; resolve to the inode + owning mount.
    let vp = match crate::pathresolve::resolve_path_raw(path.as_str(), false) {
        Ok(p)  => p,
        Err(e) => return crate::namei_common::errno_from_vfs(e),
    };
    if let Err(rv) = crate::landlock::check(&vp,
        ::security::landlock::access::TRUNCATE) { return rv; }
    ::fs::truncate::vfs_truncate(&vp, len, &crate::pathresolve::current_cred())
}
