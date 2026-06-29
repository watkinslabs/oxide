// 088 symlink — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.
// Hosts the shared symlink_impl core (also used by 266_symlinkat).

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::{errno_from_vfs, path_exists, read_user_path, resolve_parent};

/// `symlink(target, linkpath)` slot 88.
/// # C: O(N parent entries)
pub fn sys_symlink(args: &SyscallArgs) -> i64 {
    // Linux `getname`: NULL/bad ptr → EFAULT, empty string → ENOENT,
    // ≥ PATH_MAX → ENAMETOOLONG (D29; was EINVAL on empty target).
    let target = match read_user_path(args.a0) { Ok(s) => s, Err(rv) => return rv };
    let link   = match read_user_path(args.a1) { Ok(s) => s, Err(rv) => return rv };
    symlink_impl(target, link)
}

/// # C: O(N parent entries)
pub(crate) fn symlink_impl(target: String, link: String) -> i64 {
    let l = match crate::pathresolve::resolve_at_result(crate::pathresolve::AT_FDCWD, &link) {
        Ok(p) => p, Err(rv) => return rv,
    };
    if let Err(rv) = crate::landlock::check(&l,
        ::security::landlock::access::MAKE_SYM) { return rv; }
    if vfs::mount::is_readonly_path(&l) {
        return -(Errno::Erofs.as_i32() as i64);
    }
    if path_exists(&l) {
        return -(Errno::Eexist.as_i32() as i64);
    }
    let (pino, name) = match resolve_parent(&l) { Ok(x) => x, Err(rv) => return rv };
    match pino.symlink_child(&name, target.as_bytes()) {
        Ok(())  => 0,
        Err(e)  => {
            crate::namei_common::trace_run_vfs_error(b"symlink", &l, e);
            errno_from_vfs(e)
        }
    }
}
