// 087 unlink — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::{read_user_path, errno_from_vfs, resolve_parent, unlink_unix_socket_path};

/// `unlink(path)` slot 87.
/// # C: O(N parent entries)
pub fn sys_unlink(args: &SyscallArgs) -> i64 {
    // X4: EFAULT(bad ptr) / ENOENT(empty) / ENAMETOOLONG, not EINVAL.
    let raw = match read_user_path(args.a0) {
        Ok(s) => s, Err(rv) => return rv,
    };
    let p = match crate::pathresolve::resolve_at_result(crate::pathresolve::AT_FDCWD, &raw) {
        Ok(p) => p, Err(rv) => return rv,
    };
    if let Err(rv) = crate::landlock::check(&p,
        ::security::landlock::access::REMOVE_FILE) { return rv; }
    if vfs::mount::is_readonly_path(&p) {
        return -(Errno::Erofs.as_i32() as i64);
    }
    let (pino, name) = match resolve_parent(&p) { Ok(x) => x, Err(rv) => return rv };
    match pino.unlink_child(&name) {
        // d_delete: drop the cached dentry so a stale positive isn't reused
        // (stat/open after unlink must miss). See pathresolve::d_delete_path.
        Ok(())  => { unlink_unix_socket_path(&p); crate::pathresolve::d_delete_path(&p); 0 }
        Err(vfs::VfsError::Enoent) if unlink_unix_socket_path(&p) => 0,
        Err(e)  => errno_from_vfs(e),
    }
}
