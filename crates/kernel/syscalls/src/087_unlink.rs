// 087 unlink — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::{read_user_path, errno_from_vfs, resolve_parent, unlink_unix_socket_path};

/// D30: capture the victim leaf dentry for `abs` BEFORE the backend removes the
/// name, so the post-removal `dcache::d_unlink` (which `drop_link`s the inode and
/// retires it on the last name) has a positive dentry to drive. Resolved
/// NO-FOLLOW on the final component — unlink/rmdir act on the symlink itself, not
/// its target. `None` when the name doesn't resolve (already-gone / special
/// cases); callers fall back to the path-based dcache invalidation. Shared by
/// `sys_unlink`, `sys_unlinkat`, `do_rmdir`, and `rename_impl`'s overwrite path.
/// # C: O(components)
pub(crate) fn victim_dentry(abs: &str) -> Option<alloc::sync::Arc<vfs::Dentry>> {
    crate::pathresolve::resolve_path_result(abs, true).ok().map(|vp| vp.dentry)
}

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
    // D30: grab the victim dentry before the backend drops the name (it would no
    // longer resolve afterwards) so `d_unlink` can drive the nlink↔alias coupling.
    let victim = victim_dentry(&p);
    // D29: parent dir `i_rwsem` EXCLUSIVE across the backend unlink (Linux
    // `do_unlinkat` locks the parent); dropped before the dcache delete below.
    let r = { let _g = pino.inode_lock(); pino.unlink_child(&name) };
    match r {
        // D30: backend `i_op->unlink` ran first; now `d_unlink` reflects it —
        // `drop_link`s the inode (mirrors the backend's link drop in the in-memory
        // inode), tears this name's dentry down, and on the LAST name prunes the
        // sibling aliases so the inode retires via the normal iput/evict window
        // (Linux `vfs_unlink` tail). No cached victim → path-based d_delete clears
        // any stale positive so stat/open after unlink still misses.
        Ok(())  => {
            unlink_unix_socket_path(&p);
            match victim {
                Some(d) => { vfs::dcache::d_unlink(&d); }
                None    => crate::pathresolve::d_delete_path(&p),
            }
            0
        }
        Err(vfs::VfsError::Enoent) if unlink_unix_socket_path(&p) => 0,
        Err(e)  => errno_from_vfs(e),
    }
}
