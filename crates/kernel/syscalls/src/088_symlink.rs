// 088 symlink — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.
// Hosts the shared symlink_impl core (also used by 266_symlinkat).

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use alloc::vec::Vec;
use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::{
    errno_from_vfs, read_user_path, read_user_path_bytes, resolve_create_parent_at,
    render_child_path, parent_mount_readonly, drop_child_cache,
};

/// `symlink(target, linkpath)` slot 88.
/// # C: O(N parent entries)
pub fn sys_symlink(args: &SyscallArgs) -> i64 {
    // Linux `getname`: NULL/bad ptr → EFAULT, empty string → ENOENT,
    // ≥ PATH_MAX → ENAMETOOLONG (D29; was EINVAL on empty target).
    let target = match read_user_path_bytes(args.a0) { Ok(s) => s, Err(rv) => return rv };
    let link   = match read_user_path(args.a1) { Ok(s) => s, Err(rv) => return rv };
    symlink_impl(crate::pathresolve::AT_FDCWD, target, link)
}

/// # C: O(N parent entries)
pub(crate) fn symlink_impl(dirfd: i32, target: Vec<u8>, link: String) -> i64 {
    let (parent, name) = match resolve_create_parent_at(dirfd, &link) {
        Ok(x) => x, Err(rv) => return rv,
    };
    let l = render_child_path(&parent, &name);
    if let Err(rv) = crate::namei_common::check_create_leaf(
        &parent, &name, &link, crate::path_ops_policy::CreateKind::NonDir) { return rv; }
    if parent_mount_readonly(&parent) {
        return -(Errno::Erofs.as_i32() as i64);
    }
    if let Err(rv) = crate::landlock::check_parent(&parent,
        ::security::landlock::access::MAKE_SYM) { return rv; }
    // Thread the mount idmap + caller cred so the new symlink gets the right
    // owner (symlinks carry no umask). Linux `->symlink(struct mnt_idmap *, ...)`.
    let cred = crate::pathresolve::current_cred();
    if let Err(e) = vfs::may_create(&parent.inode, &cred) {
        return errno_from_vfs(e);
    }
    let ctx = vfs::CreateCtx { idmap: &vfs::IDENTITY, cred: &cred, umask: 0 };
    // D29: parent dir `i_rwsem` EXCLUSIVE across the backend symlink (Linux
    // `filename_create` → `->symlink`); dropped before the dcache update below.
    let r = { let _g = parent.inode.inode_lock(); parent.inode.symlink_child(&name, &target, &ctx) };
    match r {
        Ok(())  => {
            drop_child_cache(&parent, &name);
            vfs::fire_dirent_create(&parent.inode, &name, false);
            0
        }
        Err(e)  => {
            crate::namei_common::trace_run_vfs_error(b"symlink", &l, e);
            errno_from_vfs(e)
        }
    }
}
