// 084 rmdir — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.
// Hosts the shared do_rmdir core (also used by 263_unlinkat AT_REMOVEDIR).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::namei_common::{
    child_dentry, drop_child_cache, errno_from_vfs, parent_mount_readonly, read_user_path,
    resolve_rmdir_parent_at,
};

/// Single rmdir core — both `rmdir(2)` (slot 84, x86 legacy) and
/// `unlinkat(…, AT_REMOVEDIR)` (the only form aarch64 has) delegate
/// here so the two ABI entry points can never diverge (Linux routes
/// both through `do_rmdirat`).
/// Pseudo-fs dirs (cgroupfs, …) own their rmdir; ext4 dirs go to the
/// ext4 backend; everything else is read-only.
/// # C: O(1)
pub(crate) fn do_rmdir_at(dirfd: i32, raw: &str) -> i64 {
    if let Some(rv) = crate::namei_common::rmdir_dot_errno(raw) { return rv; }
    let (parent, name) = match resolve_rmdir_parent_at(dirfd, raw) {
        Ok(x) => x, Err(rv) => return rv,
    };
    // D30: capture the victim dir dentry before the backend removes it.
    let victim = child_dentry(&parent, &name);
    // The removal right is a property of the containing directory: a rule
    // granting it on the victim itself must not authorise removing the victim.
    if let Err(rv) = crate::landlock::check_parent(&parent,
        ::landlock::uapi::ACCESS_FS_REMOVE_DIR) { return rv; }
    if parent_mount_readonly(&parent) {
        return -(syscall::errno::Errno::Erofs.as_i32() as i64);
    }
    if let Some(d) = victim.as_ref() {
        let cred = crate::pathresolve::current_cred();
        if let Err(e) = vfs::namei::may_delete_dentry(&parent.inode, d, true, &cred) {
            return errno_from_vfs(e);
        }
        // `vfs_rmdir`'s `is_local_mountpoint` gate: a directory that something
        // is mounted on top of keeps its name until the mount goes away.
        if d.is_mounted() { return -(syscall::errno::Errno::Ebusy.as_i32() as i64); }
    }
    // The parent directory loses a name: recall any delegation on it before the
    // backend removes the subdirectory. Only the parent — a directory being
    // removed is empty, so nothing cached about the victim survives its
    // disappearance.
    if let Some(rv) = crate::deleg_break::break_deleg_for_mutation(&parent.inode) { return rv; }
    // D29: parent dir `i_rwsem` EXCLUSIVE across the backend rmdir (Linux
    // `do_rmdir` locks the parent); dropped before the dcache invalidate below.
    let r = { let _g = parent.inode.inode_lock(); parent.inode.rmdir(&name) };
    match r {
        // D25+D30: backend rmdir ran first. With the victim dir dentry in hand,
        // `d_invalidate` FIRST tears down its whole cached subtree (the dentry +
        // any negative dentries cached for names looked up inside it) while it is
        // still hashed, then `d_unlink` drives the nlink↔alias coupling
        // (`drop_link` + last-alias prune) on the now-disconnected dir inode. The
        // invalidate must precede the unlink: d_unlink unhashes the dentry, after
        // which d_invalidate would early-return and skip the subtree. No cached
        // victim → the path-based whole-subtree invalidate, as before.
        Ok(())  => {
            match victim {
                Some(d) => { vfs::d_invalidate(&d); vfs::dcache::d_unlink(&d); }
                None    => drop_child_cache(&parent, &name),
            }
            vfs::fire_dirent_delete(&parent.inode, &name, true);
            0
        }
        Err(e)  => errno_from_vfs(e),
    }
}

/// `rmdir(path)` slot 84 (x86 legacy; absent on aarch64).
/// # C: O(1)
pub fn sys_rmdir(args: &SyscallArgs) -> i64 {
    // D1/D2: PATH_MAX errno contract (EFAULT/ENOENT-on-empty/ENAMETOOLONG).
    let raw = match read_user_path(args.a0) {
        Ok(s) => s, Err(rv) => return rv,
    };
    do_rmdir_at(crate::pathresolve::AT_FDCWD, &raw)
}
