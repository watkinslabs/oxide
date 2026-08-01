// 086 link — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::{
    drop_child_cache, errno_from_vfs, parent_mount_readonly, read_user_path,
    resolve_link_parent_at,
};

pub(crate) fn link_path_at(srcp: &vfs::VfsPath, dirfd: i32, raw_link: &str) -> i64 {
    let src = srcp.inode.clone();
    let src_mnt_id = srcp.mnt_id;
    let (parent, name) = match resolve_link_parent_at(dirfd, raw_link) {
        Ok(x) => x, Err(rv) => return rv,
    };
    // `filename_create` decides the destination name first: an occupied name is
    // EEXIST and a trailing slash on a free one is ENOENT, both AHEAD of the
    // read-only mount, the cross-mount test and every permission check. So
    // `link(a, existing)` reports EEXIST even on a read-only mount, and even
    // when the source and destination are on different mounts.
    if let Err(rv) = crate::namei_common::check_create_leaf(
        &parent, &name, raw_link, crate::path_ops_policy::CreateKind::NonDir) { return rv; }
    if parent_mount_readonly(&parent) {
        return -(Errno::Erofs.as_i32() as i64);
    }
    // Cross-mount hardlinks are EXDEV even when both sides share a superblock:
    // the name would escape the mount the caller reached the inode through.
    if src_mnt_id != parent.mnt_id {
        return -(Errno::Exdev.as_i32() as i64);
    }
    let cred = crate::pathresolve::current_cred();
    // `may_linkat` — the hardlink-protection gate. Linux runs it at the syscall
    // layer BEFORE the destination directory's create permission, so a caller
    // barred from linking an unsafe source sees EPERM rather than the EACCES /
    // EMLINK it would hit a step later.
    if let Err(e) = vfs::may_linkat(&src, &cred) {
        return errno_from_vfs(e);
    }
    // Linking is a reparenting: the destination hierarchy must allow creating
    // this file type AND must be no less restricted than the source, otherwise
    // the new name would grant the file rights it did not have.
    let src_target = ::landlock::refer::Target { dentry: srcp.dentry.clone(), inode: src.clone() };
    let src_dir = match srcp.dentry.parent() {
        Some(d) => vfs::VfsPath { mnt_id: srcp.mnt_id, dentry: d.clone(),
                                  inode: d.inode().unwrap_or_else(|| src.clone()),
                                  last_component: None },
        None => srcp.clone(),
    };
    if let Err(rv) = crate::landlock::check_refer(&src_dir, &src_target, &parent, None,
                                                  false, false) { return rv; }
    if let Err(e) = vfs::may_create(&parent.inode, &cred) {
        return errno_from_vfs(e);
    }
    if let Err(e) = vfs::may_link_source(&src, &cred) {
        return errno_from_vfs(e);
    }
    let ctx = vfs::CreateCtx { idmap: &vfs::IDENTITY, cred: &cred, umask: 0 };
    let r = { let _g = parent.inode.inode_lock(); parent.inode.link_child(&src, &name, &ctx) };
    match r {
        Ok(())  => {
            src.set_state(0, vfs::I_LINKABLE);
            drop_child_cache(&parent, &name);
            vfs::fire_dirent_create(&parent.inode, &name, false);
            // Linux `fsnotify_link` = `fsnotify_link_count(inode)` + the named
            // FS_CREATE on the parent. A watch on the FILE must see its link
            // count move; only the parent leg existed.
            ::fs::inotify::fire_link_count(&src);
            0
        }
        Err(e)  => errno_from_vfs(e),
    }
}

/// `link(target, link)` slot 86. Hardlink only — both must
/// resolve to ext4 paths.
/// # C: O(1)
pub fn sys_link(args: &SyscallArgs) -> i64 {
    // D1/D2: PATH_MAX errno contract (EFAULT/ENOENT-on-empty/ENAMETOOLONG).
    let target = match read_user_path(args.a0) {
        Ok(s) => s, Err(rv) => return rv,
    };
    let link = match read_user_path(args.a1) {
        Ok(s) => s, Err(rv) => return rv,
    };
    // link(2) does NOT follow the trailing symlink of the source (Linux
    // `do_linkat` without `AT_SYMLINK_FOLLOW`): the inode of the source name
    // itself is linked. A directory source is EPERM (no fs permits dir links).
    let src = match crate::pathresolve::resolve_at_path(crate::pathresolve::AT_FDCWD, &target,
        vfs::LookupFlags { no_follow_final: true, ..Default::default() }) {
        Ok(p) => p,
        Err(rv) => return rv,
    };
    link_path_at(&src, crate::pathresolve::AT_FDCWD, &link)
}
