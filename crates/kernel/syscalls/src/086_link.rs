// 086 link — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::{
    drop_child_cache, errno_from_vfs, parent_mount_readonly, read_user_path,
    render_child_path, render_parent_path, resolve_link_parent_at,
};

fn same_superblock(a: &vfs::InodeRef, b: &vfs::InodeRef) -> bool {
    match (a.i_sb(), b.i_sb()) {
        (Some(sa), Some(sb)) => alloc::sync::Arc::ptr_eq(&sa, &sb),
        _ => false,
    }
}

pub(crate) fn link_inode_at(src: vfs::InodeRef, dirfd: i32, raw_link: &str) -> i64 {
    let (parent, name) = match resolve_link_parent_at(dirfd, raw_link) {
        Ok(x) => x, Err(rv) => return rv,
    };
    let p = render_child_path(&parent, &name);
    if let Err(rv) = crate::landlock::check(&p,
        ::security::landlock::access::MAKE_REG) { return rv; }
    if parent_mount_readonly(&parent) {
        return -(Errno::Erofs.as_i32() as i64);
    }
    if matches!(src.file_type(), vfs::FileType::Directory) {
        return -(Errno::Eperm.as_i32() as i64);
    }
    if !same_superblock(&src, &parent.inode) {
        return -(Errno::Exdev.as_i32() as i64);
    }
    let r = { let _g = parent.inode.inode_lock(); parent.inode.link_child(&src, &name, &vfs::CreateCtx::root()) };
    match r {
        Ok(())  => {
            drop_child_cache(&parent, &name);
            let pp = render_parent_path(&parent);
            vfs::fire_dirent_create(&pp, &name);
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
        Ok(p) => p.inode,
        Err(rv) => return rv,
    };
    link_inode_at(src, crate::pathresolve::AT_FDCWD, &link)
}
