// 086 link — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::{read_user_path, errno_from_vfs, resolve_parent};

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
    let t = match crate::pathresolve::resolve_at_result(crate::pathresolve::AT_FDCWD, &target) {
        Ok(p) => p, Err(rv) => return rv,
    };
    let l = match crate::pathresolve::resolve_at_result(crate::pathresolve::AT_FDCWD, &link) {
        Ok(p) => p, Err(rv) => return rv,
    };
    if let Err(rv) = crate::landlock::check(&l,
        ::security::landlock::access::MAKE_REG) { return rv; }
    let (tm, _) = match vfs::mount::resolve_mount(&t) {
        Some(v) => v, None => return -(Errno::Enoent.as_i32() as i64),
    };
    let (lm, _) = match vfs::mount::resolve_mount(&l) {
        Some(v) => v, None => return -(Errno::Enoent.as_i32() as i64),
    };
    if (lm.flags.load(core::sync::atomic::Ordering::Acquire) & vfs::mount::MNT_RDONLY) != 0 {
        return -(Errno::Erofs.as_i32() as i64);
    }
    if tm.mnt_id != lm.mnt_id {
        return -(Errno::Exdev.as_i32() as i64);
    }
    // link(2) does NOT follow the trailing symlink of the source (Linux
    // `do_linkat` without `AT_SYMLINK_FOLLOW`): the inode of the source name
    // itself is linked. A directory source is EPERM (no fs permits dir links).
    let src = match crate::pathresolve::resolve_path_result(&t, true) {
        Ok(p) => p.inode,
        Err(e) => return errno_from_vfs(e),
    };
    if matches!(src.file_type(), vfs::FileType::Directory) {
        return -(Errno::Eperm.as_i32() as i64);
    }
    // D9/D29: route through the resolved new-path PARENT's `i_op->link` (Linux
    // `vfs_link` → `dir->i_op->link`) instead of the whole-path `FileSystem::link`,
    // holding that parent's `i_rwsem` EXCLUSIVE across the backend (Linux
    // `filename_create`). The backend resolves via `i_op.lookup` (no nested
    // `i_rwsem`) → deadlock-free. On a parent-resolve miss, fall back to the
    // whole-path FS link (byte-equivalent, conservative).
    let r = match resolve_parent(&l) {
        Ok((pino, name)) => {
            let _g = pino.inode_lock();
            pino.link_child(&src, &name, &vfs::CreateCtx::root())
        }
        Err(_) => tm.fs().link(&t, &l),
    };
    match r {
        Ok(())  => { crate::pathresolve::d_drop_path(&l); 0 }
        Err(e)  => errno_from_vfs(e),
    }
}
