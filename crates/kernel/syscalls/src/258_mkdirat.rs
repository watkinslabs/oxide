// 258 mkdirat — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::{
    read_user_path, errno_from_vfs, strip_trailing_slash, resolve_create_parent_at,
    render_child_path, render_parent_path, child_exists, parent_mount_readonly, drop_child_cache,
};

/// `mkdirat(dirfd, path, mode)` slot 258. Ignores dirfd (paths
/// resolved absolute or cwd-relative).
/// # C: O(1)
pub fn sys_mkdirat(args: &SyscallArgs) -> i64 {
    // D1/D2: PATH_MAX errno contract (EFAULT/ENOENT-on-empty/ENAMETOOLONG).
    let raw = match read_user_path(args.a1) {
        Ok(s) => s, Err(rv) => return rv,
    };
    let raw = strip_trailing_slash(&raw);
    let (parent, name) = match resolve_create_parent_at(args.a0 as i32, raw) {
        Ok(x) => x,
        Err(rv) => { crate::mount_common::mnt_log("mkdirat_noparent", raw, rv); return rv; }
    };
    let p = render_child_path(&parent, &name);
    if let Err(rv) = crate::landlock::check(&p,
        ::security::landlock::access::MAKE_DIR) { return rv; }
    // Linux do_mkdirat: `mode &= ~current_umask()` (D23).
    let umask = sched::live::current()
        .map(|c| c.umask.load(core::sync::atomic::Ordering::Acquire)).unwrap_or(0);
    let mode = (args.a2 as u32) & 0o7777 & !umask;
    // D57: parent walk (ENOTDIR) → EEXIST → EROFS, matching Linux ordering
    // (see 083_mkdir for the rationale + the systemd cg_create constraint).
    if !matches!(parent.inode.file_type(), vfs::FileType::Directory) {
        return -(Errno::Enotdir.as_i32() as i64);
    }
    match child_exists(&parent, &name) {
        Ok(true) => return -(Errno::Eexist.as_i32() as i64),
        Ok(false) => {}
        Err(rv) => return rv,
    }
    if parent_mount_readonly(&parent) {
        return -(Errno::Erofs.as_i32() as i64);
    }
    // Thread the mount idmap + caller cred + umask for the new dir's owner.
    let cred = crate::pathresolve::current_cred();
    let ctx = vfs::CreateCtx { idmap: &vfs::IDENTITY, cred: &cred, umask: umask as u16 };
    // D29: parent dir `i_rwsem` EXCLUSIVE across the backend mkdir (Linux
    // `filename_create` → `->mkdir`); dropped before the dcache update below.
    let r = { let _g = parent.inode.inode_lock(); parent.inode.mkdir(&name, mode, &ctx) };
    match r {
        Ok(_) => {
            drop_child_cache(&parent, &name);
            let pp = render_parent_path(&parent);
            vfs::fire_dirent_create(&pp, &name);
            0
        }
        Err(e) => {
            crate::namei_common::trace_run_vfs_error(b"mkdirat", &p, e);
            let rv = errno_from_vfs(e);
            crate::mount_common::mnt_log("mkdirat", &p, rv);
            rv
        }
    }
}
