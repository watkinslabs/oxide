// 258 mkdirat — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::{
    read_user_path, errno_from_vfs, strip_trailing_slash, resolve_create_parent_at,
    render_child_path, child_exists, parent_mount_readonly, drop_child_cache,
};

#[cfg(feature = "debug-mount")]
fn trace_runtime_dir(op: &'static str, raw: &str, rendered: Option<&str>, rv: i64) {
    if crate::mount_common::traced_path(raw)
        || rendered.is_some_and(crate::mount_common::traced_path)
    {
        crate::mount_common::mnt_log(op, rendered.unwrap_or(raw), rv);
    }
}

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
        Err(rv) => {
            #[cfg(feature = "debug-udevdb")]
            crate::namei_common::trace_udevdb_path(b"mkdirat", raw, rv);
            #[cfg(feature = "debug-mount")]
            trace_runtime_dir("mkdirat_noparent", raw, None, rv);
            return rv;
        }
    };
    let p = render_child_path(&parent, &name);
    let umask = sched::live::current()
        .map(|c| c.umask()).unwrap_or(0);
    let mode = (args.a2 as u32) & 0o7777;
    // D57: parent walk (ENOTDIR) → EEXIST → EROFS, matching Linux ordering
    // (see 083_mkdir for the rationale + the systemd cg_create constraint).
    if !matches!(parent.inode.file_type(), vfs::FileType::Directory) {
        #[cfg(feature = "debug-udevdb")]
        crate::namei_common::trace_udevdb_path(b"mkdirat", &p, -(Errno::Enotdir.as_i32() as i64));
        #[cfg(feature = "debug-mount")]
        trace_runtime_dir("mkdirat_enotdir", raw, Some(&p), -(Errno::Enotdir.as_i32() as i64));
        return -(Errno::Enotdir.as_i32() as i64);
    }
    match child_exists(&parent, &name) {
        Ok(true) => {
            #[cfg(feature = "debug-udevdb")]
            crate::namei_common::trace_udevdb_path(b"mkdirat", &p, -(Errno::Eexist.as_i32() as i64));
            #[cfg(feature = "debug-mount")]
            trace_runtime_dir("mkdirat_eexist", raw, Some(&p), -(Errno::Eexist.as_i32() as i64));
            return -(Errno::Eexist.as_i32() as i64);
        }
        Ok(false) => {}
        Err(rv) => {
            #[cfg(feature = "debug-udevdb")]
            crate::namei_common::trace_udevdb_path(b"mkdirat", &p, rv);
            #[cfg(feature = "debug-mount")]
            trace_runtime_dir("mkdirat_exists", raw, Some(&p), rv);
            return rv;
        }
    }
    if parent_mount_readonly(&parent) {
        #[cfg(feature = "debug-udevdb")]
        crate::namei_common::trace_udevdb_path(b"mkdirat", &p, -(Errno::Erofs.as_i32() as i64));
        #[cfg(feature = "debug-mount")]
        trace_runtime_dir("mkdirat_rofs", raw, Some(&p), -(Errno::Erofs.as_i32() as i64));
        return -(Errno::Erofs.as_i32() as i64);
    }
    if let Err(rv) = crate::landlock::check_parent(&parent,
        ::security::landlock::access::MAKE_DIR) { return rv; }
    let cred = crate::pathresolve::current_cred();
    if let Err(e) = vfs::may_create(&parent.inode, &cred) {
        #[cfg(feature = "debug-eacces")]
        if e == vfs::VfsError::Eacces {
            crate::namei_common::trace_create_eacces(b"mkdirat", &p, &parent.inode, &cred);
        }
        let rv = errno_from_vfs(e);
        #[cfg(feature = "debug-udevdb")]
        crate::namei_common::trace_udevdb_path(b"mkdirat", &p, rv);
        #[cfg(feature = "debug-mount")]
        trace_runtime_dir("mkdirat_create_perm", raw, Some(&p), rv);
        return rv;
    }
    // Thread the mount idmap + caller cred + umask for the new dir's owner.
    let ctx = vfs::CreateCtx { idmap: &vfs::IDENTITY, cred: &cred, umask: umask as u16 };
    // D29: parent dir `i_rwsem` EXCLUSIVE across the backend mkdir (Linux
    // `filename_create` → `->mkdir`); dropped before the dcache update below.
    let r = { let _g = parent.inode.inode_lock(); parent.inode.mkdir(&name, mode, &ctx) };
    match r {
        Ok(_) => {
            #[cfg(feature = "debug-udevdb")]
            crate::namei_common::trace_udevdb_path(b"mkdirat", &p, 0);
            #[cfg(feature = "debug-mount")]
            trace_runtime_dir("mkdirat", raw, Some(&p), 0);
            drop_child_cache(&parent, &name);
            vfs::fire_dirent_create(&parent.inode, &name);
            0
        }
        Err(e) => {
            crate::namei_common::trace_run_vfs_error(b"mkdirat", &p, e);
            let rv = errno_from_vfs(e);
            #[cfg(feature = "debug-udevdb")]
            crate::namei_common::trace_udevdb_path(b"mkdirat", &p, rv);
            #[cfg(feature = "debug-mount")]
            trace_runtime_dir("mkdirat", raw, Some(&p), rv);
            rv
        }
    }
}
