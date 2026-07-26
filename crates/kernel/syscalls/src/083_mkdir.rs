// 083 mkdir — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::{
    read_user_path, errno_from_vfs, strip_trailing_slash, resolve_create_parent_at,
    render_child_path, child_exists, parent_mount_readonly, drop_child_cache,
};

/// `mkdir(path, mode)` slot 83.
/// # C: O(N parent entries)
pub fn sys_mkdir(args: &SyscallArgs) -> i64 {
    // D1/D2: PATH_MAX errno contract (EFAULT/ENOENT-on-empty/ENAMETOOLONG).
    let raw = match read_user_path(args.a0) {
        Ok(s) => s, Err(rv) => return rv,
    };
    let raw = strip_trailing_slash(&raw);
    let (parent, name) = match resolve_create_parent_at(crate::pathresolve::AT_FDCWD, raw) {
        Ok(x) => x, Err(rv) => {
            #[cfg(feature = "debug-udevdb")]
            crate::namei_common::trace_udevdb_path(b"mkdir", raw, rv);
            #[cfg(feature = "debug-mount")]
            if crate::mount_common::traced_path(raw) { crate::mount_common::mnt_log("mkdir_noparent", raw, rv); }
            return rv;
        }
    };
    let p = render_child_path(&parent, &name);
    let umask = sched::live::current()
        .map(|c| c.umask.load(core::sync::atomic::Ordering::Acquire)).unwrap_or(0);
    let mode = (args.a1 as u32) & 0o7777;
    // D57: walk the parent FIRST so a non-directory path component surfaces
    // ENOTDIR (Linux filename_create), then EEXIST (target present) BEFORE
    // EROFS — Linux returns EEXIST before mnt_want_write, and systemd's
    // cg_create relies on mkdir of an existing dir under a RO pseudo-fs
    // returning EEXIST (success), not EROFS. resolve_parent is a read-only
    // walk, so reordering it ahead of these checks cannot leak the parent's
    // EROFS.
    if !matches!(parent.inode.file_type(), vfs::FileType::Directory) {
        let rv = -(Errno::Enotdir.as_i32() as i64);
        #[cfg(feature = "debug-udevdb")]
        crate::namei_common::trace_udevdb_path(b"mkdir", &p, rv);
        return rv;
    }
    match child_exists(&parent, &name) {
        Ok(true) => {
            #[cfg(feature = "debug-udevdb")]
            crate::namei_common::trace_udevdb_path(b"mkdir", &p, -(Errno::Eexist.as_i32() as i64));
            #[cfg(feature = "debug-mount")]
            if p.contains("/run/systemd/journal") { crate::mount_common::mnt_log("mkdir_eexist", &p, -(Errno::Eexist.as_i32() as i64)); }
            return -(Errno::Eexist.as_i32() as i64);
        }
        Ok(false) => {}
        Err(rv) => {
            #[cfg(feature = "debug-udevdb")]
            crate::namei_common::trace_udevdb_path(b"mkdir", &p, rv);
            #[cfg(feature = "debug-mount")]
            if crate::mount_common::traced_path(raw) { crate::mount_common::mnt_log("mkdir_exists", raw, rv); }
            return rv;
        }
    }
    if parent_mount_readonly(&parent) {
        #[cfg(feature = "debug-udevdb")]
        crate::namei_common::trace_udevdb_path(b"mkdir", &p, -(Errno::Erofs.as_i32() as i64));
        #[cfg(feature = "debug-mount")]
        if crate::mount_common::traced_path(raw) { crate::mount_common::mnt_log("mkdir_rofs", raw, -(Errno::Erofs.as_i32() as i64)); }
        return -(Errno::Erofs.as_i32() as i64);
    }
    if let Err(rv) = crate::landlock::check_parent(&parent,
        ::security::landlock::access::MAKE_DIR) { return rv; }
    let cred = crate::pathresolve::current_cred();
    if let Err(e) = vfs::may_create(&parent.inode, &cred) {
        let rv = errno_from_vfs(e);
        #[cfg(feature = "debug-udevdb")]
        crate::namei_common::trace_udevdb_path(b"mkdir", &p, rv);
        return rv;
    }
    // Thread the mount idmap + caller cred + umask so the new dir gets the right
    // owner (Linux `->mkdir(struct mnt_idmap *, ...)`).
    let ctx = vfs::CreateCtx { idmap: &vfs::IDENTITY, cred: &cred, umask: umask as u16 };
    // D29: hold the parent dir's `i_rwsem` EXCLUSIVE across the backend mkdir
    // (Linux `filename_create` → `->mkdir`). Scope is just the op; the rank-40
    // i_rwsem is dropped before the rank-50/60 object-cache drop below.
    let r = { let _g = parent.inode.inode_lock(); parent.inode.mkdir(&name, mode, &ctx) };
    match r {
        Ok(_) => {
            #[cfg(feature = "debug-udevdb")]
            crate::namei_common::trace_udevdb_path(b"mkdir", &p, 0);
            #[cfg(feature = "debug-mount")]
            if p.contains("/run/systemd/journal") { crate::mount_common::mnt_log("mkdir", &p, 0); }
            drop_child_cache(&parent, &name);
            vfs::fire_dirent_create(&parent.inode, &name);
            0
        }
        Err(e) => {
            crate::namei_common::trace_run_vfs_error(b"mkdir", &p, e);
            let rv = errno_from_vfs(e);
            #[cfg(feature = "debug-udevdb")]
            crate::namei_common::trace_udevdb_path(b"mkdir", &p, rv);
            #[cfg(feature = "debug-mount")]
            if crate::mount_common::traced_path(&p) { crate::mount_common::mnt_log("mkdir", &p, rv); }
            rv
        }
    }
}
