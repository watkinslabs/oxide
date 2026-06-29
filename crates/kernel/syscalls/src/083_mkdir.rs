// 083 mkdir — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::{
    read_path, errno_from_vfs, resolve_parent, path_exists, strip_trailing_slash,
};

/// `mkdir(path, mode)` slot 83.
/// # C: O(N parent entries)
pub fn sys_mkdir(args: &SyscallArgs) -> i64 {
    let raw = match read_path(args.a0) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let p = match crate::pathresolve::resolve_at_result(crate::pathresolve::AT_FDCWD, &raw) {
        Ok(p) => p, Err(rv) => return rv,
    };
    let p = String::from(strip_trailing_slash(&p));
    if let Err(rv) = crate::landlock::check(&p,
        ::security::landlock::access::MAKE_DIR) { return rv; }
    // Linux do_mkdirat: `mode &= ~current_umask()` (D23).
    let umask = sched::live::current()
        .map(|c| c.umask.load(core::sync::atomic::Ordering::Acquire)).unwrap_or(0);
    let mode = (args.a1 as u32) & 0o7777 & !umask;
    // D57: walk the parent FIRST so a non-directory path component surfaces
    // ENOTDIR (Linux filename_create), then EEXIST (target present) BEFORE
    // EROFS — Linux returns EEXIST before mnt_want_write, and systemd's
    // cg_create relies on mkdir of an existing dir under a RO pseudo-fs
    // returning EEXIST (success), not EROFS. resolve_parent is a read-only
    // walk, so reordering it ahead of these checks cannot leak the parent's
    // EROFS.
    let (pino, name) = match resolve_parent(&p) { Ok(x) => x, Err(rv) => return rv };
    if !matches!(pino.file_type(), vfs::FileType::Directory) {
        return -(Errno::Enotdir.as_i32() as i64);
    }
    if path_exists(&p) { return -(Errno::Eexist.as_i32() as i64); }
    if vfs::mount::is_readonly_path(&p) {
        return -(Errno::Erofs.as_i32() as i64);
    }
    // Thread the mount idmap + caller cred + umask so the new dir gets the right
    // owner (Linux `->mkdir(struct mnt_idmap *, ...)`).
    let cred = crate::pathresolve::current_cred();
    let ctx = vfs::CreateCtx { idmap: &vfs::IDENTITY, cred: &cred, umask: umask as u16 };
    // D29: hold the parent dir's `i_rwsem` EXCLUSIVE across the backend mkdir
    // (Linux `filename_create` → `->mkdir`). Scope is just the op; the rank-40
    // i_rwsem is dropped before the rank-50/60 dcache `d_drop_path` below.
    let r = { let _g = pino.inode_lock(); pino.mkdir(&name, mode, &ctx) };
    match r {
        Ok(_) => { crate::pathresolve::d_drop_path(&p); 0 }
        Err(e) => {
            crate::namei_common::trace_run_vfs_error(b"mkdir", &p, e);
            errno_from_vfs(e)
        }
    }
}
