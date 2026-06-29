// 258 mkdirat — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::{
    read_path, errno_from_vfs, resolve_parent, path_exists, strip_trailing_slash,
};

/// `mkdirat(dirfd, path, mode)` slot 258. Ignores dirfd (paths
/// resolved absolute or cwd-relative).
/// # C: O(1)
pub fn sys_mkdirat(args: &SyscallArgs) -> i64 {
    let raw = match read_path(args.a1) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    // BUG D follow-up: resolve against the real dirfd (a0).
    let p = match crate::pathresolve::resolve_at_result(args.a0 as i32, &raw) {
        Ok(rp) => rp, Err(rv) => return rv,
    };
    let p = String::from(strip_trailing_slash(&p));
    if let Err(rv) = crate::landlock::check(&p,
        ::security::landlock::access::MAKE_DIR) { return rv; }
    // Linux do_mkdirat: `mode &= ~current_umask()` (D23).
    let umask = sched::live::current()
        .map(|c| c.umask.load(core::sync::atomic::Ordering::Acquire)).unwrap_or(0);
    let mode = (args.a2 as u32) & 0o7777 & !umask;
    // D57: parent walk (ENOTDIR) → EEXIST → EROFS, matching Linux ordering
    // (see 083_mkdir for the rationale + the systemd cg_create constraint).
    let (pino, name) = match resolve_parent(&p) {
        Ok(x) => x,
        Err(rv) => { crate::mount_common::mnt_log("mkdirat_noparent", &p, rv); return rv; }
    };
    if !matches!(pino.file_type(), vfs::FileType::Directory) {
        return -(Errno::Enotdir.as_i32() as i64);
    }
    if path_exists(&p) { return -(Errno::Eexist.as_i32() as i64); }
    if vfs::mount::is_readonly_path(&p) {
        return -(Errno::Erofs.as_i32() as i64);
    }
    // Thread the mount idmap + caller cred + umask for the new dir's owner.
    let cred = crate::pathresolve::current_cred();
    let ctx = vfs::CreateCtx { idmap: &vfs::IDENTITY, cred: &cred, umask: umask as u16 };
    // D29: parent dir `i_rwsem` EXCLUSIVE across the backend mkdir (Linux
    // `filename_create` → `->mkdir`); dropped before the dcache update below.
    let r = { let _g = pino.inode_lock(); pino.mkdir(&name, mode, &ctx) };
    match r {
        Ok(_) => { crate::pathresolve::d_drop_path(&p); 0 }
        Err(e) => {
            crate::namei_common::trace_run_vfs_error(b"mkdirat", &p, e);
            let rv = errno_from_vfs(e);
            crate::mount_common::mnt_log("mkdirat", &p, rv);
            rv
        }
    }
}
