// 080 chdir — one syscall, one file (docs/53 §0). ABI shim only: the directory
// gate, MAY_EXEC check and pwd install are `fs::cwd::set_fs_pwd`.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_chdir(path)` — slot 80.
/// # C: O(N_path)
pub fn sys_chdir(args: &SyscallArgs) -> i64 {
    let path_ptr = args.a0;
    // D1/D2: PATH_MAX errno contract (EFAULT/ENOENT-on-empty/ENAMETOOLONG).
    let path = match crate::namei_common::read_user_path(path_ptr) {
        Ok(s)   => s,
        Err(rv) => return rv,
    };
    // chdir(2) follows symlinks (LOOKUP_FOLLOW | LOOKUP_DIRECTORY); a resolved
    // non-directory final target is ENOTDIR, decided by the work-fn.
    let vp = match crate::pathresolve::resolve_path_raw(path.as_str(), false) {
        Ok(p)  => p,
        Err(e) => return crate::namei_common::errno_from_vfs(e),
    };
    ::fs::cwd::set_fs_pwd(vp, &crate::pathresolve::current_cred())
}
