// 080 chdir — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `sys_chdir(path)` — slot 80.
/// # C: O(N_devfs_entries)
pub fn sys_chdir(args: &SyscallArgs) -> i64 {
    let path_ptr = args.a0;
    // D1/D2: PATH_MAX errno contract (EFAULT/ENOENT-on-empty/ENAMETOOLONG).
    let path = match crate::namei_common::read_user_path(path_ptr) {
        Ok(s)   => s,
        Err(rv) => return rv,
    };
    let raw: &str = path.as_str();
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Einval.as_i32() as i64),
    };
    let resolved = crate::pathresolve::resolve_cwd(raw);
    let s = resolved.as_str();
    // chdir(2) follows symlinks to a directory — resolve via the
    // path-walk and require a directory. A resolved non-directory final
    // target is ENOTDIR (not ENOENT); other walk errors are preserved.
    let path_obj = match crate::pathresolve::resolve_path_result(s, false) {
        Ok(p) if matches!(p.inode.file_type(), vfs::FileType::Directory) => p,
        Ok(_)  => return -(Errno::Enotdir.as_i32() as i64),
        Err(e) => return crate::namei_common::errno_from_vfs(e),
    };
    // SAFETY: single-mutator per `13§5`; current task is sole writer.
    unsafe {
        *cur.cwd.get() = alloc::string::String::from(s);
        *cur.cwd_vfs.get() = Some(path_obj);
    }
    0
}
