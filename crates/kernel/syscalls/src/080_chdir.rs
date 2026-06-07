// 080 chdir — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

/// `sys_chdir(path)` — slot 80.
/// # C: O(N_devfs_entries)
pub fn sys_chdir(args: &SyscallArgs) -> i64 {
    let path_ptr = args.a0;
    if path_ptr == 0 || path_ptr >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: ptr in user range; user page mapped (caller's user code already executed from this AS); read bounded at 256 B.
    let path = match unsafe { devfs::read_user_cstr(path_ptr, 256) } {
        Some(p) if !p.is_empty() => p,
        _                        => return -(Errno::Einval.as_i32() as i64),
    };
    let raw = match core::str::from_utf8(path) {
        Ok(s)  => s,
        Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Einval.as_i32() as i64),
    };
    let resolved = crate::pathresolve::resolve_cwd(raw);
    let s = resolved.as_str();
    // chdir(2) follows symlinks to a directory — resolve via the
    // path-walk and require a directory.
    let resolves = crate::pathresolve::resolve(s, false)
        .map(|i| matches!(i.file_type(), vfs::FileType::Directory))
        .unwrap_or(false);
    if !resolves { return -(Errno::Enoent.as_i32() as i64); }
    // SAFETY: single-mutator per `13§5`; current task is sole writer.
    unsafe { *cur.cwd.get() = alloc::string::String::from(s); }
    0
}
