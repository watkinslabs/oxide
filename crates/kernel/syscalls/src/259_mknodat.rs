// 259 mknodat — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::namei_common::read_user_path;

/// `mknodat(dirfd, path, mode, dev)` slot 259. Ignores dirfd.
/// # C: O(N parent entries)
pub fn sys_mknodat(args: &SyscallArgs) -> i64 {
    // D1/D2: PATH_MAX errno contract (EFAULT/ENOENT-on-empty/ENAMETOOLONG).
    let raw = match read_user_path(args.a1) {
        Ok(s) => s, Err(rv) => return rv,
    };
    // BUG D follow-up: resolve against the real dirfd (a0).
    let raw = match crate::pathresolve::resolve_at_result(args.a0 as i32, &raw) {
        Ok(p) => p, Err(rv) => return rv,
    };
    crate::s133_mknod::mknod_impl(raw, args.a2 as u16, args.a3 as u32)
}
