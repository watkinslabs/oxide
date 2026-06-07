// 266 symlinkat — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::read_path;

/// `symlinkat(target, newdirfd, linkpath)` slot 266. Ignores newdirfd
/// (paths resolved absolute or cwd-relative).
/// # C: O(N parent entries)
pub fn sys_symlinkat(args: &SyscallArgs) -> i64 {
    let target = match read_path(args.a0) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let link = match read_path(args.a2) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    // BUG D follow-up: resolve linkpath against newdirfd (a1). The symlink
    // target is stored verbatim (never resolved at creation).
    let link = crate::pathresolve::resolve_at(args.a1 as i32, &link).unwrap_or(link);
    crate::s088_symlink::symlink_impl(target, link)
}
