// 266 symlinkat — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::namei_common::read_user_path;

/// `symlinkat(target, newdirfd, linkpath)` slot 266. `linkpath` is resolved
/// against `newdirfd` (a1); the target is stored verbatim.
/// # C: O(N parent entries)
pub fn sys_symlinkat(args: &SyscallArgs) -> i64 {
    // Linux `getname`: empty target/link → ENOENT (not EINVAL) (D29).
    let target = match read_user_path(args.a0) { Ok(s) => s, Err(rv) => return rv };
    let link   = match read_user_path(args.a2) { Ok(s) => s, Err(rv) => return rv };
    crate::s088_symlink::symlink_impl(args.a1 as i32, target, link)
}
