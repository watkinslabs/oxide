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
    // Resolve linkpath against newdirfd (a1). The symlink target is stored
    // verbatim (never resolved at creation).
    let link = match crate::pathresolve::resolve_at_result(args.a1 as i32, &link) {
        Ok(p) => p, Err(rv) => return rv,
    };
    crate::s088_symlink::symlink_impl(target, link)
}
