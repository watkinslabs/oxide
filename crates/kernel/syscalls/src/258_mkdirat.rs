// 258 mkdirat — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::{
    read_path, resolve, errno_from_vfs, resolve_parent, path_exists, strip_trailing_slash,
};

/// `mkdirat(dirfd, path, mode)` slot 258. Ignores dirfd (paths
/// resolved absolute or cwd-relative).
/// # C: O(1)
pub fn sys_mkdirat(args: &SyscallArgs) -> i64 {
    let raw = match read_path(args.a1) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    // BUG D follow-up: resolve against the real dirfd (a0).
    let p = match crate::pathresolve::resolve_at(args.a0 as i32, &raw) {
        Some(rp) => rp, None => resolve(&raw).unwrap_or(raw),
    };
    let p = String::from(strip_trailing_slash(&p));
    if let Err(rv) = crate::landlock::check(&p,
        ::security::landlock::access::MAKE_DIR) { return rv; }
    let mode = args.a2 as u16;
    if path_exists(&p) { return -(Errno::Eexist.as_i32() as i64); }
    let (pino, name) = match resolve_parent(&p) { Ok(x) => x, Err(rv) => return rv };
    match pino.mkdir(&name, mode as u32) { Ok(_) => 0, Err(e) => errno_from_vfs(e) }
}
