// 088 symlink — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.
// Hosts the shared symlink_impl core (also used by 266_symlinkat).

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::{read_path, resolve, errno_from_vfs, resolve_parent};

/// `symlink(target, linkpath)` slot 88.
/// # C: O(N parent entries)
pub fn sys_symlink(args: &SyscallArgs) -> i64 {
    let target = match read_path(args.a0) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let link = match read_path(args.a1) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    symlink_impl(target, link)
}

/// # C: O(N parent entries)
pub(crate) fn symlink_impl(target: String, link: String) -> i64 {
    let l = resolve(&link).unwrap_or(link);
    if let Err(rv) = crate::landlock::check(&l,
        ::security::landlock::access::MAKE_SYM) { return rv; }
    let (pino, name) = match resolve_parent(&l) { Ok(x) => x, Err(rv) => return rv };
    match pino.symlink_child(&name, target.as_bytes()) {
        Ok(())  => 0,
        Err(e)  => errno_from_vfs(e),
    }
}
