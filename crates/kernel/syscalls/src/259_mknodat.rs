// 259 mknodat — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::read_path;

/// `mknodat(dirfd, path, mode, dev)` slot 259. Ignores dirfd.
/// # C: O(N parent entries)
pub fn sys_mknodat(args: &SyscallArgs) -> i64 {
    let raw = match read_path(args.a1) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    // BUG D follow-up: resolve against the real dirfd (a0).
    let raw = crate::pathresolve::resolve_at(args.a0 as i32, &raw).unwrap_or(raw);
    crate::s133_mknod::mknod_impl(raw, args.a2 as u16, args.a3 as u32)
}
