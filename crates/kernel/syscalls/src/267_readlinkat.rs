// 267 readlinkat — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_readlinkat(dirfd, path, buf, bufsize)` — slot 267.
/// v1 ignores `dirfd` (no real cwd resolution) and routes
/// through `sys_readlink`.
/// # C: O(1)
pub fn sys_readlinkat(args: &SyscallArgs) -> i64 {
    let inner = SyscallArgs { a0: args.a1, a1: args.a2, a2: args.a3, a3: 0, a4: 0, a5: 0 };
    crate::s089_readlink::sys_readlink(&inner)
}
