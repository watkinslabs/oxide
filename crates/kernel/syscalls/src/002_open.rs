// 002 open — one syscall, one file (docs/53 §0).
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::open_common::{O_CREAT, O_TRUNC, O_WRONLY};

/// `sys_open(path, flags, mode)` — legacy open(2) is openat(AT_FDCWD, path,
/// flags, mode). Keep all path authority in the openat implementation.
/// # C: O(N_path)
pub fn sys_open(args: &SyscallArgs) -> i64 {
    let sa = SyscallArgs {
        a0: crate::pathresolve::AT_FDCWD as u64,
        a1: args.a0,
        a2: args.a1,
        a3: args.a2,
        a4: 0,
        a5: 0,
    };
    crate::s257_openat::sys_openat(&sa)
}

/// `sys_creat(path, mode)` — legacy creat(2) is openat(AT_FDCWD, path,
/// O_CREAT|O_WRONLY|O_TRUNC, mode). # C: O(N_path)
pub fn sys_creat(args: &SyscallArgs) -> i64 {
    let sa = SyscallArgs {
        a0: crate::pathresolve::AT_FDCWD as u64,
        a1: args.a0,
        a2: (O_CREAT | O_WRONLY | O_TRUNC) as u64,
        a3: args.a1,
        a4: 0,
        a5: 0,
    };
    crate::s257_openat::sys_openat(&sa)
}
