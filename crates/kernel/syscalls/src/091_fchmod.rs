// 091 fchmod — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::perms_common::{resolve_fd_file, do_chmod};

/// `sys_fchmod(fd, mode)` — slot 91.
/// # C: O(1)
pub fn sys_fchmod(args: &SyscallArgs) -> i64 {
    let f = match resolve_fd_file(args.a0 as i32) { Ok(f) => f, Err(rv) => return rv };
    do_chmod(f.inode(), f.mnt_id(), args.a1 as u16)
}
