// 091 fchmod — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::perms_common::{resolve_fd_inode, now_ns};

/// `sys_fchmod(fd, mode)` — slot 91.
/// # C: O(1)
pub fn sys_fchmod(args: &SyscallArgs) -> i64 {
    let inode = match resolve_fd_inode(args.a0 as i32) { Ok(i) => i, Err(rv) => return rv };
    let m = args.a1 as u16;
    if inode.set_perm(m).is_err() { vfs::inode_times::set_mode(&inode, m, now_ns()); }
    0
}
