// 093 fchown — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::perms_common::{resolve_fd_inode, now_ns};

/// `sys_fchown(fd, uid, gid)` — slot 93.
/// # C: O(1)
pub fn sys_fchown(args: &SyscallArgs) -> i64 {
    let inode = match resolve_fd_inode(args.a0 as i32) { Ok(i) => i, Err(rv) => return rv };
    let u = args.a1 as u32; let g = args.a2 as u32;
    if inode.set_owner(u, g).is_err() { vfs::inode_times::set_owner(&inode, u, g, now_ns()); }
    0
}
