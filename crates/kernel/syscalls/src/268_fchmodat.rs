// 268 fchmodat — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::perms_common::{resolve_at_target, now_ns};

/// `sys_fchmodat(dirfd, path, mode, flags)` — slot 268.
/// # C: O(N_path)
pub fn sys_fchmodat(args: &SyscallArgs) -> i64 {
    let inode = match resolve_at_target(args.a0 as i32, args.a1, args.a3 as u32, (args.a3 as u32 & 0x100) == 0) { Ok(i) => i, Err(rv) => return rv };
    let m = args.a2 as u16;
    if inode.set_perm(m).is_err() { vfs::inode_times::set_mode(&inode, m, now_ns()); }
    0
}
