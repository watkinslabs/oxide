// 260 fchownat — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::perms_common::{resolve_at_target, now_ns};

/// `sys_fchownat(dirfd, path, uid, gid, flags)` — slot 260.
/// # C: O(N_path)
pub fn sys_fchownat(args: &SyscallArgs) -> i64 {
    let inode = match resolve_at_target(args.a0 as i32, args.a1, args.a4 as u32, (args.a4 as u32 & 0x100) == 0) { Ok(i) => i, Err(rv) => return rv };
    let u = args.a2 as u32; let g = args.a3 as u32;
    if inode.set_owner(u, g).is_err() { vfs::inode_times::set_owner(&inode, u, g, now_ns()); }
    0
}
