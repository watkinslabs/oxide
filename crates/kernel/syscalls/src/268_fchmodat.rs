// 268 fchmodat — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::perms_common::{resolve_at_target_mnt, do_chmod, AT_SYMLINK_NOFOLLOW};

/// `sys_fchmodat(dirfd, path, mode, flags)` — slot 268.
/// # C: O(N_path)
pub fn sys_fchmodat(args: &SyscallArgs) -> i64 {
    let follow = (args.a3 as u32 & AT_SYMLINK_NOFOLLOW) == 0;
    let (inode, mnt_id) = match resolve_at_target_mnt(args.a0 as i32, args.a1, args.a3 as u32, follow) {
        Ok(p) => p, Err(rv) => return rv,
    };
    do_chmod(&inode, mnt_id, args.a2 as u16)
}
