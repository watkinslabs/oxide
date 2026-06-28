// 260 fchownat — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::perms_common::{resolve_at_target_mnt, do_chown, AT_SYMLINK_NOFOLLOW};

/// `sys_fchownat(dirfd, path, uid, gid, flags)` — slot 260.
/// # C: O(N_path)
pub fn sys_fchownat(args: &SyscallArgs) -> i64 {
    let follow = (args.a4 as u32 & AT_SYMLINK_NOFOLLOW) == 0;
    let (inode, mnt_id) = match resolve_at_target_mnt(args.a0 as i32, args.a1, args.a4 as u32, follow) {
        Ok(p) => p, Err(rv) => return rv,
    };
    do_chown(&inode, mnt_id, args.a2 as u32, args.a3 as u32)
}
