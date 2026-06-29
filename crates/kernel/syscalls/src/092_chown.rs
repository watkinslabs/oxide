// 092 chown (also serves lchown slot 94) — one syscall fn, one file
// (docs/53 §0). chown follows symlinks; lchown's no-follow distinction
// is handled by the resolver flag at the call site.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::perms_common::{resolve_path_mnt, do_chown, AT_FDCWD};

/// `sys_chown(path, uid, gid)` / `sys_lchown(path, uid, gid)` — slots 92/94.
/// # C: O(N_path)
pub fn sys_chown(args: &SyscallArgs) -> i64 {
    let (inode, mnt_id) = match resolve_path_mnt(AT_FDCWD, args.a0, true) { Ok(p) => p, Err(rv) => return rv };
    do_chown(&inode, mnt_id, args.a1 as u32, args.a2 as u32)
}
