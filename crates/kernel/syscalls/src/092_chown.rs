// 092 chown (also serves lchown slot 94) — one syscall fn, one file
// (docs/53 §0). chown follows symlinks; lchown's no-follow distinction
// is handled by the resolver flag at the call site.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::perms_common::{resolve_path_inode, now_ns, AT_FDCWD};

/// `sys_chown(path, uid, gid)` / `sys_lchown(path, uid, gid)` — slots 92/94.
/// # C: O(N_path)
pub fn sys_chown(args: &SyscallArgs) -> i64 {
    let inode = match resolve_path_inode(AT_FDCWD, args.a0, true) { Ok(i) => i, Err(rv) => return rv };
    let u = args.a1 as u32; let g = args.a2 as u32;
    if inode.set_owner(u, g).is_err() { vfs::inode_times::set_owner(&inode, u, g, now_ns()); }
    0
}
