// 432 fsmount — one syscall, one file (docs/53 §0). Moved verbatim from fsmount.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::InodeRef;

use crate::fsmount_common::*;

/// `sys_fsmount(fs_fd, flags, attr_flags)` — slot 432. Materialises a
/// detached mount object from the `fs_context`; returns a new fd for it.
/// `FSMOUNT_CLOEXEC = 1`.
/// # C: O(1)
pub fn sys_fsmount(args: &SyscallArgs) -> i64 {
    const FSMOUNT_CLOEXEC: u64 = 1;
    if let Some(rv) = require_sys_admin() { return rv; }  // Linux may_mount (D49)
    let fd = args.a0 as i32;
    let inode = match fd_inode(fd) { Some(i) => i, None => return -(Errno::Ebadf.as_i32() as i64) };
    let ctx = match inode.private::<FsContextInode>() {
        Some(c) => c, None => return -(Errno::Einval.as_i32() as i64),
    };
    let source = ctx.source.lock().clone();
    let mo: InodeRef = MountObjectInode::new(ctx.fstype.clone(), source);
    install_fd(mo, "fsmount", (args.a1 & FSMOUNT_CLOEXEC) != 0)
}
