// 430 fsopen — one syscall, one file (docs/53 §0). Moved verbatim from fsmount.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::InodeRef;

use crate::fsmount_common::*;

/// `sys_fsopen(fsname, flags)` — slot 430. Creates an `fs_context` fd for
/// `fsname`. `FSOPEN_CLOEXEC = 1`.
/// # C: O(1)
pub fn sys_fsopen(args: &SyscallArgs) -> i64 {
    const FSOPEN_CLOEXEC: u64 = 1;
    let fsname = match read_cstr(args.a0, 64) {
        Some(s) => s, None => return -(Errno::Efault.as_i32() as i64),
    };
    if !fstype_ok(&fsname) { return -(Errno::Enodev.as_i32() as i64); }
    let inode = FsContextInode::new(fsname) as InodeRef;
    install_fd(inode, "fscontext", (args.a1 & FSOPEN_CLOEXEC) != 0)
}
