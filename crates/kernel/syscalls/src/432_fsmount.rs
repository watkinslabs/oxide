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
    // MOUNT_ATTR_* (uapi `linux/mount.h`) settable via fsmount. IDMAP is NOT
    // accepted here (Linux do_fsmount rejects it — only mount_setattr sets idmap).
    const MOUNT_ATTR_RDONLY:     u64 = 0x00_0001;
    const MOUNT_ATTR_NOSUID:     u64 = 0x00_0002;
    const MOUNT_ATTR_NODEV:      u64 = 0x00_0004;
    const MOUNT_ATTR_NOEXEC:     u64 = 0x00_0008;
    const MOUNT_ATTR__ATIME:     u64 = 0x00_0070; // mask: RELATIME(0)/NOATIME(0x10)/STRICTATIME(0x20)
    const MOUNT_ATTR_NOATIME:    u64 = 0x00_0010;
    const MOUNT_ATTR_STRICTATIME:u64 = 0x00_0020;
    const MOUNT_ATTR_NODIRATIME: u64 = 0x00_0080;
    const MOUNT_ATTR_NOSYMFOLLOW:u64 = 0x20_0000;
    const ATTR_VALID: u64 = MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV
        | MOUNT_ATTR_NOEXEC | MOUNT_ATTR__ATIME | MOUNT_ATTR_NODIRATIME | MOUNT_ATTR_NOSYMFOLLOW;
    if let Some(rv) = require_sys_admin() { return rv; }  // Linux may_mount (D49)
    // Validate the fsmount(2) flag words the old shim silently dropped (D51):
    // `flags` outside FSMOUNT_CLOEXEC → EINVAL; `attr_flags` outside the settable
    // MOUNT_ATTR_* set → EINVAL; the atime sub-field must name exactly one mode.
    if args.a1 & !FSMOUNT_CLOEXEC != 0 { return -(Errno::Einval.as_i32() as i64); }
    if args.a2 & !ATTR_VALID != 0 { return -(Errno::Einval.as_i32() as i64); }
    match args.a2 & MOUNT_ATTR__ATIME {
        0 | MOUNT_ATTR_NOATIME | MOUNT_ATTR_STRICTATIME => {}
        _ => return -(Errno::Einval.as_i32() as i64),
    }
    let fd = args.a0 as i32;
    let inode = match fd_inode(fd) { Some(i) => i, None => return -(Errno::Ebadf.as_i32() as i64) };
    let ctx = match inode.private::<FsContextInode>() {
        Some(c) => c, None => return -(Errno::Einval.as_i32() as i64),
    };
    let source = ctx.source.lock().clone();
    let mo: InodeRef = MountObjectInode::new(ctx.fstype.clone(), source);
    install_fd(mo, "fsmount", (args.a1 & FSMOUNT_CLOEXEC) != 0)
}
