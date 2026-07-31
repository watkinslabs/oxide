// 430 fsopen — one syscall, one file (docs/53 §0). Moved verbatim from fsmount.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::InodeRef;

use crate::fsmount_common::*;

/// `sys_fsopen(fsname, flags)` — slot 430. Creates an `fs_context` fd for
/// `fsname`. The `flags` word carries ONLY `FSOPEN_CLOEXEC` (Linux
/// `fs/fsopen.c`: `if (flags & ~FSOPEN_CLOEXEC) return -EINVAL`) — fsopen has NO
/// superblock-flag bits, so the context is seeded `sb_flags=0` (superblock D19);
/// the user-settable `SB_*` flags (`ro`/`sync`/…) arrive later via
/// `fsconfig(FSCONFIG_SET_FLAG)` and are committed at `vfs_get_tree`. `FSOPEN_CLOEXEC = 1`.
/// # C: O(1)
pub fn sys_fsopen(args: &SyscallArgs) -> i64 {
    const FSOPEN_CLOEXEC: u64 = 1;
    if let Some(rv) = may_mount_or_eperm() { return rv; }  // Linux may_mount (D49)
    if args.a1 & !FSOPEN_CLOEXEC != 0 { return -(Errno::Einval.as_i32() as i64); }
    // `strndup_user(_fs_name, PAGE_SIZE)` — a 64-byte private cap turned a long
    // filesystem name into ENAMETOOLONG where Linux says ENODEV.
    let fsname = match read_cstr_req(args.a0, 4096) {
        Ok(s) => s, Err(rv) => return rv,
    };
    // Admission is `get_fs_type(fs_name)` and NOTHING else. A hardcoded name
    // whitelist ran ahead of it — a second source of truth for "which
    // filesystems exist" that could only ever disagree with the registry by
    // refusing a type that IS registered.
    ensure_filesystems_registered();
    let Some(ty) = vfs::fs::get_fs_type(&fsname) else {
        return -(Errno::Enodev.as_i32() as i64);
    };
    let inode: InodeRef = FsContextInode::new(fsname, ty);
    install_fd(inode, "[fscontext]", (args.a1 & FSOPEN_CLOEXEC) != 0)
}
