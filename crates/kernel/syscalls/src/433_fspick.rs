// 433 fspick — one syscall, one file (docs/53 §0). Moved verbatim from fsmount.rs.
#![cfg(target_os = "oxide-kernel")]

use alloc::string::ToString;

use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::InodeRef;

use crate::fsmount_common::*;

/// `sys_fspick(dirfd, path, flags)` — slot 433. Opens an `fs_context` for
/// the EXISTING mount at `path` (for reconfiguration via fsconfig). We tag
/// it with the mount's fstype. `FSPICK_CLOEXEC = 1`.
/// # C: O(N_mounts)
pub fn sys_fspick(args: &SyscallArgs) -> i64 {
    const FSPICK_CLOEXEC: u64 = 1;
    let path = match read_cstr(args.a1, 256) {
        Some(s) => s, None => return -(Errno::Efault.as_i32() as i64),
    };
    let abs = crate::pathresolve::resolve_cwd(&path);
    let abs = if abs.len() > 1 { abs.trim_end_matches('/').to_string() } else { abs };
    let (mnt, _) = match vfs::mount::resolve_mount(&abs) {
        Some(m) => m, None => return -(Errno::Enoent.as_i32() as i64),
    };
    let inode = FsContextInode::new(mnt.fs.name().to_string()) as InodeRef;
    install_fd(inode, "fspick", (args.a2 & FSPICK_CLOEXEC) != 0)
}
