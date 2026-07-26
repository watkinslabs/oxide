// 090 chmod — one syscall, one file (docs/53 §0).
// v1 stores the mode overlay in `inode_times` so statx surfaces it back
// to userspace when the Inode impl lacks native perm storage.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::perms_common::{resolve_path_mnt, do_chmod, AT_FDCWD};

/// `sys_chmod(path, mode)` — slot 90.
/// # C: O(N_path)
pub fn sys_chmod(args: &SyscallArgs) -> i64 {
    let (inode, mnt_id) = match resolve_path_mnt(AT_FDCWD, args.a0, true) { Ok(p) => p, Err(rv) => {
        #[cfg(feature = "debug-mount")]
        if let Ok(path) = crate::namei_common::read_user_path(args.a0) {
            if crate::mount_common::traced_path(&path) { crate::mount_common::mnt_log("chmod_resolve", &path, rv); }
        }
        return rv;
    } };
    let rc = do_chmod(&inode, mnt_id, args.a1 as u16);
    #[cfg(feature = "debug-mount")]
    if rc < 0 {
        if let Ok(path) = crate::namei_common::read_user_path(args.a0) {
            if crate::mount_common::traced_path(&path) { crate::mount_common::mnt_log("chmod", &path, rc); }
        }
    }
    // FAN_ATTRIB / IN_ATTRIB on a successful metadata change (Linux fsnotify_change).
    if rc == 0 { ::fs::inotify::fire_attrib(&inode); }
    rc
}
