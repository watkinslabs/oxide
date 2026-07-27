// 092 chown — one syscall fn, one file (docs/53 §0). Follows the final
// symlink (Linux `do_fchownat(AT_FDCWD, ..., 0)`); the no-follow variant is
// its own slot, `094_lchown.rs`.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::perms_common::{resolve_path_mnt, do_chown, AT_FDCWD};

/// `sys_chown(path, uid, gid)` — slot 92.
/// # C: O(N_path)
pub fn sys_chown(args: &SyscallArgs) -> i64 {
    let (inode, mnt_id) = match resolve_path_mnt(AT_FDCWD, args.a0, true) { Ok(p) => p, Err(rv) => {
        #[cfg(feature = "debug-mount")]
        if let Ok(path) = crate::namei_common::read_user_path(args.a0) {
            if crate::mount_common::traced_path(&path) { crate::mount_common::mnt_log("chown_resolve", &path, rv); }
        }
        return rv;
    } };
    let rc = do_chown(&inode, mnt_id, args.a1 as u32, args.a2 as u32);
    #[cfg(feature = "debug-mount")]
    if rc < 0 {
        if let Ok(path) = crate::namei_common::read_user_path(args.a0) {
            if crate::mount_common::traced_path(&path) { crate::mount_common::mnt_log("chown", &path, rc); }
        }
    }
    // FAN_ATTRIB / IN_ATTRIB on a successful ownership change (Linux fsnotify_change).
    if rc == 0 { ::fs::inotify::fire_attrib(&inode); }
    rc
}
