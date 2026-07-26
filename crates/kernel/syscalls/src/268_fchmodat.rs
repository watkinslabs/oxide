// 268 fchmodat — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::perms_common::{resolve_at_target_mnt, do_chmod, AT_SYMLINK_NOFOLLOW};

#[cfg(feature = "debug-mount")]
fn log_fchmodat_empty(dirfd: i32, rv: i64) {
    let Ok(f) = crate::perms_common::resolve_fd_file(dirfd) else { return; };
    let path = vfs::mount::render_path_for_mount(f.mnt_id(), f.dentry());
    if path.starts_with("/run/systemd") || path.contains("systemd/journal") {
        crate::mount_common::mnt_log("fchmodat_empty", &path, rv);
    }
}

/// Common `fchmodat2` body with an explicit Linux flags word. # C: O(N_path)
pub(crate) fn sys_fchmodat_flags(args: &SyscallArgs, flags: u32) -> i64 {
    #[cfg(feature = "debug-mount")]
    let empty_path = crate::namei_common::read_user_path(args.a1).map(|p| p.is_empty()).unwrap_or(false);
    let follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    let (inode, mnt_id) = match resolve_at_target_mnt(args.a0 as i32, args.a1, flags, follow) {
        Ok(p) => p, Err(rv) => {
            #[cfg(feature = "debug-mount")]
            if empty_path { log_fchmodat_empty(args.a0 as i32, rv); }
            #[cfg(feature = "debug-mount")]
            if let Ok(path) = crate::namei_common::read_user_path(args.a1) {
                if crate::mount_common::traced_path(&path) { crate::mount_common::mnt_log("fchmodat_resolve", &path, rv); }
            }
            return rv;
        }
    };
    let rv = do_chmod(&inode, mnt_id, args.a2 as u16);
    #[cfg(feature = "debug-mount")]
    if empty_path { log_fchmodat_empty(args.a0 as i32, rv); }
    #[cfg(feature = "debug-mount")]
    if rv < 0 {
        if let Ok(path) = crate::namei_common::read_user_path(args.a1) {
            if crate::mount_common::traced_path(&path) { crate::mount_common::mnt_log("fchmodat", &path, rv); }
        }
    }
    rv
}

/// `sys_fchmodat(dirfd, path, mode)` — slot 268.
/// # C: O(N_path)
pub fn sys_fchmodat(args: &SyscallArgs) -> i64 {
    sys_fchmodat_flags(args, 0)
}
