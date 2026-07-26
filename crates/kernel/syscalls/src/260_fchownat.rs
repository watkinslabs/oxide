// 260 fchownat — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::perms_common::{resolve_at_target_mnt, do_chown, AT_SYMLINK_NOFOLLOW};

#[cfg(feature = "debug-mount")]
fn log_fchownat_empty(dirfd: i32, rv: i64) {
    let Ok(f) = crate::perms_common::resolve_fd_file(dirfd) else { return; };
    let path = vfs::mount::render_path_for_mount(f.mnt_id(), f.dentry());
    if path.starts_with("/run/systemd") || path.contains("systemd/journal") {
        crate::mount_common::mnt_log("fchownat_empty", &path, rv);
    }
}

/// `sys_fchownat(dirfd, path, uid, gid, flags)` — slot 260.
/// # C: O(N_path)
pub fn sys_fchownat(args: &SyscallArgs) -> i64 {
    #[cfg(feature = "debug-mount")]
    let empty_path = crate::namei_common::read_user_path(args.a1).map(|p| p.is_empty()).unwrap_or(false);
    let flags = args.a4 as u32;
    let follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    let (inode, mnt_id) = match resolve_at_target_mnt(args.a0 as i32, args.a1, flags, follow) {
        Ok(p) => p, Err(rv) => {
            #[cfg(feature = "debug-mount")]
            if empty_path { log_fchownat_empty(args.a0 as i32, rv); }
            #[cfg(feature = "debug-mount")]
            if let Ok(path) = crate::namei_common::read_user_path(args.a1) {
                if crate::mount_common::traced_path(&path) { crate::mount_common::mnt_log("fchownat_resolve", &path, rv); }
            }
            return rv;
        }
    };
    let rv = do_chown(&inode, mnt_id, args.a2 as u32, args.a3 as u32);
    #[cfg(feature = "debug-mount")]
    if empty_path { log_fchownat_empty(args.a0 as i32, rv); }
    #[cfg(feature = "debug-mount")]
    if rv < 0 {
        if let Ok(path) = crate::namei_common::read_user_path(args.a1) {
            if crate::mount_common::traced_path(&path) { crate::mount_common::mnt_log("fchownat", &path, rv); }
        }
    }
    rv
}
