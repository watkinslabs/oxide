// 093 fchown — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::perms_common::{resolve_fd_file, do_chown};

#[cfg(feature = "debug-mount")]
fn log_runtime_fchown(f: &vfs::File, rv: i64) {
    let path = vfs::mount::render_path_for_mount(f.mnt_id(), f.dentry());
    if path.starts_with("/run/systemd") || path.contains("systemd/journal") {
        crate::mount_common::mnt_log("fchown", &path, rv);
    }
}

/// `sys_fchown(fd, uid, gid)` — slot 93.
/// # C: O(1)
pub fn sys_fchown(args: &SyscallArgs) -> i64 {
    let f = match resolve_fd_file(args.a0 as i32) { Ok(f) => f, Err(rv) => return rv };
    let rv = do_chown(f.inode(), f.mnt_id(), args.a1 as u32, args.a2 as u32);
    #[cfg(feature = "debug-mount")]
    log_runtime_fchown(&f, rv);
    rv
}
