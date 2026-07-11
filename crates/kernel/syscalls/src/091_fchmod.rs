// 091 fchmod — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::perms_common::{resolve_fd_file, do_chmod};

#[cfg(feature = "debug-mount")]
fn log_runtime_fchmod(f: &vfs::File, rv: i64) {
    let path = vfs::mount::render_path_for_mount(f.mnt_id(), f.dentry());
    if path.starts_with("/run/systemd") || path.contains("systemd/journal") {
        crate::mount_common::mnt_log("fchmod", &path, rv);
    }
}

/// `sys_fchmod(fd, mode)` — slot 91.
/// # C: O(1)
pub fn sys_fchmod(args: &SyscallArgs) -> i64 {
    let f = match resolve_fd_file(args.a0 as i32) { Ok(f) => f, Err(rv) => return rv };
    let rv = do_chmod(f.inode(), f.mnt_id(), args.a1 as u16);
    #[cfg(feature = "debug-udevdb")]
    crate::namei_common::trace_udevdb_file(b"fchmod", &f, rv);
    #[cfg(feature = "debug-mount")]
    log_runtime_fchmod(&f, rv);
    rv
}
