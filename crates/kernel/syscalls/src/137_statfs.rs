// 137 statfs — one syscall, one file (docs/53 §0). Moved verbatim from statfs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

use crate::userbuf::validate_user_buf_writable;
use crate::statfs_common::{statfs_for_mount, write_statfs, STATFS_BYTES};

#[cfg(feature = "debug-mount")]
fn log_runtime_statfs(path_ptr: u64, rv: i64) {
    if let Ok(path) = crate::namei_common::read_user_path(path_ptr) {
        if path.starts_with("/run/systemd") || path.contains("systemd/journal") {
            crate::mount_common::mnt_log("statfs", &path, rv);
        }
    }
}

/// `sys_statfs(path, buf)` — slot 137. Resolves `path` (following symlinks) and
/// reports the resolved mount's own superblock accounting plus that mount's
/// statvfs `ST_*` flags (Linux `user_path_at(LOOKUP_FOLLOW)` → `vfs_statfs`).
/// # C: O(N_mounts)
pub fn sys_statfs(args: &SyscallArgs) -> i64 {
    let path_ptr = args.a0;
    let buf      = args.a1;
    if let Err(rv) = validate_user_buf_writable(buf, STATFS_BYTES as u64, 1) { return rv; }
    let lf = vfs::LookupFlags {
        no_follow_final: false,
        follow: true,
        ..Default::default()
    };
    // Linux statfs() is `user_path_at(LOOKUP_FOLLOW)` then `vfs_statfs(&path)`:
    // resolve once to the authoritative `(vfsmount,dentry)` and report that
    // mount's superblock. Do not stringify and re-resolve through cwd/root.
    let vp = match crate::pathresolve::resolve_at_lookup(crate::perms_common::AT_FDCWD, path_ptr, lf) {
        Ok(p) => p,
        Err(rv) => {
            #[cfg(feature = "debug-mount")]
            log_runtime_statfs(path_ptr, rv);
            return rv;
        }
    };
    let Some(m) = vfs::mount::mount_by_id(vp.mnt_id) else {
        #[cfg(feature = "debug-mount")]
        log_runtime_statfs(path_ptr, -(syscall::errno::Errno::Enoent.as_i32() as i64));
        return -(syscall::errno::Errno::Enoent.as_i32() as i64);
    };
    let st = statfs_for_mount(&m);
    write_statfs(buf, &st);
    #[cfg(feature = "debug-mount")]
    log_runtime_statfs(path_ptr, 0);
    0
}
