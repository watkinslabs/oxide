// 137 statfs — one syscall, one file (docs/53 §0). Moved verbatim from statfs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

use crate::userbuf::validate_user_buf;
use crate::statfs_common::{statfs_for_mount, write_statfs};

/// `sys_statfs(path, buf)` — slot 137. Reports the `f_type` magic of
/// the filesystem backing `path`.
/// # C: O(N_mounts)
pub fn sys_statfs(args: &SyscallArgs) -> i64 {
    let path_ptr = args.a0;
    let buf      = args.a1;
    if let Err(rv) = validate_user_buf(buf, 120, 8) { return rv; }
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
        Err(rv) => return rv,
    };
    let Some(m) = vfs::mount::mount_by_id(vp.mnt_id) else {
        return -(syscall::errno::Errno::Enoent.as_i32() as i64);
    };
    let st = statfs_for_mount(&m);
    write_statfs(buf, &st);
    0
}
