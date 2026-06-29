// 137 statfs — one syscall, one file (docs/53 §0). Moved verbatim from statfs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

use crate::userbuf::validate_user_buf;
use crate::statfs_common::{statfs_for_path, write_statfs};

/// `sys_statfs(path, buf)` — slot 137. Reports the `f_type` magic of
/// the filesystem backing `path`.
/// # C: O(N_mounts)
pub fn sys_statfs(args: &SyscallArgs) -> i64 {
    let path_ptr = args.a0;
    let buf      = args.a1;
    if let Err(rv) = validate_user_buf(buf, 120, 8) { return rv; }
    if path_ptr == 0 || path_ptr >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: ptr in user range; user page mapped (caller's user code ran from this AS); read bounded at 256 B.
    let raw = match unsafe { devfs::read_user_cstr(path_ptr, 256) } {
        Some(p) => match core::str::from_utf8(p) {
            Ok(s) => s,
            Err(_) => return -(Errno::Einval.as_i32() as i64),
        },
        None => return -(Errno::Efault.as_i32() as i64),
    };
    // Linux statfs() is `user_path_at(LOOKUP_FOLLOW)` then `vfs_statfs`: the path
    // must exist (else ENOENT) and a relative path resolves against cwd. The old
    // code fed the raw string straight to `resolve_mount`, which falls back to
    // the root mount for ANY string — so a nonexistent path wrongly succeeded.
    let abspath = match crate::pathresolve::resolve_at_result(crate::perms_common::AT_FDCWD, raw) {
        Ok(p) => p, Err(rv) => return rv,
    };
    if crate::pathresolve::resolve(abspath.as_str(), false).is_none() {
        return -(Errno::Enoent.as_i32() as i64);
    }
    let st = statfs_for_path(abspath.as_str());
    write_statfs(buf, &st);
    0
}
