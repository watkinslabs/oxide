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
    let st = match unsafe { devfs::read_user_cstr(path_ptr, 256) } {
        Some(p) => match core::str::from_utf8(p) {
            Ok(s) => statfs_for_path(s),
            Err(_) => return -(Errno::Einval.as_i32() as i64),
        },
        None => return -(Errno::Efault.as_i32() as i64),
    };
    write_statfs(buf, &st);
    0
}
