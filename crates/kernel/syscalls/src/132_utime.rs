// 132 utime — one syscall, one file (docs/53 §0). Moved verbatim from utime.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::utime_common::{now_ns, resolve_target, AT_FDCWD};

/// `sys_utime(path, times)` — slot 132 (older API). `times` is a
/// `struct utimbuf { time_t actime; time_t modtime; }` (16 bytes).
/// NULL ⇒ both = now. Routes through `notify_change` (owner/CAP_FOWNER for the
/// explicit times, EROFS). Always follows symlinks. # C: O(N_path)
pub fn sys_utime(args: &SyscallArgs) -> i64 {
    let path_ptr = args.a0;
    let times_ptr = args.a1;
    let (inode, mnt_id) = match resolve_target(AT_FDCWD, path_ptr, false) {
        Ok(t) => t, Err(rv) => return rv,
    };
    let now = now_ns();
    let mut ia = vfs::Iattr { valid: vfs::ATTR_ATIME | vfs::ATTR_MTIME, ctime_ns: now, ..Default::default() };
    if times_ptr == 0 {
        ia.atime_ns = now; ia.mtime_ns = now;
    } else {
        if let Err(rv) = crate::userbuf::validate_user_buf(times_ptr, 16, 1) { return rv; }
        // SAFETY: full utimbuf byte range validated readable; Linux copyin accepts unaligned storage.
        let (asec, msec) = unsafe {
            (core::ptr::read_unaligned( times_ptr       as *const i64),
             core::ptr::read_unaligned((times_ptr + 8)  as *const i64))
        };
        if asec < 0 || msec < 0 {
            return -(Errno::Einval.as_i32() as i64);
        }
        ia.atime_ns = (asec as u64) * 1_000_000_000;
        ia.mtime_ns = (msec as u64) * 1_000_000_000;
        ia.valid |= vfs::ATTR_ATIME_SET | vfs::ATTR_MTIME_SET;
    }
    crate::perms_common::notify_change(&inode, mnt_id, ia)
}
