// 235 utimes — one syscall, one file (docs/53 §0). Moved verbatim from utime.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::utime_common::{now_ns, resolve_target, AT_FDCWD};

/// `sys_utimes(path, times[2])` — slot 235. Times are 16-byte timeval
/// (sec, usec) pairs; no dirfd / flags. NULL ⇒ both = now. Routes through
/// `notify_change` (owner/CAP_FOWNER for the explicit times, EROFS). Always
/// follows symlinks. # C: O(N_path)
pub fn sys_utimes(args: &SyscallArgs) -> i64 {
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
        if times_ptr.checked_add(32).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
            return -(Errno::Efault.as_i32() as i64);
        }
        // SAFETY: times_ptr+32 validated < USER_VA_END; CPL=0 reads two timeval (i64+i64) pairs through caller's AS.
        let (asec, ausec, msec, musec) = unsafe {
            (core::ptr::read_volatile( times_ptr        as *const i64),
             core::ptr::read_volatile((times_ptr +  8)  as *const i64),
             core::ptr::read_volatile((times_ptr + 16)  as *const i64),
             core::ptr::read_volatile((times_ptr + 24)  as *const i64))
        };
        if asec < 0 || msec < 0 || ausec < 0 || musec < 0
            || ausec >= 1_000_000 || musec >= 1_000_000 {
            return -(Errno::Einval.as_i32() as i64);
        }
        ia.atime_ns = (asec as u64) * 1_000_000_000 + (ausec as u64) * 1_000;
        ia.mtime_ns = (msec as u64) * 1_000_000_000 + (musec as u64) * 1_000;
        ia.valid |= vfs::ATTR_ATIME_SET | vfs::ATTR_MTIME_SET;
    }
    crate::perms_common::notify_change(&inode, mnt_id, ia)
}
