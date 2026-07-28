// 235 utimes — one syscall, one file (docs/53 §0).
//
// Linux implements this as `do_futimesat(AT_FDCWD, filename, utimes)`
// (`fs/utimes.c:203-207`), so it is slot 261 with the dirfd pinned. The decode
// is shared, not copied, and the microsecond validation therefore precedes the
// path lookup here too.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::utime_common::{now, read_timeval_pair, resolve_target, AT_FDCWD};
use crate::utimes_abi::{iattr_from_times, iattr_touch};

/// `sys_utimes(path, times[2])` — slot 235. Times are 16-byte timeval
/// (sec, usec) pairs; no dirfd / flags. NULL ⇒ both = now. Routes through
/// `notify_change` (owner/CAP_FOWNER for the explicit times, EROFS). Always
/// follows symlinks. # C: O(N_path)
pub fn sys_utimes(args: &SyscallArgs) -> i64 {
    let path_ptr = args.a0;
    let times_ptr = args.a1;
    let times = if times_ptr == 0 {
        None
    } else {
        match read_timeval_pair(times_ptr) { Ok(t) => Some(t), Err(rv) => return rv }
    };
    let (inode, mnt_id) = match resolve_target(AT_FDCWD, path_ptr, false, false) {
        Ok(t) => t, Err(rv) => return rv,
    };
    let now = now();
    let ia = match times {
        Some(t) => iattr_from_times(t, now),
        None => iattr_touch(now),
    };
    crate::perms_common::notify_change(&inode, mnt_id, ia)
}
