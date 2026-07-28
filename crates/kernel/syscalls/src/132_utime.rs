// 132 utime — one syscall, one file (docs/53 §0). Moved verbatim from utime.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::utime_common::{now, read_utimbuf, resolve_target, AT_FDCWD};
use crate::utimes_abi::{iattr_from_times, iattr_touch};

/// `sys_utime(path, times)` — slot 132 (older API). `times` is a
/// `struct utimbuf { time_t actime; time_t modtime; }` (16 bytes).
/// NULL ⇒ both = now. Routes through `notify_change` (owner/CAP_FOWNER for the
/// explicit times, EROFS). Always follows symlinks.
///
/// `SYSCALL_DEFINE2(utime)` (`fs/utimes.c:208-221`) validates NOTHING: both
/// fields land in `tv_sec` with `tv_nsec = 0`, so a negative `actime` is an
/// ordinary pre-1970 request — which is how `tar -x` restores an old archive.
/// # C: O(N_path)
pub fn sys_utime(args: &SyscallArgs) -> i64 {
    let path_ptr = args.a0;
    let times_ptr = args.a1;
    let times = if times_ptr == 0 {
        None
    } else {
        match read_utimbuf(times_ptr) { Ok(t) => Some(t), Err(rv) => return rv }
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
