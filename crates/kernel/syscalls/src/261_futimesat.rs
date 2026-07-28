// 261 futimesat — one syscall, one file (docs/53 §0).
//
// `futimesat(dfd, filename, struct timeval[2])` — three arguments, MICROsecond
// resolution, no `flags`, always follows symlinks (`do_utimes(..., 0)`).
// Linux keeps it live on x86_64 (`arch/x86/entry/syscalls/syscall_64.tbl:273`,
// built because `arch/x86/include/asm/unistd.h:24` defines
// `__ARCH_WANT_SYS_UTIME`), so it is a full implementation, not an ENOSYS slot.
//
// It shares its entire decode with `utimes(2)`: Linux writes `sys_utimes` as
// `do_futimesat(AT_FDCWD, filename, utimes)` (`fs/utimes.c:203-207`).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

use crate::utime_common::{iattr_from_times, iattr_touch, now_ns, read_timeval_pair, resolve_target};

/// `sys_futimesat(dirfd, path, times[2])` — slot 261. `times == NULL` sets both
/// stamps to now (write permission suffices); otherwise both are explicit and
/// the owner/CAP_FOWNER rule applies. The `tv_usec` range is validated BEFORE
/// the path lookup, so a bad microsecond field is EINVAL even when the path
/// does not exist (`fs/utimes.c:183-185`, ahead of `do_utimes`).
/// # C: O(N_path)
pub fn sys_futimesat(args: &SyscallArgs) -> i64 {
    let dirfd = args.a0 as i32;
    let path_ptr = args.a1;
    let times_ptr = args.a2;
    let times = if times_ptr == 0 {
        None
    } else {
        match read_timeval_pair(times_ptr) { Ok(t) => Some(t), Err(rv) => return rv }
    };
    // `do_utimes(dfd, filename, tstimes, 0)`: flags are hard-zero, so the
    // lookup always follows a trailing symlink.
    let (inode, mnt_id) = match resolve_target(dirfd, path_ptr, false) {
        Ok(t) => t, Err(rv) => return rv,
    };
    let now = now_ns();
    let ia = match times {
        Some(t) => iattr_from_times(t, now),
        None => iattr_touch(now),
    };
    crate::perms_common::notify_change(&inode, mnt_id, ia)
}
