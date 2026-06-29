// utime_common — shared helpers for the utime/utimes/utimensat handlers
// (docs/53 §0). Moved verbatim from utime.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::InodeRef;

pub(crate) const AT_FDCWD: i32 = -100;

/// Dispatch helper for utimes/utime so syscall_glue.rs only carries
/// one match arm.
/// # C: O(1)
pub fn sys_utime_dispatch(nr: u64, args: &SyscallArgs) -> i64 {
    if nr == syscall::nrs::NR_UTIMES { crate::s235_utimes::sys_utimes(args) }
    else                                   { crate::s132_utime::sys_utime(args) }
}

/// # C: O(1)
pub(crate) fn now_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

/// Resolve a utimes target to `(inode, mnt_id)`. `path_ptr == 0` updates the
/// `dirfd` open fd directly (utimensat NULL path). `no_follow` honours
/// AT_SYMLINK_NOFOLLOW on the final component (U2: utimensat operates on the
/// symlink itself). The owning `mnt_id` lets `notify_change` enforce EROFS.
/// # C: O(N_path)
pub(crate) fn resolve_target(dirfd: i32, path_ptr: u64, no_follow: bool) -> Result<(InodeRef, u64), i64> {
    if path_ptr == 0 {
        // utimensat with NULL path = update by fd.
        let cur = match sched::live::current() {
            Some(c) => c, None => return Err(-(Errno::Ebadf.as_i32() as i64)),
        };
        // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
        let fdt = match unsafe { cur.fd_table_ref() } {
            Some(t) => t.clone(), None => return Err(-(Errno::Ebadf.as_i32() as i64)),
        };
        let f = match fdt.get(dirfd) {
            Ok(f) => f, Err(_) => return Err(-(Errno::Ebadf.as_i32() as i64)),
        };
        return Ok((f.inode().clone(), f.mnt_id()));
    }
    // D1/D2: PATH_MAX errno contract (EFAULT/ENOENT-on-empty/ENAMETOOLONG).
    // (path_ptr == 0 handled above: utimensat NULL path updates by fd.)
    let raw = crate::namei_common::read_user_path(path_ptr)?;
    // BUG D: resolve against the dirfd's directory for a real fd-relative
    // dirfd; resolve_at(AT_FDCWD, raw) == resolve_cwd(raw) so the common
    // AT_FDCWD/absolute callers are unchanged.
    let resolved = crate::pathresolve::resolve_at_result(dirfd, &raw)?;
    let s = resolved.as_str();
    match crate::pathresolve::resolve_path_result(s, no_follow) {
        Ok(p)  => Ok((p.inode, p.mnt_id)),
        Err(e) => Err(crate::namei_common::errno_from_vfs(e)),
    }
}
