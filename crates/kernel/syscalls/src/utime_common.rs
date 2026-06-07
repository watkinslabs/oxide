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

/// # C: O(N_path)
pub(crate) fn resolve_inode(dirfd: i32, path_ptr: u64) -> Result<InodeRef, i64> {
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
        return Ok(f.inode().clone());
    }
    if path_ptr >= hal::USER_VA_END {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    // SAFETY: path_ptr in user range; bounded read via devfs::read_user_cstr.
    let bytes = unsafe { devfs::read_user_cstr(path_ptr, 256) };
    let raw = match bytes.and_then(|b| if b.is_empty() { None } else { core::str::from_utf8(b).ok() }) {
        Some(s) => s, None => return Err(-(Errno::Einval.as_i32() as i64)),
    };
    // BUG D: resolve against the dirfd's directory for a real fd-relative
    // dirfd; resolve_at(AT_FDCWD, raw) == resolve_cwd(raw) so the common
    // AT_FDCWD/absolute callers are unchanged.
    let resolved = crate::pathresolve::resolve_at(dirfd, raw)
        .unwrap_or_else(|| crate::pathresolve::resolve_cwd(raw));
    let s = resolved.as_str();
    // utimensat/utimes follow symlinks (AT_SYMLINK_NOFOLLOW handling
    // rides the dirfd rewrite); resolve via the path-walk.
    crate::pathresolve::resolve(s, false)
        .ok_or(-(Errno::Enoent.as_i32() as i64))
}
