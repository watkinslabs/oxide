// utime_common — shared helpers for the utime/utimes/utimensat handlers
// (docs/53 §0). Moved verbatim from utime.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::InodeRef;

pub(crate) use crate::utimes_abi::AT_FDCWD;

/// Dispatch helper for utimes/utime so syscall_glue.rs only carries
/// one match arm.
/// # C: O(1)
pub fn sys_utime_dispatch(nr: u64, args: &SyscallArgs) -> i64 {
    if nr == syscall::nrs::NR_UTIMES { crate::s235_utimes::sys_utimes(args) }
    else                                   { crate::s132_utime::sys_utime(args) }
}

/// Read the caller's `struct timeval[2]` and decode it (`do_futimesat`,
/// `fs/utimes.c:174-191`). Runs BEFORE the path lookup, matching Linux: a
/// malformed `tv_usec` is EINVAL even when the pathname does not exist.
/// # C: O(1)
pub(crate) fn read_timeval_pair(times_ptr: u64) -> Result<crate::utimes_abi::TimesNs, i64> {
    let mut raw = [0u8; crate::utimes_abi::TIMEVAL_PAIR_BYTES];
    uaccess::copy_from_user(&mut raw, times_ptr)
        .map_err(|_| -(Errno::Efault.as_i32() as i64))?;
    crate::utimes_abi::decode_timeval_pair(&raw).map_err(|e| -(e.as_i32() as i64))
}

/// `vfs::Iattr` for an explicit (atime, mtime) pair — both times supplied, so
/// both carry `ATTR_*_SET` and the owner/CAP_FOWNER rule applies.
/// # C: O(1)
pub(crate) fn iattr_from_times(times: crate::utimes_abi::TimesNs, now: u64) -> vfs::Iattr {
    vfs::Iattr {
        valid: vfs::ATTR_ATIME | vfs::ATTR_MTIME | vfs::ATTR_ATIME_SET | vfs::ATTR_MTIME_SET,
        ctime_ns: now,
        atime_ns: times.atime_ns,
        mtime_ns: times.mtime_ns,
        ..Default::default()
    }
}

/// `vfs::Iattr` for `times == NULL` — Linux `ATTR_TOUCH`: both times become
/// now and write permission suffices.
/// # C: O(1)
pub(crate) fn iattr_touch(now: u64) -> vfs::Iattr {
    vfs::Iattr {
        valid: vfs::ATTR_ATIME | vfs::ATTR_MTIME,
        ctime_ns: now,
        atime_ns: now,
        mtime_ns: now,
        ..Default::default()
    }
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
    // `do_utimes` (`fs/utimes.c:137-139`): a NULL pathname selects the fd form
    // ONLY when `dfd` is a real descriptor. With AT_FDCWD it falls through to
    // the path lookup, which faults on the NULL name — EFAULT, not EBADF on
    // fd -100.
    if crate::utimes_abi::utimes_target(dirfd, path_ptr == 0) != crate::utimes_abi::UtimesTarget::Path {
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
    let lf = vfs::LookupFlags {
        no_follow_final: no_follow,
        follow: !no_follow,
        ..Default::default()
    };
    let p = crate::pathresolve::resolve_at_lookup(dirfd, path_ptr, lf)?;
    Ok((p.inode, p.mnt_id))
}
