// utime_common — the copy-in + target-resolution half of the
// utime/utimes/futimesat/utimensat handlers (docs/53 §0). Every decision the
// family makes (validation, sentinel resolution, `Iattr` assembly) lives in the
// UNGATED `utimes_abi` / `utimensat_abi` modules so the hosted suite can reach
// it; this file is the gated shim that touches user memory and the namespace.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::Timespec64;
use vfs::InodeRef;

pub(crate) use crate::utimes_abi::AT_FDCWD;

/// Dispatch helper for utimes/utime so syscall_glue.rs only carries
/// one match arm.
/// # C: O(1)
pub fn sys_utime_dispatch(nr: u64, args: &SyscallArgs) -> i64 {
    if nr == syscall::nrs::NR_UTIMES { crate::s235_utimes::sys_utimes(args) }
    else                                   { crate::s132_utime::sys_utime(args) }
}

/// Read the caller's `struct timeval[2]` and decode it (Linux's `do_futimesat`).
/// Runs BEFORE the path lookup, matching Linux: a
/// malformed `tv_usec` is EINVAL even when the pathname does not exist.
/// # C: O(1)
pub(crate) fn read_timeval_pair(times_ptr: u64) -> Result<crate::utimes_abi::Times, i64> {
    let mut raw = [0u8; crate::utimes_abi::TIMEVAL_PAIR_BYTES];
    uaccess::copy_from_user(&mut raw, times_ptr)
        .map_err(|_| -(Errno::Efault.as_i32() as i64))?;
    crate::utimes_abi::decode_timeval_pair(&raw).map_err(|e| -(e.as_i32() as i64))
}

/// Read the caller's `struct utimbuf` (Linux's `SYSCALL_DEFINE2(utime)`).
/// Two `get_user`s there, one 16-byte copy here.
/// # C: O(1)
pub(crate) fn read_utimbuf(times_ptr: u64) -> Result<crate::utimes_abi::Times, i64> {
    let mut raw = [0u8; crate::utimes_abi::UTIMBUF_BYTES];
    uaccess::copy_from_user(&mut raw, times_ptr)
        .map_err(|_| -(Errno::Efault.as_i32() as i64))?;
    Ok(crate::utimes_abi::decode_utimbuf(&raw))
}

/// Read the caller's `struct __kernel_timespec[2]` (`get_timespec64` twice).
/// Copied BEFORE any flag check or lookup, so a bad
/// pointer is EFAULT regardless of the rest of the call. # C: O(1)
pub(crate) fn read_timespec_pair(times_ptr: u64) -> Result<[crate::utimensat_abi::RawTimespec; 2], i64> {
    let mut raw = [0u8; crate::utimensat_abi::TIMESPEC_PAIR_BYTES];
    uaccess::copy_from_user(&mut raw, times_ptr)
        .map_err(|_| -(Errno::Efault.as_i32() as i64))?;
    Ok(crate::utimensat_abi::decode_timespec_pair(&raw))
}

/// Current `CLOCK_REALTIME` as a `timespec64` — Linux `current_time`
/// reads `ktime_get_coarse_real_ts64`, the WALL clock. The
/// monotonic counter this used to return is not an epoch-relative time at all,
/// so every "now" stamp it produced was the machine's uptime. `timekeeper` is
/// the canonical owner of the wall clock and is the same source installed as
/// vfs's `realtime_provider` (`crate::mount`). # C: O(1)
pub(crate) fn now() -> Timespec64 {
    Timespec64::from_clock_ns(timekeeper::realtime_ns())
}

/// Resolve a utimes target to `(inode, mnt_id)`. `path_ptr == 0` updates the
/// `dirfd` open fd directly (utimensat NULL path). `no_follow` honours
/// AT_SYMLINK_NOFOLLOW on the final component (U2: utimensat operates on the
/// symlink itself); `empty` honours AT_EMPTY_PATH, which `do_utimes_path`
/// accepts alongside it so `utimensat(fd, "", t,
/// AT_EMPTY_PATH)` stamps the open fd. The owning `mnt_id` lets
/// `notify_change` enforce EROFS.
/// # C: O(N_path)
pub(crate) fn resolve_target(dirfd: i32, path_ptr: u64, no_follow: bool, empty: bool)
    -> Result<(InodeRef, u64), i64>
{
    // `do_utimes`: a NULL pathname selects the fd form
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
        empty,
        ..Default::default()
    };
    let p = crate::pathresolve::resolve_at_lookup(dirfd, path_ptr, lf)?;
    Ok((p.inode, p.mnt_id))
}
