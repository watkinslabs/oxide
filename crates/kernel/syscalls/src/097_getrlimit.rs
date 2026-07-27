// 097 getrlimit — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::userbuf::validate_user_buf_writable;

/// `sizeof(struct rlimit)` on LP64: two `__kernel_ulong_t`.
const RLIMIT_BYTES: u64 = 16;
/// `rlim_max` byte offset within `struct rlimit`.
const OFF_RLIM_MAX: u64 = 8;

/// `sys_getrlimit(resource, rlim)` — slot 97. Linux routes this through
/// `do_prlimit(current, resource, NULL, &value)`, which reads
/// `tsk->signal->rlim[resource]` — the PROCESS-WIDE table shared by every
/// thread — and rejects `resource >= RLIM_NLIMITS` with EINVAL BEFORE the
/// copy-out, so a bad resource index reports EINVAL even when `rlim` is also
/// unwritable.
/// # C: O(1)
pub fn sys_getrlimit(args: &SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let resource = args.a0 as usize;
    let rlim = args.a1;
    // `do_prlimit` validates the resource first; `copy_to_user` (EFAULT) runs
    // only on success. Reordering these swaps the errno userspace sees.
    if resource >= sched::rlimit::rlim::COUNT {
        return -(Errno::Einval.as_i32() as i64);
    }
    if let Err(rv) = validate_user_buf_writable(rlim, RLIMIT_BYTES, 1) { return rv; }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    let (rcur, rmax) = cur.rlimit(resource);
    // SAFETY: rlim validated writable for the 16-byte `struct rlimit` result.
    unsafe {
        core::ptr::write_unaligned( rlim                as *mut u64, rcur);
        core::ptr::write_unaligned((rlim + OFF_RLIM_MAX) as *mut u64, rmax);
    }
    0
}
