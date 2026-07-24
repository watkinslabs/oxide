// 204 sched_getaffinity — one syscall, one file (docs/53 §0). Moved verbatim from affinity.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::affinity_common::{affinity_target, online_cpu_mask};
use crate::userbuf::validate_user_buf_writable;

/// `sys_sched_getaffinity(pid, cpusetsize, mask)` — slot 204. Writes the
/// task's `cpus_allowed` bitmask (masked to online CPUs) into the user
/// buffer; returns the bytes written (8).
/// # C: O(1)
pub fn sys_sched_getaffinity(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let (pid, cpusetsize, mask) = (args.a0 as u32, args.a1, args.a2);
    // Linux `sched_getaffinity`: `(len * 8) < nr_cpu_ids` (here <8 bytes for the
    // u64 cpu_set_t) then `len & (sizeof(unsigned long)-1)` — both are EINVAL.
    if cpusetsize < 8 { return -(syscall::errno::Errno::Einval.as_i32() as i64); }
    if cpusetsize & 7 != 0 { return -(syscall::errno::Errno::Einval.as_i32() as i64); }
    if let Err(rv) = validate_user_buf_writable(mask, 8, 1) { return rv; }
    let t = match affinity_target(pid) { Some(t) => t, None => return -(syscall::errno::Errno::Esrch.as_i32() as i64) };
    let m = t.cpus_allowed.load(Ordering::Acquire) & online_cpu_mask();
    // SAFETY: mask validated writable for the supported 8-byte cpu_set_t.
    unsafe { core::ptr::write_unaligned(mask as *mut u64, m); }
    8
}
