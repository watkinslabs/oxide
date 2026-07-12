// 203 sched_setaffinity — one syscall, one file (docs/53 §0). Moved verbatim from affinity.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::affinity_common::{affinity_target, online_cpu_mask};
use crate::userbuf::validate_user_buf;

/// `sys_sched_setaffinity(pid, cpusetsize, mask)` — slot 203. Stores the
/// user mask (intersected with online CPUs) into the task's
/// `cpus_allowed`. EINVAL if the result is empty (Linux semantics).
/// # C: O(1)
pub fn sys_sched_setaffinity(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let (pid, cpusetsize, mask) = (args.a0 as u32, args.a1, args.a2);
    if cpusetsize < 8 { return -(syscall::errno::Errno::Einval.as_i32() as i64); }
    if let Err(rv) = validate_user_buf(mask, 8, 1) { return rv; }
    // SAFETY: mask validated readable for the supported 8-byte cpu_set_t.
    let want = unsafe { core::ptr::read_unaligned(mask as *const u64) };
    let eff = want & online_cpu_mask();
    if eff == 0 { return -(syscall::errno::Errno::Einval.as_i32() as i64); }
    let t = match affinity_target(pid) { Some(t) => t, None => return -(syscall::errno::Errno::Esrch.as_i32() as i64) };
    t.cpus_allowed.store(eff, Ordering::Release);
    // Honor the new mask now: relocate the task off any disallowed CPU — a
    // queued task moves immediately; a running one is nudged to reschedule
    // (full running-task eviction is the Phase C on_cpu handshake).
    sched::live::relocate_for_affinity(&t, eff);
    0
}
