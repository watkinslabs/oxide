// 203 sched_setaffinity — one syscall, one file (docs/53 §0). Moved verbatim from affinity.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::affinity_common::{affinity_target, online_cpu_mask};

/// `sys_sched_setaffinity(pid, cpusetsize, mask)` — slot 203. Stores the
/// user mask (intersected with online CPUs) into the task's
/// `cpus_allowed`. EINVAL if the result is empty (Linux semantics).
/// # C: O(1)
pub fn sys_sched_setaffinity(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let (pid, cpusetsize, mask) = (args.a0 as u32, args.a1, args.a2);
    if mask == 0 || mask >= hal::USER_VA_END || cpusetsize < 8 {
        return -(syscall::errno::Errno::Einval.as_i32() as i64);
    }
    // SAFETY: mask validated < USER_VA_END; 8-byte read within the user buffer (cpusetsize>=8); CPL=0 reads through caller's AS.
    let want = unsafe { core::ptr::read_volatile(mask as *const u64) };
    let eff = want & online_cpu_mask();
    if eff == 0 { return -(syscall::errno::Errno::Einval.as_i32() as i64); }
    let t = match affinity_target(pid) { Some(t) => t, None => return -(syscall::errno::Errno::Esrch.as_i32() as i64) };
    t.cpus_allowed.store(eff, Ordering::Release);
    0
}
