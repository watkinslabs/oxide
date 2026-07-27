// 203 sched_setaffinity — one syscall, one file (docs/53 §0). Thin shim:
// decode the user cpumask, resolve the target, hand the decision to
// `affinity_abi` (hosted-tested), commit.

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::affinity_abi::{self, CPUMASK_SIZE};
use crate::affinity_common::{active_cpu_mask, affinity_target};
use crate::userbuf::validate_user_buf_readable;

/// `sys_sched_setaffinity(pid, len, user_mask_ptr)` — slot 203. `len` is in
/// BYTES and carries no minimum: Linux `get_user_cpu_mask` zero-fills the mask
/// and copies `min(len, cpumask_size())` bytes, so a caller whose `cpu_set_t`
/// is narrower than the kernel's mask still works. Errno order is Linux's
/// `sched_setaffinity`: EFAULT (copy_from_user) → ESRCH (find_task_by_vpid) →
/// EINVAL (PF_NO_SETAFFINITY) → EPERM (check_same_owner / CAP_SYS_NICE) →
/// EINVAL (mask naming no active CPU).
/// # C: O(N_cpus + log N)
pub fn sys_sched_setaffinity(args: &SyscallArgs) -> i64 {
    let (pid, len, uptr) = (args.a0 as u32, args.a1 as usize, args.a2);
    let n = affinity_abi::set_copy_len(len);
    let mut bytes = [0u8; CPUMASK_SIZE];
    if n > 0 {
        if let Err(rv) = validate_user_buf_readable(uptr, n as u64, 1) { return rv; }
        if uaccess::copy_from_user(&mut bytes[..n], uptr).is_err() {
            return -(Errno::Efault.as_i32() as i64);
        }
    }
    let want = affinity_abi::mask_from_bytes(&bytes[..n]);

    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    let t = match affinity_target(pid) {
        Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64),
    };

    let decided = affinity_abi::setaffinity_decide(
        want,
        t.cpuset_cpus_allowed.load(Ordering::Acquire),
        active_cpu_mask(),
        t.no_setaffinity.load(Ordering::Acquire),
        crate::sched_policy::check_same_owner(cur, &t),
        cur.has_cap(sched::cap::SYS_NICE),
    );
    let eff = match decided { Ok(m) => m, Err(e) => return -(e.as_i32() as i64) };

    // Linux parks the raw request in `user_cpus_ptr` so a later cpuset change
    // re-applies it instead of erasing it.
    t.user_cpus_allowed.store(want, Ordering::Release);
    t.cpus_allowed.store(eff, Ordering::Release);
    // Honor the new mask now: relocate the task off any disallowed CPU — a
    // queued task moves immediately; a running one is nudged to reschedule
    // (full running-task eviction is the Phase C on_cpu handshake).
    sched::live::relocate_for_affinity(&t, eff);
    0
}
