// 204 sched_getaffinity — one syscall, one file (docs/53 §0). Thin shim: the
// `len` rules and the return-value contract live in `affinity_abi`.

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::affinity_abi;
use crate::affinity_common::{active_cpu_mask, affinity_target};
use crate::userbuf::validate_user_buf_writable;

/// `sys_sched_getaffinity(pid, len, user_mask_ptr)` — slot 204. Returns the
/// number of BYTES written (`min(len, cpumask_size())`), never 0: glibc's
/// wrapper zero-fills `cpuset[ret..cpusetsize]` from it and `__get_nprocs`
/// grows its buffer until the call stops returning EINVAL. Errno order is
/// Linux's: both `len` EINVALs are decided before the task lookup, and the
/// lookup (ESRCH) before the copy-out (EFAULT).
/// # C: O(1)
pub fn sys_sched_getaffinity(args: &SyscallArgs) -> i64 {
    let (pid, len, uptr) = (args.a0 as u32, args.a1 as usize, args.a2);
    let retlen = match affinity_abi::getaffinity_retlen(len) {
        Ok(n) => n, Err(e) => return -(e.as_i32() as i64),
    };
    let t = match affinity_target(pid) {
        Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64),
    };
    let m = affinity_abi::reported_mask(t.cpus_allowed.load(Ordering::Acquire), active_cpu_mask());
    if let Err(rv) = validate_user_buf_writable(uptr, retlen as u64, 1) { return rv; }
    if uaccess::copy_to_user(uptr, &m.to_le_bytes()[..retlen]).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    retlen as i64
}
