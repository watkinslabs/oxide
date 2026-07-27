// 148 sched_rr_get_interval — one syscall, one file (docs/53 §0).
// Linux `sys_sched_rr_get_interval` → `sched_rr_get_interval()`: `pid < 0` →
// EINVAL, missing pid → ESRCH, and the interval comes from the task's CLASS
// hook — the RR quantum for SCHED_RR, ZERO for SCHED_FIFO, the CFS slice for
// the fair policies. Only after that does `put_timespec64` report EFAULT, so a
// bad pid beats a NULL pointer.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::sched_policy;
use crate::userbuf::validate_user_buf_writable;

/// `struct __kernel_timespec { i64 tv_sec; i64 tv_nsec; }`.
const TIMESPEC_SIZE: u64 = 16;
/// Nanoseconds per second.
const NSEC_PER_SEC: u64 = 1_000_000_000;

/// `sys_sched_rr_get_interval(pid, tp)` — slot 148. `pid==0` = caller.
/// # C: O(N_tasks) on non-self lookup
pub fn sys_sched_rr_get_interval(args: &SyscallArgs) -> i64 {
    let tp = args.a1;
    let pid = match sched_policy::pid_arg(args.a0) { Ok(v) => v, Err(rv) => return rv };
    let task = if pid == 0 {
        sched::live::current().and_then(|c| sched::live::registry::lookup(c.tid))
    } else {
        sched::live::registry::resolve_user_pid(pid)
    };
    let t = match task { Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64) };
    // Linux `get_rr_interval_fair` reports 0 on an otherwise-idle runqueue.
    let rq_loaded = match sched::live::runqueue::global() {
        Some(rq) => rq.nr_running.load(core::sync::atomic::Ordering::Acquire) != 0,
        None => false,
    };
    let ns = sched_policy::rr_interval_ns(sched_policy::task_policy(&t), rq_loaded);
    if tp == 0 { return -(Errno::Efault.as_i32() as i64); }
    if let Err(rv) = validate_user_buf_writable(tp, TIMESPEC_SIZE, 1) { return rv; }
    // SAFETY: tp validated writable for struct timespec { i64 sec; i64 nsec }; CPL=0.
    unsafe {
        core::ptr::write_unaligned( tp      as *mut i64, (ns / NSEC_PER_SEC) as i64);
        core::ptr::write_unaligned((tp + 8) as *mut i64, (ns % NSEC_PER_SEC) as i64);
    }
    0
}
