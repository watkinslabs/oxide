// 471 rseq_slice_yield — one syscall, one file (docs/53 §0).
// Linux `kernel/rseq.c:812`.
#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;
use syscall::SyscallArgs;

/// `sys_rseq_slice_yield()` — slot 471.
///
/// Contrary to the name, this DOES NOT schedule: Linux's comment is explicit
/// ("The syscall does not schedule because the syscall entry work immediately
/// relinquishes the CPU and schedules if required"). The body is a read-and-
/// clear of `current->rseq.slice.yielded`, returning 1 only when this thread
/// held a granted time-slice extension that the syscall-entry work just
/// consumed, and 0 when the extension was never granted or was already revoked.
/// Calling `sched_yield` here instead — as this slot used to — gives userspace
/// a side effect Linux documents as absent, on a syscall whose entire point is
/// being side-effect free.
/// # C: O(1)
pub fn sys_rseq_slice_yield(_args: &SyscallArgs) -> i64 {
    let Some(cur) = sched::live::current() else { return 0 };
    cur.rseq_slice_yielded.swap(false, Ordering::AcqRel) as i64
}
