// `prctl(PR_RSEQ_SLICE_EXTENSION, cmd, ctrl)` — Linux `kernel/rseq.c
// rseq_slice_extension_prctl`.
//
// The option lets a thread ask the scheduler for a short, bounded time-slice
// extension when it is preempted inside a restartable-sequence critical
// section, using the v2 `struct rseq` `slice_ctrl` word to negotiate the
// grant. It needs three things this port does not have: the v2 `rseq`
// registration layout, a per-task slice grant the tick honours, and the
// grant-revocation write-back on return to user.
//
// A kernel built without slice-extension support answers **ENOTSUPP** for
// every sub-command, after the shared `arg4 || arg5` rule. ENOTSUPP is 524 —
// an internal errno that this one interface genuinely leaks to userspace, so
// answering EINVAL or EOPNOTSUPP instead would be a different observable
// answer than the caller's `errno == ENOTSUPP` probe expects.
//
// UNGATED: the tail rule and the refusal value are hosted-testable.

use syscall::errno::Errno;

/// Linux `ENOTSUPP` (`include/linux/errno.h`) — a kernel-internal errno that
/// is not in the userspace `errno.h` sequence. `rseq_slice_extension_prctl`'s
/// unsupported stub returns it directly, so it reaches userspace verbatim.
const ENOTSUPP: i64 = 524;

/// `PR_RSEQ_SLICE_EXTENSION` with no slice-extension support compiled in.
/// # C: O(1)
pub fn decide(_cmd: u64, _ctrl: u64, a4: u64, a5: u64) -> i64 {
    if a4 != 0 || a5 != 0 { return -(Errno::Einval.as_i32() as i64); }
    -ENOTSUPP
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prctl::uapi::*;

    const EINVAL: i64 = -(Errno::Einval.as_i32() as i64);

    #[test]
    fn tail_arguments_are_rejected_before_the_unsupported_answer() {
        assert_eq!(decide(PR_RSEQ_SLICE_EXTENSION_GET, 0, 1, 0), EINVAL);
        assert_eq!(decide(PR_RSEQ_SLICE_EXTENSION_GET, 0, 0, 1), EINVAL);
    }

    #[test]
    fn every_sub_command_reports_the_internal_not_supported_errno() {
        for cmd in [PR_RSEQ_SLICE_EXTENSION_GET, PR_RSEQ_SLICE_EXTENSION_SET, 0, 99] {
            assert_eq!(decide(cmd, PR_RSEQ_SLICE_EXT_ENABLE, 0, 0), -524,
                       "ENOTSUPP, not EINVAL/EOPNOTSUPP");
        }
    }
}
