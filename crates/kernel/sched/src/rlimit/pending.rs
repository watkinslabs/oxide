// `RLIMIT_SIGPENDING`: how many signal records one USER may hold queued
// across every task it owns (Linux `sig_get_ucounts`).
//
// The counted resource is per-user, not per-task and not per-signal: the
// account is charged when a record is queued and released when it is
// dequeued or flushed, and the admission test compares the account's
// post-charge value against the TARGET task's limit.
//
// STATUS: this is the decision half only. The charge itself needs a
// `ucounts::Counter::Sigpending` and a charge/release pair at every mutation
// of the two record queues (`sigqueue::queues_{push,pop,clear}` and their
// `ThreadGroup::shared_sigqueue` callers), plus a hand-off in
// `sched::ucounts::recharge_after_setuid` so a `set*uid` moves a task's queued
// records to its new account. Until that lands, the record queues are bounded
// by the fixed per-signal `RT_QUEUE_CAP` instead, which bounds memory but is
// not the Linux limit.

use super::INFINITY;

/// Linux `sig_get_ucounts`:
///
/// ```text
/// sigpending = inc_rlimit_get_ucounts(ucounts, UCOUNT_RLIMIT_SIGPENDING, override_rlimit);
/// if (!sigpending) return NULL;
/// if (!override_rlimit && sigpending > task_rlimit(t, RLIMIT_SIGPENDING)) { dec; return NULL; }
/// ```
///
/// `charged` is the account's value AFTER this record's charge, so the very
/// first record on a zero limit is already over — a zero `RLIMIT_SIGPENDING`
/// queues nothing. `override` is Linux's `override_rlimit`, set for signals
/// the kernel must not be able to drop.
/// # C: O(1)
pub fn admits(charged: u64, limit: u64, override_rlimit: bool) -> bool {
    if override_rlimit || limit == INFINITY { return true; }
    charged <= limit
}

/// Whether a send bypasses the limit. Linux `__send_signal_locked`:
///
/// ```text
/// if (sig < SIGRTMIN) override_rlimit = (is_si_special(info) || info->si_code >= 0);
/// else                override_rlimit = 0;
/// ```
///
/// A real-time signal is NEVER exempt — it is the one a sender can queue
/// without bound. A standard signal is exempt only when the record came from
/// the kernel: `is_si_special` covers the `SEND_SIG_*` sentinels, and a
/// non-negative `si_code` is exactly the kernel-origin half of the si_code
/// space (`SI_USER` = 0 upward), leaving user-supplied negative codes
/// (`SI_QUEUE`, `SI_TIMER`, `SI_TKILL`) subject to the limit.
/// # C: O(1)
pub const fn overrides_limit(is_realtime: bool, kernel_origin: bool, si_code: i32) -> bool {
    !is_realtime && (kernel_origin || si_code >= 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zero_limit_queues_nothing() {
        assert!(!admits(1, 0, false));
        assert!(admits(1, 0, true), "an override ignores the limit entirely");
    }

    #[test]
    fn the_test_is_on_the_post_charge_value_and_strictly_greater() {
        assert!(admits(4, 4, false), "the limit'th record still lands");
        assert!(!admits(5, 4, false));
    }

    #[test]
    fn an_infinite_limit_admits_everything() {
        assert!(admits(u64::MAX - 1, INFINITY, false));
    }

    /// `SI_QUEUE`, the `sigqueue(2)` code — the negative half of the space.
    const SI_QUEUE: i32 = -1;
    /// `SI_USER`, what `kill(2)` stamps.
    const SI_USER: i32 = 0;

    #[test]
    fn a_real_time_signal_is_never_exempt() {
        assert!(!overrides_limit(true, true, SI_USER));
        assert!(!overrides_limit(true, false, SI_QUEUE));
    }

    #[test]
    fn a_standard_signal_is_exempt_only_when_the_kernel_raised_it() {
        assert!(overrides_limit(false, true, SI_QUEUE), "SEND_SIG_* sentinel");
        assert!(overrides_limit(false, false, SI_USER), "kill(2) stamps a non-negative code");
        assert!(!overrides_limit(false, false, SI_QUEUE), "sigqueue(2) is charged");
    }
}
