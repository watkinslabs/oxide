// POSIX message-queue blocking rules — Linux `ipc/mqueue.c` `wq_sleep`
// (`:708-752`) and `prepare_timeout` (`:838-846`).
//
// Non-gated on purpose: `live::posix_mq` is kernel-only, and these two rules
// are the entire user-visible contract of a blocked `mq_timedsend(2)` /
// `mq_timedreceive(2)`.
//
// Both were missing. The wait loop had NO signal check at all, so a task
// parked on a full or empty queue could not be killed — strictly worse than a
// wrong errno. And `abs_timeout` was discarded, so the "timed" half of both
// syscalls never fired: a caller asking for a bounded wait blocked forever.

use syscall::errno::Errno;

/// Linux `wq_sleep`'s exit ladder, in Linux's order. The order is the
/// contract: a task that is BOTH signalled and past its deadline reports the
/// signal, because `mqueue.c:738` is tested before `:742`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MqWait {
    /// `ewp->state == STATE_READY` (`mqueue.c:734-737`) — the queue moved.
    Ready,
    /// `signal_pending(current)` -> `-ERESTARTSYS` (`mqueue.c:738-740`). NOT
    /// `-EINTR`: with no handler frame the syscall restarts.
    Restartsys,
    /// `time == 0` -> `-ETIMEDOUT` (`mqueue.c:742-744`).
    Timedout,
    /// None of the above — go round again (`mqueue.c:717` `for (;;)`).
    Park,
}

/// Linux `wq_sleep`'s per-iteration decision.
/// # C: O(1)
pub const fn wq_sleep_verdict(ready: bool, signal_pending: bool, timed_out: bool) -> MqWait {
    if ready { return MqWait::Ready; }
    if signal_pending { return MqWait::Restartsys; }
    if timed_out { return MqWait::Timedout; }
    MqWait::Park
}

impl MqWait {
    /// The syscall return for a terminal verdict, or `None` to keep waiting.
    /// `Restartsys` is the raw Linux sentinel, not an errno — the dispatch
    /// tail turns it into a restart or into EINTR.
    /// # C: O(1)
    pub const fn to_return(self) -> Option<i64> {
        match self {
            MqWait::Ready => Some(0),
            MqWait::Restartsys => Some(syscall::restart::restart_sys()),
            MqWait::Timedout => Some(-(Errno::Etimedout.as_i32() as i64)),
            MqWait::Park => None,
        }
    }
}

/// Linux `prepare_timeout` (`mqueue.c:838-846`): `get_timespec64` (EFAULT)
/// then `timespec64_valid` (EINVAL). A NULL `u_abs_timeout` means "no
/// timeout" and is not validated at all.
///
/// Both `SYSCALL_DEFINE5(mq_timedsend)` (`mqueue.c:1236-1244`) and
/// `mq_timedreceive` (`:1250-1258`) run this in the syscall WRAPPER, before
/// `do_mq_timedsend`/`do_mq_timedreceive` reach `fdget(mqdes)` — so a
/// malformed timespec beats EBADF on a bad descriptor.
/// # C: O(1)
pub fn prepare_timeout(sec: i64, nsec: i64) -> Result<u64, Errno> {
    // `timespec64_valid`: tv_sec >= 0 and tv_nsec in [0, NSEC_PER_SEC).
    syscall::time::timespec_to_ns(sec, nsec).map_err(|_| Errno::Einval)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_outranks_everything() {
        assert_eq!(wq_sleep_verdict(true, true, true), MqWait::Ready);
        assert_eq!(wq_sleep_verdict(true, false, false), MqWait::Ready);
        assert_eq!(MqWait::Ready.to_return(), Some(0));
    }

    #[test]
    fn a_signal_outranks_an_expired_deadline() {
        // `mqueue.c:738` is tested before `:742`.
        assert_eq!(wq_sleep_verdict(false, true, true), MqWait::Restartsys);
        assert_eq!(wq_sleep_verdict(false, true, false), MqWait::Restartsys);
    }

    #[test]
    fn an_interrupted_wait_is_restartsys_never_eintr() {
        // The whole point: with no handler frame the syscall restarts. A bare
        // EINTR here would be a user-visible spurious failure.
        assert_eq!(MqWait::Restartsys.to_return(), Some(syscall::restart::restart_sys()));
        assert_ne!(MqWait::Restartsys.to_return(),
                   Some(-(Errno::Eintr.as_i32() as i64)));
    }

    #[test]
    fn an_expired_deadline_with_no_signal_is_etimedout() {
        assert_eq!(wq_sleep_verdict(false, false, true), MqWait::Timedout);
        assert_eq!(MqWait::Timedout.to_return(), Some(-(Errno::Etimedout.as_i32() as i64)));
    }

    #[test]
    fn nothing_pending_keeps_waiting() {
        assert_eq!(wq_sleep_verdict(false, false, false), MqWait::Park);
        assert_eq!(MqWait::Park.to_return(), None);
    }

    #[test]
    fn prepare_timeout_rejects_exactly_what_timespec64_valid_rejects() {
        assert_eq!(prepare_timeout(0, 0), Ok(0));
        assert_eq!(prepare_timeout(1, 500_000_000), Ok(1_500_000_000));
        for (s, n) in [(-1i64, 0i64), (0, -1), (0, 1_000_000_000), (0, i64::MAX)] {
            assert_eq!(prepare_timeout(s, n), Err(Errno::Einval), "ts={{{s},{n}}}");
        }
    }
}
