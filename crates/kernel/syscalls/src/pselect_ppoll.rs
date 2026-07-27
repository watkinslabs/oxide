// Shared pselect6/ppoll (slots 270/271) decision rules — Linux `fs/select.c`
// (`SYSCALL_DEFINE6(pselect6)`, `do_pselect`, `SYSCALL_DEFINE5(ppoll)`,
// `poll_select_finish`, `do_poll`, `do_select`, `core_sys_select`) and
// `kernel/signal.c` (`set_user_sigmask`).
//
// NOT `#[cfg(target_os = "oxide-kernel")]`: these two slots are the event-loop
// core (glibc implements `poll(2)` on `ppoll` and `select(2)` on `pselect6`),
// so the ABI rules live in ONE module compiled into the hosted test build too.

use syscall::errno::Errno;

/// `sizeof(struct sigset_argpack)`. pselect6's 6th argument is a POINTER to
/// `{ const sigset_t *ss; size_t ss_len; }` — never the sigset itself, and
/// never a bare mask value. Linux `get_sigset_argpack`.
pub const SIGSET_ARGPACK_BYTES: u64 = 16;

/// Byte offset of `ss_len` inside `struct sigset_argpack`.
pub const SIGSET_ARGPACK_LEN_OFF: u64 = 8;

/// `sizeof(struct __kernel_timespec)` — `{ i64 tv_sec, i64 tv_nsec }`.
/// pselect6/ppoll take a timespec, not select's `timeval` or poll's `int ms`.
pub const TIMESPEC_BYTES: u64 = 16;

/// Byte offset of `tv_nsec` inside `struct __kernel_timespec`.
pub const TIMESPEC_NSEC_OFF: u64 = 8;

/// Linux `set_user_sigmask`: `if (!umask) return 0;` — a NULL sigset pointer
/// means "do not touch the mask", NOT "install an empty mask". Only a
/// non-NULL pointer is size-checked, so `ppoll(…, NULL, 0)` and a pselect6
/// argpack of `{NULL, 0}` are both legal.
/// # C: O(1)
pub fn user_sigmask_wanted(ss_ptr: u64, ss_len: u64) -> Result<bool, Errno> {
    if ss_ptr == 0 { return Ok(false); }
    syscall::sigset::check_exact(ss_len)?;
    Ok(true)
}

/// Linux `poll_select_finish`'s `restore_saved_sigmask_unless(ret ==
/// -ERESTARTNOHAND)`. Oxide's select/poll engines surface Linux's
/// `-ERESTARTNOHAND` already folded to `-EINTR` (`poll_select_finish`'s
/// `sticky:` tail does the same fold), so that is the one return value that
/// must LEAVE the temporary mask installed: the syscall-return tail then
/// either builds a handler frame under it (`Task::sigmask_to_save` folds the
/// saved mask into what `rt_sigreturn` restores) or restores it itself. A
/// syscall that restores eagerly instead reopens the delivery race
/// pselect6/ppoll exist to close.
/// # C: O(1)
pub fn restores_saved_sigmask(rv: i64) -> bool {
    rv != -(Errno::Eintr.as_i32() as i64)
}

/// Linux `do_poll` / `do_select` break order for one readiness scan:
/// `if (!count) { if (signal_pending(current)) count = -ERESTARTNOHAND; }` /
/// `if (count || timed_out) break;`. Readiness outranks a pending signal, and
/// a pending signal outranks an expired timeout — so a zero timeout with a
/// deliverable signal and no ready fd is EINTR, not 0. `None` = keep waiting.
/// # C: O(1)
pub fn wait_verdict(ready: i64, timed_out: bool, signal_pending: bool) -> Option<i64> {
    if ready > 0 { return Some(ready); }
    if signal_pending { return Some(-(Errno::Eintr.as_i32() as i64)); }
    if timed_out { return Some(0); }
    None
}

/// Linux `core_sys_select`: `if (ret < 0) goto out;` — the caller's fd sets
/// (and, for poll, its `revents`) are only copied out on a non-negative
/// return, so an interrupted `select` leaves the caller's sets untouched.
/// # C: O(1)
pub fn copies_out_fd_sets(rv: i64) -> bool { rv >= 0 }

/// Linux `poll_select_finish`: the RAW pselect6/ppoll syscalls DO write the
/// remaining time back to the caller's timespec (`put_timespec64`); only the
/// glibc wrappers hide it behind a local copy. Two cases skip the update —
/// a `STICKY_TIMEOUTS` personality (`goto sticky`) and a zero timeout, whose
/// `end_time` stays `{0,0}` ("No update for zero timeout").
/// # C: O(1)
pub fn writes_back_timeout(personality: u32, req_sec: i64, req_nsec: i64) -> bool {
    if personality & sched::personality::STICKY_TIMEOUTS != 0 { return false; }
    req_sec != 0 || req_nsec != 0
}

/// Linux `poll_select_finish`: `rts = timespec64_sub(*end_time, now)` with
/// `if (rts.tv_sec < 0) rts.tv_sec = rts.tv_nsec = 0;`. An already-expired
/// deadline reports `{0,0}`, never a negative remainder.
/// # C: O(1)
pub fn remaining_timespec(deadline_ns: u64, now_ns: u64) -> (i64, i64) {
    let rem = deadline_ns.saturating_sub(now_ns);
    ((rem / syscall::time::NSEC_PER_SEC) as i64,
     (rem % syscall::time::NSEC_PER_SEC) as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argpack_layout_is_two_words_not_a_bare_sigset_pointer() {
        // `struct sigset_argpack { sigset_t __user *p; size_t size; }`.
        assert_eq!(SIGSET_ARGPACK_BYTES, 16);
        assert_eq!(SIGSET_ARGPACK_LEN_OFF, 8);
        // The pack is twice the width of the sigset it points at — reading a5
        // as a bare `sigset_t *` would consume the wrong 8 bytes.
        assert_eq!(SIGSET_ARGPACK_BYTES, 2 * syscall::sigset::SIGSET_BYTES);
    }

    #[test]
    fn timespec_layout_matches_kernel_timespec() {
        assert_eq!(TIMESPEC_BYTES, 16);
        assert_eq!(TIMESPEC_NSEC_OFF, 8);
    }

    #[test]
    fn null_sigset_pointer_leaves_the_mask_alone_whatever_the_length_says() {
        // Linux `set_user_sigmask`: `if (!umask) return 0;` runs BEFORE the
        // size check, so a garbage ss_len next to a NULL ss is not EINVAL.
        assert_eq!(user_sigmask_wanted(0, 0), Ok(false));
        assert_eq!(user_sigmask_wanted(0, 4), Ok(false));
        assert_eq!(user_sigmask_wanted(0, u64::MAX), Ok(false));
    }

    #[test]
    fn non_null_sigset_demands_exactly_sizeof_sigset_t() {
        assert_eq!(user_sigmask_wanted(0x1000, 8), Ok(true));
        for bad in [0u64, 1, 4, 7, 9, 16, 128, u64::MAX] {
            assert_eq!(user_sigmask_wanted(0x1000, bad), Err(Errno::Einval), "ss_len={bad}");
        }
    }

    #[test]
    fn only_an_interrupted_wait_keeps_the_temporary_mask_installed() {
        let eintr = -(Errno::Eintr.as_i32() as i64);
        assert!(!restores_saved_sigmask(eintr));
        // Every other outcome restores: success, timeout, and the error exits
        // Linux reaches through `poll_select_finish`.
        for rv in [0i64, 1, 7, -(Errno::Efault.as_i32() as i64), -(Errno::Ebadf.as_i32() as i64),
                   -(Errno::Einval.as_i32() as i64), -(Errno::Enomem.as_i32() as i64)] {
            assert!(restores_saved_sigmask(rv), "rv={rv}");
        }
    }

    #[test]
    fn readiness_outranks_a_pending_signal_which_outranks_a_timeout() {
        assert_eq!(wait_verdict(3, true, true), Some(3));
        assert_eq!(wait_verdict(1, false, true), Some(1));
        // The Linux zero-timeout-with-signal case: do_poll sets timed_out=1 up
        // front, yet `count = -ERESTARTNOHAND` is assigned before the break.
        assert_eq!(wait_verdict(0, true, true), Some(-(Errno::Eintr.as_i32() as i64)));
        assert_eq!(wait_verdict(0, false, true), Some(-(Errno::Eintr.as_i32() as i64)));
        assert_eq!(wait_verdict(0, true, false), Some(0));
        assert_eq!(wait_verdict(0, false, false), None);
    }

    #[test]
    fn interrupted_calls_leave_the_callers_sets_untouched() {
        assert!(!copies_out_fd_sets(-(Errno::Eintr.as_i32() as i64)));
        assert!(copies_out_fd_sets(0));
        assert!(copies_out_fd_sets(5));
    }

    #[test]
    fn zero_timeout_never_updates_the_callers_timespec() {
        assert!(!writes_back_timeout(0, 0, 0));
        assert!(writes_back_timeout(0, 0, 1));
        assert!(writes_back_timeout(0, 1, 0));
        assert!(writes_back_timeout(0, 5, 500_000_000));
    }

    #[test]
    fn sticky_timeouts_personality_suppresses_every_writeback() {
        let sticky = sched::personality::STICKY_TIMEOUTS;
        assert!(!writes_back_timeout(sticky, 5, 0));
        assert!(!writes_back_timeout(sticky | sched::personality::PER_LINUX32, 0, 1));
        // Any other persona bit must not suppress it.
        assert!(writes_back_timeout(sched::personality::WHOLE_SECONDS, 5, 0));
    }

    #[test]
    fn remaining_time_splits_ns_and_clamps_an_expired_deadline_to_zero() {
        assert_eq!(remaining_timespec(5_500_000_000, 0), (5, 500_000_000));
        assert_eq!(remaining_timespec(5_500_000_000, 5_000_000_000), (0, 500_000_000));
        assert_eq!(remaining_timespec(1_000, 9_999), (0, 0));
        assert_eq!(remaining_timespec(0, 0), (0, 0));
    }

    #[test]
    fn remaining_nanoseconds_stay_inside_one_second() {
        for now in [0u64, 1, 999_999_999, 1_000_000_000, 123_456_789_012] {
            let (_, ns) = remaining_timespec(999_999_999_999, now);
            assert!((0..1_000_000_000).contains(&ns), "now={now} ns={ns}");
        }
    }
}
