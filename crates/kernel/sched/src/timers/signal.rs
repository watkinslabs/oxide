// The `siginfo_t` a POSIX timer expiry carries, and the `posixtimer_rearm`
// stamp that completes it at dequeue.
//
// Ungated on purpose (CLAUDE.md "Phantom tests"): the record shape is the
// user-visible half of `timer_create(2)` — `si_code`, `si_tid`, `si_overrun`
// and `si_value` are what a `SIGEV_SIGNAL` handler, `sigwaitinfo(2)` and a
// `signalfd` read all decode — so it is provable by `cargo test -p sched`
// rather than only at boot.
//
// `siginfo_t`'s `_timer` arm OVERLAYS `_kill`: `si_tid` occupies `si_pid`'s
// bytes and `si_overrun` occupies `si_uid`'s. `SigInfo`'s `pid`/`uid` ARE
// those two words, so a timer record stores the id and the overrun there and
// every consumer that selects the `_timer` layout reads them back correctly.

use crate::task::SigInfo;

/// `SI_TIMER` (`<asm-generic/siginfo.h>`) — "sent by timer expiration". Selects
/// the `_timer` union arm on its own, for any signal number.
pub const SI_TIMER: i32 = -2;

/// Build the record a POSIX timer owns from `timer_create` onward.
///
/// `timer_id` is the `timer_t` the create returned, which is what `si_tid`
/// reports; `value` is the `sigev_value` the creator registered, delivered
/// verbatim as `si_value`. `si_overrun` starts at zero and is stamped by
/// [`stamp_overrun`] when the record is dequeued — the count is only knowable
/// once the delivery actually happens, which is why Linux fills it in
/// `posixtimer_rearm` and not at expiry.
/// # C: O(1)
pub fn timer_record(signo: u32, timer_id: usize, value: u64) -> SigInfo {
    SigInfo {
        signo,
        code: SI_TIMER,
        pid: timer_id as u32,
        uid: 0,
        value,
        sys: None,
        fault: None,
    }
}

/// Whether `rec` is a timer expiry, i.e. whether the `_timer` arm applies and
/// [`timer_id`]/[`stamp_overrun`] are meaningful for it. # C: O(1)
pub fn is_timer_record(rec: &SigInfo) -> bool { rec.code == SI_TIMER }

/// The `si_tid` a timer record carries. # C: O(1)
pub fn timer_id(rec: &SigInfo) -> usize { rec.pid as usize }

/// Linux `posixtimer_rearm`'s last step: write the settled overrun count into
/// the record being handed to the consumer. Linux clamps `it_overrun` to `int`
/// before it reaches userspace (`timer_getoverrun(2)` returns an `int`), so the
/// same ceiling applies here and the two can never disagree.
/// # C: O(1)
pub fn stamp_overrun(rec: &mut SigInfo, overrun: i64) {
    rec.uid = overrun.clamp(0, i32::MAX as i64) as u32;
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGALRM: u32 = crate::signum::Signum::Sigalrm as u32;
    const SIGRTMIN: u32 = crate::signum::RT_SIGNAL_MIN;

    #[test]
    fn a_timer_record_selects_the_timer_arm_for_any_signal_number() {
        // `SI_TIMER` is a negative `si_code`, so the arm is chosen by the code
        // alone — a standard signal armed by `timer_create` carries the same
        // `_timer` payload a real-time one does. The old producer queued a
        // record only for real-time signals, so a `SIGALRM` timer delivered a
        // bare bit and `sigwaitinfo` reported si_code 0.
        for sig in [SIGALRM, SIGRTMIN] {
            let rec = timer_record(sig, 3, 0xdead_beef);
            assert_eq!(rec.signo, sig);
            assert_eq!(rec.code, SI_TIMER);
            assert!(is_timer_record(&rec));
            assert_eq!(timer_id(&rec), 3);
            assert_eq!(rec.value, 0xdead_beef);
        }
    }

    #[test]
    fn si_tid_and_si_overrun_occupy_the_kill_arms_two_words() {
        // The `_timer` arm overlays `_kill`: si_tid shares si_pid's bytes and
        // si_overrun shares si_uid's. Every consumer reads them through that
        // overlay, so the producer must write them there.
        let mut rec = timer_record(SIGRTMIN, 7, 0);
        assert_eq!(rec.pid, 7);
        assert_eq!(rec.uid, 0, "overrun is unknown until the record is taken");
        stamp_overrun(&mut rec, 42);
        assert_eq!(rec.uid, 42);
    }

    #[test]
    fn the_stamped_overrun_is_clamped_to_what_timer_getoverrun_can_return() {
        let mut rec = timer_record(SIGRTMIN, 0, 0);
        stamp_overrun(&mut rec, i64::MAX);
        assert_eq!(rec.uid, i32::MAX as u32);
        stamp_overrun(&mut rec, -1);
        assert_eq!(rec.uid, 0, "a negative accumulator never reaches userspace");
    }

    #[test]
    fn a_non_timer_record_is_never_rearmed() {
        let rec = SigInfo { signo: SIGALRM, code: crate::signum::SI_USER, pid: 9, uid: 1000,
            value: 0, sys: None, fault: None };
        assert!(!is_timer_record(&rec), "an SI_USER kill(2) must not be mistaken for an expiry");
    }
}
