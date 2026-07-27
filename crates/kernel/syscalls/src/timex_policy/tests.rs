use super::*;
use sched::posix_clock::{CLOCK_BOOTTIME, CLOCK_MONOTONIC, CLOCK_MONOTONIC_COARSE,
    CLOCK_MONOTONIC_RAW, CLOCK_PROCESS_CPUTIME_ID, CLOCK_REALTIME, CLOCK_REALTIME_ALARM,
    CLOCK_REALTIME_COARSE, CLOCK_TAI, CLOCK_THREAD_CPUTIME_ID};
use timekeeper::ntp::uapi::{ADJ_FREQUENCY, TIME_ERROR, TIME_OK};

const GOOD: u64 = 0x1000;
const UNREADABLE: u64 = 0xdead;
const UNWRITABLE: u64 = 0xbeef;

#[derive(Default)]
struct Ops {
    capable: bool,
    /// What `do_adjtimex` reports; `None` means it succeeds with TIME_OK.
    adj_err: Option<Errno>,
    /// Recorded so a test can prove the capability was sampled and forwarded.
    saw_capable: Option<bool>,
    stored: Option<Timex>,
    wrote: bool,
    adj_calls: u32,
}

impl TimexOps for Ops {
    fn read_timex(&mut self, ptr: u64) -> Result<Timex, Errno> {
        if ptr == UNREADABLE { return Err(Errno::Efault); }
        Ok(Timex { tick: 10_000, ..Timex::default() })
    }
    fn write_timex(&mut self, ptr: u64, tx: &Timex) -> Result<(), Errno> {
        if ptr == UNWRITABLE { return Err(Errno::Efault); }
        self.wrote = true;
        self.stored = Some(*tx);
        Ok(())
    }
    fn may_set_time(&mut self) -> bool { self.capable }
    fn adjtimex(&mut self, tx: &mut Timex, capable: bool) -> Result<i32, Errno> {
        self.adj_calls += 1;
        self.saw_capable = Some(capable);
        tx.status = 0x40; // STA_UNSYNC, so the state is observable in the buffer
        match self.adj_err { Some(e) => Err(e), None => Ok(TIME_OK) }
    }
}

// ---- adjtimex ---------------------------------------------------------

#[test]
fn a_query_returns_the_clock_state_and_writes_the_buffer_back() {
    let mut o = Ops::default();
    assert_eq!(adjtimex(&mut o, GOOD), Ok(TIME_OK));
    assert!(o.wrote);
    assert_eq!(o.stored.unwrap().status, 0x40);
}

#[test]
fn an_unreadable_buffer_is_efault_before_anything_runs() {
    let mut o = Ops::default();
    assert_eq!(adjtimex(&mut o, UNREADABLE), Err(Errno::Efault));
    assert_eq!(o.adj_calls, 0);
    assert!(!o.wrote);
}

#[test]
fn adjtimex_writes_back_even_when_the_adjustment_was_rejected() {
    // kernel/time/time.c: `return copy_to_user(...) ? -EFAULT : ret;` — the
    // copy is unconditional, so a rejected call still refreshes the buffer.
    let mut o = Ops::default();
    o.adj_err = Some(Errno::Eperm);
    assert_eq!(adjtimex(&mut o, GOOD), Err(Errno::Eperm));
    assert!(o.wrote, "the buffer is copied back regardless of the result");
}

#[test]
fn an_unwritable_buffer_turns_even_a_successful_adjtimex_into_efault() {
    let mut o = Ops::default();
    assert_eq!(adjtimex(&mut o, UNWRITABLE), Err(Errno::Efault));
    assert_eq!(o.adj_calls, 1, "the adjustment has already taken effect");
}

#[test]
fn the_copy_back_efault_outranks_the_adjustment_error() {
    let mut o = Ops::default();
    o.adj_err = Some(Errno::Einval);
    assert_eq!(adjtimex(&mut o, UNWRITABLE), Err(Errno::Efault));
}

#[test]
fn the_capability_is_sampled_and_forwarded_to_the_validator() {
    // The validator, not this layer, decides whether the capability is needed:
    // a modes==0 query must succeed for an unprivileged caller.
    let mut o = Ops::default();
    o.capable = false;
    assert_eq!(adjtimex(&mut o, GOOD), Ok(TIME_OK));
    assert_eq!(o.saw_capable, Some(false));
    let mut o = Ops::default();
    o.capable = true;
    assert_eq!(adjtimex(&mut o, GOOD), Ok(TIME_OK));
    assert_eq!(o.saw_capable, Some(true));
}

#[test]
fn the_time_error_state_is_a_success_return_not_an_errno() {
    let mut o = Ops::default();
    o.adj_err = None;
    // TIME_ERROR is 5 — non-negative, so glibc passes it through as a state.
    assert!(TIME_ERROR >= 0 && TIME_ERROR <= 5);
    assert!(adjtimex(&mut o, GOOD).is_ok());
}

// ---- clock_adjtime ----------------------------------------------------

#[test]
fn clock_adjtime_on_clock_realtime_behaves_like_adjtimex() {
    let mut o = Ops::default();
    assert_eq!(clock_adjtime(&mut o, CLOCK_REALTIME as u64, GOOD), Ok(TIME_OK));
    assert!(o.wrote);
}

#[test]
fn clock_adjtime_faults_on_the_buffer_before_it_looks_at_the_clock_id() {
    // copy_from_user runs first in SYSCALL_DEFINE2(clock_adjtime), so a
    // nonsense clock id with a bad pointer reports EFAULT, not EINVAL.
    let mut o = Ops::default();
    assert_eq!(clock_adjtime(&mut o, 0xdead_beef, UNREADABLE), Err(Errno::Efault));
    assert_eq!(o.adj_calls, 0);
}

#[test]
fn a_clock_without_clock_adj_is_eopnotsupp_not_einval() {
    // do_clock_adjtime distinguishes "no such kclock" (EINVAL) from "this
    // kclock has no clock_adj callback" (EOPNOTSUPP). Collapsing the two would
    // tell an NTP client the id was malformed when it was merely undisciplined.
    for id in [CLOCK_MONOTONIC, CLOCK_MONOTONIC_RAW, CLOCK_REALTIME_COARSE,
        CLOCK_MONOTONIC_COARSE, CLOCK_BOOTTIME, CLOCK_REALTIME_ALARM, CLOCK_TAI,
        CLOCK_PROCESS_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID]
    {
        let mut o = Ops::default();
        assert_eq!(clock_adjtime(&mut o, id as u64, GOOD), Err(Errno::Eopnotsupp),
            "clock {id}");
        assert_eq!(o.adj_calls, 0);
        assert!(!o.wrote, "a rejected clock_adjtime does not touch the buffer");
    }
}

#[test]
fn clock_tai_is_disciplined_through_clock_realtime_not_directly() {
    // clock_tai carries no .clock_adj; ADJ_TAI on CLOCK_REALTIME is the only
    // way to move the TAI-UTC offset.
    let mut o = Ops::default();
    assert_eq!(clock_adjtime(&mut o, CLOCK_TAI as u64, GOOD), Err(Errno::Eopnotsupp));
    let mut o = Ops::default();
    o.capable = true;
    assert_eq!(clock_adjtime(&mut o, CLOCK_REALTIME as u64, GOOD), Ok(TIME_OK));
}

#[test]
fn an_id_outside_the_posix_clocks_table_is_einval() {
    for id in [10u64, 12, 99, i32::MAX as u64] {
        let mut o = Ops::default();
        assert_eq!(clock_adjtime(&mut o, id, GOOD), Err(Errno::Einval), "clock {id}");
    }
}

#[test]
fn a_dynamic_posix_clock_fd_is_einval_until_a_ptp_device_exists() {
    let dynamic = ((!3i32) << 3) | 3; // CLOCKFD encoding of fd 3
    let mut o = Ops::default();
    assert_eq!(clock_adjtime(&mut o, dynamic as u32 as u64, GOOD), Err(Errno::Einval));
}

#[test]
fn clock_adjtime_does_not_write_back_on_failure() {
    // `if (err >= 0 && copy_to_user(...))` — unlike adjtimex, the copy is
    // conditional, so a rejected adjustment leaves the buffer untouched.
    let mut o = Ops::default();
    o.adj_err = Some(Errno::Eperm);
    assert_eq!(clock_adjtime(&mut o, CLOCK_REALTIME as u64, GOOD), Err(Errno::Eperm));
    assert!(!o.wrote);
}

#[test]
fn clock_adjtime_still_faults_on_an_unwritable_buffer_after_success() {
    let mut o = Ops::default();
    assert_eq!(clock_adjtime(&mut o, CLOCK_REALTIME as u64, UNWRITABLE), Err(Errno::Efault));
    assert_eq!(o.adj_calls, 1);
}

#[test]
fn clock_supports_adj_is_the_shared_admission_table() {
    assert_eq!(clock_supports_adj(CLOCK_REALTIME as u64), Ok(()));
    assert_eq!(clock_supports_adj(CLOCK_MONOTONIC as u64), Err(Errno::Eopnotsupp));
    assert_eq!(clock_supports_adj(10), Err(Errno::Einval));
}

#[test]
fn the_mode_bits_reach_the_adjustment_unchanged() {
    // A regression guard for a shim that "helpfully" masks modes on the way in.
    struct Echo { seen: u32 }
    impl TimexOps for Echo {
        fn read_timex(&mut self, _p: u64) -> Result<Timex, Errno> {
            Ok(Timex { modes: ADJ_FREQUENCY, freq: 123, ..Timex::default() })
        }
        fn write_timex(&mut self, _p: u64, _t: &Timex) -> Result<(), Errno> { Ok(()) }
        fn may_set_time(&mut self) -> bool { true }
        fn adjtimex(&mut self, tx: &mut Timex, _c: bool) -> Result<i32, Errno> {
            self.seen = tx.modes;
            Ok(TIME_OK)
        }
    }
    let mut e = Echo { seen: 0 };
    assert_eq!(adjtimex(&mut e, GOOD), Ok(TIME_OK));
    assert_eq!(e.seen, ADJ_FREQUENCY);
}
