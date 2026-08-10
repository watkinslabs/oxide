// SQPOLL decisions: the idle window, the pin-CPU ladder, the loop's
// transitions, and the wakeup handshake — including the window a missed
// wakeup would live in.

use super::*;
use crate::io_uring_abi::enter::{IORING_ENTER_SQ_WAIT, IORING_ENTER_SQ_WAKEUP};

// ---------------------------------------------------------------- idle window

#[test]
fn an_unstated_idle_window_is_one_second_not_zero() {
    // Zero means "no preference". Reading it as "sleep immediately" would make
    // every submission pay a wakeup syscall — the exact cost SQPOLL exists to
    // remove — so the reference substitutes HZ.
    assert_eq!(sq_thread_idle_ns(0), 1_000 * NSEC_PER_MSEC);
    assert_eq!(DEFAULT_SQ_THREAD_IDLE_MS, 1_000);
}

#[test]
fn a_stated_idle_window_is_milliseconds() {
    assert_eq!(sq_thread_idle_ns(1), NSEC_PER_MSEC);
    assert_eq!(sq_thread_idle_ns(250), 250 * NSEC_PER_MSEC);
}

#[test]
fn an_absurd_idle_window_saturates_rather_than_wrapping() {
    // u32::MAX ms is ~49.7 days in ns and fits u64; the saturation is the
    // guard, not the arithmetic. A wrap here would arm a deadline in the past
    // and turn the spin window off.
    assert!(sq_thread_idle_ns(u32::MAX) > sq_thread_idle_ns(1));
}

// -------------------------------------------------------------- idle deadline

#[test]
fn a_thread_that_has_never_worked_sleeps_at_once() {
    // deadline 0 => the first empty pass is already past the window. A thread
    // that spun for a full window it never earned would burn a processor for
    // a second on every ring that is created and left idle.
    let st = PollState::new(sq_thread_idle_ns(0));
    assert_eq!(st.deadline_ns, 0);
    let o = Observed { now_ns: 1, ..Default::default() };
    assert_eq!(step(&st, &o), Step::Idle);
}

#[test]
fn work_re_arms_the_idle_window_and_the_window_then_holds_the_thread_hot() {
    let mut st = PollState::new(sq_thread_idle_ns(10)); // 10 ms
    st.touch(1_000);
    assert_eq!(st.deadline_ns, 1_000 + 10 * NSEC_PER_MSEC);

    // Inside the window with an empty ring: spin, do not sleep.
    let inside = Observed { now_ns: st.deadline_ns - 1, ..Default::default() };
    assert_eq!(step(&st, &inside), Step::Spin);

    // The deadline instant itself is still inside the window.
    let edge = Observed { now_ns: st.deadline_ns, ..Default::default() };
    assert_eq!(step(&st, &edge), Step::Spin);

    // One nanosecond past it, the thread gives up the processor.
    let past = Observed { now_ns: st.deadline_ns + 1, ..Default::default() };
    assert_eq!(step(&st, &past), Step::Idle);
}

// ------------------------------------------------------------------ loop steps

#[test]
fn work_outranks_the_idle_window_in_both_directions() {
    let mut st = PollState::new(sq_thread_idle_ns(10));
    st.touch(0);
    for now in [1u64, st.deadline_ns + 1_000_000] {
        let o = Observed { sq_ready: 3, now_ns: now, ..Default::default() };
        assert_eq!(step(&st, &o), Step::Submit(3), "an entry is drained whatever the clock says");
    }
}

#[test]
fn a_stop_request_outranks_everything_including_pending_work() {
    let st = PollState::new(sq_thread_idle_ns(0));
    let o = Observed { stop: true, park: true, sq_ready: 9, ..Default::default() };
    assert_eq!(step(&st, &o), Step::Stop);
}

#[test]
fn a_park_request_outranks_pending_work_but_not_a_stop() {
    let st = PollState::new(sq_thread_idle_ns(0));
    assert_eq!(step(&st, &Observed { park: true, sq_ready: 9, ..Default::default() }), Step::Park);
    assert_eq!(step(&st, &Observed { park: true, stop: true, ..Default::default() }), Step::Stop);
}

#[test]
fn a_disabled_ring_is_never_drained_by_its_poll_thread() {
    // IORING_SETUP_R_DISABLED: the entries are there but they are not the
    // thread's to consume until IORING_REGISTER_ENABLE_RINGS says so.
    let st = PollState::new(sq_thread_idle_ns(0));
    let o = Observed { disabled: true, sq_ready: 4, now_ns: 1, ..Default::default() };
    assert_eq!(step(&st, &o), Step::Idle);
    // And it may sleep on those entries, because nothing it does can consume
    // them — enabling the ring is what wakes it.
    assert!(sleeps_after_arm(&o));
}

#[test]
fn one_ring_takes_the_whole_batch_and_several_rings_share_it() {
    assert_eq!(cap_submit(64, false), 64);
    assert_eq!(cap_submit(64, true), SQPOLL_CAP_ENTRIES);
    assert_eq!(cap_submit(3, true), 3, "the cap is a ceiling, not a quantum");
    let st = PollState::new(0);
    let o = Observed { sq_ready: 64, shared: true, ..Default::default() };
    assert_eq!(step(&st, &o), Step::Submit(SQPOLL_CAP_ENTRIES));
}

// ------------------------------------------------------------ ring arithmetic

#[test]
fn sq_occupancy_is_wraparound_correct() {
    assert_eq!(sq_ready(5, 2), 3);
    assert_eq!(sq_ready(1, u32::MAX), 2, "free-running counters wrap; the difference does not");
    assert!(sq_full(u32::MAX.wrapping_add(4), u32::MAX, 4));
    assert!(!sq_full(u32::MAX.wrapping_add(3), u32::MAX, 4));
}

// ------------------------------------------------------- the wakeup handshake

/// The two words the submitter and the poll thread share.
#[derive(Default)]
struct Shared { sq_tail: u32, sq_head: u32, sq_flags: u32 }

/// What one interleaving produced.
#[derive(Debug, PartialEq, Eq)]
struct Play { thread_sleeps: bool, submitter_rings: bool }

impl Play {
    /// The property the whole handshake exists to hold: an entry is never left
    /// in the ring with nobody coming for it. Either the thread stayed awake to
    /// drain it, or the submitter saw the doorbell and rang it.
    fn entry_is_not_stranded(&self) -> bool { !self.thread_sleeps || self.submitter_rings }
}

fn observe(s: &Shared) -> Observed {
    Observed { sq_ready: sq_ready(s.sq_tail, s.sq_head), ..Default::default() }
}

/// Play the four-step handshake with the submitter's tail store landing before
/// the thread's tail load.
fn play_submitter_first() -> Play {
    let mut s = Shared::default();
    s.sq_tail = 1;                                  // submitter: store tail
    s.sq_flags = arm_need_wakeup(s.sq_flags);       // thread: store flag
    let thread_sleeps = sleeps_after_arm(&observe(&s)); // thread: load tail
    let submitter_rings = wakeup_required(s.sq_flags);  // submitter: load flags
    Play { thread_sleeps, submitter_rings }
}

/// Play it with the thread's tail load landing before the submitter's tail
/// store — the window a missed wakeup lives in.
fn play_thread_first() -> Play {
    let mut s = Shared::default();
    s.sq_flags = arm_need_wakeup(s.sq_flags);       // thread: store flag
    let thread_sleeps = sleeps_after_arm(&observe(&s)); // thread: load tail (empty)
    s.sq_tail = 1;                                  // submitter: store tail
    let submitter_rings = wakeup_required(s.sq_flags);  // submitter: load flags
    Play { thread_sleeps, submitter_rings }
}

#[test]
fn no_interleaving_of_the_handshake_strands_an_entry() {
    // This is the test the positive control breaks: make `arm_need_wakeup`
    // stop setting the bit and `play_thread_first` reports a sleeping thread
    // and a silent submitter — a hang.
    let a = play_submitter_first();
    assert!(a.entry_is_not_stranded(), "{a:?}");
    let b = play_thread_first();
    assert!(b.entry_is_not_stranded(), "{b:?}");
}

#[test]
fn the_submitters_store_landing_first_keeps_the_thread_awake() {
    let a = play_submitter_first();
    assert!(!a.thread_sleeps, "the thread re-reads the tail AFTER publishing the doorbell");
}

#[test]
fn the_threads_store_landing_first_puts_the_doorbell_up_for_the_submitter() {
    let b = play_thread_first();
    assert!(b.thread_sleeps, "an empty ring past the idle window is exactly when it sleeps");
    assert!(b.submitter_rings, "and the submitter it raced must see the doorbell");
}

#[test]
fn the_doorbell_goes_down_when_the_thread_wakes() {
    // Leaving it up costs a submitter one syscall per submission for as long
    // as it stays up.
    let armed = arm_need_wakeup(0);
    assert!(wakeup_required(armed));
    assert!(!wakeup_required(disarm_need_wakeup(armed)));
    // And retracting it touches nothing else in the word.
    let other = crate::io_uring_abi::uapi::IORING_SQ_CQ_OVERFLOW;
    assert_eq!(disarm_need_wakeup(arm_need_wakeup(other)), other);
}

#[test]
fn a_thread_asked_to_stop_or_park_does_not_sleep_on_the_doorbell() {
    assert!(!sleeps_after_arm(&Observed { stop: true, ..Default::default() }));
    assert!(!sleeps_after_arm(&Observed { park: true, ..Default::default() }));
}

// ------------------------------------------------------------------- SQ_AFF

const SQPOLL: u32 = IORING_SETUP_SQPOLL;
const SQ_AFF: u32 = IORING_SETUP_SQ_AFF;

#[test]
fn no_sq_aff_means_no_pin_whatever_sq_thread_cpu_holds() {
    assert_eq!(sq_cpu(SQPOLL, 99, 0), Ok(None), "sq_thread_cpu is not read without SQ_AFF");
}

#[test]
fn sq_aff_without_sqpoll_is_einval() {
    assert_eq!(sq_cpu(SQ_AFF, 0, 0b1), Err(Errno::Einval), "there is no thread to pin");
}

#[test]
fn sq_aff_pins_to_a_processor_the_creating_task_may_itself_run_on() {
    assert_eq!(sq_cpu(SQPOLL | SQ_AFF, 1, 0b11), Ok(Some(1)));
    // Confined to CPU 0: asking for CPU 1 must not be a way out of the cpuset.
    assert_eq!(sq_cpu(SQPOLL | SQ_AFF, 1, 0b01), Err(Errno::Einval));
    // Offline / nonexistent processor.
    assert_eq!(sq_cpu(SQPOLL | SQ_AFF, 3, 0b11), Err(Errno::Einval));
    assert_eq!(sq_cpu(SQPOLL | SQ_AFF, 64, u64::MAX), Err(Errno::Einval));
    assert_eq!(sq_cpu(SQPOLL | SQ_AFF, u32::MAX, u64::MAX), Err(Errno::Einval));
}

// -------------------------------------------------------------- enter(2) side

#[test]
fn enter_on_a_polled_ring_submits_nothing_and_reports_what_the_caller_published() {
    assert_eq!(enter_submitted(0), 0);
    assert_eq!(enter_submitted(7), 7);
}

#[test]
fn enter_reads_the_two_sq_flags_independently() {
    assert_eq!(enter_action(0), EnterSqpoll { wake: false, wait_room: false });
    assert_eq!(enter_action(IORING_ENTER_SQ_WAKEUP), EnterSqpoll { wake: true, wait_room: false });
    assert_eq!(enter_action(IORING_ENTER_SQ_WAIT), EnterSqpoll { wake: false, wait_room: true });
    assert_eq!(enter_action(IORING_ENTER_SQ_WAKEUP | IORING_ENTER_SQ_WAIT),
               EnterSqpoll { wake: true, wait_room: true });
}

#[test]
fn the_wake_is_unconditional_not_re_decided_against_the_doorbell() {
    // The submitter decided when it read sq_flags. Re-testing the word here —
    // after the thread may already have retracted it — would drop the wakeup
    // the submitter paid a syscall for.
    assert!(enter_action(IORING_ENTER_SQ_WAKEUP).wake);
}

/// One thread, several rings: each ring's pass is capped so a busy ring cannot
/// starve its neighbours, and a ring serving alone is not capped at all.
#[test]
fn a_shared_thread_caps_each_rings_pass_and_a_lone_one_does_not() {
    assert!(!shares(1));
    assert!(shares(2));
    assert_eq!(ring_take(1000, false, 1), 1000, "a lone ring takes everything it has");
    assert_eq!(ring_take(1000, false, 3), SQPOLL_CAP_ENTRIES);
    assert_eq!(ring_take(3, false, 3), 3, "the cap is a ceiling, not a quota");
}

/// A disabled ring contributes nothing to a shared thread's pass, and does not
/// stop the others contributing.
#[test]
fn a_disabled_ring_contributes_nothing_to_a_shared_pass() {
    assert_eq!(ring_take(50, true, 1), 0);
    assert_eq!(ring_take(50, true, 4), 0);
}

fn peer_ok() -> Peer { Peer { present: true, is_ring: true, has_thread: true, same_group: true, dead: false } }

#[test]
fn a_ring_that_does_not_ask_to_attach_gets_its_own_thread_or_none() {
    assert_eq!(attach_admit(IORING_SETUP_SQPOLL, &Peer::default()), Ok(Attach::Own));
    assert_eq!(attach_admit(0, &Peer::default()), Ok(Attach::Validate));
}

#[test]
fn attaching_names_a_descriptor_that_must_be_a_live_ring() {
    let f = IORING_SETUP_ATTACH_WQ | IORING_SETUP_SQPOLL;
    assert_eq!(attach_admit(f, &Peer::default()), Err(Errno::Enxio),
               "a descriptor naming nothing is ENXIO");
    let p = Peer { present: true, ..Peer::default() };
    assert_eq!(attach_admit(f, &p), Err(Errno::Einval), "a descriptor naming a non-ring is EINVAL");
}

/// The descriptor is validated even when this ring has no poll thread to
/// place: the request named something, and naming it wrongly is still an
/// error.
#[test]
fn attaching_without_a_poll_thread_still_validates_the_descriptor() {
    let f = IORING_SETUP_ATTACH_WQ;
    assert_eq!(attach_admit(f, &Peer::default()), Err(Errno::Enxio));
    assert_eq!(attach_admit(f, &Peer { present: true, ..Peer::default() }), Err(Errno::Einval));
    assert_eq!(attach_admit(f, &peer_ok()), Ok(Attach::Validate),
               "nothing to join to, and nothing to build");
}

#[test]
fn attaching_to_a_ring_without_a_thread_is_einval() {
    let f = IORING_SETUP_ATTACH_WQ | IORING_SETUP_SQPOLL;
    let p = Peer { has_thread: false, ..peer_ok() };
    assert_eq!(attach_admit(f, &p), Err(Errno::Einval));
}

/// A thread belonging to another thread group borrows another process's
/// address space and descriptor table, so this ring's entries would not mean
/// on it what they mean here. The sharing is refused; the request for a thread
/// is not.
#[test]
fn attaching_across_thread_groups_yields_a_thread_of_ones_own() {
    let f = IORING_SETUP_ATTACH_WQ | IORING_SETUP_SQPOLL;
    assert_eq!(attach_admit(f, &Peer { same_group: false, ..peer_ok() }), Ok(Attach::Own));
}

/// Joining a thread that has already left its loop would leave the ring with a
/// submitter that never runs, and a caller waiting for completions that never
/// come.
#[test]
fn attaching_to_a_dead_thread_is_enxio() {
    let f = IORING_SETUP_ATTACH_WQ | IORING_SETUP_SQPOLL;
    assert_eq!(attach_admit(f, &Peer { dead: true, ..peer_ok() }), Err(Errno::Enxio));
    assert_eq!(attach_admit(f, &peer_ok()), Ok(Attach::Join));
}
