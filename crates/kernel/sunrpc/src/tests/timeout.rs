// The retransmission schedule's two deadlines.

extern crate alloc;
use alloc::vec;

use crate::xprt::{RetryState, RpcTimeout, TimeoutOutcome::*};

const LINEAR: RpcTimeout = RpcTimeout {
    initval: 1000, maxval: 4000, increment: 1000, retries: 3, exponential: false,
};
const EXPO: RpcTimeout = RpcTimeout {
    initval: 1000, maxval: 16000, increment: 0, retries: 3, exponential: true,
};

#[test]
fn a_fresh_call_waits_until_its_first_minor_deadline() {
    let mut s = RetryState::start(&LINEAR, 0);
    assert_eq!(s.adjust(&LINEAR, 0), Wait);
    assert_eq!(s.adjust(&LINEAR, 999), Wait);
    assert_eq!(s.retries, 0);
}

#[test]
fn the_minor_deadline_retransmits_and_lengthens_the_next_wait() {
    let mut s = RetryState::start(&LINEAR, 0);
    assert_eq!(s.adjust(&LINEAR, 1000), Retransmit);
    assert_eq!(s.timeout, 2000);
    assert_eq!(s.retries, 1);
    assert_eq!(s.minortimeo, 3000);
}

#[test]
fn the_per_attempt_wait_is_capped_at_the_maximum() {
    // An increment that overshoots the ceiling in one step. Without the clamp
    // the next attempt would wait 10s under a policy that says never more
    // than 5s.
    let to = RpcTimeout { initval: 1000, maxval: 5000, increment: 9000, retries: 1,
                          exponential: false };
    let mut s = RetryState::start(&to, 0);
    assert_eq!(s.adjust(&to, 1000), Retransmit);
    assert_eq!(s.timeout, to.maxval);
}

#[test]
fn an_exponential_schedule_doubles_instead_of_adding() {
    let mut s = RetryState::start(&EXPO, 0);
    assert_eq!(s.adjust(&EXPO, 1000), Retransmit);
    assert_eq!(s.timeout, 2000);
    assert_eq!(s.adjust(&EXPO, 3000), Retransmit);
    assert_eq!(s.timeout, 4000);
}

#[test]
fn the_major_budget_is_the_retry_ladder_summed() {
    // Linear: initval + increment * retries. Exponential: initval << retries.
    assert_eq!(LINEAR.major_span(1000), 4000);
    assert_eq!(EXPO.major_span(1000), 8000);
}

#[test]
fn a_major_span_over_the_ceiling_is_clamped_to_it() {
    let to = RpcTimeout { initval: 1000, maxval: 2000, increment: 1000, retries: 9,
                          exponential: false };
    assert_eq!(to.major_span(1000), 2000);
}

#[test]
fn the_major_deadline_ends_the_call_even_while_minor_ones_remain() {
    // A client with only the minor deadline retransmits forever. This is the
    // check that fails if the major deadline is dropped.
    let mut s = RetryState::start(&LINEAR, 0);
    assert_eq!(s.adjust(&LINEAR, 1000), Retransmit);
    assert_eq!(s.adjust(&LINEAR, 4000), MajorTimeout);
}

#[test]
fn deadlines_advance_by_addition_so_late_polls_still_accumulate_elapsed_time() {
    // Restarting each deadline from `now` would hand back the whole interval on
    // every late poll, and the major budget would never expire.
    let mut s = RetryState::start(&LINEAR, 0);
    let major = s.majortimeo;
    s.adjust(&LINEAR, 1500);
    assert_eq!(s.majortimeo, major);
    assert_eq!(s.minortimeo, 1000 + 2000);
}

#[test]
fn a_major_timeout_leaves_a_fresh_budget_behind() {
    // The per-attempt wait and the retry count reset, and the major deadline
    // moves a whole budget further out, so a caller that chooses to keep an
    // idempotent call alive continues from a clean schedule.
    let mut s = RetryState::start(&LINEAR, 0);
    let major = s.majortimeo;
    assert_eq!(s.adjust(&LINEAR, 5000), MajorTimeout);
    assert_eq!(s.timeout, LINEAR.initval);
    assert_eq!(s.retries, 0);
    assert_eq!(s.majortimeo, major + LINEAR.major_span(LINEAR.initval));
    assert_eq!(s.adjust(&LINEAR, 5001), Retransmit);
}

#[test]
fn the_stream_default_gives_up_rather_than_resending() {
    // A stream already retransmits beneath the RPC layer; the RPC layer's job
    // there is to decide when to stop waiting.
    assert_eq!(RpcTimeout::TCP.initval, RpcTimeout::TCP.maxval);
    assert_eq!(RpcTimeout::TCP.increment, 0);
    assert_eq!(RpcTimeout::TCP.major_span(RpcTimeout::TCP.initval), 60_000);
}

#[test]
fn the_datagram_default_sends_twice_more_then_gives_up() {
    // The ladder is bounded by the MAJOR budget, not by the per-attempt
    // ceiling: 5s + 5s * 5 retries = 30s total, which the growing waits
    // (5s, then 10s, then 15s) exhaust after two retransmissions. A client
    // that only watched the per-attempt cap would keep resending past it.
    let to = RpcTimeout::UDP;
    let mut s = RetryState::start(&to, 0);
    let mut t = to.initval;
    let mut seen = vec![];
    for _ in 0..3 { seen.push(s.adjust(&to, t)); t = s.minortimeo; }
    assert_eq!(seen, vec![Retransmit, Retransmit, MajorTimeout]);
    assert_eq!(to.major_span(to.initval), 30_000);
}
