//! Space promised before it is occupied, and the two ways a promise ends.

use crate::quota::dqblk::{self, Dqblk};
use crate::quota::info::Revision;
use crate::quota::limit::{self, Ask, Verdict};
use crate::quota::uapi::SPACE_UNIT;

const NOW: u64 = 1_000_000;
const GRACE: u64 = 604_800;

fn ask() -> Ask {
    Ask { now: NOW, grace: GRACE, exempt: false, enforced: true, allocating: true }
}

/// Soft at eight units, hard at ten, nothing used.
fn limits() -> Dqblk {
    Dqblk { bsoftlimit: 8 * SPACE_UNIT, bhardlimit: 10 * SPACE_UNIT, ..Dqblk::default() }
}

#[test]
fn a_promise_holds_space_against_the_limits_without_occupying_any() {
    let mut d = limits();
    let want = 8 * SPACE_UNIT;
    let v = limit::space(&d, want, &ask());
    assert!(limit::apply_reserve(&mut d, want, v));
    assert_eq!(d.rsvspace, want);
    assert_eq!(d.curspace, 0, "nothing is occupied yet");
    assert_eq!(limit::total_space(&d), want);
}

#[test]
fn a_promise_already_made_is_measured_against_the_next_request() {
    let mut d = limits();
    limit::apply_reserve(&mut d, 8 * SPACE_UNIT, Verdict::Allow);
    // Eight promised and three more asked for is eleven, past the hard limit,
    // even though nothing occupies a byte.
    assert_eq!(limit::space(&d, 3 * SPACE_UNIT, &ask()), Verdict::Deny);
    // Exactly onto the hard limit still fits, and crosses the soft one for
    // the first time — which a promise nobody counted would never reach.
    assert_eq!(limit::space(&d, 2 * SPACE_UNIT, &ask()), Verdict::AllowStartingGrace(NOW + GRACE));
}

#[test]
fn taking_up_a_promise_moves_it_without_changing_the_total() {
    let mut d = limits();
    limit::apply_reserve(&mut d, 6 * SPACE_UNIT, Verdict::Allow);
    limit::claim_space(&mut d, 4 * SPACE_UNIT);
    assert_eq!(d.curspace, 4 * SPACE_UNIT);
    assert_eq!(d.rsvspace, 2 * SPACE_UNIT);
    assert_eq!(limit::total_space(&d), 6 * SPACE_UNIT, "the identity holds no more than before");
}

#[test]
fn claiming_more_than_was_promised_takes_only_what_was_promised() {
    let mut d = limits();
    limit::apply_reserve(&mut d, 2 * SPACE_UNIT, Verdict::Allow);
    limit::claim_space(&mut d, 9 * SPACE_UNIT);
    assert_eq!(d.rsvspace, 0);
    assert_eq!(d.curspace, 2 * SPACE_UNIT, "a caller's arithmetic cannot invent usage");
}

#[test]
fn a_promise_nothing_took_up_is_given_back() {
    let mut d = limits();
    limit::apply_reserve(&mut d, 8 * SPACE_UNIT, Verdict::Allow);
    assert_eq!(limit::space(&d, 3 * SPACE_UNIT, &ask()), Verdict::Deny);
    limit::release_reserved(&mut d, 8 * SPACE_UNIT);
    assert_eq!(d.rsvspace, 0);
    assert_eq!(limit::space(&d, 3 * SPACE_UNIT, &ask()), Verdict::Allow, "the room came back");
}

#[test]
fn occupied_space_can_go_back_to_being_a_promise() {
    let mut d = Dqblk { curspace: 5 * SPACE_UNIT, ..limits() };
    limit::reclaim_space(&mut d, 2 * SPACE_UNIT);
    assert_eq!(d.curspace, 3 * SPACE_UNIT);
    assert_eq!(d.rsvspace, 2 * SPACE_UNIT);
    assert_eq!(limit::total_space(&d), 5 * SPACE_UNIT);
    // And no more than it occupies.
    limit::reclaim_space(&mut d, 99 * SPACE_UNIT);
    assert_eq!(d.curspace, 0);
    assert_eq!(d.rsvspace, 5 * SPACE_UNIT);
}

#[test]
fn a_promise_still_over_the_soft_limit_keeps_the_clock_running() {
    let mut d = Dqblk { curspace: 9 * SPACE_UNIT, btime: NOW + GRACE, ..limits() };
    limit::apply_reserve(&mut d, 5 * SPACE_UNIT, Verdict::Allow);
    limit::free_space(&mut d, 4 * SPACE_UNIT);
    assert_eq!(limit::total_space(&d), 10 * SPACE_UNIT);
    assert_eq!(d.btime, NOW + GRACE, "still over the soft limit, promise included");
    // Giving the promise back is what brings it under.
    limit::release_reserved(&mut d, 5 * SPACE_UNIT);
    assert_eq!(d.btime, 0);
}

#[test]
fn what_is_left_to_an_identity_counts_its_promises() {
    let mut d = limits();
    assert_eq!(limit::space_remaining(&d), Some(8 * SPACE_UNIT));
    limit::apply_reserve(&mut d, 3 * SPACE_UNIT, Verdict::Allow);
    assert_eq!(limit::space_remaining(&d), Some(5 * SPACE_UNIT));
    limit::claim_space(&mut d, 3 * SPACE_UNIT);
    assert_eq!(limit::space_remaining(&d), Some(5 * SPACE_UNIT), "taking it up changes nothing");
}

#[test]
fn a_promise_is_never_written_to_the_medium() {
    let d = Dqblk { curspace: 4096, rsvspace: 8192, ..limits() };
    for rev in [Revision::R0, Revision::R1] {
        let bytes = dqblk::encode(&d, 7, rev);
        let back = dqblk::parse(&bytes, rev).unwrap();
        assert_eq!(back.curspace, 4096, "what it occupies is stored");
        assert_eq!(back.rsvspace, 0, "what this mount promised it is not");
    }
}

#[test]
fn a_reservation_that_would_cross_the_soft_limit_is_refused_and_an_allocation_is_not() {
    let d = limits();
    let reserving = Ask { allocating: false, ..ask() };
    assert_eq!(limit::space(&d, 9 * SPACE_UNIT, &reserving), Verdict::Deny);
    assert_eq!(
        limit::space(&d, 9 * SPACE_UNIT, &ask()),
        Verdict::AllowStartingGrace(NOW + GRACE),
        "an allocation may spend grace a reservation may not",
    );
}
