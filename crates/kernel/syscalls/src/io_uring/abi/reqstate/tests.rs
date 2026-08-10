use super::*;

use crate::io_uring_abi::recvsend::{step, Step, MULTISHOT_MAX_RETRY};

#[test]
fn a_waiting_request_is_claimed_exactly_once() {
    let r = ReqState::new();
    assert!(r.claim());
    // The cancellation, the deadline and the readiness callback all arrive
    // while the worker holds it, and none of them may report it.
    for _ in 0..4 { assert!(!r.claim()); }
    r.finish();
    assert!(r.is_done());
}

#[test]
fn a_finished_request_can_never_be_claimed_again() {
    let r = ReqState::new();
    assert!(r.claim());
    r.finish();
    assert!(!r.claim());
    assert_eq!(r.state(), st::DONE);
}

/// The sequence a request that stays armed lives in: claimed for a pass,
/// released, claimed again by whatever woke it — many times — and finished
/// once. Every intermediate release is re-claimable and the terminal one is
/// not, which is what keeps a re-armed request from being reported twice.
#[test]
fn a_rearmed_request_is_claimable_again_and_finishes_once() {
    let r = ReqState::new();
    for _ in 0..8 {
        assert!(r.claim());
        assert!(!r.claim(), "claimed twice while running");
        r.rearm();
        assert!(!r.is_done());
    }
    assert!(r.claim());
    r.finish();
    assert!(!r.claim());
}

/// A cancellation reaching a re-armed multishot receive between two passes
/// takes it, and the pass that follows finds it gone rather than posting on
/// top of the cancellation's completion.
#[test]
fn a_cancellation_between_two_passes_wins_and_the_next_pass_finds_it_gone() {
    let r = ReqState::new();
    assert!(r.claim());
    r.rearm();                       // yielded the worker, still armed
    assert!(r.claim());              // the cancellation gets there first
    r.finish();
    assert!(!r.claim());             // the worker's next pass reports nothing
}

/// The whole multishot receive, driven through the same two pieces the engine
/// uses: the pass decision and the lifetime gate. One completion per delivery,
/// "more follows" on every one of them, and exactly one terminal completion —
/// posted by the single claim that is never released.
#[test]
fn a_multishot_run_posts_more_on_every_completion_but_the_last() {
    // A socket delivering four times, then the group runs dry.
    const ENOBUFS: i64 = -105;
    let results = [64i64, 64, -11 /* would block */, 32, 16, ENOBUFS];
    let r = ReqState::new();
    let mut posted: alloc::vec::Vec<(i64, bool)> = alloc::vec::Vec::new();
    let mut passes = 0u32;
    let mut claimed = 0u32;
    assert!(r.claim());
    claimed += 1;
    for res in results {
        match step(res, passes) {
            Step::More => { posted.push((res, true)); passes += 1; }
            Step::Yield => {
                posted.push((res, true));
                r.rearm();
                assert!(r.claim(), "a yielded request is picked up again");
                claimed += 1;
                passes = 0;
            }
            Step::Wait => {
                // Armed on the description: nothing is posted, and the wake
                // claims it afresh.
                r.set_polled();
                r.rearm();
                assert!(r.claim());
                claimed += 1;
                passes = 0;
            }
            Step::Done(v) => { posted.push((v, false)); r.finish(); break; }
        }
    }
    assert_eq!(posted, [(64, true), (64, true), (32, true), (16, true), (ENOBUFS, false)]);
    // Four deliveries, one terminal completion, and the request was owned the
    // whole time: two claims here are the two the "would block" pass caused.
    assert_eq!(claimed, 2);
    assert!(r.is_done());
    assert!(!r.claim(), "the finished subscription cannot be reported again");
    assert!(r.polled());
}

#[test]
fn a_run_of_uninterrupted_deliveries_goes_back_on_the_queue_rather_than_holding_a_worker() {
    let r = ReqState::new();
    assert!(r.claim());
    let mut passes = 0u32;
    let mut yields = 0u32;
    for _ in 0..(MULTISHOT_MAX_RETRY * 3) {
        match step(8, passes) {
            Step::More => passes += 1,
            Step::Yield => { yields += 1; passes = 0; r.rearm(); assert!(r.claim()); }
            s => panic!("unexpected {s:?}"),
        }
    }
    assert_eq!(yields, 3);
}
