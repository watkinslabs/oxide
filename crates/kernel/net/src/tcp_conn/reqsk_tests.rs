// The request-sock rules, driven directly: what a bare acknowledgement does to
// a deferring listener's half-open request, how the SYN-ACK timer counts, and
// when the request is abandoned. These are the contracts the delivery path and
// the retransmit tick are built on; the end-to-end behaviour they produce is
// asserted over real segments in `stack/tcp_defer_accept_tests.rs`.

use super::*;
use crate::sock_opts::sol_tcp::{NS_PER_S, TCP_RTO_MAX_SEC, TCP_TIMEOUT_INIT_S, secs_to_retrans};

const RTO_MAX_NS: u64 = TCP_RTO_MAX_SEC as u64 * NS_PER_S;

#[test]
fn a_firing_is_the_unit_the_option_converts_its_seconds_against() {
    // The deferral counts firings, and `TCP_DEFER_ACCEPT` converts seconds to
    // a count against the initial timeout: the two must be the same timeout or
    // a listener would wait a different span than it asked for.
    assert_eq!(TIMEOUT_INIT_NS, TCP_TIMEOUT_INIT_S as u64 * NS_PER_S);
}

fn req(num_timeout: u8, acked: bool) -> ReqSock {
    ReqSock { num_timeout, acked, expires_ns: 0 }
}

/// The count a listener asking for `seconds` of deferral stores.
fn defer_count(seconds: i32) -> u8 {
    secs_to_retrans(seconds, TCP_TIMEOUT_INIT_S, TCP_RTO_MAX_SEC)
}

#[test]
fn only_an_acknowledgement_with_nothing_in_it_is_bare() {
    assert!(bare_ack(flags::ACK, 0));
    assert!(bare_ack(flags::ACK | flags::PSH, 0), "a push bit advances no sequence");
    assert!(!bare_ack(flags::ACK, 1), "one byte of request is what the listener wanted");
    assert!(!bare_ack(flags::ACK | flags::FIN, 0), "a close is not nothing");
    assert!(!bare_ack(flags::ACK | flags::SYN, 0), "a retransmitted SYN is not the third ACK");
    assert!(!bare_ack(flags::ACK | flags::RST, 0));
    assert!(!bare_ack(flags::PSH, 4), "a segment that acknowledges nothing is not an ACK");
}

#[test]
fn a_listener_that_did_not_defer_completes_on_the_bare_acknowledgement() {
    assert!(!req(0, false).defers_bare_ack(0, true),
        "with no deferral the third ACK creates the connection");
}

#[test]
fn a_deferring_listener_drops_the_bare_acknowledgement() {
    let count = defer_count(30);
    assert!(count > 0);
    assert!(req(0, false).defers_bare_ack(count, true));
    // Data is exactly what the deferral was waiting for, so it is never
    // dropped however early it arrives.
    assert!(!req(0, false).defers_bare_ack(count, false));
}

#[test]
fn the_deferring_period_is_counted_in_timer_firings() {
    let count = defer_count(30);
    for fired in 0..count {
        assert!(req(fired, true).defers_bare_ack(count, true),
            "still inside the period the listener asked for");
    }
    assert!(!req(count, true).defers_bare_ack(count, true),
        "the period has run out: the next acknowledgement is accepted");
    assert!(!req(count + 1, true).defers_bare_ack(count, true));
}

#[test]
fn an_undeferred_request_retransmits_until_the_ceiling() {
    for fired in 0..SYNACK_RETRIES_DEFAULT {
        let r = req(fired, false).recalc(SYNACK_RETRIES_DEFAULT, 0);
        assert!(!r.expire);
        assert!(r.resend, "every firing of an unanswered request retransmits");
    }
    assert!(req(SYNACK_RETRIES_DEFAULT, false).recalc(SYNACK_RETRIES_DEFAULT, 0).expire);
}

#[test]
fn a_deferred_request_stops_retransmitting_once_the_peer_acknowledged() {
    let count = defer_count(30);
    assert!(count > 2, "the window under test must span several firings");
    for fired in 0..count - 1 {
        let r = req(fired, true).recalc(SYNACK_RETRIES_DEFAULT, count);
        assert!(!r.resend, "the request is waiting for data, not for an acknowledgement");
    }
    // The last firing of the period solicits the acknowledgement that will
    // complete the connection, because by then the deferral no longer drops it.
    assert!(req(count - 1, true).recalc(SYNACK_RETRIES_DEFAULT, count).resend);
    assert!(req(count, true).recalc(SYNACK_RETRIES_DEFAULT, count).resend);
}

#[test]
fn a_deferred_request_the_peer_never_answered_still_retransmits() {
    let count = defer_count(30);
    for fired in 0..count {
        assert!(req(fired, false).recalc(SYNACK_RETRIES_DEFAULT, count).resend,
            "an unacknowledged request is an ordinary half-open one");
    }
}

#[test]
fn an_acknowledged_deferred_request_outlives_the_retransmit_ceiling() {
    let count = defer_count(120);
    assert!(count > SYNACK_RETRIES_DEFAULT, "the deferral must outlast the ceiling");
    let past_ceiling = req(SYNACK_RETRIES_DEFAULT, true);
    assert!(!past_ceiling.recalc(SYNACK_RETRIES_DEFAULT, count).expire,
        "the client is connected and may still send; the deferral has not run out");
    // The same request without the acknowledgement is abandoned on time.
    assert!(req(SYNACK_RETRIES_DEFAULT, false).recalc(SYNACK_RETRIES_DEFAULT, count).expire);
    // And once the period ends the request is abandoned like any other.
    assert!(req(count, true).recalc(SYNACK_RETRIES_DEFAULT, count).expire);
}

#[test]
fn a_short_deferral_expires_at_the_retransmit_ceiling_not_before() {
    // A deferral shorter than the ceiling cannot shorten the request's life:
    // the ceiling is still the thing that abandons it.
    let count = defer_count(1);
    assert!(count < SYNACK_RETRIES_DEFAULT);
    assert!(!req(count, true).recalc(SYNACK_RETRIES_DEFAULT, count).expire);
    assert!(req(SYNACK_RETRIES_DEFAULT, true).recalc(SYNACK_RETRIES_DEFAULT, count).expire);
}

#[test]
fn the_timer_doubles_per_firing_and_stops_at_the_ceiling() {
    assert_eq!(req(0, false).timeout_ns(RTO_MAX_NS), TIMEOUT_INIT_NS);
    assert_eq!(req(1, false).timeout_ns(RTO_MAX_NS), 2 * TIMEOUT_INIT_NS);
    assert_eq!(req(4, false).timeout_ns(RTO_MAX_NS), 16 * TIMEOUT_INIT_NS);
    assert_eq!(req(200, false).timeout_ns(RTO_MAX_NS), RTO_MAX_NS,
        "a shift wide enough to wrap must saturate at the ceiling, not fold back");
}

#[test]
fn a_firing_counts_itself_and_rearms_on_the_doubled_timer() {
    let mut r = req(0, false);
    r.arm(1_000, RTO_MAX_NS);
    assert!(!r.due(1_000 + TIMEOUT_INIT_NS - 1));
    assert!(r.due(1_000 + TIMEOUT_INIT_NS));
    r.on_timeout(1_000 + TIMEOUT_INIT_NS, RTO_MAX_NS);
    assert_eq!(r.num_timeout, 1);
    assert_eq!(r.expires_ns, 1_000 + 3 * TIMEOUT_INIT_NS,
        "the next firing waits twice as long as the first");
}

#[test]
fn an_unarmed_request_is_never_due() {
    // Every connection that is not a request carries the default, and the
    // retransmit tick must not mistake it for one whose timer has run out.
    let r = ReqSock::default();
    assert!(!r.armed());
    assert!(!r.due(u64::MAX));
}

#[test]
fn a_timer_armed_at_the_clock_origin_is_still_armed() {
    let mut r = req(0, false);
    r.arm(0, 0);
    assert!(r.armed(), "zero is the unarmed sentinel and must not be produced");
}

#[test]
fn a_retransmit_that_could_not_be_sent_abandons_an_unacknowledged_request() {
    let resend = Recalc { expire: false, resend: true };
    assert!(reschedules(resend, true, false), "the retransmit went out");
    assert!(!reschedules(resend, false, false), "nothing could be sent and nothing was heard");
    assert!(reschedules(resend, false, true),
        "an acknowledged request has nothing left to retransmit for");
    assert!(reschedules(Recalc { expire: false, resend: false }, false, false));
    assert!(!reschedules(Recalc { expire: true, resend: true }, true, true),
        "an expired request is dropped whatever else happened");
}

#[test]
fn a_quiet_queue_leaves_the_retransmit_ceiling_alone() {
    assert_eq!(synack_retries_under_pressure(SYNACK_RETRIES_DEFAULT, 3, 128, 3),
        SYNACK_RETRIES_DEFAULT);
    // A tiny backlog does not put a listener under pressure on its own: the
    // floor on queue length has to be passed too.
    assert_eq!(synack_retries_under_pressure(SYNACK_RETRIES_DEFAULT, 4, 1, 4),
        SYNACK_RETRIES_DEFAULT);
}

#[test]
fn a_queue_full_of_old_requests_shortens_the_retransmit_ceiling() {
    // Half the backlog is taken and none of it is young: the ceiling walks
    // down to its floor rather than holding requests nobody will complete.
    assert_eq!(synack_retries_under_pressure(SYNACK_RETRIES_DEFAULT, 64, 64, 0),
        SYNACK_RETRIES_MIN);
    // The same queue length, all of it young, is ordinary load and keeps the
    // full ceiling.
    assert_eq!(synack_retries_under_pressure(SYNACK_RETRIES_DEFAULT, 64, 64, 64),
        SYNACK_RETRIES_DEFAULT);
    // Partly young: the ceiling drops by the number of doublings it takes for
    // the young half to cover the queue.
    assert_eq!(synack_retries_under_pressure(SYNACK_RETRIES_DEFAULT, 64, 64, 32),
        SYNACK_RETRIES_DEFAULT - 1);
    assert_eq!(synack_retries_under_pressure(SYNACK_RETRIES_DEFAULT, 64, 64, 16),
        SYNACK_RETRIES_DEFAULT - 2);
    assert_eq!(synack_retries_under_pressure(SYNACK_RETRIES_DEFAULT, 64, 64, 8),
        SYNACK_RETRIES_MIN);
}

#[test]
fn the_pressure_rule_never_goes_below_its_floor() {
    assert_eq!(synack_retries_under_pressure(SYNACK_RETRIES_MIN, 1024, 8, 0), SYNACK_RETRIES_MIN);
    assert_eq!(synack_retries_under_pressure(1, 1024, 8, 0), 1,
        "a ceiling already under the floor is left where the caller set it");
}
