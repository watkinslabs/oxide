// The listen backlog's two queues, their shared bound, and both overflows.

use super::*;

/// The bound is inclusive, so a backlog of `n` holds `n + 1`. This is the rung
/// that makes `listen(fd, 0)` accept one connection; a `>=` test here refuses
/// every connection to such a listener.
#[test]
fn a_zero_backlog_still_admits_one_connection() {
    assert!(!accept_queue_is_full(0, 0), "a zero backlog holds one child");
    assert!(accept_queue_is_full(1, 0), "and no more than one");
    assert!(!syn_queue_is_full(0, 0), "the SYN queue is bounded the same way");
    assert!(syn_queue_is_full(1, 0));
}

#[test]
fn both_queues_hold_one_more_than_the_backlog_they_were_given() {
    for backlog in [1usize, 2, 5, 128, 4096] {
        assert!(!accept_queue_is_full(backlog, backlog),
            "backlog {backlog} holds its own number and one more");
        assert!(accept_queue_is_full(backlog + 1, backlog));
        assert!(!syn_queue_is_full(backlog, backlog));
        assert!(syn_queue_is_full(backlog + 1, backlog));
    }
}

/// The SYN queue is bounded by the listen backlog, never by
/// `tcp_max_syn_backlog`. A large `tcp_max_syn_backlog` must not let a small
/// listener hold more half-open requests than it asked for.
#[test]
fn the_syn_queue_is_bounded_by_the_listen_backlog_not_max_syn_backlog() {
    // A listener with backlog 2 is full at 3 half-open requests regardless of
    // how large the namespace's `tcp_max_syn_backlog` is.
    assert!(syn_queue_is_full(3, 2));
    // And the reserve rule, which is the only thing `tcp_max_syn_backlog`
    // still bounds, is a SEPARATE question with its own answer.
    assert!(admit_unproven_request(3, 4096, false, false),
        "a queue far below the reserve bound is admitted");
}

#[test]
fn cookies_switch_the_unproven_peer_reserve_off_entirely() {
    // Deep into the last quarter, and refused with cookies off ...
    assert!(!admit_unproven_request(100, 128, false, false));
    // ... but a namespace with cookies has a stateless answer and keeps no
    // reserve, so the same request is admitted.
    assert!(admit_unproven_request(100, 128, true, false));
}

#[test]
fn a_proven_peer_reaches_the_reserved_last_quarter() {
    assert!(!admit_unproven_request(100, 128, false, false), "unproven is held out");
    assert!(admit_unproven_request(100, 128, false, true), "proven peer gets in");
}

#[test]
fn the_reserve_is_exactly_the_last_quarter_of_max_syn_backlog() {
    let max = 128i64;
    // Room remaining >= max/4 (32) is admitted: qlen 96 leaves exactly 32.
    assert!(admit_unproven_request(96, max, false, false), "exactly a quarter remains");
    assert!(!admit_unproven_request(97, max, false, false), "one below a quarter is held");
}

/// A queue longer than the bound leaves NEGATIVE room. Computing that
/// unsigned wraps to an enormous number and admits every request precisely
/// when the listener is most overloaded.
#[test]
fn a_queue_past_the_bound_does_not_wrap_into_admitting_everything() {
    assert!(!admit_unproven_request(5_000, 128, false, false),
        "a queue far past the bound is not admitted by underflow");
}

#[test]
fn an_unset_max_syn_backlog_keeps_no_reserve() {
    assert!(admit_unproven_request(9_999, 0, false, false));
    assert!(admit_unproven_request(9_999, -1, false, false));
}

/// The default holds the request rather than destroying a connection the peer
/// believes established.
#[test]
fn accept_overflow_defaults_to_holding_the_request() {
    assert_eq!(accept_overflow(DEFAULT_ABORT_ON_OVERFLOW), AcceptOverflow::RetainRequest);
    assert_eq!(accept_overflow(0), AcceptOverflow::RetainRequest);
}

#[test]
fn abort_on_overflow_resets_instead() {
    assert_eq!(accept_overflow(1), AcceptOverflow::Reset);
    // Any non-zero setting selects the reset, not just one.
    assert_eq!(accept_overflow(2), AcceptOverflow::Reset);
}
