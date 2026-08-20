// The half-open request as its own record, over real segments on the delivery
// path.
//
// What these pin: a request is what an ordinary passive open leaves behind,
// the SYN-ACK it answers with is rebuilt from the one negotiation it recorded
// (so a retransmission cannot drift from the first answer), a segment for a
// request is judged by the request check rather than by a connection state
// machine, and the child the acknowledgement produces carries what the SYN
// negotiated rather than anything re-derived from the acknowledgement.

use super::*;
use super::tcp_syncookies_tests::{child, deliver, drain, head, request, sent, syn_options,
    CLIENT_SEQ, SERVER};
use crate::tcp_hdr::flags;
use crate::tcp_state::TcpState;

/// A listener with room for one request and one accepted connection.
fn fixture(stack: &NetStack, port: u16) -> (NetIfaceId, Arc<crate::loopback::LoopbackDev>,
                                            Arc<TcpListenEntry>)
{
    let (iface, lo) = stack.register_loopback();
    let listener = stack.tcp_listen(SERVER, port, true).expect("listen");
    (iface, lo, listener)
}

#[test]
fn an_ordinary_passive_open_leaves_a_request_and_no_connection() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo, listener) = fixture(&stack, 7_601);
    deliver(&stack, iface, 7_601, 40_001, flags::SYN, CLIENT_SEQ, 0, syn_options());

    assert!(request(&stack, 7_601, 40_001).is_some(),
        "the SYN is answered from a request, not from a connection");
    assert!(child(&stack, 7_601, 40_001).is_none(),
        "no transport control block exists before the handshake ends");
    assert_eq!(listener.syn_backlog_used.load(::core::sync::atomic::Ordering::Acquire), 1);
    let synack = head(&sent(&lo).expect("the SYN was answered"));
    assert_eq!(synack.flags & (flags::SYN | flags::ACK), flags::SYN | flags::ACK);
}

#[test]
fn a_retransmitted_syn_ack_carries_the_same_negotiation_as_the_first() {
    // The first answer and every later one are built from the one record the
    // SYN produced. Anything that re-derived the negotiation instead could
    // answer the retransmission with different options than the original,
    // which the peer reads as this side changing its mind mid-handshake.
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo, _listener) = fixture(&stack, 7_602);
    deliver(&stack, iface, 7_602, 40_002, flags::SYN, CLIENT_SEQ, 0, syn_options());
    let first = sent(&lo).expect("the SYN was answered");
    drain(&lo);

    let req = request(&stack, 7_602, 40_002).expect("a request");
    let now = req.rsk.lock().expires_ns;
    stack.tcp_reqsk_tick_at(now);
    let again = sent(&lo).expect("the timer retransmitted the SYN-ACK");

    let (a, b) = (head(&first), head(&again));
    assert_eq!((a.seq, a.ack, a.flags), (b.seq, b.ack, b.flags),
        "the retransmission answers the same handshake");
    assert_eq!(crate::tcp_hdr::parse_mss_option(&first),
               crate::tcp_hdr::parse_mss_option(&again));
    assert_eq!(crate::tcp_hdr::parse_wscale_option(&first),
               crate::tcp_hdr::parse_wscale_option(&again));
    assert_eq!(crate::tcp_hdr::parse_sack_permitted(&first),
               crate::tcp_hdr::parse_sack_permitted(&again));
}

#[test]
fn a_duplicate_syn_re_solicits_the_answer_without_taking_a_second_slot() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo, listener) = fixture(&stack, 7_603);
    deliver(&stack, iface, 7_603, 40_003, flags::SYN, CLIENT_SEQ, 0, syn_options());
    let first = request(&stack, 7_603, 40_003).expect("a request");
    drain(&lo);

    // The peer never saw the answer, so it repeats its SYN.
    deliver(&stack, iface, 7_603, 40_003, flags::SYN, CLIENT_SEQ, 0, syn_options());
    let again = request(&stack, 7_603, 40_003).expect("the request survives");
    assert!(Arc::ptr_eq(&first, &again), "the same request answers, not a second one");
    assert_eq!(listener.syn_backlog_used.load(::core::sync::atomic::Ordering::Acquire), 1,
        "a repeated SYN must not consume a second backlog slot");
    let synack = head(&sent(&lo).expect("the repeated SYN is answered again"));
    assert_eq!(synack.flags & (flags::SYN | flags::ACK), flags::SYN | flags::ACK);
}

#[test]
fn repeated_syn_answers_are_limited_and_a_sent_answer_pushes_the_request_timer() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo, _listener) = fixture(&stack, 7_611);
    deliver(&stack, iface, 7_611, 40_011, flags::SYN, CLIENT_SEQ, 0, syn_options());
    drain(&lo);
    let req = request(&stack, 7_611, 40_011).expect("a request");
    req.rsk.lock().expires_ns = 1;
    let skipped = crate::mib::get_tcp_ext(0, crate::mib::TcpExt::TcpAckSkippedSynRecv);

    deliver(&stack, iface, 7_611, 40_011, flags::SYN, CLIENT_SEQ, 0, syn_options());
    assert!(sent(&lo).is_some(), "the first repeated SYN is answered");
    assert_eq!(req.rsk.lock().expires_ns, crate::tcp_conn::RTO_MAX_DEFAULT_NS
        .min(crate::tcp_conn::reqsk::TIMEOUT_INIT_NS));
    drain(&lo);

    deliver(&stack, iface, 7_611, 40_011, flags::SYN, CLIENT_SEQ, 0, syn_options());
    assert!(sent(&lo).is_none(), "a replay inside the interval is silent");
    assert_eq!(crate::mib::get_tcp_ext(0, crate::mib::TcpExt::TcpAckSkippedSynRecv), skipped + 1);
}

#[test]
fn a_reset_ends_a_half_open_request_and_returns_its_slot() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo, listener) = fixture(&stack, 7_604);
    deliver(&stack, iface, 7_604, 40_004, flags::SYN, CLIENT_SEQ, 0, syn_options());
    let synack = head(&sent(&lo).expect("the SYN was answered"));
    drain(&lo);

    deliver(&stack, iface, 7_604, 40_004, flags::RST, CLIENT_SEQ.wrapping_add(1),
        synack.seq.wrapping_add(1), Default::default());

    assert!(request(&stack, 7_604, 40_004).is_none(), "the request is gone");
    assert_eq!(listener.syn_backlog_used.load(::core::sync::atomic::Ordering::Acquire), 0,
        "and its backlog slot with it");
    assert!(sent(&lo).is_none(), "a reset is answered with silence");
}

#[test]
fn the_child_a_request_promotes_carries_what_the_syn_negotiated() {
    // The negotiation is recorded once, at the SYN, and the connection is
    // opened from that record. Deriving it from the acknowledgement instead
    // would lose every option the acknowledgement does not repeat — which is
    // all of them but the timestamp.
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo, listener) = fixture(&stack, 7_605);
    deliver(&stack, iface, 7_605, 40_005, flags::SYN, CLIENT_SEQ, 0, syn_options());
    let synack = head(&sent(&lo).expect("the SYN was answered"));
    drain(&lo);

    // A bare acknowledgement, carrying none of the SYN's options.
    deliver(&stack, iface, 7_605, 40_005, flags::ACK, CLIENT_SEQ.wrapping_add(1),
        synack.seq.wrapping_add(1), Default::default());

    let opened = child(&stack, 7_605, 40_005).expect("the handshake completed");
    let conn = opened.conn.lock();
    assert_eq!(conn.state, TcpState::Established);
    assert_eq!(conn.peer_mss, 1460, "the maximum segment size the SYN announced");
    assert!(conn.wscale_ok && conn.rcv_wscale == 7, "the scale the SYN offered");
    assert!(conn.sack_ok, "the selective acknowledgement the SYN permitted");
    assert!(conn.ts_enabled, "the timestamps the SYN offered");
    assert_eq!(conn.rcv_nxt, CLIENT_SEQ.wrapping_add(1));
    assert_eq!(conn.snd_una, synack.seq.wrapping_add(1));
    drop(conn);
    assert!(Arc::ptr_eq(&stack.tcp_accept(&listener).expect("acceptable"), &opened));
    assert_eq!(listener.syn_backlog_used.load(::core::sync::atomic::Ordering::Acquire), 0,
        "the request slot is handed over with the connection");
}

#[test]
fn a_half_open_request_is_reported_by_the_diagnostic_table() {
    // A request lives in the same connection table as a full socket, so the
    // socket dump must show it — in SYN-RECV, which is what it is.
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _lo, _listener) = fixture(&stack, 7_606);
    deliver(&stack, iface, 7_606, 40_006, flags::SYN, CLIENT_SEQ, 0, syn_options());

    let dumped = stack.inet_diag_snapshot(crate::stack_diag::IPPROTO_TCP);
    let row = dumped.iter().find(|row| row.remote_port == 40_006 && row.local_port == 7_606)
        .expect("the half-open request is missing from the socket dump");
    assert_eq!(row.state, crate::stack_diag::tcp_diag_state(TcpState::SynRecv),
        "a request is reported in the state it is in");
}

#[test]
fn an_acknowledgement_naming_a_sequence_never_sent_cannot_complete_the_handshake() {
    // The half-open is completed by the acknowledgement of THIS side's
    // SYN-ACK and by nothing else. An off-path segment that guessed the
    // 4-tuple and the receive window but not the sequence this side chose
    // must not turn a request into a connection (B2050).
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo, listener) = fixture(&stack, 7_607);
    deliver(&stack, iface, 7_607, 40_007, flags::SYN, CLIENT_SEQ, 0, syn_options());
    let synack = head(&sent(&lo).expect("the SYN was answered"));
    drain(&lo);

    let forged = synack.seq.wrapping_add(4_096);
    deliver(&stack, iface, 7_607, 40_007, flags::ACK, CLIENT_SEQ.wrapping_add(1),
        forged, Default::default());

    assert!(child(&stack, 7_607, 40_007).is_none(),
        "a guessed acknowledgement completed a handshake it never acknowledged");
    assert!(request(&stack, 7_607, 40_007).is_some(),
        "the request the segment failed against is left as it was");
    assert_eq!(listener.syn_backlog_used.load(::core::sync::atomic::Ordering::Acquire), 1);
    let answer = head(&sent(&lo).expect("an unacceptable acknowledgement is answered"));
    assert_eq!(answer.flags & (flags::RST | flags::ACK), flags::RST,
        "the answer is a reset, not silence and not an acknowledgement");
    assert_eq!(answer.seq, forged,
        "the reset is built at the sequence the segment claimed to acknowledge");
}

#[test]
fn the_neighbours_of_the_completing_acknowledgement_are_refused_too() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo, _listener) = fixture(&stack, 7_608);
    deliver(&stack, iface, 7_608, 40_008, flags::SYN, CLIENT_SEQ, 0, syn_options());
    let synack = head(&sent(&lo).expect("the SYN was answered"));
    drain(&lo);

    for wrong in [synack.seq, synack.seq.wrapping_add(2)] {
        deliver(&stack, iface, 7_608, 40_008, flags::ACK, CLIENT_SEQ.wrapping_add(1),
            wrong, Default::default());
        assert!(child(&stack, 7_608, 40_008).is_none(),
            "an off-by-one acknowledgement completed the handshake");
        drain(&lo);
    }
    // The right one still works, so the check refuses the wrong answer rather
    // than every answer.
    deliver(&stack, iface, 7_608, 40_008, flags::ACK, CLIENT_SEQ.wrapping_add(1),
        synack.seq.wrapping_add(1), Default::default());
    assert!(child(&stack, 7_608, 40_008).is_some(), "the honest acknowledgement completes");
}

#[test]
fn a_reset_that_acknowledges_something_never_sent_leaves_the_request_alone() {
    // The acknowledgement number is judged before the reset bit, so a blind
    // reset cannot tear down a half-open without also naming the sequence
    // this side sent.
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo, listener) = fixture(&stack, 7_609);
    deliver(&stack, iface, 7_609, 40_009, flags::SYN, CLIENT_SEQ, 0, syn_options());
    let synack = head(&sent(&lo).expect("the SYN was answered"));
    drain(&lo);

    deliver(&stack, iface, 7_609, 40_009, flags::RST | flags::ACK,
        CLIENT_SEQ.wrapping_add(1), synack.seq.wrapping_add(7), Default::default());

    assert!(request(&stack, 7_609, 40_009).is_some(),
        "a blind reset ended a half-open it could not acknowledge");
    assert_eq!(listener.syn_backlog_used.load(::core::sync::atomic::Ordering::Acquire), 1);
}

#[test]
fn a_segment_outside_the_request_window_is_answered_with_an_acknowledgement() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo, _listener) = fixture(&stack, 7_610);
    deliver(&stack, iface, 7_610, 40_010, flags::SYN, CLIENT_SEQ, 0, syn_options());
    let synack = head(&sent(&lo).expect("the SYN was answered"));
    drain(&lo);

    // The acknowledgement is the right one; only the sequence is nowhere near
    // the window this side announced.
    deliver(&stack, iface, 7_610, 40_010, flags::ACK, CLIENT_SEQ.wrapping_add(1 << 20),
        synack.seq.wrapping_add(1), Default::default());

    assert!(child(&stack, 7_610, 40_010).is_none(), "an out-of-window segment completed");
    let answer = head(&sent(&lo).expect("an out-of-window segment is answered"));
    assert_eq!(answer.flags & (flags::RST | flags::ACK), flags::ACK,
        "the peer is told where the window is, not reset");
    assert_eq!(answer.ack, CLIENT_SEQ.wrapping_add(1));
    drain(&lo);
    let skipped = crate::mib::get_tcp_ext(0, crate::mib::TcpExt::TcpAckSkippedSynRecv);
    deliver(&stack, iface, 7_610, 40_010, flags::ACK, CLIENT_SEQ.wrapping_add(1 << 20),
        synack.seq.wrapping_add(1), Default::default());
    assert!(sent(&lo).is_none(), "the same out-of-window ACK is limited per request");
    assert_eq!(crate::mib::get_tcp_ext(0, crate::mib::TcpExt::TcpAckSkippedSynRecv), skipped + 1);
}
