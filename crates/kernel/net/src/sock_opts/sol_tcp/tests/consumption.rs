// What each accepted option CHANGES. Every test here drives the option
// through the store, into a live connection, and asserts on transport
// behaviour — not on a value read back from where it was written.

use core::sync::atomic::Ordering;
use crate::addr::{IpAddr, Ipv4Addr};
use crate::sock::SockOpts;
use crate::sock_opts::sol_tcp::*;
use crate::sock_opts::sol_tcp::apply;
use crate::sock_opts::sol_tcp::set::{self, Action, Arg, SetEnv};
use crate::sock_opts::sol_tcp::repair::{RepairEffect, RepairOpt, TCPOPT_MSS, TCPOPT_SACK_PERM,
    TCPOPT_TIMESTAMP, TCPOPT_WINDOW};
use crate::tcp_conn::{Endpoint, TcpConn, TcpCongestionControl, UnackedSegment};
use crate::tcp_state::TcpState;

fn endpoint(port: u16) -> Endpoint {
    Endpoint { ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port }
}

fn conn() -> TcpConn {
    let mut c = TcpConn::new_client(endpoint(1000), endpoint(2000), 42);
    c.state = TcpState::Established;
    c
}

/// Drive one accepted write all the way into a connection, the way the shim
/// does, and hand back what the transport must do besides.
fn write(opts: &SockOpts, c: &mut TcpConn, optname: u64, val: i32) -> apply::Effects {
    let action = set::admit(optname, Arg::Int(val), SetEnv {
        net_admin: true, state: c.state, repair: opts.tcp.repair.load(Ordering::Acquire),
        repair_queue: opts.tcp.repair_queue.load(Ordering::Acquire), ..SetEnv::default()
    }).expect("accepted");
    let effects = apply::store(opts, &action);
    apply::repair_to_conn(c, &action);
    if effects.reload { apply::to_conn(opts, c); }
    effects
}

fn queued(c: &TcpConn) -> usize {
    c.send_buf.len() + c.retx_q.iter().map(|s| s.payload.len()).sum::<usize>()
}

#[test]
fn a_named_segment_size_shrinks_the_segments_the_sender_emits() {
    let (opts, mut c) = (SockOpts::default(), conn());
    c.snd_wnd = 100_000;
    c.cwnd = 100_000;
    c.send(&alloc::vec![7u8; 4000]);
    write(&opts, &mut c, TCP_MAXSEG, 500);
    assert_eq!(c.own_mss, 500);
    let segments = c.output(1500, true, false);
    assert!(segments.len() >= 8,
        "a 500-byte segment size must cut 4000 bytes into at least eight segments");
}

#[test]
fn the_syn_retransmit_count_reaches_the_connection_that_enforces_it() {
    let (opts, mut c) = (SockOpts::default(), conn());
    assert_eq!(c.syn_retries, crate::tcp_conn::SYN_RETRIES_DEFAULT);
    write(&opts, &mut c, TCP_SYNCNT, 2);
    assert_eq!(c.syn_retries, 2);
}

#[test]
fn the_orphan_lifetime_decides_when_the_half_closed_connection_is_reaped() {
    let (opts, mut c) = (SockOpts::default(), conn());
    write(&opts, &mut c, TCP_LINGER2, 5);
    assert!(!c.linger2_expired(0, 4 * NS_PER_S));
    assert!(c.linger2_expired(0, 5 * NS_PER_S));
    // The negative sentinel means the state is left the moment it is entered.
    write(&opts, &mut c, TCP_LINGER2, -1);
    assert!(c.linger2_expired(0, 0));
}

#[test]
fn the_window_clamp_bounds_what_the_receiver_advertises() {
    let (opts, mut c) = (SockOpts::default(), conn());
    c.rcv_buf_cap = 65_536;
    c.snd_wscale = 0;
    let unclamped = c.current_rcv_window();
    write(&opts, &mut c, TCP_WINDOW_CLAMP, 4096);
    let clamped = c.current_rcv_window();
    assert_eq!(clamped, 4096);
    assert!(clamped < unclamped, "the clamp must reduce the advertised window");
    // Clearing it restores the unclamped advertisement.
    c.state = TcpState::Closed;
    write(&opts, &mut c, TCP_WINDOW_CLAMP, 0);
    assert_eq!(c.current_rcv_window(), unclamped);
}

#[test]
fn clearing_quick_acknowledgements_makes_the_receiver_withhold_the_ack() {
    let (opts, mut c) = (SockOpts::default(), conn());
    // A fresh connection acknowledges at once.
    c.rcv_nxt = 100;
    c.rcv_wup = 100;
    assert!(c.ack_now());
    write(&opts, &mut c, TCP_QUICKACK, 0);
    assert!(!c.quickack);
    c.rcv_nxt = 200;
    assert!(!c.ack_now(), "a sub-segment arrival is held for the reply to ride");
    // Past a full segment unacknowledged, the ACK goes out regardless: the
    // peer's window would otherwise stall.
    c.rcv_nxt = 100 + crate::tcp_cc::cc_mss(&c) + 1;
    assert!(c.ack_now());
}

#[test]
fn a_held_acknowledgement_goes_out_when_the_delayed_ack_window_expires() {
    let mut c = conn();
    c.quickack = false;
    c.delack_max_ns = 200 * NS_PER_TICK;
    c.ack_pending = true;
    // The first pass stamps the deadline; nothing goes out yet.
    assert!(c.delayed_ack_due(1_000).is_none());
    assert_eq!(c.ack_deadline_ns, 1_000 + 200 * NS_PER_TICK);
    assert!(c.delayed_ack_due(1_000).is_none());
    let segment = c.delayed_ack_due(1_000 + 200 * NS_PER_TICK);
    assert!(segment.is_some(), "the held acknowledgement must leave at the deadline");
    assert!(!c.ack_pending);
    assert_eq!(c.rcv_wup, c.rcv_nxt);
}

#[test]
fn a_shorter_delayed_ack_window_releases_the_acknowledgement_sooner() {
    let (opts, mut c) = (SockOpts::default(), conn());
    write(&opts, &mut c, TCP_DELACK_MAX_US, 20_000);
    assert_eq!(c.delack_max_ns, 20 * NS_PER_TICK);
    c.ack_pending = true;
    assert!(c.delayed_ack_due(0).is_none());
    assert!(c.delayed_ack_due(20 * NS_PER_TICK).is_some());
}

#[test]
fn naming_a_congestion_control_changes_how_the_window_grows() {
    let opts = SockOpts::default();
    let mut c = conn();
    let action = set::admit(TCP_CONGESTION, Arg::Name(b"reno".to_vec()),
        SetEnv { current_algo: CongestionAlgo::Cubic, ..SetEnv::default() }).unwrap();
    assert!(apply::store(&opts, &action).reload);
    apply::to_conn(&opts, &mut c);
    assert_eq!(c.congestion, TcpCongestionControl::Reno);

    // The two algorithms are not the same sender: past slow start they open
    // the window differently for the same acknowledgement stream.
    let mut reno = conn();
    reno.congestion = TcpCongestionControl::Reno;
    reno.ssthresh = 0;
    reno.cwnd = 40_000;
    let mut cubic = conn();
    cubic.congestion = TcpCongestionControl::Cubic;
    cubic.ssthresh = 0;
    cubic.cwnd = 40_000;
    cubic.cubic_w_max = 80_000;
    for _ in 0..20 {
        reno.cc_on_ack(1460, 1460);
        cubic.cc_on_ack(1460, 1460);
    }
    assert_ne!(reno.cwnd, cubic.cwnd);
}

#[test]
fn a_route_pinned_algorithm_is_not_overwritten_by_the_option_block() {
    let opts = SockOpts::default();
    opts.tcp.congestion.store(CongestionAlgo::Reno.as_u8(), Ordering::Release);
    opts.tcp.congestion_setsockopt.store(true, Ordering::Release);
    let mut c = conn();
    c.congestion = TcpCongestionControl::Cubic;
    c.cc_locked = true;
    apply::to_conn(&opts, &mut c);
    assert_eq!(c.congestion, TcpCongestionControl::Cubic);
}

#[test]
fn a_socket_that_never_named_an_algorithm_keeps_the_one_it_has() {
    let opts = SockOpts::default();
    let mut c = conn();
    c.congestion = TcpCongestionControl::Reno;
    apply::to_conn(&opts, &mut c);
    assert_eq!(c.congestion, TcpCongestionControl::Reno);
}

#[test]
fn linear_timeouts_stop_the_retransmit_timer_from_doubling_on_a_thin_stream() {
    let (opts, mut c) = (SockOpts::default(), conn());
    c.rto_ns = 1_000_000_000;
    c.retx_q.push_back(UnackedSegment { seq: 42, flags: 0, payload: alloc::vec![1u8; 10],
        last_sent_ns: 0, delivered_at_send: 0, delivered_mstamp_ns: 0, first_sent_ns: 0,
        delivery_app_limited: false, retries: 0, sacked: false });
    let doubled = {
        let mut plain = conn();
        plain.rto_ns = 1_000_000_000;
        plain.retx_q.push_back(UnackedSegment { seq: 42, flags: 0,
            payload: alloc::vec![1u8; 10], last_sent_ns: 0, delivered_at_send: 0, delivered_mstamp_ns: 0,
            first_sent_ns: 0, delivery_app_limited: false, retries: 0, sacked: false });
        plain.retransmit_due(2_000_000_000);
        plain.rto_ns
    };
    assert_eq!(doubled, 2_000_000_000, "the default sender backs off exponentially");

    write(&opts, &mut c, TCP_THIN_LINEAR_TIMEOUTS, 1);
    assert!(c.thin_lto);
    c.retransmit_due(2_000_000_000);
    assert_eq!(c.rto_ns, 1_000_000_000, "a thin stream retransmits on a flat timer");
}

#[test]
fn a_stream_thick_enough_for_duplicate_ack_recovery_still_backs_off() {
    let (opts, mut c) = (SockOpts::default(), conn());
    c.rto_ns = 1_000_000_000;
    for i in 0..6u32 {
        c.retx_q.push_back(UnackedSegment { seq: 42 + i, flags: 0,
            payload: alloc::vec![1u8; 10], last_sent_ns: 0, delivered_at_send: 0, delivered_mstamp_ns: 0,
            first_sent_ns: 0, delivery_app_limited: false, retries: 0, sacked: false });
    }
    write(&opts, &mut c, TCP_THIN_LINEAR_TIMEOUTS, 1);
    assert!(!c.is_thin_stream());
    c.retransmit_due(2_000_000_000);
    assert_eq!(c.rto_ns, 2_000_000_000);
}

#[test]
fn the_user_timeout_gives_up_on_the_connection_independently_of_the_retry_count() {
    let (opts, mut c) = (SockOpts::default(), conn());
    write(&opts, &mut c, TCP_USER_TIMEOUT, 3_000);
    assert_eq!(c.user_timeout_ns, 3_000 * NS_PER_MS);
    assert!(!c.user_timeout_expired(10 * NS_PER_S), "with nothing unacknowledged");
    c.retx_q.push_back(UnackedSegment { seq: 42, flags: 0, payload: alloc::vec![1u8; 10],
        last_sent_ns: 0, delivered_at_send: 0, delivered_mstamp_ns: 0, first_sent_ns: 0,
        delivery_app_limited: false, retries: 0, sacked: false });
    // The mark is taken the first time the queue is seen unacknowledged.
    c.retransmit_due(1 * NS_PER_S);
    assert_eq!(c.first_unacked_ns, 1 * NS_PER_S);
    assert!(!c.user_timeout_expired(3 * NS_PER_S));
    assert!(c.user_timeout_expired(4 * NS_PER_S));
    // A socket that named no timeout never expires this way.
    write(&opts, &mut c, TCP_USER_TIMEOUT, 0);
    assert!(!c.user_timeout_expired(1_000 * NS_PER_S));
}

#[test]
fn repair_stands_the_retransmit_timer_down() {
    let (opts, mut c) = (SockOpts::default(), conn());
    c.retx_q.push_back(UnackedSegment { seq: 42, flags: 0, payload: alloc::vec![1u8; 10],
        last_sent_ns: 0, delivered_at_send: 0, delivered_mstamp_ns: 0, first_sent_ns: 0,
        delivery_app_limited: false, retries: 0, sacked: false });
    assert!(!c.retransmit_due(10 * NS_PER_S).is_empty());
    write(&opts, &mut c, TCP_REPAIR, TCP_REPAIR_ON);
    assert!(c.repair);
    assert!(c.retransmit_due(20 * NS_PER_S).is_empty(),
        "nothing may be re-sent from under the process restoring the sequence state");
}

#[test]
fn the_unsent_watermark_withholds_write_readiness_and_wakes_writers_when_moved() {
    let (opts, mut c) = (SockOpts::default(), conn());
    let effects = write(&opts, &mut c, TCP_NOTSENT_LOWAT, 1024);
    assert!(effects.write_space, "moving the watermark must re-check parked writers");
    assert_eq!(c.notsent_lowat, 1024);
    c.send(&alloc::vec![0u8; 2048]);
    assert!(crate::stack::tcp_writable::tcp_is_writeable(queued(&c), 65_536),
        "the relative watermark alone would call this writable");
    assert!(!crate::stack::tcp_writable::tcp_writeable_with_lowat(
        queued(&c), 65_536, c.send_buf.len(), c.notsent_lowat));
}

#[test]
fn an_added_transmit_delay_raises_the_round_trip_estimate_and_the_timer() {
    let (opts, mut c) = (SockOpts::default(), conn());
    let mut plain = conn();
    plain.update_rtt(500_000_000);
    c.update_rtt(500_000_000);
    write(&opts, &mut c, TCP_TX_DELAY, 20_000);
    assert_eq!(c.tx_delay_ns, 20_000_000);
    assert_eq!(c.srtt_ns, plain.srtt_ns + 20_000_000, "the declared delay lengthens the path");
    assert_eq!(c.rto_ns, plain.rto_ns + 20_000_000,
        "and the retransmit timer must account for it");
    // Re-naming the same delay moves nothing: the adjustment tracks the
    // change, so it cannot compound over the life of the connection.
    let settled = c.srtt_ns;
    write(&opts, &mut c, TCP_TX_DELAY, 20_000);
    assert_eq!(c.srtt_ns, settled);
    // Withdrawing the delay shortens the path again.
    write(&opts, &mut c, TCP_TX_DELAY, 0);
    assert_eq!(c.srtt_ns, settled - 20_000_000);
}

#[test]
fn a_lowered_retransmit_ceiling_caps_the_backoff() {
    let (opts, mut c) = (SockOpts::default(), conn());
    write(&opts, &mut c, TCP_RTO_MAX_MS, 2_000);
    assert_eq!(c.rto_max_ns, 2 * NS_PER_S);
    c.rto_ns = 2 * NS_PER_S;
    c.retx_q.push_back(UnackedSegment { seq: 42, flags: 0, payload: alloc::vec![1u8; 10],
        last_sent_ns: 0, delivered_at_send: 0, delivered_mstamp_ns: 0, first_sent_ns: 0,
        delivery_app_limited: false, retries: 0, sacked: false });
    c.retransmit_due(10 * NS_PER_S);
    assert_eq!(c.rto_ns, 2 * NS_PER_S, "the backoff may not pass the caller's ceiling");
}

#[test]
fn a_lowered_retransmit_floor_raises_a_small_estimate_to_it() {
    let (opts, mut c) = (SockOpts::default(), conn());
    write(&opts, &mut c, TCP_RTO_MIN_US, 20_000);
    assert_eq!(c.rto_min_ns, 20 * NS_PER_TICK);
    c.update_rtt(1_000);
    assert_eq!(c.rto_ns, 20 * NS_PER_TICK);
}

#[test]
fn clearing_the_cork_asks_the_sender_to_flush_what_it_held() {
    let (opts, mut c) = (SockOpts::default(), conn());
    assert!(!write(&opts, &mut c, TCP_CORK, 1).uncork);
    let effects = write(&opts, &mut c, TCP_CORK, 0);
    assert!(effects.uncork, "the held partial segment must be released");
    // Clearing a cork that was never set releases nothing.
    assert!(!write(&opts, &mut c, TCP_CORK, 0).uncork);
}

#[test]
fn naming_no_delay_pushes_what_the_cork_was_holding() {
    let (opts, mut c) = (SockOpts::default(), conn());
    write(&opts, &mut c, TCP_CORK, 1);
    assert!(write(&opts, &mut c, TCP_NODELAY, 1).uncork,
        "no-delay overrides the cork for what is already queued");
    assert!(!write(&opts, &mut c, TCP_NODELAY, 0).uncork);
}

#[test]
fn releasing_repair_asks_the_sender_to_reopen_the_peers_window() {
    let (opts, mut c) = (SockOpts::default(), conn());
    write(&opts, &mut c, TCP_REPAIR, TCP_REPAIR_ON);
    assert!(write(&opts, &mut c, TCP_REPAIR, TCP_REPAIR_OFF).window_probe);
    write(&opts, &mut c, TCP_REPAIR, TCP_REPAIR_ON);
    assert!(!write(&opts, &mut c, TCP_REPAIR, TCP_REPAIR_OFF_NO_WP).window_probe);
}

#[test]
fn entering_repair_resets_which_queue_the_restore_addresses() {
    let (opts, mut c) = (SockOpts::default(), conn());
    write(&opts, &mut c, TCP_REPAIR, TCP_REPAIR_ON);
    write(&opts, &mut c, TCP_REPAIR_QUEUE, TCP_SEND_QUEUE);
    assert_eq!(opts.tcp.repair_queue.load(Ordering::Acquire), TCP_SEND_QUEUE);
    write(&opts, &mut c, TCP_REPAIR, TCP_REPAIR_OFF);
    write(&opts, &mut c, TCP_REPAIR, TCP_REPAIR_ON);
    assert_eq!(opts.tcp.repair_queue.load(Ordering::Acquire), TCP_NO_QUEUE);
}

#[test]
fn a_restored_sequence_moves_the_side_the_repair_queue_selected() {
    let mut c = conn();
    apply::repair_to_conn(&mut c, &Action::QueueSeq { queue: TCP_SEND_QUEUE, seq: 5_000 });
    assert_eq!((c.snd_una, c.snd_nxt), (5_000, 5_000));
    apply::repair_to_conn(&mut c, &Action::QueueSeq { queue: TCP_RECV_QUEUE, seq: 9_000 });
    assert_eq!((c.rcv_nxt, c.rcv_read_seq), (9_000, 9_000));
}

#[test]
fn a_restored_window_becomes_the_window_the_read_direction_publishes() {
    let mut c = conn();
    let w = RepairWindow { snd_wl1: 11, snd_wnd: 22, max_window: 33, rcv_wnd: 44, rcv_wup: 55 };
    apply::repair_to_conn(&mut c, &Action::RepairWindow(w));
    assert_eq!((c.snd_wl1, c.snd_wnd, c.max_window, c.rcv_wnd, c.rcv_wup), (11, 22, 33, 44, 55));
    assert_eq!(apply::repair_window_of(&c), w);
}

#[test]
fn restored_handshake_options_reinstate_what_the_connection_negotiated() {
    let mut c = conn();
    let records = [
        RepairOpt { code: TCPOPT_MSS, val: 1300 },
        RepairOpt { code: TCPOPT_WINDOW, val: 0x0009_0007 },
        RepairOpt { code: TCPOPT_SACK_PERM, val: 0 },
        RepairOpt { code: TCPOPT_TIMESTAMP, val: 0 },
    ];
    let (effects, err) = repair::admit_opts(&records);
    assert_eq!(err, None);
    apply::repair_to_conn(&mut c, &Action::RepairOptions { effects: effects.clone(), err: None });
    assert_eq!(c.mss_clamp, 1300);
    assert_eq!(c.peer_mss, 1300);
    assert_eq!((c.snd_wscale, c.rcv_wscale), (7, 9));
    assert!(c.sack_ok);
    assert!(c.ts_enabled);
    assert!(effects.contains(&RepairEffect::SackPerm));
    // The restored scale is what the advertised window is shifted by, so a
    // restored connection advertises the same window it did before.
    c.rcv_buf_cap = 65_536;
    assert_eq!(c.current_rcv_window(), (65_536u32 >> 7) as u16);
}

#[test]
fn a_restored_segment_size_reaches_the_sender() {
    let mut c = conn();
    c.snd_wnd = 100_000;
    c.cwnd = 100_000;
    apply::repair_to_conn(&mut c, &Action::RepairOptions {
        effects: alloc::vec![RepairEffect::MssClamp(300)], err: None });
    c.send(&alloc::vec![7u8; 1500]);
    assert!(c.output(1500, true, false).len() >= 5);
}

#[test]
fn an_installed_timestamp_bias_becomes_the_connections_own_offset() {
    let (opts, mut c) = (SockOpts::default(), conn());
    write(&opts, &mut c, TCP_REPAIR, TCP_REPAIR_ON);
    let action = set::admit(TCP_TIMESTAMP, Arg::Int(1000), SetEnv {
        repair: true, clock_ts_ms: 400, ..SetEnv::default() }).unwrap();
    apply::store(&opts, &action);
    apply::to_conn(&opts, &mut c);
    assert_eq!(c.ts_off, 600);
}

#[test]
fn an_accepted_socket_inherits_the_listeners_policy() {
    let listener = SockOpts::default();
    let mut c = conn();
    write(&listener, &mut c, TCP_MAXSEG, 700);
    write(&listener, &mut c, TCP_USER_TIMEOUT, 9_000);
    write(&listener, &mut c, TCP_THIN_LINEAR_TIMEOUTS, 1);
    write(&listener, &mut c, TCP_NOTSENT_LOWAT, 4096);
    let child = SockOpts::default();
    child.tcp.inherit(&listener.tcp);
    let mut cc = conn();
    apply::to_conn(&child, &mut cc);
    assert_eq!(cc.own_mss, 700);
    assert_eq!(cc.user_timeout_ns, 9_000 * NS_PER_MS);
    assert!(cc.thin_lto);
    assert_eq!(cc.notsent_lowat, 4096);
}

#[test]
fn a_socket_that_asked_to_save_the_handshake_collects_it_at_accept() {
    let opts = SockOpts::default();
    let mut c = conn();
    c.syn_bytes = Some(alloc::vec![0xAAu8; 40]);
    // Without the option the record is dropped rather than carried for the
    // life of the connection.
    apply::collect_saved_syn(&opts, &mut c);
    assert!(opts.tcp.saved_syn.lock().is_none());
    assert!(c.syn_bytes.is_none());

    let asked = SockOpts::default();
    let mut c = conn();
    c.syn_bytes = Some(alloc::vec![0xAAu8; 40]);
    write(&asked, &mut c, TCP_SAVE_SYN, 1);
    apply::collect_saved_syn(&asked, &mut c);
    assert_eq!(asked.tcp.saved_syn.lock().as_deref(), Some(&[0xAAu8; 40][..]));
    assert!(c.syn_bytes.is_none(), "the record is handed over, not copied");
}

#[test]
fn the_default_option_block_leaves_the_connection_on_its_own_defaults() {
    let opts = SockOpts::default();
    let mut c = conn();
    apply::to_conn(&opts, &mut c);
    assert_eq!(c.own_mss, 0, "no caller named a segment size");
    assert_eq!(c.window_clamp, u32::MAX);
    assert_eq!(c.notsent_lowat, u32::MAX);
    assert_eq!(c.user_timeout_ns, 0);
    assert_eq!(c.rto_max_ns, crate::tcp_conn::RTO_MAX_DEFAULT_NS);
    assert_eq!(c.delack_max_ns, crate::tcp_conn::DELACK_MAX_DEFAULT_NS);
    assert_eq!(c.linger2_ns, crate::tcp_conn::LINGER2_DEFAULT_NS);
    assert!(c.quickack, "a socket is not in ping-pong mode until something puts it there");
    assert!(!c.repair);
}
