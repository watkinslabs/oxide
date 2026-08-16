// Sequence arithmetic, option parsing, and the window check. An inverted
// comparison here is the highest-value defect in the crate: it either admits
// a blind-injected segment or refuses a legitimate one.

use crate::proto::tcp_state::*;
use crate::proto::tcp_window::*;

fn seg(seq: u32, ack: u32, win: u16, flags: u8, datalen: u32) -> TcpSeg<'static> {
    TcpSeg { seq, ack, win, flags, datalen, options: &[] }
}

#[test]
fn modular_comparison_survives_wrap() {
    assert!(before(1, 2));
    assert!(after(2, 1));
    // Straddling the wrap: a plain `<` reports the opposite of the truth here.
    assert!(before(0xffff_fff0, 0x0000_0010));
    assert!(after(0x0000_0010, 0xffff_fff0));
    assert!(!before(5, 5));
    assert!(!after(5, 5));
}

#[test]
fn segment_end_counts_syn_and_fin() {
    assert_eq!(seg(1000, 0, 0, TCPHDR_SYN, 0).end(), 1001, "SYN consumes one sequence");
    assert_eq!(seg(1000, 0, 0, TCPHDR_FIN | TCPHDR_ACK, 0).end(), 1001);
    assert_eq!(seg(1000, 0, 0, TCPHDR_ACK, 100).end(), 1100);
    assert_eq!(seg(1000, 0, 0, TCPHDR_SYN | TCPHDR_ACK, 0).end(), 1001);
    assert_eq!(seg(1000, 0, 0, TCPHDR_ACK, 0).end(), 1000, "a bare ACK occupies nothing");
}

#[test]
fn parses_window_scale_and_sack_permitted() {
    // NOP, window-scale 7, SACK-permitted, EOL.
    let opts = [TCPOPT_NOP, TCPOPT_WINDOW, 3, 7, TCPOPT_SACK_PERM, 2, TCPOPT_EOL];
    let o = parse_options(&opts);
    assert_eq!(o.scale, 7);
    assert_eq!(o.flags & IP_CT_TCP_FLAG_WINDOW_SCALE, IP_CT_TCP_FLAG_WINDOW_SCALE);
    assert_eq!(o.flags & IP_CT_TCP_FLAG_SACK_PERM, IP_CT_TCP_FLAG_SACK_PERM);
}

#[test]
fn window_scale_is_clamped() {
    let opts = [TCPOPT_WINDOW, 3, 200];
    assert_eq!(parse_options(&opts).scale, TCP_MAX_WSCALE,
        "an over-large scale must clamp, not shift a u32 out of range");
}

#[test]
fn malformed_option_list_stops_the_walk() {
    // Length byte of 0 would loop forever; length past the buffer would read
    // out of bounds. Both must simply end the walk.
    assert_eq!(parse_options(&[TCPOPT_WINDOW, 0, 7]).flags, 0);
    assert_eq!(parse_options(&[TCPOPT_WINDOW, 60, 7]).flags, 0);
    assert_eq!(parse_options(&[TCPOPT_WINDOW]).flags, 0);
}

#[test]
fn sack_right_edge_takes_the_highest_block() {
    // kind=5 len=18: two 8-byte blocks.
    let mut o = alloc::vec![TCPOPT_SACK, 18];
    o.extend_from_slice(&1000u32.to_be_bytes());
    o.extend_from_slice(&2000u32.to_be_bytes());
    o.extend_from_slice(&5000u32.to_be_bytes());
    o.extend_from_slice(&6000u32.to_be_bytes());
    assert_eq!(sack_right_edge(&o, 500), 6000);
    assert_eq!(sack_right_edge(&[], 500), 500, "no SACK means the plain ACK");
}

fn established_track() -> TcpTrack {
    let mut t = TcpTrack { state: TCP_CONNTRACK_ESTABLISHED, ..TcpTrack::default() };
    for d in 0..2 {
        t.seen[d] = TcpDirState {
            td_end: 1000, td_maxend: 1000 + 8000, td_maxwin: 8000,
            td_maxack: 1000, td_scale: 0, flags: 0,
        };
    }
    t
}

#[test]
fn in_window_segment_is_accepted_and_advances_end() {
    let mut t = established_track();
    let s = seg(1000, 1000, 8000, TCPHDR_ACK, 100);
    assert_eq!(in_window(&mut t, 0, TCP_ACK_SET, &s, false), TcpAction::Accept);
    assert_eq!(t.seen[0].td_end, 1100);
}

#[test]
fn sequence_past_the_right_edge_is_refused() {
    let mut t = established_track();
    // Far beyond td_maxend and beyond any workaround allowance.
    let s = seg(1000 + 8000 + 100_000, 1000, 8000, TCPHDR_ACK, 10);
    assert_eq!(in_window(&mut t, 0, TCP_ACK_SET, &s, false), TcpAction::Invalid);
}

#[test]
fn ack_above_what_the_peer_has_sent_is_refused() {
    let mut t = established_track();
    // Acknowledging data the peer never sent is the classic blind-injection
    // signature; accepting it would advance the peer's window for an attacker.
    let s = seg(1000, 1000 + 50_000, 8000, TCPHDR_ACK, 0);
    assert_eq!(in_window(&mut t, 0, TCP_ACK_SET, &s, false), TcpAction::Invalid);
}

#[test]
fn liberal_mode_accepts_what_strict_mode_refuses() {
    let mut a = established_track();
    let s = seg(1000, 1000 + 50_000, 8000, TCPHDR_ACK, 0);
    assert_eq!(in_window(&mut a, 0, TCP_ACK_SET, &s, false), TcpAction::Invalid);
    let mut b = established_track();
    assert_eq!(in_window(&mut b, 0, TCP_ACK_SET, &s, true), TcpAction::Accept);
}

#[test]
fn already_acked_retransmission_is_ignored_not_refused() {
    let mut t = established_track();
    t.seen[0].td_end = 100_000;
    t.seen[0].td_maxend = 108_000;
    t.seen[1].td_maxwin = 8000;
    // Well below the left edge: old data, not an attack.
    let s = seg(1000, 1000, 8000, TCPHDR_ACK, 10);
    assert_eq!(in_window(&mut t, 0, TCP_ACK_SET, &s, false), TcpAction::Ignore);
}

#[test]
fn first_syn_initialises_the_sender() {
    let mut t = TcpTrack { state: TCP_CONNTRACK_SYN_SENT, ..TcpTrack::default() };
    let s = TcpSeg { seq: 1000, ack: 0, win: 4096, flags: TCPHDR_SYN, datalen: 0,
                     options: &[TCPOPT_WINDOW, 3, 5, TCPOPT_SACK_PERM, 2] };
    assert_eq!(in_window(&mut t, 0, TCP_SYN_SET, &s, false), TcpAction::Accept);
    assert_eq!(t.seen[0].td_end, 1001);
    assert!(t.seen[0].td_maxwin >= 1);
}

#[test]
fn zero_window_becomes_one() {
    let mut t = TcpTrack { state: TCP_CONNTRACK_SYN_SENT, ..TcpTrack::default() };
    let s = seg(1000, 0, 0, TCPHDR_SYN, 0);
    in_window(&mut t, 0, TCP_SYN_SET, &s, false);
    assert_eq!(t.seen[0].td_maxwin, 1,
        "a zero window must not collapse every later bound to a point");
}

#[test]
fn window_scale_needs_both_directions() {
    let mut t = TcpTrack { state: TCP_CONNTRACK_SYN_SENT, ..TcpTrack::default() };
    // Only the sender announces scaling; the receiver never did.
    let s = TcpSeg { seq: 1000, ack: 0, win: 4096, flags: TCPHDR_SYN, datalen: 0,
                     options: &[TCPOPT_WINDOW, 3, 7] };
    in_window(&mut t, 0, TCP_SYN_SET, &s, false);
    assert_eq!(t.seen[0].td_scale, 0, "one-sided scaling must not be applied");
}

#[test]
fn identical_acks_count_as_retransmissions() {
    let mut t = established_track();
    let s = seg(1000, 1000, 8000, TCPHDR_ACK, 0);
    for _ in 0..3 { in_window(&mut t, 0, TCP_ACK_SET, &s, false); }
    assert_eq!(t.retrans, 2, "the first is not a retransmission, the next two are");
    let other = seg(1010, 1000, 8000, TCPHDR_ACK, 0);
    in_window(&mut t, 0, TCP_ACK_SET, &other, false);
    assert_eq!(t.retrans, 0, "a different ack resets the run");
}

#[test]
fn reset_answering_a_syn_is_rebased_onto_the_senders_end() {
    let mut t = TcpTrack { state: TCP_CONNTRACK_SYN_SENT, ..TcpTrack::default() };
    t.seen[0] = TcpDirState { td_end: 1001, td_maxend: 1001, td_maxwin: 4096,
                              td_maxack: 0, td_scale: 0, flags: 0 };
    t.seen[1] = TcpDirState { td_end: 0, td_maxend: 0, td_maxwin: 4096,
                              td_maxack: 0, td_scale: 0, flags: 0 };
    // A RST with seq 0 in SYN_SENT is a legitimate refusal, not an injection.
    let s = seg(0, 1001, 0, TCPHDR_RST | TCPHDR_ACK, 0);
    assert_ne!(in_window(&mut t, 1, TCP_RST_SET, &s, false), TcpAction::Invalid);
}
