// Whole TCP flows driven segment by segment in both directions, asserting the
// state after each one. A table cell that is right in isolation can still be
// unreachable or reached wrongly; only a scripted flow shows that.

use crate::proto::tcp::*;
use crate::proto::tcp_state::*;
use crate::proto::tcp_window::{TcpSeg, TcpTrack};
use crate::uapi::*;

struct Flow { track: TcpTrack, status: u32, confirmed: bool, sysctl: TcpSysctl }

impl Flow {
    fn new() -> Self {
        Self { track: TcpTrack::default(), status: 0, confirmed: false,
               sysctl: TcpSysctl::default() }
    }

    fn send(&mut self, dir: u8, seq: u32, ack: u32, flags: u8, datalen: u32)
        -> TcpVerdict
    {
        let seg = TcpSeg { seq, ack, win: 8192, flags, datalen, options: &[] };
        let (v, delta) = packet(&mut self.track, dir, &seg, self.status,
                                self.confirmed, &self.sysctl);
        if matches!(v, TcpVerdict::Accept { .. }) {
            self.confirmed = true;
            if dir == IP_CT_DIR_REPLY { self.status |= IPS_SEEN_REPLY; }
            if delta.set_assured { self.status |= IPS_ASSURED; }
        }
        v
    }

    fn state(&self) -> u8 { self.track.state }
}

fn timeout_of(v: TcpVerdict) -> u32 {
    match v { TcpVerdict::Accept { timeout } => timeout, other => panic!("{other:?}") }
}

#[test]
fn three_way_handshake_reaches_established_and_assured() {
    let mut f = Flow::new();
    f.send(0, 1000, 0, TCPHDR_SYN, 0);
    assert_eq!(f.state(), TCP_CONNTRACK_SYN_SENT);
    f.send(1, 5000, 1001, TCPHDR_SYN | TCPHDR_ACK, 0);
    assert_eq!(f.state(), TCP_CONNTRACK_SYN_RECV);
    f.send(0, 1001, 5001, TCPHDR_ACK, 0);
    assert_eq!(f.state(), TCP_CONNTRACK_ESTABLISHED);
    assert_eq!(f.status & IPS_SEEN_REPLY, IPS_SEEN_REPLY);
    // The flow only becomes assured once the handshake completes, which is
    // what protects it from early drop under table pressure.
    f.send(1, 5001, 1001, TCPHDR_ACK, 0);
    assert_eq!(f.status & IPS_ASSURED, IPS_ASSURED);
}

#[test]
fn orderly_close_walks_fin_wait_to_time_wait() {
    let mut f = Flow::new();
    f.send(0, 1000, 0, TCPHDR_SYN, 0);
    f.send(1, 5000, 1001, TCPHDR_SYN | TCPHDR_ACK, 0);
    f.send(0, 1001, 5001, TCPHDR_ACK, 0);
    f.send(1, 5001, 1001, TCPHDR_ACK, 0);
    assert_eq!(f.state(), TCP_CONNTRACK_ESTABLISHED);

    f.send(0, 1001, 5001, TCPHDR_FIN | TCPHDR_ACK, 0);
    assert_eq!(f.state(), TCP_CONNTRACK_FIN_WAIT);
    f.send(1, 5001, 1002, TCPHDR_ACK, 0);
    assert_eq!(f.state(), TCP_CONNTRACK_CLOSE_WAIT);
    f.send(1, 5001, 1002, TCPHDR_FIN | TCPHDR_ACK, 0);
    assert_eq!(f.state(), TCP_CONNTRACK_LAST_ACK);
    let v = f.send(0, 1002, 5002, TCPHDR_ACK, 0);
    assert_eq!(f.state(), TCP_CONNTRACK_TIME_WAIT);
    assert_eq!(timeout_of(v), TCP_TIMEOUTS[TCP_CONNTRACK_TIME_WAIT as usize]);
}

#[test]
fn simultaneous_open_converges_on_established() {
    let mut f = Flow::new();
    f.send(0, 1000, 0, TCPHDR_SYN, 0);
    f.send(1, 5000, 0, TCPHDR_SYN, 0);
    assert_eq!(f.state(), TCP_CONNTRACK_SYN_SENT2);
    f.send(0, 1000, 5001, TCPHDR_SYN | TCPHDR_ACK, 0);
    assert_eq!(f.state(), TCP_CONNTRACK_SYN_RECV);
    f.send(1, 5001, 1001, TCPHDR_ACK, 0);
    assert_eq!(f.state(), TCP_CONNTRACK_ESTABLISHED,
        "the simultaneous-open marker must promote SYN_RECV past the table");
}

#[test]
fn reply_reset_to_an_unreplied_flow_kills_it() {
    let mut f = Flow::new();
    f.send(0, 1000, 0, TCPHDR_SYN, 0);
    // The server refuses. Holding the entry for the close timeout would let a
    // scan pin one table slot per probe.
    let v = f.send(1, 0, 1001, TCPHDR_RST | TCPHDR_ACK, 0);
    assert_eq!(v, TcpVerdict::Kill);
}

#[test]
fn syn_retransmit_does_not_renew_the_timeout() {
    let mut f = Flow::new();
    f.send(0, 1000, 0, TCPHDR_SYN, 0);
    let v = f.send(0, 1000, 0, TCPHDR_SYN, 0);
    assert_eq!(v, TcpVerdict::Ignore,
        "renewing on retransmit lets a client hold a binding open forever");
}

#[test]
fn reset_after_established_closes() {
    let mut f = Flow::new();
    f.send(0, 1000, 0, TCPHDR_SYN, 0);
    f.send(1, 5000, 1001, TCPHDR_SYN | TCPHDR_ACK, 0);
    f.send(0, 1001, 5001, TCPHDR_ACK, 0);
    f.send(1, 5001, 1001, TCPHDR_ACK, 0);
    let v = f.send(0, 1001, 5001, TCPHDR_RST, 0);
    assert_eq!(f.state(), TCP_CONNTRACK_CLOSE);
    assert_eq!(timeout_of(v), TCP_TIMEOUTS[TCP_CONNTRACK_CLOSE as usize],
        "a RST arms the close timeout regardless of the state's own default");
}

#[test]
fn a_bare_ack_cannot_open_a_flow_when_pickup_is_off() {
    let mut t = TcpTrack::default();
    let strict = TcpSysctl { loose: false, ..TcpSysctl::default() };
    let seg = TcpSeg { seq: 1000, ack: 2000, win: 8192, flags: TCPHDR_ACK,
                       datalen: 0, options: &[] };
    assert!(!new_conn(&mut t, &seg, &strict));
    // With pickup on, the same segment seeds a mid-connection entry and the
    // transition table promotes it straight to ESTABLISHED.
    let loose = TcpSysctl { loose: true, ..TcpSysctl::default() };
    let mut t2 = TcpTrack::default();
    assert!(new_conn(&mut t2, &seg, &loose));
    assert_eq!(t2.state, TCP_CONNTRACK_NONE,
        "seeding records window state; the state itself is the table's job");
    let (v, _) = packet(&mut t2, 0, &seg, 0, false, &loose);
    assert!(matches!(v, TcpVerdict::Accept { .. }));
    assert_eq!(t2.state, TCP_CONNTRACK_ESTABLISHED);
}

#[test]
fn a_flag_combination_the_table_rejects_cannot_open_a_flow() {
    let mut t = TcpTrack::default();
    let s = TcpSyn::fin();
    assert!(!new_conn(&mut t, &s, &TcpSysctl::default()),
        "a bare FIN from nothing is not the start of a connection");
}

struct TcpSyn;
impl TcpSyn {
    fn fin() -> TcpSeg<'static> {
        TcpSeg { seq: 1000, ack: 0, win: 8192, flags: TCPHDR_FIN, datalen: 0, options: &[] }
    }
}

#[test]
fn timeout_shortens_under_retransmission() {
    let mut t = TcpTrack { state: TCP_CONNTRACK_ESTABLISHED, last_win: 8192,
                           ..TcpTrack::default() };
    let s = TcpSysctl::default();
    assert_eq!(select_timeout(&t, TCP_CONNTRACK_ESTABLISHED, TCP_ACK_SET, &s),
        TCP_TIMEOUTS[TCP_CONNTRACK_ESTABLISHED as usize]);
    t.retrans = TCP_MAX_RETRANS;
    assert_eq!(select_timeout(&t, TCP_CONNTRACK_ESTABLISHED, TCP_ACK_SET, &s),
        TCP_TIMEOUTS[TCP_CONNTRACK_RETRANS as usize],
        "a flow that keeps retransmitting is not a five-day conversation");
}

#[test]
fn timeout_shortens_on_a_zero_window() {
    let t = TcpTrack { state: TCP_CONNTRACK_ESTABLISHED, last_win: 0,
                       ..TcpTrack::default() };
    assert_eq!(select_timeout(&t, TCP_CONNTRACK_ESTABLISHED, TCP_ACK_SET,
                              &TcpSysctl::default()),
        TCP_TIMEOUTS[TCP_CONNTRACK_RETRANS as usize]);
}

#[test]
fn timeout_shortens_while_data_is_unacknowledged() {
    let mut t = TcpTrack { state: TCP_CONNTRACK_ESTABLISHED, last_win: 8192,
                           ..TcpTrack::default() };
    t.seen[0].flags |= IP_CT_TCP_FLAG_DATA_UNACKNOWLEDGED;
    assert_eq!(select_timeout(&t, TCP_CONNTRACK_ESTABLISHED, TCP_ACK_SET,
                              &TcpSysctl::default()),
        TCP_TIMEOUTS[TCP_CONNTRACK_UNACK as usize]);
}

#[test]
fn a_syn_reopening_a_closed_flow_asks_for_a_retry() {
    let mut f = Flow::new();
    f.send(0, 1000, 0, TCPHDR_SYN, 0);
    f.send(1, 5000, 1001, TCPHDR_SYN | TCPHDR_ACK, 0);
    f.send(0, 1001, 5001, TCPHDR_ACK, 0);
    f.send(1, 5001, 1001, TCPHDR_ACK, 0);
    f.send(0, 1001, 5001, TCPHDR_FIN | TCPHDR_ACK, 0);
    f.send(1, 5001, 1002, TCPHDR_ACK, 0);
    f.send(1, 5001, 1002, TCPHDR_FIN | TCPHDR_ACK, 0);
    f.send(0, 1002, 5002, TCPHDR_ACK, 0);
    assert_eq!(f.state(), TCP_CONNTRACK_TIME_WAIT);
    // The client aborts and reopens. The old entry describes a conversation
    // that no longer exists and must be replaced, not reused.
    let v = f.send(0, 9000, 0, TCPHDR_SYN, 0);
    assert_eq!(v, TcpVerdict::Repeat);
}
