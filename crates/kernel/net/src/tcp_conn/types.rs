use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use crate::addr::IpAddr;

/// Endpoint = (ip, port).
/// v1-minimum: one connection can speak both IPv4/IPv6.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TcpCongestionControl {
    Reno,
    Cubic,
}

/// One unacked segment on the retransmission queue.
#[derive(Clone, Debug)]
pub struct UnackedSegment {
    pub seq:         u32,
    pub flags:       u8,
    pub payload:     Vec<u8>,
    pub last_sent_ns: u64,
    pub retries:     u32,
    pub sacked:      bool,
}

/// One received segment retained until the gap before it arrives.
///
/// Payload, urgent metadata, and FIN occupy the same TCP sequence space, so
/// they must remain one record while the segment is out of order.
#[derive(Clone, Debug)]
pub struct OutOfOrderSegment {
    pub payload: Vec<u8>,
    pub urgent: Option<(u32, u8)>,
    pub fin: bool,
}

impl OutOfOrderSegment {
    /// Build a payload-only retained segment for the SACK test fixtures. # C: O(1)
    #[cfg(test)]
    pub(crate) fn data(payload: Vec<u8>) -> Self {
        Self { payload, urgent: None, fin: false }
    }

    /// Count the TCP sequence space retained by this segment. # C: O(1)
    pub(crate) fn sequence_len(&self) -> u32 {
        self.payload.len() as u32 + u32::from(self.fin)
    }
}

#[derive(Debug)]
pub struct TcpConn {
    pub local:  Endpoint,
    pub remote: Endpoint,
    pub state:  crate::tcp_state::TcpState,
    pub snd_una: u32,
    pub snd_nxt: u32,
    pub rcv_nxt: u32,
    /// Sequence number of the next byte visible to a normal stream receive.
    pub rcv_read_seq: u32,
    pub window:  u16,
    pub send_buf: VecDeque<u8>,
    pub recv_buf: VecDeque<u8>,
    /// Latest TCP urgent byte and its stream sequence; syscall OOB delivery consumes it later.
    pub urgent: Option<(u32, u8)>,
    /// Urgent stream sequence consumed before out-of-order data promotion.
    pub oob_consumed: Option<u32>,
    pub retx_q:   VecDeque<UnackedSegment>,
    pub srtt_ns:    u64,
    pub rttvar_ns:  u64,
    pub rto_ns:     u64,
    pub tw_start_ns: u64,
    pub peer_mss: u16,
    /// Observed receive MSS used for delayed-ACK decisions; zero uses the live policy hint.
    pub rcv_mss: u16,
    pub snd_wscale: u8,
    pub rcv_wscale: u8,
    pub snd_wnd: u32,
    /// Every valid TCP segment admitted to this connection.
    pub segs_in: u32,
    /// Payload bytes accepted into the contiguous receive stream.
    pub bytes_received: u64,
    /// Segments retained because they arrived beyond `rcv_nxt`.
    pub rcv_ooopack: u32,
    /// Bytes cumulatively acknowledged by the peer.
    pub bytes_acked: u64,
    /// Every TCP segment successfully handed to the network output path.
    pub segs_out: u32,
    /// Outbound segments carrying payload.
    pub data_segs_out: u32,
    /// Payload bytes handed to the network output path.
    pub bytes_sent: u64,
    /// Payload bytes handed to retransmission.
    pub bytes_retrans: u64,
    /// Complete out-of-order segments, including control flags that consume
    /// sequence space such as FIN.
    pub ooo_buf: BTreeMap<u32, OutOfOrderSegment>,
    pub ts_enabled: bool,
    pub ts_recent:  u32,
    /// Linux `tp->tsoffset` — the per-connection TSval bias from
    /// `secure_tcp_seq_and_ts_off`'s high half. Without it every connection
    /// from this host advertises the same timestamp clock, publishing host
    /// uptime and letting an off-path observer correlate connections.
    pub ts_off:     u32,
    pub own_mss: u16,
    /// Last path MTU synchronized onto this connection's send state.
    pub path_mtu: u32,
    pub congestion: TcpCongestionControl,
    pub cc_locked: bool,
    pub cwnd:     u32,
    pub cwnd_clamp: u32,
    pub ssthresh: u32,
    pub dup_acks: u8,
    pub reordering: u32,
    pub rto_min_ns: u64,
    pub rto_min_locked: bool,
    pub window_clamp: u32,
    pub route_features: u32,
    pub quickack: bool,
    pub fastopen_no_cookie: bool,
    /// The fast-open option this side's next handshake segment carries, if
    /// any. Decided before the segment is built, because the decision needs
    /// state a connection does not own: the accept queue's keys and bound on
    /// a listener, the namespace's cookie cache on a client. Cleared once the
    /// segment is built, so a SYN retransmit goes out bare — a middlebox that
    /// ate the first one is exactly what the retransmit has to get past.
    pub fastopen_opt: Option<crate::tcp_conn::fastopen::Cookie>,
    /// This side's opening SYN carried a fast-open option, and which kind.
    /// The answer's cookie is only believed when one was asked for.
    pub syn_fastopen: bool,
    pub syn_fastopen_exp: bool,
    /// This side's opening SYN carried the program's data.
    pub syn_data: bool,
    /// That data was acknowledged: a fast open that worked end to end.
    pub syn_data_acked: bool,
    /// This active open left a blackhole pause that had run out, so a
    /// success on it clears the recurrence count that produced the pause.
    pub fastopen_confirming: bool,
    /// Why this connection's fast open did not put the program's bytes in
    /// the SYN, as `TCP_INFO` reports it.
    pub fastopen_client_fail: u8,
    /// Segments carrying data this connection has received. A fast-open
    /// connection that has received none is the state a middlebox
    /// interfering with it produces.
    pub data_segs_in: u32,
    /// A fast open on this connection met the shape a middlebox eating one
    /// produces, waiting for the layer that owns the namespace's pause to
    /// record it.
    pub fastopen_blackhole_seen: bool,
    /// What the SYN-ACK taught, waiting for the layer that owns the
    /// namespace's cookie cache to record it.
    pub fastopen_learned: Option<crate::tcp_fastopen::Learned>,
    /// This child was opened by a SYN whose data was taken. It reached the
    /// accept queue at the SYN rather than at the handshake's end, so the
    /// acknowledgement that completes the handshake must not publish it a
    /// second time.
    pub fastopen_child: bool,
    pub cubic_w_max:    u32,
    pub cubic_epoch_ms: u32,
    pub cubic_k_ms:     u32,
    pub rcv_buf_cap: u32,
    pub rcv_buf_max: u32,
    pub rcv_peak: u32,
    /// Receive-window slow-start threshold; caps the advertised free space.
    pub rcv_ssthresh: u32,
    /// Receiver-side RTT sample measured over one advertised receive window.
    pub rcv_rtt_ns: u64,
    pub rcv_rtt_stamp_ns: u64,
    pub rcv_rtt_seq: u32,
    /// Bytes copied to the application during the latest receiver RTT sample.
    pub rcv_space: u32,
    pub rcv_space_stamp_ns: u64,
    pub rcv_space_read_seq: u32,
    /// Linux `sk->sk_userlocks & SOCK_RCVBUF_LOCK` (`net/core/sock.c:975`):
    /// once `setsockopt(SO_RCVBUF)` names a size, receive-window autotuning
    /// stops and the advertised window follows the caller's number.
    pub rcv_buf_locked: bool,
    pub ecn_enabled: bool,
    pub send_ece:    bool,
    pub send_cwr:    bool,
    pub ecn_last_reduce_ms: u32,
    pub ka_enabled:  bool,
    pub ka_idle_ns:  u64,
    pub ka_intvl_ns: u64,
    pub ka_cnt_max:  u32,
    pub ka_count:    u32,
    pub last_rx_ns:  u64,
    /// Last successfully transmitted sequence-consuming TCP segment.
    pub last_data_sent_ns: u64,
    /// Last received TCP segment carrying payload.
    pub last_data_recv_ns: u64,
    /// Last received TCP segment carrying the ACK flag.
    pub last_ack_recv_ns: u64,
    pub next_ka_ns:  u64,
    /// `TCP_SYNCNT`: how many times the initial SYN is retransmitted before
    /// the connection attempt is abandoned.
    pub syn_retries: u32,
    /// `TCP_LINGER2`: how long the connection may hold FIN-WAIT-2 before it
    /// is torn down. `0` = leave the state as soon as it is entered.
    pub linger2_ns: u64,
    /// `TCP_THIN_LINEAR_TIMEOUTS`: retransmit a thin stream on a flat timer
    /// instead of doubling it, so a one-segment flow recovers in one RTO.
    pub thin_lto: bool,
    /// `TCP_USER_TIMEOUT`: abort once data has gone unacknowledged this long,
    /// regardless of the retransmit count. `0` = no caller-imposed limit.
    pub user_timeout_ns: u64,
    /// Wall time the oldest unacknowledged segment was first sent, which is
    /// what the user timeout is measured from.
    pub first_unacked_ns: u64,
    /// `TCP_REPAIR`: the connection's sequence state is under external
    /// control, so timers and probes stand down.
    pub repair: bool,
    /// `TCP_REPAIR_OPTIONS` restored maximum segment size.
    pub mss_clamp: u16,
    /// The peer permits selective acknowledgement, so this side may send SACK
    /// blocks. Negotiated on the handshake, and restored directly by
    /// `TCP_REPAIR_OPTIONS`.
    pub sack_ok: bool,
    /// The peer offered window scaling, so both scales are in effect. A peer
    /// that omitted the option disables scaling in both directions, which is
    /// not the same as a peer that offered a scale of zero.
    pub wscale_ok: bool,
    /// `TCP_NOTSENT_LOWAT`: unsent bytes above this make the socket
    /// unwritable, so a writer is woken only when the queue has drained.
    pub notsent_lowat: u32,
    /// `TCP_TX_DELAY`: an artificial one-way delay folded into the smoothed
    /// round-trip estimate.
    pub tx_delay_ns: u64,
    /// `TCP_RTO_MAX_MS` / `TCP_DELACK_MAX_US` as the timer ceilings they set.
    pub rto_max_ns: u64,
    pub delack_max_ns: u64,
    /// Adaptive delayed-ACK interval from validated payload arrivals; zero
    /// means the delayed-ACK engine has not yet seen data.
    pub delack_ato_ns: u64,
    /// Repair-visible window state: the sequence of the last window update,
    /// the largest window the peer ever advertised, and the receive window
    /// with the sequence it was advertised from.
    pub snd_wl1: u32,
    pub max_window: u32,
    pub rcv_wnd: u32,
    pub rcv_wup: u32,
    /// An acknowledgement is owed but was withheld because the socket is in
    /// ping-pong mode, and the deadline by which it must go out anyway.
    pub ack_pending: bool,
    pub ack_deadline_ns: u64,
    /// `TCP_SAVE_SYN`: the handshake packet that opened this connection, from
    /// the network header onward, kept until `TCP_SAVED_SYN` collects it.
    pub syn_bytes: Option<alloc::vec::Vec<u8>>,
    /// What the IPv4 header of that packet carried, and the interface it
    /// arrived on. An accepted socket publishes these through IP_PKTOPTIONS,
    /// and they are the only receive-side header state a stream socket keeps.
    pub rcv_iif: u32,
    pub rcv_ttl: u8,
    pub rcv_tos: u8,
    /// Request-sock state while this passive connection is half-open: the
    /// SYN-ACK timer's accounting and the `TCP_DEFER_ACCEPT` deferral. Unarmed
    /// on every connection that was never a request.
    pub rsk: crate::tcp_conn::reqsk::ReqSock,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TcpConnError {
    BadState,
    BadHdr,
    Reset,
}

/// Wire format constant from `TCP_HDR_MIN_LEN`; exported because it is used
/// by tests that construct minimal TCP frames.
pub const OWN_MSS_DEFAULT: u16 = 1460;
pub const RCV_MSS_DEFAULT: u16 = 536;
pub const RCV_MSS_MIN: u16 = 48;
pub const OWN_WSCALE: u8 = 7;
/// Retransmit-timeout ceiling and delayed-acknowledgement ceiling a connection
/// runs with until `TCP_RTO_MAX_MS` / `TCP_DELACK_MAX_US` name others.
pub const RTO_MAX_DEFAULT_NS: u64 = 120_000_000_000;
pub const DELACK_MAX_DEFAULT_NS: u64 = 200_000_000;
pub const DELACK_ATO_MIN_NS: u64 = 40_000_000;
/// SYN retransmits before an unanswered connection attempt is abandoned, and
/// data retransmits before an established connection is.
pub const SYN_RETRIES_DEFAULT: u32 = 6;
pub const DATA_RETRIES_DEFAULT: u32 = 15;
/// FIN-WAIT-2 hold time a connection runs with until `TCP_LINGER2` names one.
pub const LINGER2_DEFAULT_NS: u64 = 60_000_000_000;

/// What the network header of a passive open's opening packet carried, and the
/// interface it arrived on — the state `IP_PKTOPTIONS` publishes on the
/// accepted socket. An IPv6 open records nothing: the option is an IPv4-level
/// one, and its IPv6 twin reports its own header's fields. A zero interface
/// index is what "nothing was recorded" means. # C: O(1)
pub fn passive_rcv_header(packet: &[u8], ipv6: bool, iif: u32) -> (u32, u8, u8) {
    if ipv6 || packet.len() < crate::ipv4::IPV4_HDR_LEN { return (0, 0, 0); }
    (iif, packet[8], packet[1])
}

#[cfg(test)]
mod size_tests {
    /// The passive-open path builds a `TcpConn` on the SOFTIRQ stack
    /// (`build_passive_child`), and that stack is the 16 KiB per-CPU hardirq
    /// stack whose measured peak is already ~14.5 KiB. Print-and-pin the size so
    /// a growth shows up here rather than as a guard-page double fault.
    #[test]
    fn a_tcp_conn_is_small_enough_to_build_on_the_softirq_stack() {
        let n = core::mem::size_of::<super::TcpConn>();
        let e = core::mem::size_of::<crate::stack::TcpEntry>();
        assert!(n + e <= 1536, "TcpConn is {n} bytes, TcpEntry is {e} bytes — the passive-open path builds one on the \
            hardirq stack, which has ~1.5 KiB of headroom");
    }
}
