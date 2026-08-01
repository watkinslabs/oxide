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
    pub snd_wscale: u8,
    pub rcv_wscale: u8,
    pub snd_wnd: u32,
    pub ooo_buf: BTreeMap<u32, Vec<u8>>,
    /// URG metadata retained with an out-of-order payload until promotion.
    pub ooo_urgent: BTreeMap<u32, Option<(u32, u8)>>,
    pub ts_enabled: bool,
    pub ts_recent:  u32,
    /// Linux `tp->tsoffset` — the per-connection TSval bias from
    /// `secure_tcp_seq_and_ts_off`'s high half. Without it every connection
    /// from this host advertises the same timestamp clock, publishing host
    /// uptime and letting an off-path observer correlate connections.
    pub ts_off:     u32,
    pub own_mss: u16,
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
    pub cubic_w_max:    u32,
    pub cubic_epoch_ms: u32,
    pub cubic_k_ms:     u32,
    pub rcv_buf_cap: u32,
    pub rcv_buf_max: u32,
    pub rcv_peak: u32,
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
pub const OWN_WSCALE: u8 = 7;
/// Retransmit-timeout ceiling and delayed-acknowledgement ceiling a connection
/// runs with until `TCP_RTO_MAX_MS` / `TCP_DELACK_MAX_US` name others.
pub const RTO_MAX_DEFAULT_NS: u64 = 120_000_000_000;
pub const DELACK_MAX_DEFAULT_NS: u64 = 200_000_000;
/// SYN retransmits before an unanswered connection attempt is abandoned, and
/// data retransmits before an established connection is.
pub const SYN_RETRIES_DEFAULT: u32 = 6;
pub const DATA_RETRIES_DEFAULT: u32 = 15;
/// FIN-WAIT-2 hold time a connection runs with until `TCP_LINGER2` names one.
pub const LINGER2_DEFAULT_NS: u64 = 60_000_000_000;
