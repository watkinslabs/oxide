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
