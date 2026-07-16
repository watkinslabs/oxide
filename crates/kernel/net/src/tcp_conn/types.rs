use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use crate::addr::{IpAddr, Ipv4Addr};

/// Endpoint = (ip, port).
/// v1-minimum: one connection can speak both IPv4/IPv6.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
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
    pub ts_enabled: bool,
    pub ts_recent:  u32,
    pub own_mss: u16,
    pub cwnd:     u32,
    pub ssthresh: u32,
    pub dup_acks: u8,
    pub cubic_w_max:    u32,
    pub cubic_epoch_ms: u32,
    pub cubic_k_ms:     u32,
    pub rcv_buf_cap: u32,
    pub rcv_buf_max: u32,
    pub rcv_peak: u32,
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
