// Linux value and length table for every `IPPROTO_TCP` `getsockopt` read.
//
// Ordering contract: the caller's declared length is imported first (a bad
// pointer is `EFAULT`), a negative length is `EINVAL`, and only then is the
// option number classified — so an unknown number with a negative length is
// `EINVAL`, not `ENOPROTOOPT`.

use syscall::errno::Errno;
use alloc::vec::Vec;
use crate::tcp_state::TcpState;
use super::*;
use super::repair::RepairWindow;

/// How one accepted read publishes its value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Read {
    /// Publish `min(len, bytes.len())` bytes, then that length. A zero-length
    /// value is how "nothing to report" is answered.
    Clipped(Vec<u8>),
    /// Publish exactly `bytes`, without rewriting the length word; the
    /// caller's length had to match already.
    Fixed(Vec<u8>),
    /// Publish `bytes` when the caller's buffer holds them, and consume the
    /// value; otherwise publish the length required and fail.
    Consume(Vec<u8>),
    /// Delegated to the `TCP_INFO` writer, which owns that struct's layout.
    Info,
}

/// The live values one read is answered from. Every field is what a specific
/// option number publishes, so the shim fills it and this module decides
/// nothing about where the numbers came from.
#[derive(Copy, Clone, Debug)]
pub struct GetEnv<'a> {
    pub state: TcpState,
    pub repair: bool,
    pub repair_queue: i32,
    /// `TCP_MAXSEG`: the negotiated segment size, the caller-named one, and
    /// the size repair restored.
    pub mss_cache: i32,
    pub user_mss: i32,
    pub mss_clamp: i32,
    pub nodelay: bool,
    pub cork: bool,
    pub keepidle_s: i32,
    pub keepintvl_s: i32,
    pub keepcnt: i32,
    pub syncnt: i32,
    pub syncnt_default: i32,
    pub linger2_s: i32,
    pub fin_timeout_default_s: i32,
    pub defer_accept: u8,
    pub window_clamp: i32,
    /// The socket is in ping-pong mode; `TCP_QUICKACK` reads back its inverse.
    pub pingpong: bool,
    pub algo: CongestionAlgo,
    /// The attached upper-layer protocol, if the registry has one.
    pub ulp: Option<u8>,
    pub thin_lto: bool,
    pub user_timeout_ms: i32,
    pub fastopen_max_qlen: i32,
    pub fastopen_connect: bool,
    pub fastopen_no_cookie: bool,
    pub fastopen_key: Option<&'a [u8]>,
    /// `TCP_TIMESTAMP`: the transmit clock at the socket's resolution, plus
    /// the caller-installed bias.
    pub clock_ts: i32,
    pub tsoffset: i32,
    pub usec_ts: bool,
    pub notsent_lowat: u32,
    pub recvmsg_inq: bool,
    pub tx_delay_us: i32,
    pub save_syn: i32,
    pub saved_syn: Option<&'a [u8]>,
    /// `TCP_QUEUE_SEQ`: the send-side write sequence and the receive-side
    /// next-expected sequence.
    pub write_seq: u32,
    pub rcv_nxt: u32,
    pub repair_window: RepairWindow,
    pub rto_max_ticks: i32,
    pub rto_min_ticks: i32,
    pub delack_max_ticks: i32,
    pub rto_max_default_ticks: i32,
    pub rto_min_default_ticks: i32,
    pub delack_max_default_ticks: i32,
    /// `CAP_NET_ADMIN` in the socket's owning user namespace.
    pub net_admin: bool,
}

fn int(val: i32) -> Result<Read, Errno> { Ok(Read::Clipped(val.to_ne_bytes().to_vec())) }

/// Ticks back to microseconds, for the timer windows the read direction
/// reports in their caller-facing unit. # C: O(1)
pub fn ticks_to_usecs(ticks: i32) -> i32 {
    ((ticks as i64).saturating_mul(1_000_000) / HZ) as i32
}

/// Ticks back to milliseconds. # C: O(1)
pub fn ticks_to_msecs(ticks: i32) -> i32 {
    ((ticks as i64).saturating_mul(1000) / HZ) as i32
}

/// Answer one `IPPROTO_TCP` read. `len` is the caller's declared buffer
/// length, already screened for a negative value. # C: O(value bytes)
pub fn read(optname: u64, len: usize, env: GetEnv<'_>) -> Result<Read, Errno> {
    match optname {
        TCP_MAXSEG => {
            let mut val = env.mss_cache;
            if env.user_mss != 0
                && matches!(env.state, TcpState::Closed | TcpState::Listen) {
                val = env.user_mss;
            }
            if env.repair { val = env.mss_clamp; }
            int(val)
        }
        TCP_NODELAY => int(env.nodelay as i32),
        TCP_CORK => int(env.cork as i32),
        TCP_KEEPIDLE => int(env.keepidle_s),
        TCP_KEEPINTVL => int(env.keepintvl_s),
        TCP_KEEPCNT => int(env.keepcnt),
        TCP_SYNCNT => int(if env.syncnt != 0 { env.syncnt } else { env.syncnt_default }),
        TCP_LINGER2 => {
            let val = env.linger2_s;
            int(if val >= 0 {
                if val != 0 { val } else { env.fin_timeout_default_s }
            } else { val })
        }
        TCP_DEFER_ACCEPT => int(retrans_to_secs(env.defer_accept,
            TCP_TIMEOUT_INIT_S, TCP_RTO_MAX_SEC)),
        TCP_WINDOW_CLAMP => int(env.window_clamp),
        TCP_INFO => Ok(Read::Info),
        TCP_CC_INFO => {
            // A read of the algorithm's private statistics: neither registered
            // algorithm keeps any beyond what the connection report already
            // carries, so the read succeeds with nothing published.
            Ok(Read::Clipped(Vec::new()))
        }
        TCP_QUICKACK => int(!env.pingpong as i32),
        TCP_CONGESTION => Ok(Read::Clipped(ca::name_buf(env.algo).to_vec())),
        TCP_ULP => Ok(Read::Clipped(match env.ulp.and_then(ulp::name) {
            Some(name) => {
                let mut buf = alloc::vec![0u8; ULP_NAME_MAX];
                buf[..name.len()].copy_from_slice(name.as_bytes());
                buf
            }
            None => Vec::new(),
        })),
        TCP_FASTOPEN_KEY => Ok(Read::Clipped(
            env.fastopen_key.map(|k| k.to_vec()).unwrap_or_default())),
        TCP_THIN_LINEAR_TIMEOUTS => int(env.thin_lto as i32),
        // Fast retransmit after one duplicate acknowledgement is not a mode
        // the sender has, so the read is always the disabled answer.
        TCP_THIN_DUPACK => int(0),
        TCP_REPAIR => int(env.repair as i32),
        TCP_REPAIR_QUEUE => {
            if !env.repair { return Err(Errno::Einval); }
            int(env.repair_queue)
        }
        TCP_REPAIR_WINDOW => {
            if len != REPAIR_WINDOW_LEN { return Err(Errno::Einval); }
            if !env.repair { return Err(Errno::Eperm); }
            Ok(Read::Fixed(env.repair_window.to_bytes().to_vec()))
        }
        TCP_QUEUE_SEQ => match env.repair_queue {
            q if q == TCP_SEND_QUEUE => int(env.write_seq as i32),
            q if q == TCP_RECV_QUEUE => int(env.rcv_nxt as i32),
            _ => Err(Errno::Einval),
        },
        TCP_USER_TIMEOUT => int(env.user_timeout_ms),
        TCP_FASTOPEN => int(env.fastopen_max_qlen),
        TCP_FASTOPEN_CONNECT => int(env.fastopen_connect as i32),
        TCP_FASTOPEN_NO_COOKIE => int(env.fastopen_no_cookie as i32),
        TCP_TX_DELAY => int(env.tx_delay_us),
        TCP_TIMESTAMP => {
            let val = env.clock_ts.wrapping_add(env.tsoffset);
            int(if env.usec_ts { val | 1 } else { val & !1 })
        }
        TCP_NOTSENT_LOWAT => int(env.notsent_lowat as i32),
        TCP_INQ => int(env.recvmsg_inq as i32),
        TCP_SAVE_SYN => int(env.save_syn),
        TCP_SAVED_SYN => match env.saved_syn {
            None => Ok(Read::Clipped(Vec::new())),
            Some(bytes) if len < bytes.len() => Err(Errno::Einval),
            Some(bytes) => Ok(Read::Consume(bytes.to_vec())),
        },
        TCP_AO_REPAIR => {
            if !env.net_admin || env.state == TcpState::Listen { return Err(Errno::Eperm); }
            Err(Errno::Enoprotoopt)
        }
        TCP_AO_GET_KEYS | TCP_AO_INFO => Err(Errno::Enoprotoopt),
        // The zero-copy receive never reaches this table: it carries an
        // optlen-versioned operand and publishes in place, so the shim answers
        // it before the generic value screen runs
        // (`sol_tcp::zerocopy`). Reaching here means that route was lost.
        TCP_ZEROCOPY_RECEIVE => Err(Errno::Einval),
        // Multipath extension segments are not negotiated by this transport,
        // so no connection is ever carried by it.
        TCP_IS_MPTCP => int(0),
        TCP_RTO_MAX_MS => int(ticks_to_msecs(
            if env.rto_max_ticks != 0 { env.rto_max_ticks } else { env.rto_max_default_ticks })),
        TCP_RTO_MIN_US => int(ticks_to_usecs(
            if env.rto_min_ticks != 0 { env.rto_min_ticks } else { env.rto_min_default_ticks })),
        TCP_DELACK_MAX_US => int(ticks_to_usecs(if env.delack_max_ticks != 0 {
            env.delack_max_ticks } else { env.delack_max_default_ticks })),
        _ => Err(Errno::Enoprotoopt),
    }
}

/// The length a `TCP_SAVED_SYN` read must publish when the caller's buffer is
/// too small: the size the value needs, reported alongside the failure so a
/// second call can size its buffer. # C: O(1)
pub fn saved_syn_required(env: &GetEnv<'_>) -> Option<usize> {
    env.saved_syn.map(|b| b.len())
}
