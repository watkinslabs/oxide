// `IPPROTO_TCP` option level for `setsockopt`/`getsockopt` (slots 54/55).
//
// Module manifest:
// - this file: UAPI numbers, the per-socket option storage, and the shared
//   value transforms (seconds↔retransmit count, microseconds↔tick windows).
// - `set`: Linux-ordered admission for every `IPPROTO_TCP` write.
// - `get`: Linux value/length table for every `IPPROTO_TCP` read.
// - `ca`: the congestion-control registry names resolve through.
// - `ulp`: the upper-layer-protocol registry names resolve through.
// - `repair`: `TCP_REPAIR_WINDOW` / `TCP_REPAIR_OPTIONS` operand shapes.
// - `defer`: the `TCP_DEFER_ACCEPT` hand-over rule.
// - `apply`: pushes accepted option state into a live connection.
// - `zerocopy`: `TCP_ZEROCOPY_RECEIVE`'s operand layout and decision rules.
// - `tests`: hosted coverage for the ordering, capability, and length rules.
//
// No target gate: the decision logic must run under hosted `cargo test`.

pub mod set;
pub mod get;
pub mod ca;
pub mod ulp;
pub mod repair;
pub mod apply;
pub mod zerocopy;
#[cfg(test)]
mod tests;

use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU8, Ordering};
use alloc::sync::Arc;
use alloc::vec::Vec;
use sync::{Spinlock, Socket as SockLockClass};

pub use ca::{CA_NAME_MAX, CongestionAlgo};
pub use ulp::ULP_NAME_MAX;
pub use repair::{RepairOpt, RepairWindow, REPAIR_OPT_LEN, REPAIR_WINDOW_LEN};

pub const SOL_TCP: u64 = 6;

pub const TCP_NODELAY: u64 = 1;
pub const TCP_MAXSEG: u64 = 2;
pub const TCP_CORK: u64 = 3;
pub const TCP_KEEPIDLE: u64 = 4;
pub const TCP_KEEPINTVL: u64 = 5;
pub const TCP_KEEPCNT: u64 = 6;
pub const TCP_SYNCNT: u64 = 7;
pub const TCP_LINGER2: u64 = 8;
pub const TCP_DEFER_ACCEPT: u64 = 9;
pub const TCP_WINDOW_CLAMP: u64 = 10;
pub const TCP_INFO: u64 = 11;
pub const TCP_QUICKACK: u64 = 12;
pub const TCP_CONGESTION: u64 = 13;
pub const TCP_MD5SIG: u64 = 14;
pub const TCP_THIN_LINEAR_TIMEOUTS: u64 = 16;
pub const TCP_THIN_DUPACK: u64 = 17;
pub const TCP_USER_TIMEOUT: u64 = 18;
pub const TCP_REPAIR: u64 = 19;
pub const TCP_REPAIR_QUEUE: u64 = 20;
pub const TCP_QUEUE_SEQ: u64 = 21;
pub const TCP_REPAIR_OPTIONS: u64 = 22;
pub const TCP_FASTOPEN: u64 = 23;
pub const TCP_TIMESTAMP: u64 = 24;
pub const TCP_NOTSENT_LOWAT: u64 = 25;
pub const TCP_CC_INFO: u64 = 26;
pub const TCP_SAVE_SYN: u64 = 27;
pub const TCP_SAVED_SYN: u64 = 28;
pub const TCP_REPAIR_WINDOW: u64 = 29;
pub const TCP_FASTOPEN_CONNECT: u64 = 30;
pub const TCP_ULP: u64 = 31;
pub const TCP_MD5SIG_EXT: u64 = 32;
pub const TCP_FASTOPEN_KEY: u64 = 33;
pub const TCP_FASTOPEN_NO_COOKIE: u64 = 34;
pub const TCP_ZEROCOPY_RECEIVE: u64 = 35;
/// `TCP_CM_INQ` is the same number under its cmsg-type spelling.
pub const TCP_INQ: u64 = 36;
pub const TCP_CM_INQ: u64 = TCP_INQ;
pub const TCP_TX_DELAY: u64 = 37;
pub const TCP_AO_ADD_KEY: u64 = 38;
pub const TCP_AO_DEL_KEY: u64 = 39;
pub const TCP_AO_INFO: u64 = 40;
pub const TCP_AO_GET_KEYS: u64 = 41;
pub const TCP_AO_REPAIR: u64 = 42;
pub const TCP_IS_MPTCP: u64 = 43;
pub const TCP_RTO_MAX_MS: u64 = 44;
pub const TCP_RTO_MIN_US: u64 = 45;
pub const TCP_DELACK_MAX_US: u64 = 46;

/// `TCP_REPAIR` operand window.
pub const TCP_REPAIR_ON: i32 = 1;
pub const TCP_REPAIR_OFF: i32 = 0;
pub const TCP_REPAIR_OFF_NO_WP: i32 = -1;

/// `TCP_REPAIR_QUEUE` operands, bounded by `TCP_QUEUES_NR`.
pub const TCP_NO_QUEUE: i32 = 0;
pub const TCP_RECV_QUEUE: i32 = 1;
pub const TCP_SEND_QUEUE: i32 = 2;
pub const TCP_QUEUES_NR: i32 = 3;

/// `TCP_SAVE_SYN`: 0 disabled, 1 from the network header, 2 from the link
/// header.
pub const SAVE_SYN_MAX: i32 = 2;

/// The ceilings the keepalive and SYN counters accept.
pub const MAX_TCP_KEEPIDLE: i32 = 32767;
pub const MAX_TCP_KEEPINTVL: i32 = 32767;
pub const MAX_TCP_KEEPCNT: i32 = 127;
pub const MAX_TCP_SYNCNT: i32 = 127;

/// `TCP_MIN_MSS` and `MAX_TCP_WINDOW` bound a `TCP_MAXSEG` request.
pub const TCP_MIN_MSS: i32 = 88;
pub const MAX_TCP_WINDOW: i32 = 32767;

/// The largest window scale `TCP_REPAIR_OPTIONS` accepts.
pub const TCP_MAX_WSCALE: u32 = crate::tcp_hdr::WSCALE_MAX as u32;

/// The seconds ceiling `TCP_LINGER2` saturates to.
pub const TCP_FIN_TIMEOUT_MAX_S: i32 = 120;
/// The FIN-WAIT-2 default in seconds — what `TCP_LINGER2` reads back when the
/// socket never named one.
pub const TCP_FIN_TIMEOUT_S: i32 = 60;
/// The SYN retransmit default — what `TCP_SYNCNT` reads back unset.
pub const TCP_SYN_RETRIES: i32 = 6;

/// The initial and ceiling retransmit timeouts, in seconds, that
/// `TCP_DEFER_ACCEPT` converts a seconds request against.
pub const TCP_TIMEOUT_INIT_S: i32 = 1;
pub const TCP_RTO_MAX_SEC: i32 = 120;

/// Timer granularity in ticks per second. The `TCP_RTO_*` and
/// `TCP_DELACK_MAX_US` windows are expressed in ticks, so their accepted value
/// ranges follow from it.
pub const HZ: i64 = 1000;
/// The floor, in ticks, for any of those timer windows.
pub const TCP_TIMEOUT_MIN_TICKS: i64 = 2;
/// The retransmit-timeout floor and the delayed-ACK ceiling, both `HZ/5`.
pub const TCP_RTO_MIN_TICKS: i64 = HZ / 5;
pub const TCP_DELACK_MAX_TICKS: i64 = HZ / 5;

/// `TCP_TX_DELAY` is folded into a `u32` smoothed-RTT estimate shifted by 3,
/// so the accepted delay is bounded by the bits that leaves.
pub const TX_DELAY_LIMIT: i32 = 1 << (31 - 3);

/// Nanoseconds per tick / millisecond / microsecond, for the `apply` transforms.
pub const NS_PER_TICK: u64 = 1_000_000_000 / HZ as u64;
pub const NS_PER_MS: u64 = 1_000_000;
pub const NS_PER_S: u64 = 1_000_000_000;

/// The floor a non-zero `TCP_WINDOW_CLAMP` is raised to. # C: O(1)
pub fn window_clamp_floor() -> i32 { crate::sysctl::SOCK_MIN_RCVBUF / 2 }

/// Microseconds rounded up to whole timer ticks. # C: O(1)
pub fn usecs_to_ticks(usec: i32) -> i64 {
    let usec = usec as i64;
    if usec <= 0 { return 0; }
    (usec.saturating_mul(HZ) + 999_999) / 1_000_000
}

/// Milliseconds rounded up to whole timer ticks. # C: O(1)
pub fn msecs_to_ticks(msec: i32) -> i64 {
    let msec = msec as i64;
    if msec <= 0 { return 0; }
    (msec.saturating_mul(HZ) + 999) / 1000
}

/// How many retransmits fit in `seconds`, given the initial timeout and the
/// exponential backoff ceiling — the form `TCP_DEFER_ACCEPT` stores.
/// # C: O(retransmits)
pub fn secs_to_retrans(seconds: i32, timeout: i32, rto_max: i32) -> u8 {
    if seconds <= 0 { return 0; }
    let mut res: u8 = 1;
    let mut timeout = timeout;
    let mut period = timeout;
    while seconds > period && res < u8::MAX {
        res += 1;
        timeout = timeout.saturating_mul(2);
        if timeout > rto_max { timeout = rto_max; }
        period = period.saturating_add(timeout);
    }
    res
}

/// The seconds window `retrans` retransmits cover — what `TCP_DEFER_ACCEPT`
/// reads back. # C: O(retransmits)
pub fn retrans_to_secs(retrans: u8, timeout: i32, rto_max: i32) -> i32 {
    let mut period = 0i32;
    let mut delta = timeout;
    for _ in 0..retrans {
        period = period.saturating_add(delta);
        delta = delta.saturating_mul(2);
        if delta > rto_max { delta = rto_max; }
    }
    period
}

/// Per-socket `IPPROTO_TCP` option state. Each field is the value one option
/// number owns; the transforms that produce it live above, and the connection
/// state it drives is installed by `apply`.
pub struct TcpOpts {
    /// `TCP_MAXSEG` (the caller-advertised MSS); 0 = never named.
    pub maxseg: AtomicI32,
    /// `TCP_SYNCNT`; 0 = follow the namespace default.
    pub syncnt: AtomicI32,
    /// `TCP_LINGER2` in seconds; `-1` = leave FIN-WAIT-2 at once, `0` = follow
    /// the namespace FIN timeout.
    pub linger2_s: AtomicI32,
    /// `TCP_DEFER_ACCEPT` as the retransmit count it is stored as.
    pub defer_accept: AtomicU8,
    /// `TCP_WINDOW_CLAMP`; 0 = unclamped.
    pub window_clamp: AtomicI32,
    /// `TCP_QUICKACK` cleared means the socket is in ping-pong (delayed-ACK)
    /// mode, which is the inverse of what the option reads back.
    pub pingpong: AtomicBool,
    /// `TCP_CONGESTION` as a registry slot.
    pub congestion: AtomicU8,
    /// The socket named its congestion control, so a route-supplied algorithm
    /// must not overwrite it.
    pub congestion_setsockopt: AtomicBool,
    /// `TCP_THIN_LINEAR_TIMEOUTS`.
    pub thin_lto: AtomicBool,
    /// `TCP_USER_TIMEOUT` in milliseconds; 0 = no caller-imposed limit.
    pub user_timeout_ms: AtomicI32,
    /// `TCP_REPAIR` and `TCP_REPAIR_QUEUE`.
    pub repair: AtomicBool,
    pub repair_queue: AtomicI32,
    /// `TCP_SAVE_SYN` mode, and the bytes it captured for `TCP_SAVED_SYN`.
    pub save_syn: AtomicI32,
    pub saved_syn: Spinlock<Option<Vec<u8>>, SockLockClass>,
    /// This socket's accept queue's fast-open state: the bound `TCP_FASTOPEN`
    /// names and the keys `TCP_FASTOPEN_KEY` installs. Held here rather than
    /// as two option values because it belongs to the accept queue, which
    /// outlives a `shutdown` and is NOT what a socket accepted from this one
    /// comes away with.
    pub fastopen: Arc<crate::tcp_fastopen::FastOpenQueue>,
    /// `TCP_FASTOPEN_CONNECT` and `TCP_FASTOPEN_NO_COOKIE` — per-socket, and
    /// the only two of the family that are.
    pub fastopen_connect: AtomicBool,
    pub fastopen_no_cookie: AtomicBool,
    /// `TCP_TIMESTAMP`: the caller-installed TSval bias, and the low bit that
    /// selects a microsecond timestamp clock.
    pub tsoffset: AtomicI32,
    pub usec_ts: AtomicBool,
    /// `TCP_NOTSENT_LOWAT`; `u32::MAX` = the option is not limiting writes.
    pub notsent_lowat: AtomicU32,
    /// `TCP_INQ`: report the unread byte count as a receive cmsg.
    pub recvmsg_inq: AtomicBool,
    /// `TCP_TX_DELAY` in microseconds.
    pub tx_delay_us: AtomicI32,
    /// `TCP_RTO_MAX_MS`, `TCP_RTO_MIN_US`, `TCP_DELACK_MAX_US` as tick counts;
    /// 0 = follow the transport default.
    pub rto_max_ticks: AtomicI32,
    pub rto_min_ticks: AtomicI32,
    pub delack_max_ticks: AtomicI32,
}

/// Reported without the two variable-length values, whose locks must not be
/// taken from a diagnostic path.
impl core::fmt::Debug for TcpOpts {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TcpOpts")
            .field("congestion", &self.algo())
            .field("repair", &self.repair.load(Ordering::Acquire))
            .field("notsent_lowat", &self.notsent_lowat.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl Default for TcpOpts {
    fn default() -> Self {
        Self {
            maxseg: AtomicI32::new(0),
            syncnt: AtomicI32::new(0),
            linger2_s: AtomicI32::new(0),
            defer_accept: AtomicU8::new(0),
            window_clamp: AtomicI32::new(0),
            pingpong: AtomicBool::new(false),
            congestion: AtomicU8::new(ca::DEFAULT.as_u8()),
            congestion_setsockopt: AtomicBool::new(false),
            thin_lto: AtomicBool::new(false),
            user_timeout_ms: AtomicI32::new(0),
            repair: AtomicBool::new(false),
            repair_queue: AtomicI32::new(TCP_NO_QUEUE),
            save_syn: AtomicI32::new(0),
            saved_syn: Spinlock::new(None),
            fastopen: Arc::new(crate::tcp_fastopen::FastOpenQueue::new()),
            fastopen_connect: AtomicBool::new(false),
            fastopen_no_cookie: AtomicBool::new(false),
            tsoffset: AtomicI32::new(0),
            usec_ts: AtomicBool::new(false),
            notsent_lowat: AtomicU32::new(u32::MAX),
            recvmsg_inq: AtomicBool::new(false),
            tx_delay_us: AtomicI32::new(0),
            rto_max_ticks: AtomicI32::new(0),
            rto_min_ticks: AtomicI32::new(0),
            delack_max_ticks: AtomicI32::new(0),
        }
    }
}

impl TcpOpts {
    /// The congestion control this socket selects. # C: O(1)
    pub fn algo(&self) -> CongestionAlgo {
        CongestionAlgo::from_u8(self.congestion.load(Ordering::Acquire))
    }

    /// Copy a listener's `IPPROTO_TCP` policy onto a socket accepted from it —
    /// the state a child inherits through the request socket. # C: O(1)
    pub fn inherit(&self, src: &TcpOpts) {
        macro_rules! copy_i32 { ($f:ident) => {
            self.$f.store(src.$f.load(Ordering::Acquire), Ordering::Release) }; }
        macro_rules! copy_bool { ($f:ident) => {
            self.$f.store(src.$f.load(Ordering::Acquire), Ordering::Release) }; }
        copy_i32!(maxseg); copy_i32!(syncnt); copy_i32!(linger2_s);
        copy_i32!(window_clamp); copy_i32!(user_timeout_ms); copy_i32!(save_syn);
        copy_i32!(tx_delay_us); copy_i32!(rto_max_ticks); copy_i32!(rto_min_ticks);
        copy_i32!(delack_max_ticks);
        copy_bool!(congestion); copy_bool!(congestion_setsockopt); copy_bool!(thin_lto);
        copy_bool!(fastopen_no_cookie); copy_bool!(recvmsg_inq); copy_bool!(pingpong);
        self.notsent_lowat.store(src.notsent_lowat.load(Ordering::Acquire), Ordering::Release);
    }
}
