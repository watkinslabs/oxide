// SOL_SOCKET generic option table for `setsockopt`/`getsockopt` (slots 54/55).
//
// Module manifest:
// - this file: UAPI numbers, caller/socket context types, generic option
//   storage, and the shared value transforms.
// - `set`: Linux-ordered admission for every SOL_SOCKET write.
// - `get`: Linux value/length table for every SOL_SOCKET read.
// - `varlen`: the reads whose value is not one fixed-width scalar.
// - `tests`: hosted coverage for the ordering, capability, and length rules.
//
// No target gate: the decision logic must run under hosted `cargo test`.

// The six numbers `vsock_socket` also needs live in the crate's ungated UAPI
// owner; re-exported here so this table stays the single place to look.
pub use crate::uapi::{SOL_SOCKET, SO_ACCEPTCONN, SO_DOMAIN, SO_OOBINLINE, SO_PROTOCOL, SO_TYPE,
    SO_ZEROCOPY};

pub mod set;
pub mod get;
pub mod varlen;
#[cfg(test)]
mod tests;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicI32, AtomicI64, AtomicU64, Ordering};


pub const SO_DEBUG: u64 = 1;
pub const SO_REUSEADDR: u64 = 2;
pub const SO_ERROR: u64 = 4;
pub const SO_DONTROUTE: u64 = 5;
pub const SO_BROADCAST: u64 = 6;
pub const SO_SNDBUF: u64 = 7;
pub const SO_RCVBUF: u64 = 8;
pub const SO_KEEPALIVE: u64 = 9;
pub const SO_NO_CHECK: u64 = 11;
pub const SO_PRIORITY: u64 = 12;
pub const SO_LINGER: u64 = 13;
pub const SO_BSDCOMPAT: u64 = 14;
pub const SO_REUSEPORT: u64 = 15;
pub const SO_PASSCRED: u64 = 16;
pub const SO_PEERCRED: u64 = 17;
pub const SO_RCVLOWAT: u64 = 18;
pub const SO_SNDLOWAT: u64 = 19;
pub const SO_RCVTIMEO_OLD: u64 = 20;
pub const SO_SNDTIMEO_OLD: u64 = 21;
pub const SO_BINDTODEVICE: u64 = 25;
pub const SO_ATTACH_FILTER: u64 = 26;
pub const SO_DETACH_FILTER: u64 = 27;
pub const SO_PEERNAME: u64 = 28;
pub const SO_TIMESTAMP_OLD: u64 = 29;
pub const SO_PEERSEC: u64 = 31;
pub const SO_SNDBUFFORCE: u64 = 32;
pub const SO_RCVBUFFORCE: u64 = 33;
pub const SO_PASSSEC: u64 = 34;
pub const SO_TIMESTAMPNS_OLD: u64 = 35;
pub const SO_MARK: u64 = 36;
pub const SO_TIMESTAMPING_OLD: u64 = 37;
pub const SO_RXQ_OVFL: u64 = 40;
pub const SO_WIFI_STATUS: u64 = 41;
pub const SO_PEEK_OFF: u64 = 42;
pub const SO_NOFCS: u64 = 43;
pub const SO_LOCK_FILTER: u64 = 44;
pub const SO_SELECT_ERR_QUEUE: u64 = 45;
pub const SO_BUSY_POLL: u64 = 46;
pub const SO_MAX_PACING_RATE: u64 = 47;
pub const SO_BPF_EXTENSIONS: u64 = 48;
pub const SO_INCOMING_CPU: u64 = 49;
pub const SO_ATTACH_BPF: u64 = 50;
pub const SO_ATTACH_REUSEPORT_CBPF: u64 = 51;
pub const SO_ATTACH_REUSEPORT_EBPF: u64 = 52;
pub const SO_CNX_ADVICE: u64 = 53;
pub const SO_MEMINFO: u64 = 55;
pub const SO_INCOMING_NAPI_ID: u64 = 56;
pub const SO_COOKIE: u64 = 57;
pub const SO_PEERGROUPS: u64 = 59;
pub const SO_TXTIME: u64 = 61;
pub const SO_BINDTOIFINDEX: u64 = 62;
pub const SO_TIMESTAMP_NEW: u64 = 63;
pub const SO_TIMESTAMPNS_NEW: u64 = 64;
pub const SO_TIMESTAMPING_NEW: u64 = 65;
pub const SO_RCVTIMEO_NEW: u64 = 66;
pub const SO_SNDTIMEO_NEW: u64 = 67;
pub const SO_DETACH_REUSEPORT_BPF: u64 = 68;
pub const SO_PREFER_BUSY_POLL: u64 = 69;
pub const SO_BUSY_POLL_BUDGET: u64 = 70;
pub const SO_NETNS_COOKIE: u64 = 71;
pub const SO_BUF_LOCK: u64 = 72;
pub const SO_RESERVE_MEM: u64 = 73;
pub const SO_TXREHASH: u64 = 74;
pub const SO_RCVMARK: u64 = 75;
pub const SO_PASSPIDFD: u64 = 76;
pub const SO_PEERPIDFD: u64 = 77;
pub const SO_DEVMEM_DONTNEED: u64 = 80;
pub const SO_RCVPRIORITY: u64 = 82;
pub const SO_PASSRIGHTS: u64 = 83;
/// `SO_INQ` doubles as the `SCM_INQ` control-message type it enables.
pub const SO_INQ: u64 = 84;
pub const SCM_INQ: i32 = SO_INQ as i32;
/// `SO_GET_FILTER` shares `SO_ATTACH_FILTER`'s number; the read direction gives
/// it the separate meaning.
pub const SO_GET_FILTER: u64 = SO_ATTACH_FILTER;

/// `SOCK_SNDBUF_LOCK | SOCK_RCVBUF_LOCK`.
pub const SOCK_BUF_LOCK_MASK: i32 = 3;
pub const SOCK_SNDBUF_LOCK: i32 = 1;
pub const SOCK_RCVBUF_LOCK: i32 = 2;
/// `SOF_TXTIME_DEADLINE_MODE | SOF_TXTIME_REPORT_ERRORS`.
pub const SOF_TXTIME_FLAGS_MASK: u32 = 3;
pub const SOF_TXTIME_DEADLINE_MODE: u32 = 1;
pub const SOF_TXTIME_REPORT_ERRORS: u32 = 2;
/// `TC_PRIO_BESTEFFORT ..= TC_PRIO_INTERACTIVE` — the unprivileged band.
pub const TC_PRIO_BESTEFFORT: i32 = 0;
pub const TC_PRIO_INTERACTIVE: i32 = 6;
/// The buffer floors and ceilings are owned by the sysctl leaves that publish
/// them; re-exported so this table stays the single place to look.
pub use crate::sysctl::{BufCeilings, DEFAULT_RMEM_MAX, DEFAULT_WMEM_MAX, SOCK_MIN_RCVBUF,
    SOCK_MIN_SNDBUF};
/// `SO_SNDLOWAT` is fixed at one byte and is not settable.
pub const SNDLOWAT: i32 = 1;
/// `bpf_tell_extensions()` — the classic-BPF ancillary extension count.
pub const BPF_EXTENSIONS: i32 = 42;
/// `SO_BUSY_POLL_BUDGET` is a `u16` field.
pub const BUSY_POLL_BUDGET_MAX: i32 = u16::MAX as i32;
/// `MIN_NAPI_ID`: smaller identifiers are reserved, so `SO_INCOMING_NAPI_ID`
/// aggregates every non-NAPI receive down to zero.
pub const MIN_NAPI_ID: u32 = 8;
/// `SK_MEMINFO_VARS` — the `u32` slot count `SO_MEMINFO` writes back.
pub const SK_MEMINFO_VARS: usize = 9;
/// `struct dmabuf_token` is two `u32`s, and `SO_DEVMEM_DONTNEED` accepts at
/// most `MAX_DONTNEED_TOKENS` of them in one call.
pub const DEVMEM_TOKEN_SIZE: usize = 8;
pub const MAX_DONTNEED_TOKENS: usize = 128;

const USEC_PER_SEC: i64 = 1_000_000;
const NSEC_PER_SEC: i64 = 1_000_000_000;
const NSEC_PER_USEC: i64 = 1_000;
/// Stored `*timeo_ns` for a caller-requested immediate timeout: Linux writes a
/// jiffy count of `0`, which makes the very next wait give up at once. Oxide
/// keeps `0` for "wait forever", so an already-expired one-nanosecond deadline
/// carries the same observable meaning.
pub const IMMEDIATE_TIMEOUT_NS: i64 = 1;

/// Caller capabilities in the socket's owning user namespace. # C: O(1)
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub struct OptCaps { pub net_admin: bool, pub net_raw: bool }

impl OptCaps {
    /// Options gated on "either network capability". # C: O(1)
    pub fn net_raw_or_admin(&self) -> bool { self.net_raw || self.net_admin }
}

/// Socket personality the SOL_SOCKET table branches on. # C: O(1)
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub struct OptSock {
    pub family: u16,
    /// `sk_type == SOCK_STREAM`.
    pub stream: bool,
    /// `sk_is_tcp`.
    pub tcp: bool,
    /// `sk_type == SOCK_DGRAM && sk_protocol == IPPROTO_UDP`.
    pub udp: bool,
    /// The socket carries a `set_peek_off` operation.
    pub peek_off_capable: bool,
}

impl OptSock {
    /// `sk_is_inet`. # C: O(1)
    pub fn inet(&self) -> bool {
        self.family == crate::socket_args::AF_INET as u16
            || self.family == crate::socket_args::AF_INET6 as u16
    }
    /// `sk_is_unix`. # C: O(1)
    pub fn unix(&self) -> bool { self.family == crate::socket_args::AF_UNIX as u16 }
    /// `sk_may_scm_recv`. # C: O(1)
    pub fn may_scm_recv(&self) -> bool { crate::scm::may_scm_recv(self.family) }
}

/// `sock_flag` bits the generic table owns. Values are private to this crate;
/// only the option numbers above are ABI. # C: O(1)
pub mod flag {
    pub const DEBUG: u64 = 1 << 0;
    pub const LOCALROUTE: u64 = 1 << 1;
    pub const NO_CHECK_TX: u64 = 1 << 2;
    pub const LINGER: u64 = 1 << 3;
    pub const RXQ_OVFL: u64 = 1 << 4;
    pub const WIFI_STATUS: u64 = 1 << 5;
    pub const NOFCS: u64 = 1 << 6;
    pub const SELECT_ERR_QUEUE: u64 = 1 << 7;
    pub const ZEROCOPY: u64 = 1 << 8;
    pub const TXTIME: u64 = 1 << 9;
    pub const RCVMARK: u64 = 1 << 10;
    pub const RCVPRIORITY: u64 = 1 << 11;
    pub const SCM_SECURITY: u64 = 1 << 12;
    pub const SCM_PIDFD: u64 = 1 << 13;
    /// `sk_scm_rights` is enabled on every AF_UNIX socket at creation, so the
    /// stored bit records the caller having turned it OFF.
    pub const SCM_RIGHTS_OFF: u64 = 1 << 14;
    pub const TXTIME_DEADLINE_MODE: u64 = 1 << 15;
    pub const TXTIME_REPORT_ERRORS: u64 = 1 << 16;
    pub const RCVTSTAMP: u64 = 1 << 17;
    pub const RCVTSTAMPNS: u64 = 1 << 18;
    pub const TSTAMP_NEW: u64 = 1 << 19;
    pub const PREFER_BUSY_POLL: u64 = 1 << 20;
}

/// Indexed scalar slots the generic table owns. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Scalar {
    RcvLowat = 0,
    /// `SO_INQ` — AF_UNIX stream `recvmsg_inq`.
    Inq = 11,
    PeekOff = 1,
    IncomingCpu = 2,
    BusyPoll = 3,
    BufLock = 4,
    ReserveMem = 5,
    TxRehash = 6,
    LingerSeconds = 7,
    TxTimeClockid = 8,
    TimestampingBindPhc = 9,
    BusyPollBudget = 10,
}

impl Scalar { pub const COUNT: usize = 12; }

/// Generic SOL_SOCKET state Linux keeps on every `struct sock`. # C: O(1)
#[derive(Debug)]
pub struct GenericSockOpts {
    flags: AtomicU64,
    scalars: [AtomicI32; Scalar::COUNT],
    max_pacing_rate: Arc<AtomicU64>,
    cookie: AtomicI64,
}

impl Default for GenericSockOpts {
    fn default() -> Self {
        Self {
            flags: AtomicU64::new(0),
            scalars: {
                let slots = [const { AtomicI32::new(0) }; Scalar::COUNT];
                slots[Scalar::RcvLowat as usize].store(1, Ordering::Relaxed);
                slots
            },
            max_pacing_rate: Arc::new(AtomicU64::new(u64::MAX)),
            cookie: AtomicI64::new(0),
        }
    }
}

impl GenericSockOpts {
    /// # C: O(1)
    pub fn flag(&self, bit: u64) -> bool { self.flags.load(Ordering::Acquire) & bit != 0 }

    /// # C: O(1)
    pub fn set_flag(&self, bit: u64, on: bool) {
        if on { self.flags.fetch_or(bit, Ordering::AcqRel); }
        else { self.flags.fetch_and(!bit, Ordering::AcqRel); }
    }

    /// # C: O(1)
    pub fn scalar(&self, slot: Scalar) -> i32 {
        self.scalars[slot as usize].load(Ordering::Acquire)
    }

    /// # C: O(1)
    pub fn set_scalar(&self, slot: Scalar, value: i32) {
        self.scalars[slot as usize].store(value, Ordering::Release);
    }

    /// # C: O(1)
    pub fn max_pacing_rate(&self) -> u64 { self.max_pacing_rate.load(Ordering::Acquire) }

    /// Share the sole `SO_MAX_PACING_RATE` cell with a transport owner. # C: O(1)
    pub fn max_pacing_rate_cell(&self) -> Arc<AtomicU64> { self.max_pacing_rate.clone() }

    /// Adopt the canonical transport pacing cap after a passive open. # C: O(1)
    pub fn use_max_pacing_rate_cell(&mut self, cell: Arc<AtomicU64>) {
        self.max_pacing_rate = cell;
    }

    /// # C: O(1)
    pub fn set_max_pacing_rate(&self, value: u64) {
        self.max_pacing_rate.store(value, Ordering::Release);
    }

    /// `sock_gen_cookie`: allocate once, then report the same value. # C: O(1)
    pub fn cookie(&self, next: impl FnOnce() -> i64) -> i64 {
        let current = self.cookie.load(Ordering::Acquire);
        if current != 0 { return current; }
        let candidate = next();
        match self.cookie.compare_exchange(0, candidate, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => candidate,
            Err(existing) => existing,
        }
    }
}

/// `sock_gen_cookie`: hand out a fresh, never-zero socket cookie. # C: O(1)
pub fn next_cookie() -> i64 {
    static NEXT: AtomicI64 = AtomicI64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// `sk_setsockopt`: every option except `SO_BINDTODEVICE` reads an `int`
/// first, so a short buffer is `EINVAL` and a bad pointer `EFAULT` before the
/// option number is ever classified. # C: O(1)
pub fn reads_int_argument(optname: u64) -> bool { optname != SO_BINDTODEVICE }

/// `SO_INQ` is answered by the AF_UNIX stream protocol rather than by the
/// generic table, and that path screens the length for an EXACT `int` before
/// it looks at the option number: four bytes exactly, not four or more.
/// # C: O(1)
pub fn exact_int_argument(optname: u64) -> bool { optname == SO_INQ }

/// `__sock_set_rcvbuf` / `set_sndbuf`: clamp to the sysctl ceiling as an
/// unsigned quantity, cap at `INT_MAX/2`, double, then floor at the protocol
/// minimum. The forced variants skip the ceiling and clamp negatives to zero.
/// # C: O(1)
pub fn buf_value(request: i32, minimum: i32, ceiling: u32, forced: bool) -> i32 {
    let clamped = if forced { request.max(0) } else { (request as u32).min(ceiling) as i32 };
    clamped.min(i32::MAX / 2).saturating_mul(2).max(minimum)
}

/// `sock_set_timeout`: `EDOM` outside a normalized microsecond field, an
/// immediate timeout for a negative second field, and "wait forever" for an
/// all-zero value. # C: O(1)
pub fn timeout_ns_from_timeval(sec: i64, usec: i64) -> Result<i64, syscall::errno::Errno> {
    if !(0..USEC_PER_SEC).contains(&usec) { return Err(syscall::errno::Errno::Edom); }
    if sec < 0 { return Ok(IMMEDIATE_TIMEOUT_NS); }
    if sec == 0 && usec == 0 { return Ok(0); }
    let seconds = (sec as i128).saturating_mul(NSEC_PER_SEC as i128);
    let micros = (usec as i128).saturating_mul(NSEC_PER_USEC as i128);
    Ok(seconds.saturating_add(micros).min(i64::MAX as i128) as i64)
}

/// `sock_get_timeout`: an unset or immediate timeout reports `{0, 0}`.
/// # C: O(1)
pub fn timeval_from_timeout_ns(ns: i64) -> (i64, i64) {
    if ns <= IMMEDIATE_TIMEOUT_NS { return (0, 0); }
    (ns / NSEC_PER_SEC, (ns % NSEC_PER_SEC) / NSEC_PER_USEC)
}
