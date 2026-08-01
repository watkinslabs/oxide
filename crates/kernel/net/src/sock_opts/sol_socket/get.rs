// Linux value/length table for every SOL_SOCKET `getsockopt` read.

use syscall::errno::Errno;
use super::*;

/// Non-generic socket state the SOL_SOCKET read table needs, snapshotted by
/// the caller before the table runs. # C: O(1)
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub struct SockView {
    pub sock: OptSock,
    pub reuseaddr: i32,
    pub reuseport: i32,
    pub keepalive: i32,
    pub broadcast: i32,
    pub oobinline: i32,
    pub sndbuf: i32,
    pub rcvbuf: i32,
    pub priority: i32,
    pub mark: i32,
    pub passcred: i32,
    pub timestamping_flags: i32,
    pub sndtimeo_ns: i64,
    pub rcvtimeo_ns: i64,
    pub bound_ifindex: i32,
    pub acceptconn: i32,
    pub socket_type: i32,
    pub protocol: i32,
    pub netns_cookie: u64,
    pub socket_cookie: u64,
    /// `sk_napi_id` recorded by the receive path. Identifiers below
    /// `MIN_NAPI_ID` are reserved and aggregate to zero on the way out.
    pub napi_id: u32,
}

/// One SOL_SOCKET read result plus the natural Linux length. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Value {
    Int(i32),
    /// `u64` payload whose natural length is eight bytes.
    U64(u64),
    Linger { on: i32, seconds: i32 },
    Timeval { sec: i64, usec: i64 },
    TxTime { clockid: i32, flags: u32 },
    Timestamping { flags: i32, bind_phc: i32 },
}

/// Natural `lv` for the value — the length Linux truncates the request to.
/// # C: O(1)
pub fn natural_len(value: &Value) -> usize {
    match value {
        Value::Int(_) => 4,
        Value::U64(_) => 8,
        Value::Linger { .. } => 8,
        Value::Timeval { .. } => 16,
        Value::TxTime { .. } => 8,
        Value::Timestamping { .. } => 8,
    }
}

/// Little/big-endian-neutral native encoding of the value. Returns the
/// natural length written into `out`. # C: O(1)
pub fn encode(value: &Value, out: &mut [u8; 16]) -> usize {
    match value {
        Value::Int(v) => { out[..4].copy_from_slice(&v.to_ne_bytes()); 4 }
        Value::U64(v) => { out[..8].copy_from_slice(&v.to_ne_bytes()); 8 }
        Value::Linger { on, seconds } => {
            out[..4].copy_from_slice(&on.to_ne_bytes());
            out[4..8].copy_from_slice(&seconds.to_ne_bytes());
            8
        }
        Value::Timeval { sec, usec } => {
            out[..8].copy_from_slice(&sec.to_ne_bytes());
            out[8..16].copy_from_slice(&usec.to_ne_bytes());
            16
        }
        Value::TxTime { clockid, flags } => {
            out[..4].copy_from_slice(&clockid.to_ne_bytes());
            out[4..8].copy_from_slice(&flags.to_ne_bytes());
            8
        }
        Value::Timestamping { flags, bind_phc } => {
            out[..4].copy_from_slice(&flags.to_ne_bytes());
            out[4..8].copy_from_slice(&bind_phc.to_ne_bytes());
            8
        }
    }
}

/// `sk_getsockopt` for the options whose value is fully described by generic
/// socket state. `requested` is the caller's `optlen` after the `len < 0`
/// screen. Options with their own copyout shape (`SO_ERROR`, `SO_PEERCRED`,
/// `SO_PEERPIDFD`, `SO_BINDTODEVICE`, `SO_PEERNAME`, `SO_PEERSEC`,
/// `SO_PEERGROUPS`, `SO_MEMINFO`, `SO_GET_FILTER`, `SO_LOCK_FILTER`) are the
/// caller's responsibility and reach this table as `ENOPROTOOPT`.
/// `SO_BUSY_POLL_BUDGET` has no read direction. # C: O(1)
pub fn value(optname: u64, requested: i32, state: &GenericSockOpts, view: &SockView)
    -> Result<Value, Errno>
{
    let flag_int = |bit: u64| Value::Int(i32::from(state.flag(bit)));
    Ok(match optname {
        SO_DEBUG => flag_int(flag::DEBUG),
        SO_DONTROUTE => flag_int(flag::LOCALROUTE),
        SO_BROADCAST => Value::Int(view.broadcast),
        SO_SNDBUF => Value::Int(view.sndbuf),
        SO_RCVBUF => Value::Int(view.rcvbuf),
        SO_REUSEADDR => Value::Int(view.reuseaddr),
        SO_REUSEPORT => Value::Int(view.reuseport),
        SO_KEEPALIVE => Value::Int(view.keepalive),
        SO_TYPE => Value::Int(view.socket_type),
        SO_PROTOCOL => Value::Int(view.protocol),
        SO_DOMAIN => Value::Int(view.sock.family as i32),
        SO_OOBINLINE => Value::Int(view.oobinline),
        SO_NO_CHECK => flag_int(flag::NO_CHECK_TX),
        SO_PRIORITY => Value::Int(view.priority),
        SO_LINGER => Value::Linger {
            on: i32::from(state.flag(flag::LINGER)),
            seconds: state.scalar(Scalar::LingerSeconds),
        },
        // Linux keeps the option settable and readable but stores nothing.
        SO_BSDCOMPAT => Value::Int(0),
        SO_TIMESTAMP_OLD => Value::Int(i32::from(
            state.flag(flag::RCVTSTAMP) && !state.flag(flag::TSTAMP_NEW)
                && !state.flag(flag::RCVTSTAMPNS))),
        SO_TIMESTAMPNS_OLD => Value::Int(i32::from(
            state.flag(flag::RCVTSTAMPNS) && !state.flag(flag::TSTAMP_NEW))),
        SO_TIMESTAMP_NEW => Value::Int(i32::from(
            state.flag(flag::RCVTSTAMP) && state.flag(flag::TSTAMP_NEW))),
        SO_TIMESTAMPNS_NEW => Value::Int(i32::from(
            state.flag(flag::RCVTSTAMPNS) && state.flag(flag::TSTAMP_NEW))),
        SO_TIMESTAMPING_OLD | SO_TIMESTAMPING_NEW => {
            // The newer option reports flags only when they were set through
            // the same option; the legacy one always reports them.
            if optname == SO_TIMESTAMPING_OLD || state.flag(flag::TSTAMP_NEW) {
                Value::Timestamping {
                    flags: view.timestamping_flags,
                    bind_phc: state.scalar(Scalar::TimestampingBindPhc),
                }
            } else {
                Value::Timestamping { flags: 0, bind_phc: 0 }
            }
        }
        SO_RCVTIMEO_OLD | SO_RCVTIMEO_NEW => {
            let (sec, usec) = timeval_from_timeout_ns(view.rcvtimeo_ns);
            Value::Timeval { sec, usec }
        }
        SO_SNDTIMEO_OLD | SO_SNDTIMEO_NEW => {
            let (sec, usec) = timeval_from_timeout_ns(view.sndtimeo_ns);
            Value::Timeval { sec, usec }
        }
        SO_RCVLOWAT => Value::Int(state.scalar(Scalar::RcvLowat)),
        SO_SNDLOWAT => Value::Int(SNDLOWAT),
        SO_PASSCRED => {
            if !view.sock.may_scm_recv() { return Err(Errno::Eopnotsupp); }
            Value::Int(view.passcred)
        }
        SO_PASSSEC => {
            if !view.sock.may_scm_recv() { return Err(Errno::Eopnotsupp); }
            flag_int(flag::SCM_SECURITY)
        }
        SO_PASSPIDFD => {
            if !view.sock.unix() { return Err(Errno::Eopnotsupp); }
            flag_int(flag::SCM_PIDFD)
        }
        SO_PASSRIGHTS => {
            if !view.sock.unix() { return Err(Errno::Eopnotsupp); }
            Value::Int(i32::from(!state.flag(flag::SCM_RIGHTS_OFF)))
        }
        SO_ACCEPTCONN => Value::Int(view.acceptconn),
        SO_MARK => Value::Int(view.mark),
        SO_RCVMARK => flag_int(flag::RCVMARK),
        SO_RCVPRIORITY => flag_int(flag::RCVPRIORITY),
        SO_RXQ_OVFL => flag_int(flag::RXQ_OVFL),
        SO_WIFI_STATUS => flag_int(flag::WIFI_STATUS),
        SO_PEEK_OFF => {
            if !view.sock.peek_off_capable { return Err(Errno::Eopnotsupp); }
            Value::Int(state.scalar(Scalar::PeekOff))
        }
        SO_NOFCS => flag_int(flag::NOFCS),
        SO_BPF_EXTENSIONS => Value::Int(BPF_EXTENSIONS),
        SO_SELECT_ERR_QUEUE => flag_int(flag::SELECT_ERR_QUEUE),
        SO_BUSY_POLL => Value::Int(state.scalar(Scalar::BusyPoll)),
        SO_PREFER_BUSY_POLL => flag_int(flag::PREFER_BUSY_POLL),
        SO_INCOMING_NAPI_ID =>
            Value::Int(if view.napi_id >= MIN_NAPI_ID { view.napi_id as i32 } else { 0 }),
        SO_MAX_PACING_RATE => {
            // The 64-bit form is used only when the caller offers room for it.
            let rate = state.max_pacing_rate();
            if requested as usize >= core::mem::size_of::<u64>() { Value::U64(rate) }
            else { Value::Int(rate.min(u32::MAX as u64) as u32 as i32) }
        }
        SO_INCOMING_CPU => Value::Int(state.scalar(Scalar::IncomingCpu)),
        SO_COOKIE => {
            if (requested as usize) < core::mem::size_of::<u64>() { return Err(Errno::Einval); }
            Value::U64(view.socket_cookie)
        }
        SO_ZEROCOPY => flag_int(flag::ZEROCOPY),
        SO_TXTIME => Value::TxTime {
            clockid: state.scalar(Scalar::TxTimeClockid),
            flags: u32::from(state.flag(flag::TXTIME_DEADLINE_MODE)) * SOF_TXTIME_DEADLINE_MODE
                | u32::from(state.flag(flag::TXTIME_REPORT_ERRORS)) * SOF_TXTIME_REPORT_ERRORS,
        },
        SO_BINDTOIFINDEX => Value::Int(view.bound_ifindex),
        SO_NETNS_COOKIE => {
            if requested as usize != core::mem::size_of::<u64>() { return Err(Errno::Einval); }
            Value::U64(view.netns_cookie)
        }
        SO_BUF_LOCK => Value::Int(state.scalar(Scalar::BufLock) & SOCK_BUF_LOCK_MASK),
        SO_RESERVE_MEM => Value::Int(state.scalar(Scalar::ReserveMem)),
        SO_TXREHASH => {
            if !view.sock.tcp { return Err(Errno::Eopnotsupp); }
            Value::Int(state.scalar(Scalar::TxRehash))
        }
        _ => return Err(Errno::Enoprotoopt),
    })
}
