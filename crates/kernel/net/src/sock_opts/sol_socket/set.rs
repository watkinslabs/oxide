// Linux-ordered admission for every SOL_SOCKET `setsockopt` write.

use syscall::errno::Errno;
use super::*;

/// Argument shape the caller must supply for one option. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ArgClass {
    /// A bare `int`.
    Int,
    /// `struct linger` — two `int`s.
    Linger,
    /// `struct __kernel_sock_timeval` — two 64-bit fields.
    Timeval,
    /// `struct sock_txtime` — `clockid` then `flags`.
    TxTime,
    /// `struct so_timestamping` when the caller supplies the full struct,
    /// otherwise the leading `int` alone.
    Timestamping,
    /// `SO_MAX_PACING_RATE` reads a `long` when the caller supplies one.
    PacingRate,
    /// `SO_BINDTODEVICE` takes a NUL-padded interface name, no `int`.
    Device,
    /// Handled by the socket-filter owner, not by this table.
    Filter,
    /// Reuseport-group program attach/detach — the reuseport owner imports the
    /// program descriptor and runs the group ladder.
    Reuseport,
    /// `SO_DEVMEM_DONTNEED` — an array of release tokens, not a scalar.
    Devmem,
}

/// One accepted SOL_SOCKET write. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Action {
    /// Accepted with no observable state change.
    Accept,
    Flag { bit: u64, on: bool },
    Reuseaddr(i32),
    Reuseport(i32),
    Keepalive(i32),
    Broadcast(i32),
    Oobinline(i32),
    SndBuf(i32),
    RcvBuf(i32),
    Priority(i32),
    Mark(i32),
    Passcred(i32),
    /// `SO_TIMESTAMPING_OLD` / `_NEW`.
    Timestamping { flags: i32, bind_phc: i32, new: bool },
    /// `SO_TIMESTAMP*` / `SO_TIMESTAMPNS*` receive-stamp personality.
    RecvTimestamps { on: bool, new: bool, nanoseconds: bool },
    Linger { on: bool, seconds: i32 },
    Timeout { send: bool, ns: i64 },
    Scalar { slot: Scalar, value: i32 },
    PacingRate(u64),
    BindToIfindex(i32),
    TxTime { clockid: i32, deadline_mode: bool, report_errors: bool },
}

/// The argument the caller actually supplied, already imported. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Arg {
    Int(i32),
    Linger { on: i32, seconds: i32 },
    Timeval { sec: i64, usec: i64 },
    TxTime { clockid: i32, flags: u32 },
    Timestamping { flags: i32, bind_phc: i32 },
    /// A wide pacing rate when the caller passed `sizeof(long)` bytes.
    PacingRate(u64),
}

impl Arg {
    fn int(self) -> i32 { if let Arg::Int(v) = self { v } else { 0 } }
    fn boolean(self) -> bool { self.int() != 0 }
}

/// Live state outside the socket personality that one write is judged against:
/// the caller's network capabilities, whether a device is already bound, the
/// send/receive ceilings, and the budget a `SO_BUSY_POLL_BUDGET` raise is
/// compared to. # C: O(1)
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub struct SetEnv {
    pub caps: OptCaps,
    pub bound_device: bool,
    pub ceilings: BufCeilings,
    pub busy_poll_budget: i32,
}

/// `CLOCK_REALTIME`, `CLOCK_MONOTONIC`, `CLOCK_TAI` — the clocks `SO_TXTIME`
/// accepts.
pub const CLOCK_REALTIME: i32 = 0;
pub const CLOCK_MONOTONIC: i32 = 1;
pub const CLOCK_TAI: i32 = 11;

/// Argument shape for one option number. # C: O(1)
pub fn arg_class(optname: u64) -> ArgClass {
    match optname {
        SO_BINDTODEVICE => ArgClass::Device,
        SO_ATTACH_FILTER | SO_DETACH_FILTER | SO_ATTACH_BPF | SO_LOCK_FILTER => ArgClass::Filter,
        SO_ATTACH_REUSEPORT_CBPF | SO_ATTACH_REUSEPORT_EBPF | SO_DETACH_REUSEPORT_BPF =>
            ArgClass::Reuseport,
        SO_DEVMEM_DONTNEED => ArgClass::Devmem,
        SO_LINGER => ArgClass::Linger,
        SO_RCVTIMEO_OLD | SO_RCVTIMEO_NEW | SO_SNDTIMEO_OLD | SO_SNDTIMEO_NEW => ArgClass::Timeval,
        SO_TXTIME => ArgClass::TxTime,
        SO_TIMESTAMPING_OLD | SO_TIMESTAMPING_NEW => ArgClass::Timestamping,
        SO_MAX_PACING_RATE => ArgClass::PacingRate,
        _ => ArgClass::Int,
    }
}

/// Linux `sk_setsockopt` admission for one SOL_SOCKET write. Callers must
/// already have enforced the leading `int` length rule
/// (`reads_int_argument`) and imported `arg` per `arg_class`. # C: O(1)
pub fn admit(optname: u64, arg: Arg, sock: OptSock, env: SetEnv) -> Result<Action, Errno> {
    let SetEnv { caps, bound_device, ceilings, busy_poll_budget } = env;
    let value = arg.int();
    let on = arg.boolean();
    match optname {
        // Read-only identity and error slots.
        SO_TYPE | SO_PROTOCOL | SO_DOMAIN | SO_ERROR => Err(Errno::Enoprotoopt),

        SO_PRIORITY => {
            let allowed = (TC_PRIO_BESTEFFORT..=TC_PRIO_INTERACTIVE).contains(&value)
                || caps.net_raw_or_admin();
            if allowed { Ok(Action::Priority(value)) } else { Err(Errno::Eperm) }
        }
        SO_BUSY_POLL => {
            if value < 0 { return Err(Errno::Einval); }
            Ok(Action::Scalar { slot: Scalar::BusyPoll, value })
        }
        SO_PREFER_BUSY_POLL => {
            if on && !caps.net_admin { return Err(Errno::Eperm); }
            Ok(Action::Flag { bit: flag::PREFER_BUSY_POLL, on })
        }
        SO_BUSY_POLL_BUDGET => {
            // Raising the budget is privileged, and that ladder runs before the
            // field-width screen, so an over-wide raise is `EPERM` not `EINVAL`.
            if value > busy_poll_budget && !caps.net_admin { return Err(Errno::Eperm); }
            if !(0..=BUSY_POLL_BUDGET_MAX).contains(&value) { return Err(Errno::Einval); }
            Ok(Action::Scalar { slot: Scalar::BusyPollBudget, value })
        }
        SO_MAX_PACING_RATE => Ok(Action::PacingRate(match arg {
            Arg::PacingRate(wide) => wide,
            _ if value as u32 == u32::MAX => u64::MAX,
            _ => value as u32 as u64,
        })),
        SO_TXREHASH => {
            if !sock.tcp { return Err(Errno::Eopnotsupp); }
            if !(-1..=1).contains(&value) { return Err(Errno::Einval); }
            // `SOCK_TXREHASH_DEFAULT` resolves to the namespace default, which
            // this stack keeps at `SOCK_TXREHASH_ENABLED`.
            let value = if value as u8 == u8::MAX { 1 } else { value };
            Ok(Action::Scalar { slot: Scalar::TxRehash, value })
        }
        SO_PEEK_OFF => {
            if !sock.peek_off_capable { return Err(Errno::Eopnotsupp); }
            Ok(Action::Scalar { slot: Scalar::PeekOff, value })
        }
        SO_SNDTIMEO_OLD | SO_SNDTIMEO_NEW | SO_RCVTIMEO_OLD | SO_RCVTIMEO_NEW => {
            let Arg::Timeval { sec, usec } = arg else { return Err(Errno::Einval); };
            let send = matches!(optname, SO_SNDTIMEO_OLD | SO_SNDTIMEO_NEW);
            Ok(Action::Timeout { send, ns: timeout_ns_from_timeval(sec, usec)? })
        }

        SO_DEBUG => {
            if on && !caps.net_admin { return Err(Errno::Eacces); }
            Ok(Action::Flag { bit: flag::DEBUG, on })
        }
        SO_REUSEADDR => Ok(Action::Reuseaddr(value)),
        SO_REUSEPORT => {
            if on && !sock.inet() { return Err(Errno::Eopnotsupp); }
            Ok(Action::Reuseport(i32::from(on)))
        }
        SO_DONTROUTE => Ok(Action::Flag { bit: flag::LOCALROUTE, on }),
        SO_BROADCAST => Ok(Action::Broadcast(i32::from(on))),
        SO_SNDBUF => Ok(Action::SndBuf(buf_value(value, SOCK_MIN_SNDBUF, ceilings.wmem_max, false))),
        SO_SNDBUFFORCE => {
            if !caps.net_admin { return Err(Errno::Eperm); }
            Ok(Action::SndBuf(buf_value(value, SOCK_MIN_SNDBUF, ceilings.wmem_max, true)))
        }
        SO_RCVBUF => Ok(Action::RcvBuf(buf_value(value, SOCK_MIN_RCVBUF, ceilings.rmem_max, false))),
        SO_RCVBUFFORCE => {
            if !caps.net_admin { return Err(Errno::Eperm); }
            Ok(Action::RcvBuf(buf_value(value, SOCK_MIN_RCVBUF, ceilings.rmem_max, true)))
        }
        SO_KEEPALIVE => Ok(Action::Keepalive(i32::from(on))),
        SO_OOBINLINE => Ok(Action::Oobinline(i32::from(on))),
        SO_NO_CHECK => Ok(Action::Flag { bit: flag::NO_CHECK_TX, on }),
        SO_LINGER => {
            let Arg::Linger { on: linger_on, seconds } = arg else { return Err(Errno::Einval); };
            Ok(Action::Linger { on: linger_on != 0, seconds })
        }
        SO_BSDCOMPAT | SO_CNX_ADVICE => Ok(Action::Accept),
        SO_TIMESTAMP_OLD | SO_TIMESTAMP_NEW | SO_TIMESTAMPNS_OLD | SO_TIMESTAMPNS_NEW =>
            Ok(Action::RecvTimestamps {
                on,
                new: matches!(optname, SO_TIMESTAMP_NEW | SO_TIMESTAMPNS_NEW),
                nanoseconds: matches!(optname, SO_TIMESTAMPNS_OLD | SO_TIMESTAMPNS_NEW),
            }),
        SO_TIMESTAMPING_OLD | SO_TIMESTAMPING_NEW => {
            let new = optname == SO_TIMESTAMPING_NEW;
            match arg {
                Arg::Timestamping { flags, bind_phc } =>
                    Ok(Action::Timestamping { flags, bind_phc, new }),
                _ => Ok(Action::Timestamping { flags: value, bind_phc: 0, new }),
            }
        }
        SO_RCVLOWAT => {
            let value = if value < 0 { i32::MAX } else if value == 0 { 1 } else { value };
            Ok(Action::Scalar { slot: Scalar::RcvLowat, value })
        }
        SO_MARK => {
            if !caps.net_raw_or_admin() { return Err(Errno::Eperm); }
            Ok(Action::Mark(value))
        }
        SO_RCVMARK => Ok(Action::Flag { bit: flag::RCVMARK, on }),
        SO_RCVPRIORITY => Ok(Action::Flag { bit: flag::RCVPRIORITY, on }),
        SO_RXQ_OVFL => Ok(Action::Flag { bit: flag::RXQ_OVFL, on }),
        SO_WIFI_STATUS => Ok(Action::Flag { bit: flag::WIFI_STATUS, on }),
        SO_NOFCS => Ok(Action::Flag { bit: flag::NOFCS, on }),
        SO_SELECT_ERR_QUEUE => Ok(Action::Flag { bit: flag::SELECT_ERR_QUEUE, on }),
        SO_PASSCRED => {
            if !sock.may_scm_recv() { return Err(Errno::Eopnotsupp); }
            Ok(Action::Passcred(i32::from(on)))
        }
        SO_PASSSEC => {
            if !sock.may_scm_recv() { return Err(Errno::Eopnotsupp); }
            Ok(Action::Flag { bit: flag::SCM_SECURITY, on })
        }
        SO_PASSPIDFD => {
            if !sock.unix() { return Err(Errno::Eopnotsupp); }
            Ok(Action::Flag { bit: flag::SCM_PIDFD, on })
        }
        SO_PASSRIGHTS => {
            if !sock.unix() { return Err(Errno::Eopnotsupp); }
            Ok(Action::Flag { bit: flag::SCM_RIGHTS_OFF, on: !on })
        }
        SO_INCOMING_CPU => Ok(Action::Scalar { slot: Scalar::IncomingCpu, value }),
        SO_ZEROCOPY => {
            if sock.inet() {
                if !(sock.tcp || sock.udp) { return Err(Errno::Eopnotsupp); }
            } else {
                return Err(Errno::Eopnotsupp);
            }
            if !(0..=1).contains(&value) { return Err(Errno::Einval); }
            Ok(Action::Flag { bit: flag::ZEROCOPY, on })
        }
        SO_TXTIME => {
            let Arg::TxTime { clockid, flags } = arg else { return Err(Errno::Einval); };
            if flags & !SOF_TXTIME_FLAGS_MASK != 0 { return Err(Errno::Einval); }
            if clockid != CLOCK_MONOTONIC && !caps.net_admin { return Err(Errno::Eperm); }
            if !matches!(clockid, CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_TAI) {
                return Err(Errno::Einval);
            }
            Ok(Action::TxTime {
                clockid,
                deadline_mode: flags & SOF_TXTIME_DEADLINE_MODE != 0,
                report_errors: flags & SOF_TXTIME_REPORT_ERRORS != 0,
            })
        }
        SO_BINDTOIFINDEX => {
            bind_device_allowed(caps, bound_device)?;
            if value < 0 { return Err(Errno::Einval); }
            Ok(Action::BindToIfindex(value))
        }
        SO_BUF_LOCK => {
            if value & !SOCK_BUF_LOCK_MASK != 0 { return Err(Errno::Einval); }
            Ok(Action::Scalar { slot: Scalar::BufLock, value })
        }
        SO_RESERVE_MEM => {
            if value < 0 { return Err(Errno::Einval); }
            Ok(Action::Scalar { slot: Scalar::ReserveMem, value })
        }
        _ => Err(Errno::Enoprotoopt),
    }
}

/// `sock_bindtoindex_locked`: re-pointing a socket that already has a bound
/// device needs `CAP_NET_RAW` in the socket's user namespace. # C: O(1)
pub fn bind_device_allowed(caps: OptCaps, bound_device: bool) -> Result<(), Errno> {
    if bound_device && !caps.net_raw { return Err(Errno::Eperm); }
    Ok(())
}

/// `sock_setbindtodevice`: the name is truncated to `IFNAMSIZ - 1`, never
/// rejected for length. # C: O(1)
pub const IFNAMSIZ: usize = 16;

/// # C: O(1)
pub fn device_name_len(optlen: u32) -> usize {
    core::cmp::min(optlen as usize, IFNAMSIZ - 1)
}

/// `sock_devmem_dontneed`: the option releases device-memory receive tokens, so
/// it is a stream-socket-only operation whose argument is a whole number of
/// tokens. The wrong socket shape outranks the length screen. Returns the token
/// count the caller must import. # C: O(1)
pub fn devmem_dontneed_tokens(sock: OptSock, optlen: u32) -> Result<usize, Errno> {
    if !sock.tcp { return Err(Errno::Ebadf); }
    let optlen = optlen as usize;
    if optlen % DEVMEM_TOKEN_SIZE != 0 || optlen > DEVMEM_TOKEN_SIZE * MAX_DONTNEED_TOKENS {
        return Err(Errno::Einval);
    }
    Ok(optlen / DEVMEM_TOKEN_SIZE)
}
