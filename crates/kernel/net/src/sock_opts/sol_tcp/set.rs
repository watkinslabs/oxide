// Linux-ordered admission for every `IPPROTO_TCP` `setsockopt` write.
//
// Ordering contract the shim must preserve: the string and key options are
// classified and length-screened FIRST; every other option number — including
// one this level does not know — passes the leading `int` screen before it is
// classified, so a short buffer is `EINVAL` and a faulting one `EFAULT` ahead
// of `ENOPROTOOPT`.

use syscall::errno::Errno;
use alloc::vec::Vec;
use crate::tcp_state::TcpState;
use super::*;
use super::repair::{RepairEffect, RepairOpt, RepairWindow};

/// Argument shape the caller must supply for one option. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ArgClass {
    /// A bare `int`, and the default for an unrecognised option number.
    Int,
    /// A NUL-terminated name; no `int` screen.
    Name,
    /// One or two fixed-width fast-open keys; no `int` screen.
    FastopenKey,
    /// An `int` screen, then `struct tcp_repair_window`.
    RepairWindow,
    /// An `int` screen, then an array of `struct tcp_repair_opt`.
    RepairOptions,
}

/// Argument shape for one option number. # C: O(1)
pub fn arg_class(optname: u64) -> ArgClass {
    match optname {
        TCP_CONGESTION | TCP_ULP => ArgClass::Name,
        TCP_FASTOPEN_KEY => ArgClass::FastopenKey,
        TCP_REPAIR_WINDOW => ArgClass::RepairWindow,
        TCP_REPAIR_OPTIONS => ArgClass::RepairOptions,
        _ => ArgClass::Int,
    }
}

/// The argument the caller supplied, already imported by the shim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Arg {
    Int(i32),
    /// A name truncated to the option's buffer and cut at the first NUL.
    Name(Vec<u8>),
    FastopenKey { primary: [u8; FASTOPEN_KEY_LEN], backup: Option<[u8; FASTOPEN_KEY_LEN]> },
    /// The caller's declared length plus the decoded window, or the fault the
    /// copy took. Both are needed because the repair screen runs before the
    /// length screen, which runs before the copy.
    RepairWindow { optlen: u32, value: Result<RepairWindow, Errno> },
    /// The decoded records, or the fault the copy took.
    RepairOptions(Result<Vec<RepairOpt>, Errno>),
}

impl Arg {
    fn int(&self) -> i32 { if let Arg::Int(v) = self { *v } else { 0 } }
    fn boolean(&self) -> bool { self.int() != 0 }
}

/// Live state outside the option storage that one write is judged against.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SetEnv {
    /// `CAP_NET_ADMIN` in the socket's owning user namespace.
    pub net_admin: bool,
    pub state: TcpState,
    /// The socket is already under repair.
    pub repair: bool,
    /// Which queue repair writes address.
    pub repair_queue: i32,
    /// No unacknowledged segment is outstanding.
    pub rtx_queue_empty: bool,
    /// The application has consumed everything the receiver holds.
    pub recv_queue_drained: bool,
    /// An acknowledgement is queued but not yet on the wire.
    pub ack_scheduled: bool,
    /// The connection has already put data on the wire.
    pub bytes_sent: bool,
    /// A route pinned the congestion control, so the socket may not change it.
    pub cc_locked: bool,
    pub current_algo: CongestionAlgo,
    /// The namespace fast-open enable bits.
    pub fastopen_sysctl: i32,
    pub somaxconn: i32,
    /// The receiver's next expected sequence, for the repair-window screen.
    pub rcv_nxt: u32,
    /// The transmit timestamp clock at both resolutions, for the timestamp
    /// bias the caller installs.
    pub clock_ts_ms: i32,
    pub clock_ts_us: i32,
}

impl Default for SetEnv {
    fn default() -> Self {
        Self { net_admin: false, state: TcpState::Closed, repair: false,
               repair_queue: TCP_NO_QUEUE, rtx_queue_empty: true,
               recv_queue_drained: true, ack_scheduled: false,
               bytes_sent: false, cc_locked: false,
               current_algo: ca::DEFAULT, fastopen_sysctl: 0, somaxconn: 4096,
               rcv_nxt: 0, clock_ts_ms: 0, clock_ts_us: 0 }
    }
}

/// One accepted `IPPROTO_TCP` write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    /// Validated with no state change — the operand window is the whole
    /// contract for the option.
    Accept,
    Nodelay(bool),
    Cork(bool),
    KeepIdle(i32),
    KeepIntvl(i32),
    KeepCnt(i32),
    MaxSeg(i32),
    SynCnt(i32),
    Linger2(i32),
    DeferAccept(u8),
    WindowClamp(i32),
    /// `pingpong` is the delayed-ACK mode the write leaves the socket in;
    /// `push_ack` releases an ACK the socket was holding.
    QuickAck { pingpong: bool, push_ack: bool },
    Congestion(CongestionAlgo),
    ThinLto(bool),
    UserTimeout(i32),
    /// `window_probe` asks the sender to reopen the peer's window after
    /// repair released it.
    Repair { on: bool, window_probe: bool },
    RepairQueue(i32),
    QueueSeq { queue: i32, seq: u32 },
    /// The records that passed, plus the error that stopped the rest. The
    /// prefix is installed either way.
    RepairOptions { effects: Vec<RepairEffect>, err: Option<Errno> },
    RepairWindow(RepairWindow),
    SaveSyn(i32),
    Fastopen(i32),
    FastopenConnect(bool),
    FastopenNoCookie(bool),
    FastopenKey { primary: [u8; FASTOPEN_KEY_LEN], backup: Option<[u8; FASTOPEN_KEY_LEN]> },
    Timestamp { tsoffset: i32, usec_ts: bool },
    NotsentLowat(u32),
    Inq(bool),
    TxDelay(i32),
    RtoMaxTicks(i32),
    RtoMinTicks(i32),
    DelackMaxTicks(i32),
}

/// Repair may only be driven by a caller that can administer the network, and
/// never against a listener, whose children carry no sequence state of their
/// own. # C: O(1)
pub fn can_repair(env: &SetEnv) -> bool {
    env.net_admin && env.state != TcpState::Listen
}

/// The delayed-ACK mode a `TCP_QUICKACK` write leaves behind. Clearing it
/// parks the socket in ping-pong; setting it leaves ping-pong and releases a
/// held ACK, and an even operand re-enters ping-pong straight after, so one
/// pending ACK goes out without turning the mode off. # C: O(1)
pub fn quickack(val: i32, established: bool, ack_scheduled: bool) -> (bool, bool) {
    if val == 0 { return (true, false); }
    if established && ack_scheduled { return (val & 1 == 0, true); }
    (false, false)
}

/// Admission for one `IPPROTO_TCP` write. The shim has already run the
/// per-class length screen and imported `arg`. # C: O(repair records)
pub fn admit(optname: u64, arg: Arg, env: SetEnv) -> Result<Action, Errno> {
    let val = arg.int();
    let on = arg.boolean();
    let established = matches!(env.state, TcpState::Established | TcpState::CloseWait);
    let closed_or_listen = matches!(env.state, TcpState::Closed | TcpState::Listen);
    match optname {
        TCP_CONGESTION => {
            let Arg::Name(name) = arg else { return Err(Errno::Einval); };
            if env.cc_locked { return Err(Errno::Eperm); }
            let name = core::str::from_utf8(&name).map_err(|_| Errno::Enoent)?;
            let algo = ca::find(name).ok_or(Errno::Enoent)?;
            // Naming the algorithm already in use is always allowed, even one
            // an unprivileged caller could not have switched to.
            if algo == env.current_algo { return Ok(Action::Congestion(algo)); }
            if !algo.unrestricted() && !env.net_admin { return Err(Errno::Eperm); }
            Ok(Action::Congestion(algo))
        }
        TCP_ULP => {
            let Arg::Name(name) = arg else { return Err(Errno::Einval); };
            let name = core::str::from_utf8(&name).map_err(|_| Errno::Enoent)?;
            ulp::find(name).map(|_| Action::Accept).ok_or(Errno::Enoent)
        }
        TCP_FASTOPEN_KEY => {
            let Arg::FastopenKey { primary, backup } = arg else { return Err(Errno::Einval); };
            Ok(Action::FastopenKey { primary, backup })
        }

        // Options answered without taking the socket lock.
        TCP_SYNCNT => {
            if !(1..=MAX_TCP_SYNCNT).contains(&val) { return Err(Errno::Einval); }
            Ok(Action::SynCnt(val))
        }
        TCP_USER_TIMEOUT => {
            if val < 0 { return Err(Errno::Einval); }
            Ok(Action::UserTimeout(val))
        }
        TCP_KEEPINTVL => {
            if !(1..=MAX_TCP_KEEPINTVL).contains(&val) { return Err(Errno::Einval); }
            Ok(Action::KeepIntvl(val))
        }
        TCP_KEEPCNT => {
            if !(1..=MAX_TCP_KEEPCNT).contains(&val) { return Err(Errno::Einval); }
            Ok(Action::KeepCnt(val))
        }
        TCP_LINGER2 => Ok(Action::Linger2(if val < 0 { -1 }
            else { core::cmp::min(val, TCP_FIN_TIMEOUT_MAX_S) })),
        TCP_DEFER_ACCEPT => Ok(Action::DeferAccept(
            secs_to_retrans(val, TCP_TIMEOUT_INIT_S, TCP_RTO_MAX_SEC))),
        TCP_RTO_MAX_MS => {
            if val < 1000 || val > TCP_RTO_MAX_SEC * 1000 { return Err(Errno::Einval); }
            Ok(Action::RtoMaxTicks(msecs_to_ticks(val) as i32))
        }
        TCP_RTO_MIN_US => {
            let ticks = usecs_to_ticks(val);
            if ticks > TCP_RTO_MIN_TICKS || ticks < TCP_TIMEOUT_MIN_TICKS {
                return Err(Errno::Einval);
            }
            Ok(Action::RtoMinTicks(ticks as i32))
        }
        TCP_DELACK_MAX_US => {
            let ticks = usecs_to_ticks(val);
            if ticks > TCP_DELACK_MAX_TICKS || ticks < TCP_TIMEOUT_MIN_TICKS {
                return Err(Errno::Einval);
            }
            Ok(Action::DelackMaxTicks(ticks as i32))
        }
        TCP_MAXSEG => {
            if val != 0 && !(TCP_MIN_MSS..=MAX_TCP_WINDOW).contains(&val) {
                return Err(Errno::Einval);
            }
            Ok(Action::MaxSeg(val))
        }

        // Options answered under the socket lock.
        TCP_NODELAY => Ok(Action::Nodelay(on)),
        TCP_CORK => Ok(Action::Cork(on)),
        TCP_THIN_LINEAR_TIMEOUTS => {
            if !(0..=1).contains(&val) { return Err(Errno::Einval); }
            Ok(Action::ThinLto(on))
        }
        TCP_THIN_DUPACK => {
            // The operand window is enforced, but fast retransmit after a
            // single duplicate acknowledgement is not a mode the sender has:
            // recovery is driven by the reordering estimate.
            if !(0..=1).contains(&val) { return Err(Errno::Einval); }
            Ok(Action::Accept)
        }
        TCP_REPAIR => {
            if !can_repair(&env) { return Err(Errno::Eperm); }
            match val {
                TCP_REPAIR_ON => Ok(Action::Repair { on: true, window_probe: false }),
                TCP_REPAIR_OFF => Ok(Action::Repair { on: false, window_probe: true }),
                TCP_REPAIR_OFF_NO_WP => Ok(Action::Repair { on: false, window_probe: false }),
                _ => Err(Errno::Einval),
            }
        }
        TCP_REPAIR_QUEUE => {
            if !env.repair { return Err(Errno::Eperm); }
            if (val as u32) < TCP_QUEUES_NR as u32 { Ok(Action::RepairQueue(val)) }
            else { Err(Errno::Einval) }
        }
        TCP_QUEUE_SEQ => {
            if env.state != TcpState::Closed { return Err(Errno::Eperm); }
            match env.repair_queue {
                q if q == TCP_SEND_QUEUE => {
                    if !env.rtx_queue_empty { return Err(Errno::Eperm); }
                    Ok(Action::QueueSeq { queue: TCP_SEND_QUEUE, seq: val as u32 })
                }
                q if q == TCP_RECV_QUEUE => {
                    if !env.recv_queue_drained { return Err(Errno::Eperm); }
                    Ok(Action::QueueSeq { queue: TCP_RECV_QUEUE, seq: val as u32 })
                }
                _ => Err(Errno::Einval),
            }
        }
        TCP_REPAIR_OPTIONS => {
            if !env.repair { return Err(Errno::Einval); }
            if !(env.state == TcpState::Established && !env.bytes_sent) {
                return Err(Errno::Eperm);
            }
            let Arg::RepairOptions(records) = arg else { return Err(Errno::Einval); };
            let records = records?;
            let (effects, err) = repair::admit_opts(&records);
            Ok(Action::RepairOptions { effects, err })
        }
        TCP_KEEPIDLE => {
            if !(1..=MAX_TCP_KEEPIDLE).contains(&val) { return Err(Errno::Einval); }
            Ok(Action::KeepIdle(val))
        }
        TCP_SAVE_SYN => {
            if !(0..=SAVE_SYN_MAX).contains(&val) { return Err(Errno::Einval); }
            Ok(Action::SaveSyn(val))
        }
        TCP_WINDOW_CLAMP => {
            if val == 0 {
                if env.state != TcpState::Closed { return Err(Errno::Einval); }
                return Ok(Action::WindowClamp(0));
            }
            Ok(Action::WindowClamp(core::cmp::max(window_clamp_floor(), val)))
        }
        TCP_QUICKACK => {
            let (pingpong, push_ack) = quickack(val, established, env.ack_scheduled);
            Ok(Action::QuickAck { pingpong, push_ack })
        }
        TCP_AO_REPAIR => {
            if !can_repair(&env) { return Err(Errno::Eperm); }
            // The authentication option is not carried on any segment this
            // transport emits, so there are no sequence-number extensions to
            // restore.
            Err(Errno::Enoprotoopt)
        }
        TCP_AO_ADD_KEY | TCP_AO_DEL_KEY | TCP_AO_INFO | TCP_MD5SIG | TCP_MD5SIG_EXT =>
            Err(Errno::Enoprotoopt),
        TCP_FASTOPEN => {
            if val >= 0 && closed_or_listen {
                Ok(Action::Fastopen(core::cmp::min(val, env.somaxconn)))
            } else { Err(Errno::Einval) }
        }
        TCP_FASTOPEN_CONNECT => {
            if !(0..=1).contains(&val) { return Err(Errno::Einval); }
            if env.fastopen_sysctl & TFO_CLIENT_ENABLE == 0 { return Err(Errno::Eopnotsupp); }
            if env.state != TcpState::Closed { return Err(Errno::Einval); }
            Ok(Action::FastopenConnect(on))
        }
        TCP_FASTOPEN_NO_COOKIE => {
            if !(0..=1).contains(&val) { return Err(Errno::Einval); }
            if !closed_or_listen { return Err(Errno::Einval); }
            Ok(Action::FastopenNoCookie(on))
        }
        TCP_TIMESTAMP => {
            if !env.repair { return Err(Errno::Eperm); }
            let usec_ts = val & 1 != 0;
            let clock = if usec_ts { env.clock_ts_us } else { env.clock_ts_ms };
            Ok(Action::Timestamp { tsoffset: val.wrapping_sub(clock), usec_ts })
        }
        TCP_REPAIR_WINDOW => {
            let Arg::RepairWindow { optlen, value } = arg else { return Err(Errno::Einval); };
            if !env.repair { return Err(Errno::Eperm); }
            if optlen as usize != REPAIR_WINDOW_LEN { return Err(Errno::Einval); }
            Ok(Action::RepairWindow(value?.admit(env.rcv_nxt)?))
        }
        TCP_NOTSENT_LOWAT => Ok(Action::NotsentLowat(val as u32)),
        TCP_INQ => {
            if !(0..=1).contains(&val) { return Err(Errno::Einval); }
            Ok(Action::Inq(on))
        }
        TCP_TX_DELAY => {
            if val < 0 || val >= TX_DELAY_LIMIT { return Err(Errno::Einval); }
            Ok(Action::TxDelay(val))
        }
        _ => Err(Errno::Enoprotoopt),
    }
}
