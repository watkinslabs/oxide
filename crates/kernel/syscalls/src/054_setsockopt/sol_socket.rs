// SOL_SOCKET argument import + application for slot 54. The option table,
// capability ladder, and value transforms live in `net::sock_opts::sol_socket`
// (`docs/53§4`); this file only moves bytes and stores accepted results.
#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use syscall::errno::Errno;
use net::sock::InetSocket;
use net::sock_opts::sol_socket::{self as sol, Scalar, flag};
use net::sock_opts::sol_socket::set::{Action, Arg, ArgClass};

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Caller's network capabilities in the socket's owning namespace. # C: O(1)
pub(super) fn caps_for(sock: &InetSocket) -> sol::OptCaps {
    let Some(cur) = sched::live::current() else { return sol::OptCaps::default(); };
    let namespace = &sock.net_namespace;
    sol::OptCaps {
        net_admin: nscg::has_net_admin_for(cur, namespace),
        net_raw: nscg::has_net_raw_for(cur, namespace),
    }
}

fn read_bytes<const N: usize>(optval: u64) -> Result<[u8; N], Errno> {
    let mut bytes = [0u8; N];
    uaccess::copy_from_user(&mut bytes, optval).map_err(|_| Errno::Efault)?;
    Ok(bytes)
}

fn i32_at(bytes: &[u8], offset: usize) -> i32 {
    i32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn i64_at(bytes: &[u8], offset: usize) -> i64 {
    i64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

/// Import the caller's argument in Linux order: the leading `int` screen runs
/// for every option except `SO_BINDTODEVICE`, so a short buffer is `EINVAL`
/// and a bad pointer `EFAULT` before the option number is classified.
/// # C: O(1)
fn import(optname: u64, optval: u64, optlen: u32) -> Result<Arg, Errno> {
    if optlen < core::mem::size_of::<i32>() as u32 { return Err(Errno::Einval); }
    let leading = i32_at(&read_bytes::<4>(optval)?, 0);
    match net::sock_opts::sol_socket::set::arg_class(optname) {
        ArgClass::Int | ArgClass::Device | ArgClass::Filter => Ok(Arg::Int(leading)),
        ArgClass::Linger => {
            if optlen < 8 { return Err(Errno::Einval); }
            let bytes = read_bytes::<8>(optval)?;
            Ok(Arg::Linger { on: i32_at(&bytes, 0), seconds: i32_at(&bytes, 4) })
        }
        ArgClass::Timeval => {
            if optlen < 16 { return Err(Errno::Einval); }
            let bytes = read_bytes::<16>(optval)?;
            Ok(Arg::Timeval { sec: i64_at(&bytes, 0), usec: i64_at(&bytes, 8) })
        }
        ArgClass::TxTime => {
            if optlen != 8 { return Err(Errno::Einval); }
            let bytes = read_bytes::<8>(optval)?;
            Ok(Arg::TxTime { clockid: i32_at(&bytes, 0), flags: i32_at(&bytes, 4) as u32 })
        }
        ArgClass::Timestamping => {
            if optlen != 8 { return Ok(Arg::Int(leading)); }
            let bytes = read_bytes::<8>(optval)?;
            Ok(Arg::Timestamping { flags: i32_at(&bytes, 0), bind_phc: i32_at(&bytes, 4) })
        }
        ArgClass::PacingRate => {
            if optlen < 8 { return Ok(Arg::Int(leading)); }
            Ok(Arg::PacingRate(u64::from_ne_bytes(read_bytes::<8>(optval)?)))
        }
    }
}

/// `sk_setsockopt` for one SOL_SOCKET write. # C: O(1)
pub(super) fn set(sock: &Arc<InetSocket>, optname: u64, optval: u64, optlen: u32) -> i64 {
    debug_assert!(sol::reads_int_argument(optname));
    let arg = match import(optname, optval, optlen) { Ok(a) => a, Err(e) => return errno(e) };
    let personality = net::sock_opts::describe(sock);
    let bound_device = sock.opts.bound_ifindex.load(Ordering::Acquire) != 0;
    let action = match net::sock_opts::sol_socket::set::admit(
        optname, arg, personality, caps_for(sock), bound_device)
    {
        Ok(action) => action,
        Err(e) => return errno(e),
    };
    apply(sock, action)
}

fn apply(sock: &Arc<InetSocket>, action: Action) -> i64 {
    let generic = &sock.opts.generic;
    match action {
        Action::Accept => {}
        Action::Flag { bit, on } => generic.set_flag(bit, on),
        Action::Reuseaddr(v) => sock.opts.reuseaddr.store(v, Ordering::Release),
        Action::Reuseport(v) => sock.opts.reuseport.store(v, Ordering::Release),
        Action::Keepalive(v) => {
            sock.opts.keepalive.store(v, Ordering::Release);
            if let net::sock::SockKind::TcpConn(entry) = &*sock.kind.lock() {
                net::sock_opts::apply_tcp_keepalive_opts(sock, entry);
            }
        }
        Action::Broadcast(v) => sock.opts.broadcast.store(v, Ordering::Release),
        Action::Oobinline(v) => sock.opts.oobinline.store(v, Ordering::Release),
        Action::SndBuf(v) => sock.opts.sndbuf.store(v, Ordering::Release),
        Action::RcvBuf(v) => {
            sock.opts.rcvbuf.store(v, Ordering::Release);
            // Linux `__sock_set_rcvbuf` also takes `SOCK_RCVBUF_LOCK`, which
            // stops receive-window autotuning from overriding the request.
            sock.opts.rcvbuf_locked.store(true, Ordering::Release);
            generic.set_scalar(Scalar::BufLock,
                generic.scalar(Scalar::BufLock) | sol::SOCK_RCVBUF_LOCK);
            super::main::sync_rcvbuf(sock, v);
        }
        Action::Priority(v) => sock.opts.priority.store(v, Ordering::Release),
        Action::Mark(v) => sock.opts.mark.store(v, Ordering::Release),
        Action::Passcred(v) => sock.opts.passcred.store(v, Ordering::Release),
        Action::Timestamping { flags, bind_phc, new } => {
            sock.opts.timestamping.store(flags, Ordering::Release);
            generic.set_scalar(Scalar::TimestampingBindPhc, bind_phc);
            generic.set_flag(flag::TSTAMP_NEW, new);
        }
        Action::RecvTimestamps { on, new, nanoseconds } => {
            generic.set_flag(flag::RCVTSTAMP, on);
            generic.set_flag(flag::RCVTSTAMPNS, on && nanoseconds);
            if on { generic.set_flag(flag::TSTAMP_NEW, new); }
        }
        Action::Linger { on, seconds } => {
            generic.set_flag(flag::LINGER, on);
            // Linux only republishes the linger time while the switch is on.
            if on { generic.set_scalar(Scalar::LingerSeconds, seconds); }
        }
        Action::Timeout { send, ns } => {
            let slot = if send { &sock.opts.sndtimeo_ns } else { &sock.opts.rcvtimeo_ns };
            slot.store(ns, Ordering::Release);
        }
        Action::Scalar { slot, value } => {
            if slot == Scalar::BufLock {
                sock.opts.rcvbuf_locked.store(value & sol::SOCK_RCVBUF_LOCK != 0, Ordering::Release);
            }
            generic.set_scalar(slot, value);
        }
        Action::PacingRate(rate) => generic.set_max_pacing_rate(rate),
        Action::BindToIfindex(index) => return bind_to_ifindex(sock, index),
        Action::TxTime { clockid, deadline_mode, report_errors } => {
            generic.set_flag(flag::TXTIME, true);
            generic.set_scalar(Scalar::TxTimeClockid, clockid);
            generic.set_flag(flag::TXTIME_DEADLINE_MODE, deadline_mode);
            generic.set_flag(flag::TXTIME_REPORT_ERRORS, report_errors);
        }
    }
    0
}

/// Publish a caller-named interface index on the socket. # C: O(log N)
pub(super) fn bind_to_ifindex(sock: &Arc<InetSocket>, index: i32) -> i64 {
    let iface = if index == 0 {
        None
    } else {
        let id = net::NetIfaceId::from_raw(index as u32);
        if net::sock::stack().ifaces.lookup_in_ns(id, sock.net_ns()).is_none() {
            return errno(Errno::Enodev);
        }
        Some(id)
    };
    match sock.set_bound_iface(iface) {
        Ok(()) => 0,
        Err(e) => crate::net_common::errno_from_neterr(e),
    }
}
