// SOL_SOCKET on an AF_NETLINK fd.
//
// SOL_SOCKET never reaches a family's own option table: it is answered once,
// generically, before family dispatch, and the family op sees only its own
// level. This module is that generic step for netlink, and it owns no decision
// of its own — the argument import, the admission ladder, the capability gates
// and every value transform are the SAME ones the internet families use, so a
// write judged here cannot be judged differently there. It applies the results
// this socket has a home for; the rest is state a netlink socket does not yet
// carry.

use syscall::errno::Errno;

use net::sock_opts::sol_socket::{self as sol, flag};
use net::sock_opts::sol_socket::set::Action;

use super::NetlinkFileRef;

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// The socket personality the generic table branches on. A netlink socket is
/// a datagram socket of no internet transport, so every family-gated option
/// takes the family's own answer. # C: O(1)
fn personality() -> sol::OptSock {
    sol::OptSock { family: net::socket_args::AF_NETLINK_WIRE, stream: false, tcp: false,
                   udp: false, peek_off_capable: false }
}

/// Caller's network capabilities in the socket's owning namespace. # C: O(1)
fn caps_for(target: &NetlinkFileRef) -> sol::OptCaps {
    let Some(cur) = sched::live::current() else { return sol::OptCaps::default(); };
    let namespace = &target.socket().net_ns;
    sol::OptCaps {
        net_admin: nscg::has_net_admin_for(cur, namespace),
        net_raw: nscg::has_net_raw_for(cur, namespace),
    }
}

/// `sock_setsockopt` for a netlink socket. # C: O(1)
pub fn set(target: &NetlinkFileRef, optname: u64, optval: u64, optlen: u64) -> i64 {
    let socket = target.socket();
    let optlen = optlen.min(u32::MAX as u64) as u32;
    let arg = match crate::s054_setsockopt::sol_socket::import(optname, optval, optlen) {
        Ok(arg) => arg,
        Err(e) => return errno(e),
    };
    let env = sol::set::SetEnv {
        caps: caps_for(target),
        bound_device: false,
        ceilings: net::sysctl::buf_ceilings(),
        busy_poll_budget: socket.generic.scalar(sol::Scalar::BusyPollBudget),
    };
    let action = match sol::set::admit(optname, arg, personality(), env) {
        Ok(action) => action,
        Err(e) => return errno(e),
    };
    apply(target, action);
    0
}

/// Store one admitted write. # C: O(1)
fn apply(target: &NetlinkFileRef, action: Action) {
    use core::sync::atomic::Ordering;
    let socket = target.socket();
    match action {
        Action::SndBuf(v) => socket.sndbuf.store(v.max(0) as usize, Ordering::Release),
        Action::RcvBuf(v) => socket.rcvbuf.store(v.max(0) as usize, Ordering::Release),
        Action::Passcred(v) => socket.scm.set(v != 0),
        Action::Flag { bit: flag::SCM_SECURITY, on } => socket.scm_security.set(on),
        Action::Flag { bit, on } => socket.generic.set_flag(bit, on),
        Action::Scalar { slot, value } => socket.generic.set_scalar(slot, value),
        Action::PacingRate(rate) => socket.generic.set_max_pacing_rate(rate),
        // `sk_rcvtimeo`, read back by the receive wait for `sock_intr_errno`:
        // without it a timed netlink receive is impossible and every
        // interrupted one must report ERESTARTSYS. The send half has no
        // blocking wait on this family to bound.
        Action::Timeout { send: false, ns } =>
            socket.rcvtimeo_ns.store(ns.max(0) as u64, Ordering::Release),
        _ => {}
    }
}

/// `sock_getsockopt` for a netlink socket, through the same value table every
/// other family reads. `None` when the option is not one this level answers.
/// # C: O(1)
pub fn get(target: &NetlinkFileRef, optname: u64, requested: usize)
    -> Option<Result<alloc::vec::Vec<u8>, i64>>
{
    use core::sync::atomic::Ordering;
    let socket = target.socket();
    let requested = i32::try_from(requested).unwrap_or(i32::MAX);
    let view = sol::get::SockView {
        sock: personality(),
        sndbuf: socket.sndbuf.load(Ordering::Acquire).min(i32::MAX as usize) as i32,
        rcvbuf: socket.rcvbuf.load(Ordering::Acquire).min(i32::MAX as usize) as i32,
        passcred: socket.scm.value(),
        rcvtimeo_ns: socket.rcvtimeo_ns.load(Ordering::Acquire).min(i64::MAX as u64) as i64,
        socket_type: net::socket_args::SOCK_RAW as i32,
        protocol: socket.protocol as i32,
        netns_cookie: net::net_ns::namespace_id(&socket.net_ns),
        socket_cookie: socket.generic.cookie(sol::next_cookie) as u64,
        ..Default::default()
    };
    let value = match sol::get::value(optname, requested, &socket.generic, &view) {
        Ok(value) => value,
        Err(e) => return Some(Err(errno(e))),
    };
    let mut bytes = [0u8; 16];
    let natural = sol::get::encode(&value, &mut bytes);
    Some(Ok(bytes[..natural].to_vec()))
}
