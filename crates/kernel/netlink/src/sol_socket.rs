//! Generic socket-option state on an AF_NETLINK socket.
//!
//! SOL_SOCKET never reaches a family's own option table: it is answered once,
//! generically, before family dispatch. The argument import, the admission
//! ladder and every value transform belong to that one generic owner; this
//! module is only where an admitted write lands on a netlink socket and where
//! the read view is assembled from it, so a write and its read-back can never
//! disagree. It lives here rather than in the syscall shim so both halves are
//! reachable without a descriptor.

use core::sync::atomic::Ordering;

use net::sock_opts::sol_socket::{self as sol, flag};
use net::sock_opts::sol_socket::set::Action;

use crate::netlink_socket::NetlinkSocket;

/// The socket personality the generic table branches on. A netlink socket is a
/// datagram socket of no internet transport, so every family-gated option takes
/// the family's own answer. # C: O(1)
pub fn personality() -> sol::OptSock {
    sol::OptSock { family: net::socket_args::AF_NETLINK_WIRE, stream: false, tcp: false,
                   udp: false, peek_off_capable: false }
}

/// Store one admitted generic write. # C: O(1)
pub fn apply(socket: &NetlinkSocket, action: Action) {
    match action {
        Action::SndBuf(v) => socket.sndbuf.store(v.max(0) as usize, Ordering::Release),
        Action::RcvBuf(v) => socket.rcvbuf.store(v.max(0) as usize, Ordering::Release),
        Action::Passcred(v) => socket.scm.set(v != 0),
        Action::Flag { bit: flag::SCM_SECURITY, on } => socket.scm_security.set(on),
        Action::Flag { bit, on } => socket.generic.set_flag(bit, on),
        Action::Scalar { slot, value } => socket.generic.set_scalar(slot, value),
        Action::PacingRate(rate) => socket.generic.set_max_pacing_rate(rate),
        // The linger switch and time, and the receive-timestamp personality,
        // are held in the same generic word for every family, so routing them
        // costs no storage: it stops the write being discarded while its read
        // answers from that word.
        Action::Linger { on, seconds } => {
            socket.generic.set_flag(flag::LINGER, on);
            if on { socket.generic.set_scalar(sol::Scalar::LingerSeconds, seconds); }
        }
        Action::RecvTimestamps { on, new, nanoseconds } => {
            socket.generic.set_flag(flag::RCVTSTAMP, on);
            socket.generic.set_flag(flag::RCVTSTAMPNS, on && nanoseconds);
            if on { socket.generic.set_flag(flag::TSTAMP_NEW, new); }
        }
        // The receive timeout bounds the receive wait, so an interrupted timed
        // receive reports the right errno instead of a restart.
        Action::Timeout { send: false, ns } =>
            socket.rcvtimeo_ns.store(ns.max(0) as u64, Ordering::Release),
        Action::Timeout { send: true, ns } =>
            socket.sndtimeo_ns.store(ns.max(0) as u64, Ordering::Release),
        _ => {}
    }
}

/// The read view of one netlink socket, for the one generic value table.
/// # C: O(1)
pub fn view(socket: &NetlinkSocket, cookie: impl FnOnce() -> i64) -> sol::get::SockView {
    sol::get::SockView {
        sock: personality(),
        sndbuf: socket.sndbuf.load(Ordering::Acquire).min(i32::MAX as usize) as i32,
        rcvbuf: socket.rcvbuf.load(Ordering::Acquire).min(i32::MAX as usize) as i32,
        passcred: socket.scm.value(),
        rcvtimeo_ns: socket.rcvtimeo_ns.load(Ordering::Acquire).min(i64::MAX as u64) as i64,
        sndtimeo_ns: socket.sndtimeo_ns.load(Ordering::Acquire).min(i64::MAX as u64) as i64,
        socket_type: net::socket_args::SOCK_RAW as i32,
        protocol: socket.protocol as i32,
        netns_cookie: net::net_ns::namespace_id(&socket.net_ns),
        socket_cookie: socket.generic.cookie(cookie) as u64,
        ..Default::default()
    }
}

/// Answer one generic read from the socket's own state, through the same value
/// table every other family reads. # C: O(1)
pub fn read(socket: &NetlinkSocket, optname: u64, requested: i32, cookie: impl FnOnce() -> i64)
    -> Result<sol::get::Value, syscall::errno::Errno>
{
    let view = view(socket, cookie);
    sol::get::value(optname, requested, &socket.generic, &view)
}

#[cfg(test)]
mod tests {
    use super::{apply, read};
    use alloc::sync::Arc;
    use net::sock_opts::sol_socket::{self as sol, flag};
    use net::sock_opts::sol_socket::set::Action;

    fn socket() -> Arc<crate::NetlinkSocket> {
        let namespace = network_namespace::initial();
        Arc::new(crate::NetlinkSocket::new(crate::proto::NETLINK_ROUTE, &namespace))
    }

    /// The linger switch and its time are stored where the read looks, so a
    /// write is no longer accepted and discarded.
    #[test]
    fn a_linger_write_survives_to_its_own_read() {
        let socket = socket();
        assert_eq!(read(&socket, sol::SO_LINGER, 8, || 1).expect("the option is answered"),
            sol::get::Value::Linger { on: 0, seconds: 0 });
        apply(&socket, Action::Linger { on: true, seconds: 7 });
        assert_eq!(read(&socket, sol::SO_LINGER, 8, || 1).expect("the option is answered"),
            sol::get::Value::Linger { on: 1, seconds: 7 });
        assert!(socket.generic.flag(flag::LINGER));
        assert_eq!(socket.generic.scalar(sol::Scalar::LingerSeconds), 7);
        // Turning it off keeps the recorded time, as the generic owner does.
        apply(&socket, Action::Linger { on: false, seconds: 0 });
        assert!(!socket.generic.flag(flag::LINGER));
        assert_eq!(socket.generic.scalar(sol::Scalar::LingerSeconds), 7);
    }

    /// The receive-timestamp personality reaches the same generic word every
    /// family keeps it in, including the nanosecond and the wide-time bits.
    #[test]
    fn a_receive_timestamp_write_survives_to_its_own_read() {
        let socket = socket();
        apply(&socket, Action::RecvTimestamps { on: true, new: true, nanoseconds: true });
        assert!(socket.generic.flag(flag::RCVTSTAMP));
        assert!(socket.generic.flag(flag::RCVTSTAMPNS));
        assert!(socket.generic.flag(flag::TSTAMP_NEW));
        apply(&socket, Action::RecvTimestamps { on: false, new: false, nanoseconds: true });
        assert!(!socket.generic.flag(flag::RCVTSTAMP));
        assert!(!socket.generic.flag(flag::RCVTSTAMPNS));
    }

    /// Both timeouts have a home, so neither read reports a value the write
    /// never produced.
    #[test]
    fn both_timeouts_are_stored_and_read_back() {
        let socket = socket();
        apply(&socket, Action::Timeout { send: true, ns: 3_000 });
        apply(&socket, Action::Timeout { send: false, ns: 5_000 });
        assert_eq!(super::view(&socket, || 1).sndtimeo_ns, 3_000);
        assert_eq!(super::view(&socket, || 1).rcvtimeo_ns, 5_000);
    }
}
