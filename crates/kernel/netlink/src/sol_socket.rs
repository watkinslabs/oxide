//! Generic socket-option state on an AF_NETLINK socket.
//!
//! SOL_SOCKET never reaches a family's own option table: it is answered once,
//! generically, before family dispatch. The argument import, the admission
//! ladder and every value transform belong to that one generic owner; this
//! module is only where an admitted write lands on a netlink socket and where
//! the read view is assembled from it, so a write and its read-back can never
//! disagree. It lives here rather than in the syscall shim so both halves are
//! reachable without a descriptor.


use net::sock_opts::sol_socket::{self as sol};
use net::sock_opts::sol_socket::set::Action;

use crate::netlink_socket::NetlinkSocket;

/// The socket personality the generic table branches on. A netlink socket is a
/// datagram socket of no internet transport, so every family-gated option takes
/// the family's own answer. # C: O(1)
pub fn personality() -> sol::OptSock {
    sol::OptSock { family: net::socket_args::AF_NETLINK_WIRE, stream: false, tcp: false,
                   udp: false, peek_off_capable: false }
}

/// Store one admitted generic write. Every generic option has its home on the
/// socket base, so nothing is stored twice and nothing is discarded; only the
/// device binding needs this family, which resolves the interface in the
/// socket's own network namespace before the base publishes it. # C: O(1)
pub fn apply(socket: &NetlinkSocket, action: Action) -> Result<(), syscall::errno::Errno> {
    if socket.base.apply(action) { return Ok(()); }
    let Action::BindToIfindex(index) = action else { return Ok(()); };
    bind_to_ifindex(socket, index)
}

/// Resolve one interface index in the socket's own namespace. # C: O(log N)
pub fn bind_to_ifindex(socket: &NetlinkSocket, index: i32)
    -> Result<(), syscall::errno::Errno>
{
    socket.base.bind_ifindex_in(net::net_ns::namespace_id(&socket.net_ns), index)
}

/// Resolve one interface NAME in the socket's own namespace. # C: O(N ifaces)
pub fn bind_to_device_name(socket: &NetlinkSocket, name: &str)
    -> Result<(), syscall::errno::Errno>
{
    socket.base.bind_device_in(net::net_ns::namespace_id(&socket.net_ns), name)
}

/// The identity of one netlink socket, for the one generic value table.
/// # C: O(1)
pub fn view(socket: &NetlinkSocket) -> sol::get::SockView {
    sol::get::SockView {
        sock: personality(),
        socket_type: net::socket_args::SOCK_RAW as i32,
        protocol: socket.protocol as i32,
        netns_cookie: net::net_ns::namespace_cookie(&socket.net_ns),
        ..Default::default()
    }
}

/// Answer one generic read from the socket's own base, through the same value
/// table every other family reads. # C: O(1)
pub fn read(socket: &NetlinkSocket, optname: u64, requested: i32)
    -> Result<sol::get::Value, syscall::errno::Errno>
{
    sol::get::value(optname, requested, &socket.base, &view(socket))
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
        assert_eq!(read(&socket, sol::SO_LINGER, 8).expect("the option is answered"),
            sol::get::Value::Linger { on: 0, seconds: 0 });
        apply(&socket, Action::Linger { on: true, seconds: 7 }).expect("the write is stored");
        assert_eq!(read(&socket, sol::SO_LINGER, 8).expect("the option is answered"),
            sol::get::Value::Linger { on: 1, seconds: 7 });
        assert!(socket.base.generic.flag(flag::LINGER));
        assert_eq!(socket.base.generic.scalar(sol::Scalar::LingerSeconds), 7);
        // Turning it off keeps the recorded time, as the generic owner does.
        apply(&socket, Action::Linger { on: false, seconds: 0 }).expect("the write is stored");
        assert!(!socket.base.generic.flag(flag::LINGER));
        assert_eq!(socket.base.generic.scalar(sol::Scalar::LingerSeconds), 7);
    }

    /// The receive-timestamp personality reaches the same generic word every
    /// family keeps it in, including the nanosecond and the wide-time bits.
    #[test]
    fn a_receive_timestamp_write_survives_to_its_own_read() {
        let socket = socket();
        apply(&socket, Action::RecvTimestamps { on: true, new: true, nanoseconds: true })
            .expect("the write is stored");
        assert!(socket.base.generic.flag(flag::RCVTSTAMP));
        assert!(socket.base.generic.flag(flag::RCVTSTAMPNS));
        assert!(socket.base.generic.flag(flag::TSTAMP_NEW));
        apply(&socket, Action::RecvTimestamps { on: false, new: false, nanoseconds: true })
            .expect("the write is stored");
        assert!(!socket.base.generic.flag(flag::RCVTSTAMP));
        assert!(!socket.base.generic.flag(flag::RCVTSTAMPNS));
    }

    /// Both timeouts have a home, so neither read reports a value the write
    /// never produced.
    #[test]
    fn both_timeouts_are_stored_and_read_back() {
        let socket = socket();
        apply(&socket, Action::Timeout { send: true, ns: 3_000 }).expect("the write is stored");
        apply(&socket, Action::Timeout { send: false, ns: 5_000 }).expect("the write is stored");
        assert_eq!(socket.base.sndtimeo(), 3_000);
        assert_eq!(socket.base.rcvtimeo(), 5_000);
    }

    /// The four options a netlink socket had no home for before it embedded
    /// the socket base: the mark, the priority, the timestamp selection and
    /// the device binding all store and read back here.
    #[test]
    fn the_four_options_netlink_had_no_home_for_now_read_back() {
        let socket = socket();
        apply(&socket, Action::Mark(0x51)).expect("the write is stored");
        apply(&socket, Action::Priority(6)).expect("the write is stored");
        apply(&socket, Action::Timestamping { flags: 0x21, bind_phc: 2, new: true })
            .expect("the write is stored");
        assert_eq!(read(&socket, sol::SO_MARK, 4), Ok(sol::get::Value::Int(0x51)));
        assert_eq!(read(&socket, sol::SO_PRIORITY, 4), Ok(sol::get::Value::Int(6)));
        assert_eq!(read(&socket, sol::SO_TIMESTAMPING_NEW, 8),
            Ok(sol::get::Value::Timestamping { flags: 0x21, bind_phc: 2 }));
        // The device binding is refused by the base and resolved by the
        // family: an index no interface owns is ENODEV, and it stays unbound.
        assert_eq!(apply(&socket, Action::BindToIfindex(4242)),
            Err(syscall::errno::Errno::Enodev));
        assert_eq!(read(&socket, sol::SO_BINDTOIFINDEX, 4), Ok(sol::get::Value::Int(0)));
        // Clearing is always admissible and reads back as unbound.
        apply(&socket, Action::BindToIfindex(0)).expect("clearing is admissible");
        assert_eq!(read(&socket, sol::SO_BINDTOIFINDEX, 4), Ok(sol::get::Value::Int(0)));
    }

    /// A netlink socket answers the generic buffer budgets from the same base
    /// its send preflight and receive admission consult.
    #[test]
    fn the_buffer_budgets_are_the_ones_the_queues_enforce() {
        let socket = socket();
        assert_eq!(read(&socket, sol::SO_RCVBUF, 4),
            Ok(sol::get::Value::Int(crate::netlink_socket::NETLINK_RCVBUF_DEFAULT as i32)));
        apply(&socket, Action::RcvBuf(8192)).expect("the write is stored");
        assert_eq!(socket.base.rcvbuf_bytes(), 8192);
        assert_eq!(read(&socket, sol::SO_RCVBUF, 4), Ok(sol::get::Value::Int(8192)));
        apply(&socket, Action::SndBuf(16384)).expect("the write is stored");
        assert_eq!(socket.base.sndbuf_bytes(), 16384);
    }
}
