// Generic socket-option state on an AF_VSOCK socket.
//
// SOL_SOCKET is answered once, generically, before family dispatch, for every
// family. This module is that step for the virtual-socket family: it owns no
// admission rule and no value transform of its own — the write lands on the
// socket base every family embeds, and the read is answered by the same value
// table the internet and netlink families read. It lives here rather than in
// the syscall shim so both halves run under hosted `cargo test`.

use core::sync::atomic::Ordering;

use crate::sock_opts::sol_socket::{self as sol};
use crate::sock_opts::sol_socket::set::Action;

use super::VsockSocket;

impl VsockSocket {
    /// The socket personality the generic table branches on. # C: O(1)
    pub fn sol_socket_personality(&self) -> sol::OptSock {
        sol::OptSock {
            family: crate::socket_args::AF_VSOCK as u16,
            stream: !self.is_datagram(),
            tcp: false,
            udp: false,
            peek_off_capable: false,
        }
    }

    /// The socket identity the generic read table needs beyond the base.
    /// # C: O(1)
    pub fn sol_socket_view(&self) -> sol::get::SockView {
        sol::get::SockView {
            sock: self.sol_socket_personality(),
            acceptconn: i32::from(matches!(*self.kind.lock(), super::VsockKind::Listener(_))),
            socket_type: self.so_type.load(Ordering::Acquire) as i32,
            protocol: 0,
            netns_cookie: crate::net_ns::namespace_cookie(&self.net_namespace),
            napi_id: 0,
        }
    }

    /// Store one admitted generic write. # C: O(log N)
    pub fn sol_socket_apply(&self, action: Action) -> Result<(), syscall::errno::Errno> {
        if self.base.apply(action) { return Ok(()); }
        let Action::BindToIfindex(index) = action else { return Ok(()); };
        self.base.bind_ifindex_in(crate::net_ns::namespace_id(&self.net_namespace), index)
    }

    /// Resolve one interface NAME in the socket's own namespace. # C: O(N ifaces)
    pub fn sol_socket_bind_device(&self, name: &str) -> Result<(), syscall::errno::Errno> {
        self.base.bind_device_in(crate::net_ns::namespace_id(&self.net_namespace), name)
    }

    /// Answer one generic read through the one value table. # C: O(1)
    pub fn sol_socket_read(&self, optname: u64, requested: i32)
        -> Result<sol::get::Value, syscall::errno::Errno>
    {
        sol::get::value(optname, requested, &self.base, &self.sol_socket_view())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socket() -> VsockSocket { VsockSocket::new() }

    /// A virtual socket now keeps both timeouts on the same base every other
    /// family uses, and the receive and send waits read that one word (a
    /// hosted build has no monotonic source, so the deadline itself is only
    /// derivable on the kernel target).
    #[test]
    fn both_timeouts_live_on_the_shared_base() {
        let socket = socket();
        socket.sol_socket_apply(Action::Timeout { send: false, ns: 2_000_000_000 })
            .expect("the write is stored");
        assert_eq!(socket.sol_socket_read(sol::SO_RCVTIMEO_OLD, 16),
            Ok(sol::get::Value::Timeval { sec: 2, usec: 0 }));
        assert_eq!(socket.base.rcvtimeo_u64(), 2_000_000_000);
        socket.sol_socket_apply(Action::Timeout { send: true, ns: 500_000 })
            .expect("the write is stored");
        assert_eq!(socket.sol_socket_read(sol::SO_SNDTIMEO_NEW, 16),
            Ok(sol::get::Value::Timeval { sec: 0, usec: 500 }));
        assert_eq!(socket.base.sndtimeo_u64(), 500_000);
    }

    /// The generic surface a virtual socket answered nothing for before it
    /// embedded the base: the buffer budgets, the mark, the priority and the
    /// switches all store and read back through the one table.
    #[test]
    fn the_generic_surface_stores_and_reads_back() {
        let socket = socket();
        for (action, optname, expected) in [
            (Action::SndBuf(9216), sol::SO_SNDBUF, sol::get::Value::Int(9216)),
            (Action::RcvBuf(4608), sol::SO_RCVBUF, sol::get::Value::Int(4608)),
            (Action::Mark(7), sol::SO_MARK, sol::get::Value::Int(7)),
            (Action::Priority(3), sol::SO_PRIORITY, sol::get::Value::Int(3)),
            (Action::Reuseaddr(1), sol::SO_REUSEADDR, sol::get::Value::Int(1)),
            (Action::Linger { on: true, seconds: 4 }, sol::SO_LINGER,
                sol::get::Value::Linger { on: 1, seconds: 4 }),
        ] {
            socket.sol_socket_apply(action).expect("the write is stored");
            assert_eq!(socket.sol_socket_read(optname, 16), Ok(expected));
        }
    }

    /// The identity options answer from the socket's own shape, not from the
    /// base, and the stream personality follows the socket type.
    #[test]
    fn the_identity_options_answer_from_the_socket_shape() {
        let socket = socket();
        assert_eq!(socket.sol_socket_read(sol::SO_DOMAIN, 4),
            Ok(sol::get::Value::Int(crate::socket_args::AF_VSOCK as i32)));
        assert_eq!(socket.sol_socket_read(sol::SO_TYPE, 4),
            Ok(sol::get::Value::Int(crate::socket_args::SOCK_STREAM as i32)));
        assert_eq!(socket.sol_socket_read(sol::SO_ACCEPTCONN, 4), Ok(sol::get::Value::Int(0)));
        // Credentials are an AF_UNIX/AF_NETLINK surface; a virtual socket is
        // told so rather than being handed a stored-and-unread switch.
        assert_eq!(socket.sol_socket_read(sol::SO_PASSCRED, 4),
            Err(syscall::errno::Errno::Eopnotsupp));
    }

    /// A device binding is resolved in the socket's own namespace, so an index
    /// no interface owns is refused instead of stored.
    #[test]
    fn a_device_binding_is_resolved_before_it_is_stored() {
        let socket = socket();
        assert_eq!(socket.sol_socket_apply(Action::BindToIfindex(4242)),
            Err(syscall::errno::Errno::Enodev));
        assert_eq!(socket.sol_socket_read(sol::SO_BINDTOIFINDEX, 4), Ok(sol::get::Value::Int(0)));
    }
}
