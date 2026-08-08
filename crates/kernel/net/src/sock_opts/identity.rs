// The socket's own identity: the type, protocol and listening state that every
// interface asking "what kind of socket is this?" must get the same answer
// from.
//
// One owner, because two of them can disagree: `SO_TYPE`/`SO_PROTOCOL`/
// `SO_ACCEPTCONN` publish it to userspace and the option security decision is
// keyed by it, and a module that denies "raw socket option writes" must see the
// same type the socket reports about itself.

use core::sync::atomic::Ordering;

use crate::sock::{InetSocket, SockKind};

/// `sk_type`.
///
/// An explicit override wins: an AF_UNIX `SOCK_SEQPACKET` listener is a
/// byte-ring `SockKind` that cannot encode the seqpacket shape, so socket
/// creation records the type it was asked for. # C: O(1)
pub fn socket_type(s: &InetSocket) -> i32 {
    let ov = s.opts.so_type.load(Ordering::Acquire);
    if ov != 0 { return ov as i32; }
    match &*s.kind.lock() {
        SockKind::Udp | SockKind::UnixDgram(_) => crate::socket_args::SOCK_DGRAM as i32,
        SockKind::Raw4(_) | SockKind::Raw6(_) => crate::socket_args::SOCK_RAW as i32,
        SockKind::Packet { sock_type, .. } => sock_type.load(Ordering::Acquire) as i32,
        SockKind::UnixMsgPair(_, _) => crate::socket_args::SOCK_SEQPACKET as i32,
        SockKind::TcpInit | SockKind::UnixUnbound(_, _)
        | SockKind::TcpListener(_)
        | SockKind::TcpConn(_)
        | SockKind::Unix(_, _)
        | SockKind::UnixListener(_) => crate::socket_args::SOCK_STREAM as i32,
    }
}

/// `sk_protocol`. An AF_UNIX socket carries no protocol number. # C: O(1)
pub fn socket_protocol(s: &InetSocket) -> i32 {
    if s.family.load(Ordering::Acquire) == crate::sock::AF_UNIX { return 0; }
    match &*s.kind.lock() {
        SockKind::Packet { protocol, .. } => protocol.load(Ordering::Acquire) as i32,
        SockKind::Raw4(endpoint) => endpoint.protocol() as i32,
        SockKind::Raw6(endpoint) => endpoint.protocol() as i32,
        SockKind::Udp => crate::socket_args::IPPROTO_UDP as i32,
        SockKind::TcpInit | SockKind::TcpListener(_) | SockKind::TcpConn(_) =>
            crate::socket_args::IPPROTO_TCP as i32,
        _ => 0,
    }
}

/// Whether this socket accepts connections. # C: O(1)
pub fn socket_acceptconn(s: &InetSocket) -> i32 {
    match &*s.kind.lock() {
        SockKind::TcpListener(_) | SockKind::UnixListener(_) => 1,
        _ => 0,
    }
}
