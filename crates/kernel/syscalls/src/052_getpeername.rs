// 052 getpeername — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::net_trace::trace_enotsock_at;
use crate::net_sockaddr::*;
use crate::net_common::socket_from_fd;

/// `getpeername(fd, addr, addrlen)` slot 52.
/// # C: O(1)
pub fn sys_getpeername(args: &SyscallArgs) -> i64 {
    let fd     = args.a0;
    let addr_p = args.a1;
    let len_p  = args.a2;
    let sock = match socket_from_fd(fd) {
        Some(s) => s, None => { trace_enotsock_at(fd, b"getpeername"); return -(Errno::Enotsock.as_i32() as i64); }
    };
    // AF_UNIX sockets keep their peer as a UnixPair (SockKind::Unix /
    // UnixMsgPair), never in the IPv4 `peer` tuple. A connected AF_UNIX end
    // must report success — Linux returns the peer's sockaddr_un (its bound
    // sun_path, e.g. "/run/systemd/private" seen by a client; a bare AF_UNIX
    // family for an unnamed peer) — not ENOTCONN. sd-bus (bus_get_peercred),
    // dbus-daemon, logind and many daemons call getpeername on their AF_UNIX
    // connections; returning ENOTCONN on a live connection broke them.
    if sock.family.load(core::sync::atomic::Ordering::Acquire) == net::sock::AF_UNIX {
        return match net::sock::unix_peer_path(&sock) {
            Some(path) => {
                let sa = encoded_sockaddr_un_path(path.as_deref());
                copy_sockaddr_to_user(addr_p, len_p, &sa)
            }
            None => -(Errno::Enotconn.as_i32() as i64),
        };
    }
    let (ip, port) = match *sock.peer.lock() {
        Some(t) => t, None => return -(Errno::Enotconn.as_i32() as i64),
    };
    let sa = encoded_sockaddr_for_socket(&sock, ip, port);
    copy_sockaddr_to_user(addr_p, len_p, &sa)
}
