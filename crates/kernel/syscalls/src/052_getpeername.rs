// 052 getpeername — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::net_trace::trace_enotsock_at;
use crate::net_sockaddr::*;
use crate::net_common::{fd_file, inode_as_inet_socket, vsock_from_file};
use net::sock::SockKind;

/// `getpeername(fd, addr, addrlen)` slot 52.
/// # C: O(1)
pub fn sys_getpeername(args: &SyscallArgs) -> i64 {
    let fd     = args.a0;
    let addr_p = args.a1;
    let len_p  = args.a2;
    let file = match fd_file(fd) {
        Some(file) => file,
        None => return -(Errno::Ebadf.as_i32() as i64),
    };
    if let Some(target) = crate::netlink_fd::from_file(file.clone()) {
        return crate::netlink_fd::getpeername(&target, addr_p, len_p);
    }
    if let Some(vsock) = vsock_from_file(file.clone()) {
        if let Err(e) = net::sock_opts::check_name_query(vsock.net_ns(), net::sock::AF_VSOCK) {
            return crate::net_common::errno_from_neterr(e);
        }
        let (port, cid) = match vsock.peer_addr() {
            Ok(addr) => addr,
            Err(e) => return crate::net_common::errno_from_neterr(e),
        };
        let sa = encoded_sockaddr_vm(port, cid);
        return copy_sockaddr_to_user(addr_p, len_p, &sa);
    }
    let sock = match inode_as_inet_socket(file.inode()) {
        Some(sock) => sock,
        None => { trace_enotsock_at(fd, b"getpeername"); return -(Errno::Enotsock.as_i32() as i64); }
    };
    if let Err(e) = net::sock_opts::check_name_query(sock.net_ns(),
        sock.family.load(core::sync::atomic::Ordering::Acquire)) {
        return crate::net_common::errno_from_neterr(e);
    }
    let raw = match &*sock.kind.lock() {
        SockKind::Raw4(endpoint) => match endpoint.snapshot().remote {
            Some(peer) => Some(encoded_sockaddr_in(peer.as_u32().to_be(), 0)),
            None => return -(Errno::Enotconn.as_i32() as i64),
        },
        SockKind::Raw6(endpoint) => match endpoint.peer() {
            Some(peer) => Some(encoded_sockaddr_in6(peer.addr.0, 0, peer.scope_id)),
            None => return -(Errno::Enotconn.as_i32() as i64),
        },
        _ => None,
    };
    if let Some(sa) = raw { return copy_sockaddr_to_user(addr_p, len_p, &sa); }
    // Linux AF_PACKET installs `packet_getname`, which rejects its peer
    // query with EOPNOTSUPP rather than falling through to generic INET peer
    // state (net/packet/af_packet.c:packet_getname). AF_PACKET owns no peer
    // address, so do not synthesize one from the generic socket tuple.
    if sock.family.load(core::sync::atomic::Ordering::Acquire) == net::sock::AF_PACKET {
        return -(Errno::Eopnotsupp.as_i32() as i64);
    }
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
