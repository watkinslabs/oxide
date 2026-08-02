#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use syscall::errno::Errno;
use net::sock::SockKind;

use crate::net_errno::errno_from_neterr;
use super::out::OptOut;

/// `IP_MTU` / `IPV6_MTU`: the path MTU toward the connected peer. Linux
/// answers ENOTCONN when the socket has no destination to resolve. # C: O(log N)
pub(super) fn socket_path_mtu(s: &Arc<net::sock::InetSocket>, ipv6: bool,
                              out: &OptOut) -> i64 {
    let dst = {
        let kind = s.kind.lock();
        match &*kind {
            SockKind::TcpConn(entry) => Some(entry.conn.lock().remote.ip),
            _ if ipv6 => s.peer6.lock().map(|(ip, _)| net::IpAddr::V6(ip)),
            _ => s.peer.lock().map(|(ip, _)| net::IpAddr::V4(ip)),
        }
    };
    let Some(dst) = dst else { return -(Errno::Enotconn.as_i32() as i64); };
    if ipv6 != matches!(dst, net::IpAddr::V6(_)) {
        return -(Errno::Enotconn.as_i32() as i64);
    }
    let raw = s.opts.bound_ifindex.load(Ordering::Acquire);
    let bound = if raw == 0 { None } else { Some(net::NetIfaceId::from_raw(raw)) };
    match net::sock::stack().path_mtu(dst, bound, false) {
        Ok(mtu) => out.i32(mtu.min(i32::MAX as u32) as i32),
        Err(error) => errno_from_neterr(error),
    }
}
