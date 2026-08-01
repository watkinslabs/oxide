#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use syscall::errno::Errno;

use super::multicast::{ipv4_group_filter_get, ipv4_msfilter_get, scalar_get};
use super::out::OptOut;
use super::path_mtu::socket_path_mtu;
use super::uapi::*;

/// `getsockopt(fd, IPPROTO_IP, ...)`. # C: O(1)
pub(super) fn get(sock: &Arc<net::sock::InetSocket>, optname: u64, out: &OptOut) -> i64 {
    match optname {
        IP_TOS => out.i32(sock.opts.ip_tos.load(Ordering::Acquire)),
        IP_TTL => {
            let ttl = sock.opts.ip_ttl.load(Ordering::Acquire);
            out.i32(if ttl < 0 { net::ipv4::IPV4_DEFAULT_TTL as i32 } else { ttl })
        }
        IP_PKTINFO => out.i32(sock.opts.ip_pktinfo.load(Ordering::Acquire)),
        IP_MTU_DISCOVER => out.i32(sock.opts.ip_mtu_discover.load(Ordering::Acquire)),
        IP_MTU => socket_path_mtu(sock, false, out),
        IP_RECVERR => out.i32(i32::from(sock.error.recverr4())),
        IP_MULTICAST_TTL => scalar_get(sock, net::sock_mcast::McastScalarGet::V4Ttl, out),
        IP_MULTICAST_LOOP => scalar_get(sock, net::sock_mcast::McastScalarGet::V4Loop, out),
        IP_MSFILTER => ipv4_msfilter_get(sock, out.optval, out.optlen_p),
        MCAST_MSFILTER => ipv4_group_filter_get(sock, out.optval, out.optlen_p),
        _ => -(Errno::Enoprotoopt.as_i32() as i64),
    }
}
