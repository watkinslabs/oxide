#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use syscall::errno::Errno;

use super::multicast::{ipv6_group_filter_get, scalar_get};
use super::out::OptOut;
use super::path_mtu::socket_path_mtu;
use super::uapi::*;

/// `getsockopt(fd, IPPROTO_IPV6, ...)`. # C: O(1)
pub(super) fn get(sock: &Arc<net::sock::InetSocket>, optname: u64, out: &OptOut) -> i64 {
    match optname {
        IPV6_V6ONLY => out.i32(sock.opts.ipv6_v6only.load(Ordering::Acquire)),
        IPV6_UNICAST_HOPS => {
            // Linux resolves a negative (unset) hop limit to the effective
            // default at read time, matching the TX path.
            let h = sock.opts.ipv6_ucast_hops.load(Ordering::Acquire);
            out.i32(if h < 0 { net::ipv6::IPV6_DEFAULT_HOP_LIMIT as i32 } else { h })
        }
        IPV6_MULTICAST_HOPS => {
            let h = sock.opts.ipv6_mcast_hops.load(Ordering::Acquire);
            // Unset multicast hop limit resolves to the Linux default of 1.
            out.i32(if h < 0 { IPV6_DEFAULT_MULTICAST_HOPS } else { h })
        }
        IPV6_MULTICAST_LOOP => scalar_get(sock, net::sock_mcast::McastScalarGet::V6Loop, out),
        IPV6_MULTICAST_IF => scalar_get(sock, net::sock_mcast::McastScalarGet::V6Iface, out),
        IPV6_MTU => socket_path_mtu(sock, true, out),
        IPV6_MTU_DISCOVER => out.i32(sock.opts.ipv6_mtu_discover.load(Ordering::Acquire)),
        IPV6_RECVERR => out.i32(i32::from(sock.error.recverr6())),
        IPV6_RECVPKTINFO => out.i32(sock.opts.ipv6_recvpktinfo.load(Ordering::Acquire)),
        IPV6_RECVHOPLIMIT => out.i32(sock.opts.ipv6_recvhoplimit.load(Ordering::Acquire)),
        IPV6_TCLASS => {
            // Linux resolves the unset (-1) sticky traffic class to 0 at read
            // time, matching the TX path.
            let t = sock.opts.ipv6_tclass.load(Ordering::Acquire);
            out.i32(if t < 0 { 0 } else { t })
        }
        IPV6_RECVTCLASS => out.i32(sock.opts.ipv6_recvtclass.load(Ordering::Acquire)),
        MCAST_MSFILTER => ipv6_group_filter_get(sock, out.optval, out.optlen_p),
        _ => -(Errno::Enoprotoopt.as_i32() as i64),
    }
}
