// The socket-facing half of the nonlocal-bind screen. Decision logic and
// classification live in `crate::bind_screen`; this file only reads the
// socket's permission bits and hands them over, so every bind path — stream,
// datagram, raw and the ICMP datagram endpoint — screens through one owner.

use super::{InetSocket, NetError};
use crate::bind_screen::{self, SockNonlocal};
use crate::NetIfaceId;
use crate::sock_opts::sol_ip::flag;

/// The socket's nonlocal-bind permission. Both bits live in the `IPPROTO_IP`
/// option word: the `IPPROTO_IPV6` option numbers write the same storage.
/// # C: O(1)
pub fn permission(sock: &InetSocket) -> SockNonlocal {
    SockNonlocal {
        freebind: sock.opts.ip.flag(flag::FREEBIND),
        transparent: sock.opts.ip.flag(flag::TRANSPARENT),
    }
}

/// Screen a candidate IPv4 local address for this socket. # C: O(N_addrs)
pub fn screen_v4(sock: &InetSocket, addr: crate::Ipv4Addr, iface: Option<NetIfaceId>)
    -> Result<(), NetError>
{
    bind_screen::screen_v4(sock.net_ns(), addr, iface, permission(sock))
}

/// Screen a candidate IPv6 local address for this socket. # C: O(N_addrs)
pub fn screen_v6(sock: &InetSocket, addr: crate::Ipv6Addr, iface: Option<NetIfaceId>)
    -> Result<(), NetError>
{
    bind_screen::screen_v6(sock.net_ns(), addr, iface, permission(sock))
}
