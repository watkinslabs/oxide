// The socket-facing half of the nonlocal-bind screen. Decision logic and
// classification live in `crate::bind_screen`; this file only reads the
// socket's permission bits and hands them over, so every bind path — stream,
// datagram, raw and the ICMP datagram endpoint — screens through one owner.

use super::{InetSocket, NetError};
use crate::bind_screen::{self, SockNonlocal};
use crate::NetIfaceId;

/// The socket's nonlocal-address permission, read off the option state the
/// socket shares with its transport endpoint — never a copy. # C: O(1)
pub fn permission(sock: &InetSocket) -> SockNonlocal { sock.opts.ip.nonlocal() }

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
