// The local-address screen every `bind(2)` path applies before it publishes a
// local endpoint. One owner for the whole rule: a socket may claim a local
// address only when the namespace owns it, unless the socket (or the
// namespace) has been told to accept nonlocal claims.
//
// No target gate: the decision logic must run under hosted `cargo test`.

use crate::addr::{Ipv4Addr, Ipv6Addr};
use crate::net_ns::NetSysctlKey;
use crate::netdev::NetError;
use crate::NetIfaceId;

/// How the namespace's address and local-route tables classify a candidate
/// IPv4 local address. `Other` covers every classification a bind refuses:
/// unicast owned by a peer, an unreachable destination, a blackhole. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum V4AddrType { Unspecified, Local, Multicast, Broadcast, Other }

/// How the namespace classifies a candidate IPv6 local address. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum V6AddrType { Unspecified, Multicast, Local, Other }

/// The per-socket half of the nonlocal-bind permission. Both bits live in the
/// IPv4 option word because the IPv6 option numbers write the same storage —
/// there is no separate v6 freebind or v6 transparent bit. # C: O(1)
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct SockNonlocal { pub freebind: bool, pub transparent: bool }

/// Whether this socket may claim an address the namespace does not own.
/// # C: O(1)
pub fn can_nonlocal(sock: SockNonlocal, sysctl_nonlocal: bool) -> bool {
    sysctl_nonlocal || sock.freebind || sock.transparent
}

/// IPv4 screen: the wildcard, a locally owned address, a multicast group and a
/// broadcast address are always claimable; anything else needs the nonlocal
/// permission. # C: O(1)
pub fn v4_admits(kind: V4AddrType, nonlocal: bool) -> bool {
    nonlocal || matches!(kind,
        V4AddrType::Unspecified | V4AddrType::Local
        | V4AddrType::Multicast | V4AddrType::Broadcast)
}

/// IPv6 screen: the wildcard and multicast groups bypass the ownership test
/// entirely — a nonlocal permission is consulted only for unicast. There is no
/// IPv6 broadcast classification. # C: O(1)
pub fn v6_admits(kind: V6AddrType, nonlocal: bool) -> bool {
    match kind {
        V6AddrType::Unspecified | V6AddrType::Multicast => true,
        V6AddrType::Local => true,
        V6AddrType::Other => nonlocal,
    }
}

/// `net.ipv4.ip_nonlocal_bind` in a live namespace. # C: O(log N)
pub fn v4_sysctl_nonlocal(ns: u64) -> bool {
    crate::sysctl::value_in(ns, NetSysctlKey::Ipv4NonlocalBind).unwrap_or(0) != 0
}

/// `net.ipv6.ip_nonlocal_bind` in a live namespace. # C: O(log N)
pub fn v6_sysctl_nonlocal(ns: u64) -> bool {
    crate::sysctl::value_in(ns, NetSysctlKey::Ipv6NonlocalBind).unwrap_or(0) != 0
}

/// Classify a candidate IPv4 local address against the namespace's interface
/// addresses, its per-interface broadcast addresses and its local route table.
/// A device binding narrows every table to that device. # C: O(N_addrs)
pub fn classify_v4(ns: u64, addr: Ipv4Addr, iface: Option<NetIfaceId>) -> V4AddrType {
    if addr.is_unspecified() { return V4AddrType::Unspecified; }
    if addr.is_multicast() { return V4AddrType::Multicast; }
    if addr.is_broadcast() { return V4AddrType::Broadcast; }
    let rows = crate::iface_addr::snapshot_ns(ns);
    let scoped = |row_iface: NetIfaceId| iface.is_none_or(|id| id == row_iface);
    if rows.iter().any(|row| row.addr == addr && scoped(row.iface)) { return V4AddrType::Local; }
    if rows.iter().any(|row| row.broadcast == Some(addr) && scoped(row.iface)) {
        return V4AddrType::Broadcast;
    }
    let local_route = crate::global_stack().routes.lookup_in(ns, addr).is_some_and(|route| {
        route.table == crate::policy_rule::RT_TABLE_LOCAL && route.src_hint == Some(addr)
            && scoped(route.iface)
    });
    if local_route { V4AddrType::Local } else { V4AddrType::Other }
}

/// Classify a candidate IPv6 local address. # C: O(N_addrs)
pub fn classify_v6(ns: u64, addr: Ipv6Addr, iface: Option<NetIfaceId>) -> V6AddrType {
    if addr.is_unspecified() { return V6AddrType::Unspecified; }
    if addr.is_multicast() { return V6AddrType::Multicast; }
    let owned = crate::global_stack().v6_addr_snapshot_in(ns).into_iter()
        .any(|(id, row)| row.addr == addr && iface.is_none_or(|want| want == id));
    if owned { V6AddrType::Local } else { V6AddrType::Other }
}

/// Apply the IPv4 screen, reporting the address as unavailable when it fails.
/// # C: O(N_addrs)
pub fn screen_v4(ns: u64, addr: Ipv4Addr, iface: Option<NetIfaceId>,
    sock: SockNonlocal) -> Result<(), NetError>
{
    let nonlocal = can_nonlocal(sock, v4_sysctl_nonlocal(ns));
    if v4_admits(classify_v4(ns, addr, iface), nonlocal) { return Ok(()); }
    Err(NetError::Eaddrnotavail)
}

/// Apply the IPv6 screen. # C: O(N_addrs)
pub fn screen_v6(ns: u64, addr: Ipv6Addr, iface: Option<NetIfaceId>,
    sock: SockNonlocal) -> Result<(), NetError>
{
    let nonlocal = can_nonlocal(sock, v6_sysctl_nonlocal(ns));
    if v6_admits(classify_v6(ns, addr, iface), nonlocal) { return Ok(()); }
    Err(NetError::Eaddrnotavail)
}

#[cfg(test)]
mod tests;
