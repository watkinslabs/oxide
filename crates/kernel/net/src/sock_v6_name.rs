// The IPv6 name-query DECISIONS `inet6_getname` makes: which scope id a
// reported address carries, and which device the live transport owner is
// bound to. No cfg gating — `sock_v6` (the kernel-only connect path) re-exports
// these, and hosted `cargo test` drives them directly.

use crate::sock::InetSocket;

const IPV6_MULTICAST_SCOPE_MASK: u8 = 0x0f;
const IPV6_SCOPE_LINK_LOCAL: u8 = 2;
const IPV6_SCOPE_OCTET: usize = 1;
pub(crate) const IPV6_NO_SCOPE_ID: u32 = 0;

/// Linux `ipv6_iface_scope_id`: expose a device only for interface- or
/// link-scoped addresses, never for global IPv6 addresses. # C: O(1)
pub fn name_scope_id(address: crate::Ipv6Addr, bound_ifindex: u32) -> u32 {
    let multicast_scope = address.is_multicast()
        && (address.0[IPV6_SCOPE_OCTET] & IPV6_MULTICAST_SCOPE_MASK) <= IPV6_SCOPE_LINK_LOCAL;
    if address.is_link_local() || multicast_scope { bound_ifindex } else { IPV6_NO_SCOPE_ID }
}

/// Resolve the device recorded by the live IPv6 transport owner for a name
/// query. A socket-level SO_BINDTODEVICE setting is authoritative before an
/// endpoint exists; otherwise the endpoint/reservation owns the binding.
/// # C: O(1)
pub fn name_bound_ifindex(sock: &InetSocket) -> u32 {
    use core::sync::atomic::Ordering;
    let configured = sock.opts.bound_ifindex.load(Ordering::Acquire);
    if configured != IPV6_NO_SCOPE_ID { return configured; }
    if let Some(endpoint) = sock.udp6.lock().as_ref().cloned() {
        return endpoint.bound_ifindex.load(Ordering::Acquire);
    }
    sock.tcp_bind.lock().as_ref().and_then(|bind| bind.bound_iface())
        .map(crate::NetIfaceId::raw).unwrap_or(IPV6_NO_SCOPE_ID)
}

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod tests;
