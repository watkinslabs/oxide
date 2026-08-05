// The router-alert chain: the raw sockets that asked to see transit packets
// carrying the IPv4 Router Alert option, and the fan-out that hands each one a
// copy before the packet is forwarded.
//
// Module manifest:
// - option recognition on a received header (`v4_present`)
// - chain membership (`v4_join` / `v4_leave` / `v4_forget`)
// - the admission answers both option levels share (`admit`)
// - the `IPV6_ROUTER_ALERT` selector shape (`v6_selector`)
// - delivery fan-out (`v4_deliver` / `v6_deliver`)
//
// No target gate: the decision logic must run under hosted `cargo test`.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use syscall::errno::Errno;
use sync::{Socket as LockClass, Spinlock};

use crate::addr::NetIfaceId;
use crate::raw4::{Raw4Datagram, Raw4Endpoint};
use crate::sock_opts::sol_ip::uapi::{IPOPT_END, IPOPT_NOOP, IPOPT_RA};

/// Length of a Router Alert option, including its type and length bytes.
const RA_OPTION_LEN: usize = 4;
/// The only Router Alert value that means "examine this packet": every other
/// value is reserved and leaves the packet on the forwarding path.
const RA_VALUE_EXAMINE: u16 = 0;
/// Fixed part of an IPv4 header, before the option area.
const IPV4_FIXED_HDR_LEN: usize = 20;
/// The stored `IPV6_ROUTER_ALERT` selector of a socket holding no chain slot.
pub const V6_NO_SLOT: i32 = -1;
/// The lowest selector value that takes a chain slot.
pub const V6_FIRST_SLOT: i32 = 0;

/// One chain member: the namespace it joined from and the endpoint that gets
/// the copy. The weak reference is what lets a closed socket fall out of the
/// chain without the receive path touching refcounts.
struct V4Entry { ns: u64, endpoint: Weak<Raw4Endpoint> }

static V4_CHAIN: Spinlock<Vec<V4Entry>, LockClass> = Spinlock::new(Vec::new());

/// The admission both option levels share: joining twice is `EADDRINUSE`,
/// leaving a chain never joined is `ENOBUFS`. # C: O(1)
pub fn admit(joining: bool, already_joined: bool) -> Result<(), Errno> {
    match (joining, already_joined) {
        (true, true) => Err(Errno::Eaddrinuse),
        (false, false) => Err(Errno::Enobufs),
        _ => Ok(()),
    }
}

/// `IPV6_ROUTER_ALERT` carries a selector, not a boolean: a negative value
/// leaves the chain, and every non-negative value joins it matching alert
/// packets carrying exactly that value. # C: O(1)
pub fn v6_selector(val: i32) -> Option<i32> {
    if val < V6_FIRST_SLOT { None } else { Some(val) }
}

/// Router Alert selector carried in the first IPv6 Hop-by-Hop header. # C: O(headers)
pub fn v6_packet_selector(next_header: u8, payload: &[u8]) -> Option<i32> {
    if next_header != 0 || payload.len() < 8 { return None; }
    let len = (payload[1] as usize + 1) * 8;
    if len > payload.len() { return None; }
    let mut offset = 2usize;
    while offset < len {
        let typ = payload[offset];
        if typ == 0 { offset += 1; continue; }
        if offset + 2 > len { return None; }
        let option_len = payload[offset + 1] as usize;
        if offset + 2 + option_len > len { return None; }
        if typ == 5 && option_len == 2 {
            return Some(u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as i32);
        }
        offset += 2 + option_len;
    }
    None
}

/// Deliver a transit IPv6 Router Alert through canonical raw endpoint tables.
/// An isolate receiver excludes packets that entered a different namespace;
/// otherwise raw sockets in every live namespace may observe the packet.
/// # C: O(N endpoints * packet)
pub fn v6_deliver(stack: &crate::stack::NetStack, ingress_ns: u64, iface: NetIfaceId,
    l3: &[u8]) -> bool
{
    let Ok(hdr) = crate::ipv6::Ipv6Hdr::parse(l3) else { return false; };
    let total = crate::ipv6::IPV6_HDR_LEN + hdr.payload_length as usize;
    if total > l3.len() { return false; }
    let payload = &l3[crate::ipv6::IPV6_HDR_LEN..total];
    let Some(selector) = v6_packet_selector(hdr.next_header, payload) else { return false; };
    let Ok(crate::ipv6_ext::ExtWalk::Done { next_header, payload }) =
        crate::ipv6_ext::walk(hdr.next_header, payload) else { return false; };
    let hatype = stack.ifaces.lookup_in_ns(iface, ingress_ns).map_or(0, |dev| dev.hardware_type());
    let mut delivered = false;
    for endpoint in stack.raw6_endpoints_all_namespaces() {
        if !endpoint.router_alert_matches(selector, ingress_ns, iface) { continue; }
        delivered |= endpoint.receive_router_alert(crate::raw6::Raw6RxPacket {
            net_ns: ingress_ns, protocol: next_header, src: hdr.src, dst: hdr.dst, iface,
            hop_limit: hdr.hop_limit, traffic_class: hdr.traffic_class,
            flow_label: hdr.flow_label, hatype, payload, packet: &l3[..total],
        }) == crate::raw6::Raw6RxDisposition::Queued;
    }
    delivered
}

/// Whether a received IPv4 header carries a Router Alert option asking routers
/// to examine the packet. Options shorter than their own length byte, or an
/// area that ends before the option does, stop the walk. # C: O(optlen)
pub fn v4_present(l3: &[u8]) -> bool {
    let Some(&first) = l3.first() else { return false };
    let ihl = (first & 0x0f) as usize * 4;
    if ihl <= IPV4_FIXED_HDR_LEN || ihl > l3.len() { return false; }
    let mut area = &l3[IPV4_FIXED_HDR_LEN..ihl];
    while let Some(&kind) = area.first() {
        if kind == IPOPT_END { return false; }
        if kind == IPOPT_NOOP { area = &area[1..]; continue; }
        let Some(&len) = area.get(1) else { return false };
        let len = len as usize;
        if len < 2 || len > area.len() { return false; }
        if kind == IPOPT_RA && len == RA_OPTION_LEN
            && u16::from_be_bytes([area[2], area[3]]) == RA_VALUE_EXAMINE
        {
            return true;
        }
        area = &area[len..];
    }
    false
}

/// Whether this endpoint already holds a chain slot. # C: O(N_chain)
pub fn v4_joined(endpoint: &Arc<Raw4Endpoint>) -> bool {
    let mut chain = V4_CHAIN.lock();
    prune(&mut chain);
    chain.iter().any(|entry| ptr_eq(&entry.endpoint, endpoint))
}

/// Take a chain slot for this endpoint. # C: O(N_chain)
pub fn v4_join(endpoint: &Arc<Raw4Endpoint>) -> Result<(), Errno> {
    let mut chain = V4_CHAIN.lock();
    prune(&mut chain);
    if chain.iter().any(|entry| ptr_eq(&entry.endpoint, endpoint)) {
        return Err(Errno::Eaddrinuse);
    }
    chain.push(V4Entry { ns: endpoint.net_ns(), endpoint: Arc::downgrade(endpoint) });
    Ok(())
}

/// Release this endpoint's chain slot. # C: O(N_chain)
pub fn v4_leave(endpoint: &Arc<Raw4Endpoint>) -> Result<(), Errno> {
    let mut chain = V4_CHAIN.lock();
    prune(&mut chain);
    let before = chain.len();
    chain.retain(|entry| !ptr_eq(&entry.endpoint, endpoint));
    if chain.len() == before { return Err(Errno::Enobufs); }
    Ok(())
}

/// Drop a closing endpoint's slot without answering an option. # C: O(N_chain)
pub fn v4_forget(endpoint: &Arc<Raw4Endpoint>) {
    let mut chain = V4_CHAIN.lock();
    chain.retain(|entry| entry.endpoint.upgrade().is_some() && !ptr_eq(&entry.endpoint, endpoint));
}

/// Hand a copy of one transit packet to every chain member watching this
/// protocol in this namespace. A member bound to a device sees only packets
/// that arrived on it. Reports whether the packet was consumed: a delivered
/// alert packet leaves the forwarding path. # C: O(N_chain * packet)
pub fn v4_deliver(ns: u64, iface: NetIfaceId, l3: &[u8]) -> bool {
    let Ok(hdr) = crate::ipv4::Ipv4Hdr::parse(l3) else { return false };
    let members: Vec<Arc<Raw4Endpoint>> = {
        let mut chain = V4_CHAIN.lock();
        prune(&mut chain);
        chain.iter().filter(|entry| entry.ns == ns)
            .filter_map(|entry| entry.endpoint.upgrade())
            .filter(|endpoint| endpoint.protocol() == hdr.proto)
            .collect()
    };
    let mut delivered = false;
    for endpoint in members {
        let state = endpoint.snapshot();
        if !state.accepting { continue; }
        if state.bound_iface.is_some_and(|bound| bound != iface) { continue; }
        delivered |= endpoint.enqueue(Raw4Datagram {
            packet: l3.to_vec(),
            source: hdr.src,
            destination: hdr.dst,
            iface,
            ttl: hdr.ttl,
            // A forwarded packet's option area is not compiled by this stack,
            // so a router-alert receiver sees none.
            options: Default::default(),
        });
    }
    delivered
}

fn ptr_eq(weak: &Weak<Raw4Endpoint>, endpoint: &Arc<Raw4Endpoint>) -> bool {
    weak.upgrade().is_some_and(|held| Arc::ptr_eq(&held, endpoint))
}

fn prune(chain: &mut Vec<V4Entry>) {
    chain.retain(|entry| entry.endpoint.upgrade().is_some());
}

#[cfg(test)]
mod tests;
