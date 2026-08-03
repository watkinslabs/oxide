/// Link-layer address for a transmit that arrived without one.
///
/// Neighbour resolution belongs to the neighbour layer, which owns the state
/// machine, the unresolved queue and the solicitation for both families and
/// hands the driver a packet with its address already attached. Nothing is
/// resolved here: a unicast next hop reaching this path is one the neighbour
/// layer declined to queue, and only the multicast mappings — computed from
/// the address, never learned — have an answer. That is why this takes no
/// device, no source address and no observer: there is no state to consult
/// and no solicitation to emit.
/// # C: O(1)
pub(super) fn link_address_for(next_hop: net::pkt::TxNextHop) -> Option<net::MacAddr> {
    match next_hop {
        net::pkt::TxNextHop::V4(ip) =>
            ip.is_broadcast().then_some(net::MacAddr::BROADCAST),
        net::pkt::TxNextHop::V6 { addr, .. } =>
            addr.is_multicast().then(|| net::ndp::multicast_ethernet(addr)),
    }
}
