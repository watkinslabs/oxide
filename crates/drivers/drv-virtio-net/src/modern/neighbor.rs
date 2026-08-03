use super::DeviceKey;




/// Link-layer address for a transmit that arrived without one.
///
/// Neighbour resolution belongs to the neighbour layer, which owns the state
/// machine, the unresolved queue and the solicitation for both families and
/// hands the driver a packet with its address already attached. Nothing is
/// resolved here: a unicast next hop reaching this path is one the neighbour
/// layer declined to queue, and only the multicast mappings — computed, never
/// learned — have an answer.
/// # C: O(1)
pub(super) fn resolve_next_hop_mac(
    device_key: DeviceKey,
    src_mac: [u8; 6],
    next_hop: net::pkt::TxNextHop,
) -> Option<net::MacAddr> {
    resolve_next_hop_mac_observed(device_key, src_mac, next_hop, &mut |_, _, _| {})
}

pub(super) fn resolve_next_hop_mac_observed(
    device_key: DeviceKey,
    src_mac: [u8; 6],
    next_hop: net::pkt::TxNextHop,
    observe: &mut dyn FnMut(&[u8], u16, usize),
) -> Option<net::MacAddr> {
    match next_hop {
        net::pkt::TxNextHop::V4(ip) => {
            if ip.is_broadcast() { return Some(net::MacAddr::BROADCAST); }
            return None;
        }
        net::pkt::TxNextHop::V6 { addr, .. } => {
            if addr.is_multicast() { return Some(net::ndp::multicast_ethernet(addr)); }
            return None;
        }
    }
}
