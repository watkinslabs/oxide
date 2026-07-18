use super::DeviceKey;

#[cfg(target_os = "oxide-kernel")]
fn ndp_lookup_for_device(device_key: DeviceKey, next_hop: net::Ipv6Addr) -> Option<net::MacAddr> {
    let iface = super::registered_iface_for(device_key)?;
    net::sock::stack().ndp_lookup(iface, next_hop)
}

#[cfg(not(target_os = "oxide-kernel"))]
fn ndp_lookup_for_device(device_key: DeviceKey, next_hop: net::Ipv6Addr) -> Option<net::MacAddr> {
    super::netdev::net_runtime_for(device_key).and_then(|runtime| runtime.ndp.lookup(next_hop))
}

fn solicited_node_multicast(ip: net::Ipv6Addr) -> net::Ipv6Addr {
    let mut out = [0u8; 16];
    out[0] = 0xff;
    out[1] = 0x02;
    out[11] = 0x01;
    out[12] = 0xff;
    out[13] = ip.0[13];
    out[14] = ip.0[14];
    out[15] = ip.0[15];
    net::Ipv6Addr(out)
}

fn solicited_node_ethernet(ip: net::Ipv6Addr) -> net::MacAddr {
    net::MacAddr([0x33, 0x33, 0xff, ip.0[13], ip.0[14], ip.0[15]])
}

fn ipv6_multicast_ethernet(ip: net::Ipv6Addr) -> net::MacAddr {
    net::MacAddr([0x33, 0x33, ip.0[12], ip.0[13], ip.0[14], ip.0[15]])
}

/// F149/F180c: resolve the route-selected next-hop MAC for an outbound packet.
/// Returns Some(mac) when the neighbor cache has the next-hop, else
/// None after firing ARP/NDP so a subsequent attempt can resolve.
/// # C: O(1) cache hit or request xmit.
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
    let next_hop_ip = match next_hop {
        net::pkt::TxNextHop::V4(ip) => ip,
        net::pkt::TxNextHop::V6 { addr, src } => {
            return resolve_ipv6_next_hop_mac(device_key, src_mac, addr, src, observe);
        }
    };
    if next_hop_ip.is_broadcast() {
        return Some(net::MacAddr([0xff; 6]));
    }
    #[cfg(target_os = "oxide-kernel")]
    let resolved = super::registered_iface_for(device_key)
        .and_then(|iface| net::sock::stack().arp_lookup(iface, next_hop_ip));
    #[cfg(not(target_os = "oxide-kernel"))]
    let resolved = super::netdev::net_runtime_for(device_key)
        .and_then(|runtime| runtime.arp.lookup(next_hop_ip));
    if let Some(m) = resolved {
        return Some(m);
    }
    // Cache miss — fire an ARP request so the next call resolves.
    if let Some(our_ip) = super::rx::first_iface_ip_for(device_key) {
        let req = net::arp::build_request(
            net::MacAddr(src_mac), our_ip, next_hop_ip,
        );
        let mut frame = alloc::vec![0u8; 14 + req.len()];
        net::ethernet::EthHdr::write_to(
            net::MacAddr([0xFF; 6]), net::MacAddr(src_mac),
            net::eth_p::ARP, &mut frame[..14],
        );
        frame[14..].copy_from_slice(&req);
        observe(&frame, net::eth_p::ARP, 14);
        let _ = super::tx::tx_frame_for(device_key, &frame);
    }
    None
}

fn resolve_ipv6_next_hop_mac(
    device_key: DeviceKey,
    src_mac: [u8; 6],
    next_hop: net::Ipv6Addr,
    src_ip: net::Ipv6Addr,
    observe: &mut dyn FnMut(&[u8], u16, usize),
) -> Option<net::MacAddr> {
    if next_hop.is_multicast() { return Some(ipv6_multicast_ethernet(next_hop)); }

    if let Some(m) = ndp_lookup_for_device(device_key, next_hop) {
        return Some(m);
    }

    #[cfg(not(target_os = "oxide-kernel"))]
    {
        let _ = src_mac;
        let _ = src_ip;
        return None;
    }

    #[cfg(target_os = "oxide-kernel")]
    {
        if src_ip == net::Ipv6Addr::ANY { return None; }
        let ns_dst = solicited_node_multicast(next_hop);
        let ns_eth = solicited_node_ethernet(next_hop);
        let ns = net::ndp::NdpMsg::build_ns(src_ip, ns_dst, net::MacAddr(src_mac), next_hop);
        let total = net::ipv6::IPV6_HDR_LEN + ns.len();
        let mut frame = alloc::vec![0u8; 14 + total];
        net::ethernet::EthHdr::write_to(
            ns_eth, net::MacAddr(src_mac), net::eth_p::IPV6, &mut frame[..14],
        );
        let v6 = net::ipv6::Ipv6Hdr::build(src_ip, ns_dst, net::IpProto::Icmpv6, ns.len() as u16);
        v6.write_to(&mut frame[14..14 + net::ipv6::IPV6_HDR_LEN]);
        frame[14 + net::ipv6::IPV6_HDR_LEN..].copy_from_slice(&ns);
        observe(&frame, net::eth_p::IPV6, 14);
        let _ = super::tx::tx_frame_for(device_key, &frame);
        None
    }
}

#[cfg(test)]
pub(super) fn test_solicited_node_multicast(ip: net::Ipv6Addr) -> net::Ipv6Addr {
    solicited_node_multicast(ip)
}

#[cfg(test)]
pub(super) fn test_solicited_node_ethernet(ip: net::Ipv6Addr) -> net::MacAddr {
    solicited_node_ethernet(ip)
}
