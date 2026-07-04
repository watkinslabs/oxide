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

/// F149/F180c: resolve next-hop MAC for an outbound IP frame body.
/// Returns Some(mac) when the neighbor cache has the next-hop, else
/// None after firing ARP/NDP so a subsequent attempt can resolve.
/// # C: O(1) cache hit; O(route lookup + request xmit) on miss.
pub(super) fn resolve_next_hop_mac(
    device_key: DeviceKey,
    src_mac: [u8; 6],
    proto: u16,
    body: &[u8],
) -> Option<net::MacAddr> {
    if proto == net::eth_p::IPV6 {
        return resolve_ipv6_next_hop_mac(device_key, src_mac, body);
    }
    if proto != net::eth_p::IPV4 || body.len() < 20 { return None; }
    let dst_ip = net::Ipv4Addr::new(body[16], body[17], body[18], body[19]);
    #[cfg(target_os = "oxide-kernel")]
    let next_hop_ip = match net::sock::stack().routes.lookup(dst_ip) {
        Some(r) => r.gateway.unwrap_or(dst_ip),
        None    => dst_ip,
    };
    #[cfg(not(target_os = "oxide-kernel"))]
    let next_hop_ip = dst_ip;
    let runtime = super::netdev::net_runtime_for(device_key);
    if let Some(m) = runtime.as_ref().and_then(|runtime| runtime.arp.lookup(next_hop_ip)) {
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
        let _ = super::tx::tx_frame_for(device_key, &frame);
    }
    None
}

fn resolve_ipv6_next_hop_mac(
    device_key: DeviceKey,
    src_mac: [u8; 6],
    body: &[u8],
) -> Option<net::MacAddr> {
    let hdr = match net::ipv6::Ipv6Hdr::parse(body) {
        Ok(h) => h,
        Err(_) => return None,
    };

    #[cfg(target_os = "oxide-kernel")]
    let (next_hop, src_ip) = {
        let stack = net::sock::stack();
        let route = stack.routes6.lookup(hdr.dst);
        match route {
            Some(r) => (r.gateway.unwrap_or(hdr.dst), r.src_hint),
            None => (hdr.dst, Some(hdr.src)),
        }
    };
    #[cfg(not(target_os = "oxide-kernel"))]
    let (next_hop, src_ip) = (hdr.dst, Some(hdr.src));

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
        let src_ip = src_ip?;
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
        let _ = super::tx::tx_frame_for(device_key, &frame);
        None
    }
}

#[cfg(not(target_os = "oxide-kernel"))]
pub(super) fn learn_ndp_from_ipv6(device_key: DeviceKey, l3: &[u8]) {
    let Ok(hdr) = net::ipv6::Ipv6Hdr::parse(l3) else {
        return;
    };
    if hdr.next_header != net::icmpv6::IPPROTO_ICMPV6 {
        return;
    }
    let payload_end = net::ipv6::IPV6_HDR_LEN + hdr.payload_length as usize;
    if payload_end > l3.len() {
        return;
    }
    let payload = &l3[net::ipv6::IPV6_HDR_LEN..payload_end];
    if payload.is_empty() {
        return;
    }
    let Some(runtime) = super::netdev::net_runtime_for(device_key) else {
        return;
    };
    match payload[0] {
        t if t == net::ndp::NDP_NS => {
            if let Ok(msg) = net::ndp::NdpMsg::parse(payload, hdr.src, hdr.dst) {
                if let Some(mac) = msg.lladdr {
                    runtime.ndp.insert(hdr.src, mac);
                }
            }
        }
        t if t == net::ndp::NDP_NA => {
            if let Ok(msg) = net::ndp::NdpMsg::parse(payload, hdr.src, hdr.dst) {
                if let Some(mac) = msg.lladdr {
                    runtime.ndp.insert(msg.target, mac);
                }
            }
        }
        t if t == net::ndp::NDP_RA => {
            if let Ok(ra) = net::ndp::RouterAdvertisement::parse(payload, hdr.src, hdr.dst) {
                if let Some(mac) = ra.source_lladdr {
                    runtime.ndp.insert(hdr.src, mac);
                }
            }
        }
        _ => {}
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
