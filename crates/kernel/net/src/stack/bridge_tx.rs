//! Bridge Ethernet transmit work through canonical neighbour ownership.

use super::*;

impl NetStack {
    const BRIDGE_NEIGHBOUR_QUEUE_LIMIT: usize = 32;
    const BRIDGE_NEIGHBOUR_QUEUE_TOTAL_LIMIT: usize = 256;
    const BRIDGE_NEIGHBOUR_RETRY_NS: u64 = 1_000_000_000;

    /// Transmit a routed L3 packet through bridge-owned IPv4 neighbor state. # C: O(packet + N ports)
    pub(crate) fn bridge_xmit_l3(&self, bridge: NetIfaceId, packet: crate::Pkt) -> NetResult<()> {
        let next_hop = packet.next_hop.ok_or(NetError::Edestaddrreq)?;
        let destination = match next_hop {
            crate::pkt::TxNextHop::V4(target) => self.arp_lookup(bridge, target),
            crate::pkt::TxNextHop::V6 { addr, .. } => self.ndp_lookup(bridge, addr),
        };
        let Some(destination) = destination else {
            let key = match next_hop {
                crate::pkt::TxNextHop::V4(ip) => IpAddr::V4(ip),
                crate::pkt::TxNextHop::V6 { addr, .. } => IpAddr::V6(addr),
            };
            let solicitation = match key {
                IpAddr::V4(target) => self.bridge_ipv4_solicitation(bridge, target)?,
                IpAddr::V6(target) => self.bridge_ipv6_solicitation(bridge, target)?,
            };
            let (solicit, id) = self.bridge_queue_neighbour(bridge, key, packet)?;
            if solicit {
                if let Err(error) = self.bridge_xmit_raw(bridge, &solicitation) {
                    self.bridge_cancel_neighbour(bridge, key, id);
                    return Err(error);
                }
            }
            return Ok(());
        };
        let (_, mac) = self.bridges.identity(bridge)?;
        let mut frame = alloc::vec![0u8; crate::ethernet::ETH_HDR_LEN + packet.len()];
        crate::ethernet::EthHdr::write_to(destination, mac, packet.proto, &mut frame);
        frame[crate::ethernet::ETH_HDR_LEN..].copy_from_slice(packet.data());
        self.bridge_xmit_raw(bridge, &frame)
    }

    /// Answer ARP for an IPv4 address owned by a bridge link. # C: O(frame + N ports)
    pub(super) fn bridge_answer_arp(&self, bridge: &crate::IngressLease, frame: &[u8],
                                    header: crate::ethernet::EthHdr) -> NetResult<()>
    {
        if header.ethertype != crate::eth_p::ARP { return Ok(()); }
        let arp = match crate::arp::ArpPkt::parse(&frame[header.hdr_len..]) { Ok(arp) => arp, Err(_) => return Ok(()) };
        let Some((address, _)) = crate::iface_addr::primary(bridge.net_ns(), bridge.iface()) else { return Ok(()) };
        if arp.opcode != crate::arp::ARP_OP_REQUEST || arp.target_ip != address { return Ok(()); }
        let body = crate::arp::build_reply(&arp, bridge.device().mac());
        let mut reply = alloc::vec![0u8; crate::ethernet::ETH_HDR_LEN + body.len()];
        crate::ethernet::EthHdr::write_to(arp.sender_mac, bridge.device().mac(), crate::eth_p::ARP, &mut reply);
        reply[crate::ethernet::ETH_HDR_LEN..].copy_from_slice(&body);
        self.bridge_xmit_raw(bridge.iface(), &reply)
    }

    /// Queue one accepted packet until this bridge next hop resolves. # C: O(N destinations)
    fn bridge_queue_neighbour(&self, bridge: NetIfaceId, next_hop: IpAddr,
                              packet: crate::Pkt) -> NetResult<(bool, u64)>
    {
        let now = super::monotonic_ns_safe();
        let mut pending = self.bridge_pending.lock();
        if pending.values().map(|row| row.packets.len()).sum::<usize>() >= Self::BRIDGE_NEIGHBOUR_QUEUE_TOTAL_LIMIT {
            return Err(NetError::Enobufs);
        }
        let row = pending.entry((bridge, next_hop)).or_insert_with(|| BridgePending {
            packets: alloc::collections::VecDeque::new(), last_solicit_ns: 0, next_id: 1,
        });
        if row.packets.len() >= Self::BRIDGE_NEIGHBOUR_QUEUE_LIMIT { return Err(NetError::Enobufs); }
        let solicit = row.packets.is_empty() || (now != 0
            && now.saturating_sub(row.last_solicit_ns) >= Self::BRIDGE_NEIGHBOUR_RETRY_NS);
        if solicit { row.last_solicit_ns = now; }
        let id = row.next_id;
        row.next_id = row.next_id.wrapping_add(1).max(1);
        row.packets.push_back((id, packet));
        Ok((solicit, id))
    }

    /// Retract one packet when its initial neighbour solicitation could not leave the bridge. # C: O(N packets)
    fn bridge_cancel_neighbour(&self, bridge: NetIfaceId, next_hop: IpAddr, id: u64) {
        let mut pending = self.bridge_pending.lock();
        let Some(row) = pending.get_mut(&(bridge, next_hop)) else { return; };
        let Some(index) = row.packets.iter().position(|(queued, _)| *queued == id) else { return; };
        row.packets.remove(index);
        if row.packets.is_empty() { pending.remove(&(bridge, next_hop)); }
    }

    /// Flush bridge packets only after the same canonical owner resolves their next hop. # C: O(N packets)
    pub(crate) fn bridge_neighbour_resolved(&self, bridge: NetIfaceId, next_hop: IpAddr) {
        let Some(pending) = self.bridge_pending.lock().remove(&(bridge, next_hop)) else { return; };
        for (_, packet) in pending.packets { let _ = self.bridge_xmit_l3(bridge, packet); }
    }

    /// Drop queued bridge packets belonging to a departing bridge interface. # C: O(N destinations)
    pub(crate) fn bridge_pending_remove_iface(&self, iface: NetIfaceId) {
        self.bridge_pending.lock().retain(|(bridge, _), _| *bridge != iface);
    }

    fn bridge_ipv4_solicitation(&self, bridge: NetIfaceId, target: crate::Ipv4Addr) -> NetResult<Vec<u8>> {
        let (net_ns, mac) = self.bridges.identity(bridge)?;
        let (source, _) = crate::iface_addr::primary(net_ns, bridge).ok_or(NetError::Eaddrnotavail)?;
        let body = crate::arp::build_request(mac, source, target);
        let mut frame = alloc::vec![0u8; crate::ethernet::ETH_HDR_LEN + body.len()];
        crate::ethernet::EthHdr::write_to(MacAddr::BROADCAST, mac, crate::eth_p::ARP, &mut frame);
        frame[crate::ethernet::ETH_HDR_LEN..].copy_from_slice(&body);
        Ok(frame)
    }

    fn bridge_ipv6_solicitation(&self, bridge: NetIfaceId, target: crate::Ipv6Addr) -> NetResult<Vec<u8>> {
        let source = self.v6_src_on_iface(bridge).ok_or(NetError::Eaddrnotavail)?;
        let destination = crate::ndp::solicited_node_multicast(target);
        let body = crate::ndp::NdpMsg::build_ns(source, destination,
            self.bridges.identity(bridge)?.1, target);
        let mut l3 = alloc::vec![0u8; crate::ipv6::IPV6_HDR_LEN + body.len()];
        let mut hdr = crate::ipv6::Ipv6Hdr::build(source, destination, crate::IpProto::Icmpv6, body.len() as u16);
        hdr.hop_limit = u8::MAX;
        hdr.write_to(&mut l3[..crate::ipv6::IPV6_HDR_LEN]);
        l3[crate::ipv6::IPV6_HDR_LEN..].copy_from_slice(&body);
        let mac = self.bridges.identity(bridge)?.1;
        let mut frame = alloc::vec![0u8; crate::ethernet::ETH_HDR_LEN + l3.len()];
        crate::ethernet::EthHdr::write_to(MacAddr([0x33, 0x33, 0xff, target.0[13], target.0[14], target.0[15]]),
            mac, crate::eth_p::IPV6, &mut frame);
        frame[crate::ethernet::ETH_HDR_LEN..].copy_from_slice(&l3);
        Ok(frame)
    }
}
