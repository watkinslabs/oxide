//! Bridge-owned IPv4 neighbor and Ethernet transmit work.

use super::*;

impl NetStack {
    /// Transmit a routed L3 packet through bridge-owned IPv4 neighbor state. # C: O(packet + N ports)
    pub(crate) fn bridge_xmit_l3(&self, bridge: NetIfaceId, packet: crate::Pkt) -> NetResult<()> {
        let destination = match packet.next_hop.ok_or(NetError::Edestaddrreq)? {
            crate::pkt::TxNextHop::V4(target) => self.bridge_ipv4_neighbor(bridge, target)?,
            crate::pkt::TxNextHop::V6 { addr, .. } => self.bridge_ipv6_neighbor(bridge, addr)?,
        };
        let (_, mac, _) = self.bridges.arp_lookup(bridge, crate::Ipv4Addr::ANY)?;
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

    fn bridge_ipv4_neighbor(&self, bridge: NetIfaceId, target: crate::Ipv4Addr) -> NetResult<MacAddr> {
        let (net_ns, mac, neighbor) = self.bridges.arp_lookup(bridge, target)?;
        match neighbor {
            Some(mac) => Ok(mac),
            None => {
                let (source, _) = crate::iface_addr::primary(net_ns, bridge)
                    .ok_or(NetError::Eaddrnotavail)?;
                let body = crate::arp::build_request(mac, source, target);
                let mut frame = alloc::vec![0u8; crate::ethernet::ETH_HDR_LEN + body.len()];
                crate::ethernet::EthHdr::write_to(MacAddr::BROADCAST, mac, crate::eth_p::ARP, &mut frame);
                frame[crate::ethernet::ETH_HDR_LEN..].copy_from_slice(&body);
                self.bridge_xmit_raw(bridge, &frame)?;
                Err(NetError::Eagain)
            }
        }
    }

    fn bridge_ipv6_neighbor(&self, bridge: NetIfaceId, target: crate::Ipv6Addr) -> NetResult<MacAddr> {
        if let Some(mac) = self.ndp_lookup(bridge, target) { return Ok(mac); }
        let source = self.v6_src_on_iface(bridge).ok_or(NetError::Eaddrnotavail)?;
        let destination = crate::ndp::solicited_node_multicast(target);
        let body = crate::ndp::NdpMsg::build_ns(source, destination,
            self.bridges.arp_lookup(bridge, crate::Ipv4Addr::ANY)?.1, target);
        let mut l3 = alloc::vec![0u8; crate::ipv6::IPV6_HDR_LEN + body.len()];
        let mut hdr = crate::ipv6::Ipv6Hdr::build(source, destination, crate::IpProto::Icmpv6, body.len() as u16);
        hdr.hop_limit = u8::MAX;
        hdr.write_to(&mut l3[..crate::ipv6::IPV6_HDR_LEN]);
        l3[crate::ipv6::IPV6_HDR_LEN..].copy_from_slice(&body);
        let mac = self.bridges.arp_lookup(bridge, crate::Ipv4Addr::ANY)?.1;
        let mut frame = alloc::vec![0u8; crate::ethernet::ETH_HDR_LEN + l3.len()];
        crate::ethernet::EthHdr::write_to(MacAddr([0x33, 0x33, 0xff, target.0[13], target.0[14], target.0[15]]),
            mac, crate::eth_p::IPV6, &mut frame);
        frame[crate::ethernet::ETH_HDR_LEN..].copy_from_slice(&l3);
        self.bridge_xmit_raw(bridge, &frame)?;
        Err(NetError::Eagain)
    }
}
