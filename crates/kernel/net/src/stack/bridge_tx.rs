//! Bridge-owned IPv4 neighbor and Ethernet transmit work.

use super::*;

impl NetStack {
    /// Transmit a routed L3 packet through bridge-owned IPv4 neighbor state. # C: O(packet + N ports)
    pub(crate) fn bridge_xmit_l3(&self, bridge: NetIfaceId, packet: crate::Pkt) -> NetResult<()> {
        let crate::pkt::TxNextHop::V4(target) = packet.next_hop.ok_or(NetError::Edestaddrreq)?
            else { return Err(NetError::Eopnotsupp); };
        let (net_ns, mac, neighbor) = self.bridges.arp_lookup(bridge, target)?;
        let destination = match neighbor {
            Some(mac) => mac,
            None => {
                let (source, _) = crate::iface_addr::primary(net_ns, bridge)
                    .ok_or(NetError::Eaddrnotavail)?;
                let body = crate::arp::build_request(mac, source, target);
                let mut frame = alloc::vec![0u8; crate::ethernet::ETH_HDR_LEN + body.len()];
                crate::ethernet::EthHdr::write_to(MacAddr::BROADCAST, mac, crate::eth_p::ARP, &mut frame);
                frame[crate::ethernet::ETH_HDR_LEN..].copy_from_slice(&body);
                self.bridge_xmit_raw(bridge, &frame)?;
                return Err(NetError::Eagain);
            }
        };
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
}
