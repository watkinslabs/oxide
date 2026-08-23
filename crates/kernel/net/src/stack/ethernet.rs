//! Canonical Ethernet ingress: parse L2 once, then dispatch the inner payload.

use super::*;

impl NetStack {
    /// Admit and dispatch one received Ethernet frame for an interface. # C: O(frame)
    pub fn deliver_ethernet(&self, iface: NetIfaceId, frame: &[u8]) -> NetResult<()> {
        let lease = self.ifaces.acquire_ingress(iface).ok_or(NetError::Enodev)?;
        self.deliver_ethernet_in(&lease, frame)
    }

    /// Admit a received Ethernet frame with the driver's RX metadata. # C: O(frame + sockets)
    pub fn deliver_ethernet_meta(&self, iface: NetIfaceId, frame: &[u8],
                                 metadata: crate::PacketRxMetadata) -> NetResult<()>
    {
        let lease = self.ifaces.acquire_ingress(iface).ok_or(NetError::Enodev)?;
        self.deliver_ethernet_meta_in(&lease, frame, metadata)
    }

    /// Dispatch an Ethernet frame under its exact admitted ingress generation. # C: O(frame)
    pub fn deliver_ethernet_in(&self, lease: &crate::IngressLease, frame: &[u8]) -> NetResult<()> {
        self.deliver_ethernet_meta_in(lease, frame, crate::PacketRxMetadata::default())
    }

    /// Dispatch one metadata-bearing Ethernet frame under its exact ingress generation. # C: O(frame + sockets)
    pub fn deliver_ethernet_meta_in(&self, lease: &crate::IngressLease, frame: &[u8],
                                    metadata: crate::PacketRxMetadata) -> NetResult<()>
    {
        let header = crate::ethernet::EthHdr::parse(frame).map_err(|_| NetError::Einval)?;
        // Netdev-family chains run on the complete link frame, before bridge
        // forwarding and packet-socket observation. A stolen verdict owns the
        // frame in the selected device and must stop this ingress path.
        let mut netdev_packet = crate::Pkt::from_owned(frame.to_vec());
        netdev_packet.proto = header.ethertype;
        netdev_packet.iface = Some(lease.iface());
        let netdev = crate::netfilter_hook::nf_hook_packet_in(
            lease.net_ns(), crate::netfilter_hook::NF_NETDEV_INGRESS,
            &mut netdev_packet, crate::netfilter_hook::NFPROTO_NETDEV,
            Some(lease.iface()), 0);
        if !netdev.accepted() { return Ok(()); }
        #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
        crate::sock::deliver_packet_ingress_meta_in(lease, frame, metadata);
        #[cfg(not(any(target_os = "oxide-kernel", test, feature = "hosted")))]
        let _ = metadata;
        if self.bridges.stp_bpdu_ingress(lease, header, frame) { return Ok(()); }
        if let Some(decision) = self.bridges.ingress(lease, header) {
            let mut error = None;
            for port in decision.egress {
                match self.ifaces.acquire_egress_in_ns(port, lease.net_ns()) {
                    Some(egress) => if let Err(next) = egress.xmit_raw(frame) { error = Some(next); },
                    None => error = Some(NetError::Enodev),
                }
            }
            if !decision.local { return error.map_or(Ok(()), Err); }
            let bridge = self.ifaces.acquire_ingress(decision.bridge)
                .filter(|bridge| bridge.net_ns() == lease.net_ns()).ok_or(NetError::Enodev)?;
            #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
            crate::sock::deliver_packet_ingress_from_in(&bridge, lease, frame, metadata);
            self.deliver_ethernet_l3_in(&bridge, frame, header)?;
            return error.map_or(Ok(()), Err);
        }
        self.deliver_ethernet_l3_in(lease, frame, header)
    }

    /// Run local L3 demultiplexing after the canonical L2 observer/bridge path.
    ///
    /// ARP reaches the same IPv4 neighbour owner every other consumer reads —
    /// the per-interface cache behind `ip neigh`, `/proc/net/arp`, the ARP
    /// ioctls, and the transmit path's resolve-or-queue. A reply that landed
    /// anywhere else would leave the neighbour INCOMPLETE and strand every
    /// packet queued on it. # C: O(frame)
    fn deliver_ethernet_l3_in(&self, lease: &crate::IngressLease, frame: &[u8],
                              header: crate::ethernet::EthHdr) -> NetResult<()>
    {
        let payload = &frame[header.hdr_len..];
        match header.ethertype {
            crate::eth_p::ARP  => self.deliver_arp_in(lease, payload),
            crate::eth_p::IPV4 => self.deliver_rx_in(lease, payload),
            crate::eth_p::IPV6 => self.deliver_rx_ipv6_in(lease, payload),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ethernet_ingress_parses_once_and_delivers_ipv4_to_the_admitted_iface() {
        let _domain = crate::hosted_fixture::init_net_domain();
        let stack = NetStack::new();
        let (iface, _lo) = stack.register_loopback();
        let local = crate::Ipv4Addr::LOOPBACK;
        let endpoint = stack.bind_udp(local, 43_210).unwrap();
        let body = b"bridge-l2-ingress";
        let mut l3 = alloc::vec![0u8; crate::ipv4::IPV4_HDR_LEN + crate::udp::UDP_HDR_LEN + body.len()];
        crate::udp::UdpHdr::build_into(43_211, 43_210, local, local, body,
            &mut l3[crate::ipv4::IPV4_HDR_LEN..]);
        crate::ipv4::Ipv4Hdr::build(local, local, crate::IpProto::Udp,
            (crate::udp::UDP_HDR_LEN + body.len()) as u16, 1).write_to(&mut l3[..crate::ipv4::IPV4_HDR_LEN]);
        let mut frame = alloc::vec![0u8; crate::ethernet::ETH_HDR_LEN + l3.len()];
        crate::ethernet::EthHdr::write_to(crate::MacAddr::BROADCAST, crate::MacAddr([2,0,0,0,0,1]),
            crate::eth_p::IPV4, &mut frame);
        frame[crate::ethernet::ETH_HDR_LEN..].copy_from_slice(&l3);

        stack.deliver_ethernet(iface, &frame).unwrap();
        assert_eq!(endpoint.recv(false).unwrap().payload, body);
    }

    #[test]
    fn ethernet_ingress_rejects_a_truncated_link_header_before_l3() {
        let _domain = crate::hosted_fixture::init_net_domain();
        let stack = NetStack::new();
        let (iface, _lo) = stack.register_loopback();
        assert_eq!(stack.deliver_ethernet(iface, &[0; crate::ethernet::ETH_HDR_LEN - 1]),
            Err(NetError::Einval));
    }

    #[test]
    fn netdev_fwd_steals_the_complete_frame_before_l3_dispatch() {
        let domain = crate::hosted_fixture::init_net_domain();
        use ::core::sync::atomic::{AtomicU32, Ordering};
        static TARGET: AtomicU32 = AtomicU32::new(0);
        fn fwd(ctx: &crate::netfilter_hook::NfHookCtx<'_>)
            -> crate::netfilter_hook::NfHookResult
        {
            if ctx.family != crate::netfilter_hook::NFPROTO_NETDEV {
                return crate::netfilter_hook::NfHookResult::ACCEPT;
            }
            crate::netfilter_hook::NfHookResult {
                verdict: 2, mark: 0, notrack: false,
                actions: alloc::vec![crate::netfilter_action::Action::Fwd {
                    oif: TARGET.load(Ordering::Acquire), gateway: None, nfproto: None,
                }],
            }
        }
        domain.set_nf_hook(fwd);
        let stack = crate::global_stack();
        let (source, _source_dev) = stack.register_loopback();
        let (target, target_dev) = stack.register_loopback();
        TARGET.store(stack.ifaces.ifindex_in_ns(target, 0).unwrap(), Ordering::Release);
        let mut frame = [0u8; crate::ethernet::ETH_HDR_LEN + 20];
        crate::ethernet::EthHdr::write_to(crate::MacAddr::BROADCAST,
            crate::MacAddr([2, 0, 0, 0, 0, 1]), crate::eth_p::IPV4, &mut frame);
        frame[crate::ethernet::ETH_HDR_LEN] = 0x45;
        stack.deliver_ethernet(source, &frame).unwrap();
        assert_eq!(target_dev.rx_len(), 1);
    }
}

#[cfg(test)]
#[path = "arp_ingress_tests.rs"]
mod arp_ingress_tests;
