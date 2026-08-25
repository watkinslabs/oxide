use crate::addr::{IpAddr, IpProto, Ipv6Addr, NetIfaceId};
use crate::ipv6::Ipv6Hdr;
use crate::netdev::NetResult;
use crate::stack::NetStack;
use crate::stack_ipv6::Udp6RxQueue;
use crate::ndp;
use crate::netfilter_hook::{NFPROTO_IPV6, NF_INET_LOCAL_IN, NF_INET_PRE_ROUTING};

mod icmp;

/// The IPv6 header state the receive ancillary messages publish, carried from
/// the parse down to the datagram queue. # C: O(headers)
pub(crate) struct RxAncillary {
    pub flow_label: u32,
    /// `(header kind, whole header bytes)`, in the order they arrived.
    pub ext_headers: alloc::vec::Vec<(u8, alloc::vec::Vec<u8>)>,
    /// Largest single fragment the datagram was reassembled from, zero when it
    /// arrived whole.
    pub frag_max: u32,
}

impl NetStack {
    /// Demux IPv6 after resolving the ingress interface owner. # C: O(payload)
    pub fn deliver_rx_ipv6(&self, iface: NetIfaceId, l3: &[u8]) -> NetResult<()> {
        let lease = self.ifaces.acquire_ingress(iface)
            .ok_or(crate::netdev::NetError::Enodev)?;
        self.deliver_rx_ipv6_in(&lease, l3)
    }

    /// Demux IPv6 under one immutable ingress ownership lease. # C: O(payload)
    pub fn deliver_rx_ipv6_in(&self, lease: &crate::IngressLease, l3: &[u8]) -> NetResult<()> {
        let net_ns = lease.net_ns();
        let iface = lease.iface();
        crate::mib6::bump_ip(net_ns, crate::mib6::Ip6Mib::InReceives);
        crate::mib6::add_ip(net_ns, crate::mib6::Ip6Mib::InOctets, l3.len() as u64);
        let mut ingress_pkt = crate::pkt::Pkt::from_owned(l3.to_vec());
        let pre_routing = crate::netfilter_hook::nf_hook_packet_in(
            net_ns, NF_INET_PRE_ROUTING, &mut ingress_pkt, NFPROTO_IPV6, Some(iface), 0);
        if !pre_routing.accepted() {
            return Ok(());
        }
        let l3 = ingress_pkt.data();
        let hdr = match Ipv6Hdr::parse(l3) {
            Ok(hdr) => hdr,
            Err(_) => {
                crate::mib6::bump_ip(net_ns, crate::mib6::Ip6Mib::InHdrErrors);
                return Err(crate::netdev::NetError::Einval);
            }
        };
        match hdr.traffic_class & 3 {
            0 => crate::mib6::bump_ip(net_ns, crate::mib6::Ip6Mib::InNoEctPkts),
            1 => crate::mib6::bump_ip(net_ns, crate::mib6::Ip6Mib::InEct1Pkts),
            2 => crate::mib6::bump_ip(net_ns, crate::mib6::Ip6Mib::InEct0Pkts),
            _ => crate::mib6::bump_ip(net_ns, crate::mib6::Ip6Mib::InCePkts),
        }
        if hdr.dst.is_multicast() {
            crate::mib6::bump_ip(net_ns, crate::mib6::Ip6Mib::InMcastPkts);
            crate::mib6::add_ip(net_ns, crate::mib6::Ip6Mib::InMcastOctets, l3.len() as u64);
        }
        if !self.v6_dst_is_local_in(net_ns, iface, hdr.dst) {
            return self.forward_ipv6_in(net_ns, iface, l3, Some(&ingress_pkt));
        }
        if !crate::netfilter_hook::nf_hook_packet_in(
            net_ns, NF_INET_LOCAL_IN, &mut ingress_pkt, NFPROTO_IPV6, Some(iface), pre_routing.mark).accepted() { return Ok(()); }
        let l3 = ingress_pkt.data();
        let payload_end = crate::ipv6::IPV6_HDR_LEN + hdr.payload_length as usize;
        if payload_end > l3.len() {
            crate::mib6::bump_ip(net_ns, crate::mib6::Ip6Mib::InTruncatedPkts);
            return Err(crate::netdev::NetError::Einval);
        }
        let payload = &l3[crate::ipv6::IPV6_HDR_LEN..payload_end];
        let mld_router_alert = crate::router_alert::v6_packet_selector(hdr.next_header, payload) == Some(0);
        let mut ancillary = RxAncillary {
            flow_label: hdr.flow_label,
            ext_headers: crate::ipv6_ext::collect(hdr.next_header, payload),
            frag_max: 0,
        };
        let assembled;
        let reassembled_packet;
        let (next_header, payload, full_packet) = match crate::ipv6_ext::walk(hdr.next_header, payload)
            .map_err(|_| crate::netdev::NetError::Einval)?
        {
            crate::ipv6_ext::ExtWalk::Done { next_header, payload } =>
                (next_header, payload, &l3[..payload_end]),
            crate::ipv6_ext::ExtWalk::Fragment {
                next_header: fragment_next_header,
                offset,
                more,
                id,
                payload,
            } => {
                let k = crate::ipv6_reasm::ReasmKey {
                    net_ns, iface: Some(iface),
                    src: hdr.src,
                    dst: hdr.dst,
                    next_header: fragment_next_header,
                    id,
                };
                let prefix = if offset == 0 {
                    Some(crate::cgroup_bpf::ipv6_fragment_prefix(
                        &l3[..payload_end], fragment_next_header,
                    ).ok_or(crate::netdev::NetError::Einval)?)
                } else {
                    None
                };
                let fragsize = l3.len() as u32;
                match self.ipv6_reasm.push_with_prefix(
                    k, crate::stack::net_now_ns(), offset, prefix.as_deref(), payload, more,
                    fragsize,
                ) {
                    Some((prefix, bytes, largest)) => {
                        assembled = bytes;
                        ancillary.frag_max = largest;
                        ancillary.ext_headers =
                            crate::ipv6_ext::collect(fragment_next_header, &assembled[..]);
                        match crate::ipv6_ext::walk(fragment_next_header, &assembled[..])
                            .map_err(|_| crate::netdev::NetError::Einval)?
                        {
                            crate::ipv6_ext::ExtWalk::Done { next_header, payload } => {
                                let Some(packet) = crate::cgroup_bpf::reassembled_ipv6(
                                    &prefix, &assembled,
                                ) else { return Err(crate::netdev::NetError::Einval); };
                                reassembled_packet = packet;
                                (next_header, payload, &reassembled_packet[..])
                            }
                            crate::ipv6_ext::ExtWalk::Fragment { .. } => {
                                return Err(crate::netdev::NetError::Einval);
                            }
                        }
                    }
                    None => return Ok(()),
                }
            }
        };
        self.deliver_rx_ipv6_payload(
            lease, hdr.src, hdr.dst, hdr.hop_limit, hdr.traffic_class,
            &ancillary, mld_router_alert, next_header, payload,
            full_packet, ingress_pkt.tproxy_target(),
        )
    }

    /// IPv6 local-input decision. Multicast groups and link-local addresses
    /// are scoped to the receiving interface and answered by the per-interface
    /// owner; every other destination runs the same three-step decision the
    /// IPv4 half does, so a local-table route delivers an address no interface
    /// owns — the transparent-proxy delivery shape, which the two families
    /// must not disagree about. # C: O(N routes + N addrs)
    fn v6_dst_is_local_in(&self, net_ns: u64, iface: NetIfaceId, ip: Ipv6Addr) -> bool {
        if ip.is_multicast() || ip.is_link_local() { return self.v6_dst_is_local(iface, ip); }
        crate::transparent::delivers_locally(
            self.v6_anycast_owned_by(iface, ip),
            || self.v6_local_route_in(net_ns, ip),
            || self.v6_addrs.lock().iter().any(|(id, addrs)| {
                self.ifaces.lookup_in_ns(*id, net_ns).is_some()
                    && addrs.iter().any(|addr| addr.addr == ip && addr.owned_at(self.ra_now_ns()))
            }))
    }

    /// Whether the namespace's local route table delivers `ip` locally.
    /// # C: O(N routes)
    fn v6_local_route_in(&self, net_ns: u64, ip: Ipv6Addr) -> bool {
        self.routes6.lookup_in_table_in(net_ns, crate::policy_rule::RT_TABLE_LOCAL, ip).is_some()
    }

    fn deliver_rx_ipv6_payload(
        &self,
        lease: &crate::IngressLease,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        hop_limit: u8,
        traffic_class: u8,
        ancillary: &RxAncillary,
        mld_router_alert: bool,
        next_header: u8,
        payload: &[u8],
        packet: &[u8],
        tproxy: Option<crate::pkt::TproxyTarget>,
    ) -> NetResult<()> {
        let (net_ns, iface) = (lease.net_ns(), lease.iface());
        let flow_label = ancillary.flow_label;
        let hatype = self.ifaces.lookup_in_ns(iface, net_ns)
            .map_or(0, |dev| dev.hardware_type());
        for endpoint in self.inet_tables(net_ns).raw6.endpoints(next_header) {
            let _ = endpoint.receive(crate::raw6::Raw6RxPacket {
                net_ns, protocol: next_header, src, dst, iface, hop_limit,
                traffic_class, flow_label, hatype, payload, packet,
            });
        }
        match next_header {
            n if n == IpProto::Icmpv6 as u8 => {
                crate::mib6::bump_ip(net_ns, crate::mib6::Ip6Mib::InDelivers);
                if !payload.is_empty()
                    && crate::ping::is_reply(crate::ping::PingFamily::V6, payload[0])
                {
                    self.deliver_ping_v6(crate::ping::Reply6 {
                        net_ns, iface, src, dst, hop_limit, traffic_class, flow_label,
                        hatype, message: payload,
                    });
                }
                self.deliver_rx_icmpv6(lease, src, dst, hop_limit, mld_router_alert, payload)?;
            }
            n if n == IpProto::Udp as u8 => {
                crate::mib6::bump_ip(net_ns, crate::mib6::Ip6Mib::InDelivers);
                self.deliver_rx_udp6(net_ns, iface, src, dst, hop_limit, traffic_class, ancillary,
                    payload, packet, tproxy)
            }
            n if n == IpProto::Tcp as u8 => {
                crate::mib6::bump_ip(net_ns, crate::mib6::Ip6Mib::InDelivers);
                let src = IpAddr::V6(src);
                let dst = IpAddr::V6(dst);
                let _ = self.deliver_tcp_packet_hop(net_ns, iface, src, dst, payload, packet,
                    hop_limit, tproxy);
            }
            _ => crate::mib6::bump_ip(net_ns, crate::mib6::Ip6Mib::InUnknownProtos),
        }
        Ok(())
    }
}
