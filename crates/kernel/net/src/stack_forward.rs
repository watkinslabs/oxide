use crate::addr::{Ipv4Addr, Ipv6Addr, NetIfaceId};
use crate::addr::IpProto;
use crate::icmp::{self, time_exceeded_code, unreach_code};
use crate::ipv4::{ip_checksum, push_ipv4_header, IPV4_HDR_LEN};
use crate::netdev::{NetError, NetResult};
use crate::netfilter_hook::{
        nf_hook_eval_in, nf_output, NFPROTO_IPV4, NFPROTO_IPV6, NF_INET_FORWARD, NF_INET_POST_ROUTING,
};
use crate::pkt::Pkt;
use crate::stack::NetStack;

const ICMP_DEST_UNREACH_ADMIN_PROHIBITED: u8 = 13;

impl NetStack {
    /// Process one Ethernet ARP payload under its admitted interface owner.
    /// Learns the sender neighbour and replies only for this interface's
    /// primary IPv4 address. # C: O(log N + frame)
    pub fn deliver_arp_in(&self, lease: &crate::IngressLease, payload: &[u8]) -> NetResult<()> {
        // A malformed ARP payload is a dropped frame, not an ingress error: the
        // reference consumes the packet and returns success to its caller, so a
        // truncated or unsupported-hardware ARP cannot fail the L2 dispatch that
        // delivered it.
        let Ok(request) = crate::arp::ArpPkt::parse(payload) else { return Ok(()); };
        let cache = self.ifaces.arp_cache_in_ns(lease.iface(), lease.net_ns())
            .ok_or(NetError::Enodev)?;
        let state = if request.opcode == crate::arp::ARP_OP_REPLY {
            crate::arp::NudState::Reachable
        } else {
            crate::arp::NudState::Stale
        };
        let resolved = cache.learn_at(request.sender_ip, request.sender_mac, state,
            crate::stack::net_now_ns());
        for job in resolved { job.resume(request.sender_mac); }
        // A bridge parks its own unresolved packets rather than in the
        // interface transmit queue, so the one neighbour owner has to release
        // both or bridged traffic waits on a binding that already exists.
        self.bridge_neighbour_resolved(lease.iface(), crate::addr::IpAddr::V4(request.sender_ip));
        if request.opcode != crate::arp::ARP_OP_REQUEST { return Ok(()); }
        let local = self.ipv4_iface_addr(lease.net_ns(), lease.iface()) == Some(request.target_ip);
        let explicit_proxy = self.arp_proxy.contains(lease.net_ns(), lease.iface(), request.target_ip);
        let routed_proxy = self.arp_proxy.enabled(lease.net_ns(), lease.iface())
            && crate::forwarding::ipv4_enabled_in(lease.net_ns()) == Some(true)
            && self.routes.lookup_result_in(lease.net_ns(), request.target_ip)
                .is_ok_and(|route| route.iface != lease.iface());
        let proxy = explicit_proxy || routed_proxy;
        if !local && !proxy { return Ok(()); }
        let local_mac = lease.device().mac();
        let reply = crate::arp::build_reply(&request, local_mac);
        let mut frame = alloc::vec![0u8; crate::ethernet::ETH_HDR_LEN + reply.len()];
        crate::ethernet::EthHdr::write_to(request.sender_mac, local_mac,
            crate::addr::eth_p::ARP, &mut frame);
        frame[crate::ethernet::ETH_HDR_LEN..].copy_from_slice(&reply);
        let egress = self.ifaces.acquire_egress_in_ns(lease.iface(), lease.net_ns())
            .ok_or(NetError::Enodev)?;
        egress.xmit_raw(&frame)
    }

    /// Mark-aware IPv4 local-input decision.  PRE_ROUTING may select a local
    /// route via an nft packet mark and an `ip rule fwmark` policy rule.
    /// # C: O(N rules * N routes + N addrs)
    pub(crate) fn ipv4_dst_is_local_mark_in(&self, net_ns: u64, dst: Ipv4Addr, mark: u32) -> bool {
        // The FIB's local route type is the routing decision that turns a
        // received destination into local input.  Interface-address lookup is
        // still needed for addresses that have not yet had their automatic
        // local-table record materialised, but it must not be the only owner:
        // policy routing can deliberately select an `RTN_LOCAL` route for a
        // nonlocal address (the transparent-proxy delivery shape).  Both
        // families run the same three-step decision, owned by
        // `crate::transparent`.
        crate::transparent::delivers_locally(
            dst.is_loopback() || dst.is_broadcast() || dst.is_multicast(),
            || self.routes.lookup_record_mark_in(net_ns, dst, mark).is_some_and(|record|
                record.kind == crate::route::RTN_LOCAL),
            || crate::iface_addr::snapshot_ns(net_ns).iter().any(|row| row.addr == dst))
    }

    fn ipv4_iface_addr(&self, net_ns: u64, iface: NetIfaceId) -> Option<Ipv4Addr> {
        crate::iface_addr::primary(net_ns, iface).map(|(addr, _)| addr)
    }

    fn should_emit_icmp_error(&self, l3: &[u8]) -> bool {
        if l3.len() < IPV4_HDR_LEN { return false; }
        if l3[9] != IpProto::Icmp as u8 { return true; }
        let total = u16::from_be_bytes([l3[2], l3[3]]) as usize;
        if total < IPV4_HDR_LEN + icmp::ICMP_HDR_LEN || total > l3.len() { return false; }
        !matches!(l3[IPV4_HDR_LEN], icmp::ICMP_TYPE_DEST_UNREACH | icmp::ICMP_TYPE_TIME_EXC)
    }

    pub(super) fn send_ipv4_error(
        &self,
        ingress: NetIfaceId,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        typ: u8,
        code: u8,
        invoking: &[u8],
    ) -> NetResult<()> {
        if !self.should_emit_icmp_error(invoking) { return Ok(()); }
        let body = match icmp::build_ipv4_error(typ, code, invoking) {
            Ok(b) => b,
            Err(_) => return Ok(()),
        };
        let net_ns = self.ifaces.namespace(ingress).ok_or(NetError::Enodev)?;
        let dev = self.ifaces.acquire_egress_in_ns(ingress, net_ns).ok_or(NetError::Enetunreach)?;
        let mut p = Pkt::with_capacity(IPV4_HDR_LEN, IPV4_HDR_LEN + body.len());
        p.put(body.len()).map_err(|_| NetError::Enobufs)?.copy_from_slice(&body);
        let id = { let mut s = self.next_ip_id.lock(); *s = s.wrapping_add(1); *s };
        push_ipv4_header(&mut p, src, dst, IpProto::Icmp, id).map_err(|_| NetError::Enobufs)?;
        p.proto = crate::addr::eth_p::IPV4;
        p.iface = Some(ingress);
        p.next_hop = Some(crate::pkt::TxNextHop::V4(dst));
        if nf_output(&p, NFPROTO_IPV4) {
            crate::mib::bump(net_ns, crate::mib::Mib::IcmpOutMsgs);
            if typ == icmp::ICMP_TYPE_DEST_UNREACH {
                crate::mib::bump(net_ns, crate::mib::Mib::IcmpOutDestUnreachs);
            }
            dev.xmit(p)?;
        }
        Ok(())
    }

    /// Forward one packet using the PRE_ROUTING packet mark for policy route
    /// selection. # C: O(N rules * N routes + len)
    pub(crate) fn forward_ipv4_mark_in(&self, net_ns: u64, ingress: NetIfaceId, l3: &[u8], mark: u32)
        -> NetResult<()>
    {
        if crate::forwarding::ipv4_enabled_in(net_ns) != Some(true) {
            crate::mib::bump(net_ns, crate::mib::Mib::IpInAddrErrors);
            return Ok(());
        }
        if l3.len() < IPV4_HDR_LEN { return Ok(()); }
        // A transit packet asking routers to examine it goes to the sockets
        // that joined the router-alert chain, ahead of the hop-limit check;
        // once one of them takes it, it leaves the forwarding path.
        if crate::router_alert::v4_present(l3)
            && crate::router_alert::v4_deliver(net_ns, ingress, l3)
        { return Ok(()); }
        let src = Ipv4Addr::from_u32(u32::from_be_bytes([l3[12], l3[13], l3[14], l3[15]]));
        let dst = Ipv4Addr::from_u32(u32::from_be_bytes([l3[16], l3[17], l3[18], l3[19]]));
        let error_src = self.ipv4_iface_addr(net_ns, ingress).unwrap_or(dst);
        if l3[8] <= 1 {
            return self.send_ipv4_error(
                ingress, error_src, src, icmp::ICMP_TYPE_TIME_EXC, time_exceeded_code::TTL, l3,
            );
        }
        let route = match self.routes.lookup_result_mark_in(net_ns, dst, mark) {
            Ok(route) => route,
            Err(NetError::Einval) => return Ok(()),
            Err(NetError::Ehostunreach) => {
                crate::mib::bump(net_ns, crate::mib::Mib::IpInAddrErrors);
                return self.send_ipv4_error(
                    ingress, error_src, src, icmp::ICMP_TYPE_DEST_UNREACH, unreach_code::HOST, l3,
                );
            }
            Err(NetError::Eacces) => {
                return self.send_ipv4_error(
                    ingress, error_src, src, icmp::ICMP_TYPE_DEST_UNREACH,
                    ICMP_DEST_UNREACH_ADMIN_PROHIBITED, l3,
                );
            }
            Err(NetError::Enetunreach) => {
                return self.send_ipv4_error(
                    ingress, error_src, src, icmp::ICMP_TYPE_DEST_UNREACH, unreach_code::NET, l3,
                );
            }
            Err(error) => return Err(error),
        };
        let dev = self.ifaces.acquire_egress_in_ns(route.iface, net_ns).ok_or(NetError::Enetunreach)?;
        let total = u16::from_be_bytes([l3[2], l3[3]]) as usize;
        if total < IPV4_HDR_LEN || total > l3.len() { return Err(NetError::Einval); }
        let mut p = Pkt::with_capacity(crate::pkt::DEFAULT_HEADROOM, crate::pkt::DEFAULT_HEADROOM + total);
        p.put(total).map_err(|_| NetError::Enobufs)?.copy_from_slice(&l3[..total]);
        {
            let b = p.data_mut();
            b[8] -= 1;
            b[10] = 0;
            b[11] = 0;
            let csum = ip_checksum(&b[..IPV4_HDR_LEN]);
            b[10..12].copy_from_slice(&csum.to_be_bytes());
        }
        p.proto = crate::addr::eth_p::IPV4;
        p.iface = Some(route.iface);
        p.next_hop = Some(crate::pkt::TxNextHop::V4(crate::route::RouteRecord::next_hop_for(route.gateway, dst)));
        if nf_hook_eval_in(net_ns, NF_INET_FORWARD, p.data(), NFPROTO_IPV4).verdict == 0 { return Ok(()); }
        if nf_hook_eval_in(net_ns, NF_INET_POST_ROUTING, p.data(), NFPROTO_IPV4).verdict == 0 { return Ok(()); }
        dev.xmit(p)
    }
}

impl NetStack {
    /// Forward one IPv6 packet within the ingress namespace. # C: O(N routes + len)
    pub(crate) fn forward_ipv6_in(&self, net_ns: u64, ingress: NetIfaceId, l3: &[u8]) -> NetResult<()> {
        if crate::forwarding::ipv6_enabled_in(net_ns) != Some(true) { return Ok(()); }
        let header = crate::ipv6::Ipv6Hdr::parse(l3).map_err(|_| NetError::Einval)?;
        let total = crate::ipv6::IPV6_HDR_LEN + header.payload_length as usize;
        if total > l3.len() { return Err(NetError::Einval); }
        if crate::router_alert::v6_deliver(self, net_ns, ingress, &l3[..total]) { return Ok(()); }
        if header.hop_limit <= 1 { return Ok(()); }
        let route = self.routes6.lookup_policy_in(net_ns, header.dst, self.policy_rules())
            .ok_or(NetError::Enetunreach)?;
        let dev = self.ifaces.acquire_egress_in_ns(route.iface, net_ns).ok_or(NetError::Enetunreach)?;
        let mut p = Pkt::with_capacity(crate::pkt::DEFAULT_HEADROOM,
            crate::pkt::DEFAULT_HEADROOM + total);
        p.put(total).map_err(|_| NetError::Enobufs)?.copy_from_slice(&l3[..total]);
        p.data_mut()[7] -= 1;
        p.proto = crate::addr::eth_p::IPV6;
        p.iface = Some(route.iface);
        p.next_hop = Some(crate::pkt::TxNextHop::V6 {
            addr: crate::route6::next_hop6_for(route.gateway, header.dst), src: Ipv6Addr::ANY,
        });
        if nf_hook_eval_in(net_ns, NF_INET_FORWARD, p.data(), NFPROTO_IPV6).verdict == 0 { return Ok(()); }
        if nf_hook_eval_in(net_ns, NF_INET_POST_ROUTING, p.data(), NFPROTO_IPV6).verdict == 0 { return Ok(()); }
        let _ = ingress;
        dev.xmit(p)?;
        crate::mib6::bump_ip(net_ns, crate::mib6::Ip6Mib::OutForwDatagrams);
        crate::mib6::account_output(net_ns, header.dst, total);
        Ok(())
    }
}
