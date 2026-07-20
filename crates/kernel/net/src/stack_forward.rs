use crate::addr::{Ipv4Addr, NetIfaceId};
use crate::addr::IpProto;
use crate::icmp::{self, time_exceeded_code, unreach_code};
use crate::ipv4::{ip_checksum, push_ipv4_header, IPV4_HDR_LEN};
use crate::netdev::{NetError, NetResult};
use crate::netfilter_hook::{
        nf_hook_eval, nf_hook_eval_in, nf_output, NFPROTO_IPV4, NF_INET_FORWARD, NF_INET_POST_ROUTING,
};
use crate::pkt::Pkt;
use crate::stack::NetStack;

const ICMP_DEST_UNREACH_ADMIN_PROHIBITED: u8 = 13;

impl NetStack {
    /// Process one Ethernet ARP payload under its admitted interface owner.
    /// Learns the sender neighbour and replies only for this interface's
    /// primary IPv4 address. # C: O(log N + frame)
    pub fn deliver_arp_in(&self, lease: &crate::IngressLease, payload: &[u8]) -> NetResult<()> {
        let request = crate::arp::ArpPkt::parse(payload).map_err(|_| NetError::Einval)?;
        let cache = self.ifaces.arp_cache_in_ns(lease.iface(), lease.net_ns())
            .ok_or(NetError::Enodev)?;
        let state = if request.opcode == crate::arp::ARP_OP_REPLY {
            crate::arp::NudState::Reachable
        } else {
            crate::arp::NudState::Stale
        };
        let resolved = cache.learn_at(request.sender_ip, request.sender_mac, state,
            crate::stack::net_now_ns());
        for job in resolved { job.resume(); }
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

    /// True when this IPv4 destination belongs to the host. # C: O(N addrs)
    pub(crate) fn ipv4_dst_is_local(&self, dst: Ipv4Addr) -> bool {
        self.ipv4_dst_is_local_in(0, dst)
    }

    /// True when `dst` belongs to one network namespace. # C: O(N addrs)
    pub(crate) fn ipv4_dst_is_local_in(&self, net_ns: u64, dst: Ipv4Addr) -> bool {
        if dst.is_loopback() || dst.is_broadcast() || dst.is_multicast() {
            return true;
        }
        crate::iface_addr::snapshot_ns(net_ns)
            .iter()
            .any(|row| row.addr == dst)
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

    fn send_ipv4_forward_error(
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
        if nf_output(&p, NFPROTO_IPV4) { dev.xmit(p)?; }
        Ok(())
    }

    /// Forward one IPv4 packet after PRE_ROUTING has accepted it. # C: O(N routes + len)
    pub(crate) fn forward_ipv4(&self, ingress: NetIfaceId, l3: &[u8]) -> NetResult<()> {
        let net_ns = self.ifaces.namespace(ingress).ok_or(NetError::Enodev)?;
        self.forward_ipv4_in(net_ns, ingress, l3)
    }

    /// Forward one IPv4 packet within the ingress namespace. # C: O(N routes + len)
    pub(crate) fn forward_ipv4_in(&self, net_ns: u64, ingress: NetIfaceId, l3: &[u8]) -> NetResult<()> {
        if crate::forwarding::ipv4_enabled_in(net_ns) != Some(true) { return Ok(()); }
        if l3.len() < IPV4_HDR_LEN { return Ok(()); }
        let src = Ipv4Addr::from_u32(u32::from_be_bytes([l3[12], l3[13], l3[14], l3[15]]));
        let dst = Ipv4Addr::from_u32(u32::from_be_bytes([l3[16], l3[17], l3[18], l3[19]]));
        let error_src = self.ipv4_iface_addr(net_ns, ingress).unwrap_or(dst);
        if l3[8] <= 1 {
            return self.send_ipv4_forward_error(
                ingress, error_src, src, icmp::ICMP_TYPE_TIME_EXC, time_exceeded_code::TTL, l3,
            );
        }
        let route = match self.routes.lookup_result_in(net_ns, dst) {
            Ok(route) => route,
            Err(NetError::Einval) => return Ok(()),
            Err(NetError::Ehostunreach) => {
                return self.send_ipv4_forward_error(
                    ingress, error_src, src, icmp::ICMP_TYPE_DEST_UNREACH, unreach_code::HOST, l3,
                );
            }
            Err(NetError::Eacces) => {
                return self.send_ipv4_forward_error(
                    ingress, error_src, src, icmp::ICMP_TYPE_DEST_UNREACH,
                    ICMP_DEST_UNREACH_ADMIN_PROHIBITED, l3,
                );
            }
            Err(NetError::Enetunreach) => {
                return self.send_ipv4_forward_error(
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
        p.next_hop = Some(crate::pkt::TxNextHop::V4(route.gateway.unwrap_or(dst)));
        if nf_hook_eval_in(net_ns, NF_INET_FORWARD, p.data(), NFPROTO_IPV4) == 0 { return Ok(()); }
        if nf_hook_eval_in(net_ns, NF_INET_POST_ROUTING, p.data(), NFPROTO_IPV4) == 0 { return Ok(()); }
        dev.xmit(p)
    }
}
