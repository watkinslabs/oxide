use crate::addr::{IpAddr, IpProto, Ipv6Addr, NetIfaceId};
use crate::ipv6::{Ipv6Hdr, IPV6_HDR_LEN, push_ipv6_header};
use crate::netdev::{NetError, NetResult};
use crate::netfilter_hook::{nf_output, NFPROTO_IPV6};
use crate::stack::NetStack;
use crate::stack::TcpKey;

/// Apply a socket's requested IPv6 fragmentation size after route PMTU selection.
/// A zero request leaves the route result unchanged. # C: O(1)
pub(crate) fn ipv6_output_mtu(route_mtu: usize, frag_size: i32) -> usize {
    if frag_size > 0 { route_mtu.min(frag_size as usize) } else { route_mtu }
}

#[cfg(test)]
mod tests {
    use super::ipv6_output_mtu;

    #[test]
    fn a_socket_fragment_size_only_reduces_the_resolved_route_mtu() {
        assert_eq!(ipv6_output_mtu(1500, 0), 1500);
        assert_eq!(ipv6_output_mtu(1500, 1280), 1280);
        assert_eq!(ipv6_output_mtu(1280, 1500), 1280);
    }
}

impl NetStack {
    pub fn send_router_solicitation(&self, iface: NetIfaceId, src: Ipv6Addr) -> NetResult<()> {
        let net_ns = self.ifaces.namespace(iface).ok_or(NetError::Enetunreach)?;
        let our_mac = if src.is_unspecified() {
            None
        } else {
            Some(self.ifaces.lookup_in_ns(iface, net_ns).ok_or(NetError::Enetunreach)?.mac())
        };
        let body = crate::ndp::NdpMsg::build_rs(
            src,
            crate::ndp::IPV6_ALL_ROUTERS,
            our_mac,
        );
        self.xmit_ipv6(iface, src, crate::ndp::IPV6_ALL_ROUTERS, IpProto::Icmpv6, &body)
    }

    pub(crate) fn send_dad_solicitation(&self, lease: &crate::IngressLease, target: Ipv6Addr)
        -> NetResult<bool>
    {
        let iface = lease.iface();
        let dst = crate::ndp::solicited_node_multicast(target);
        let body = crate::ndp::NdpMsg::build_dad_ns(target);
        let total = IPV6_HDR_LEN + body.len();
        let mut packet = crate::pkt::Pkt::with_capacity(IPV6_HDR_LEN, total);
        packet.put(body.len()).map_err(|_| NetError::Enobufs)?.copy_from_slice(&body);
        push_ipv6_header(&mut packet, Ipv6Addr::ANY, dst, IpProto::Icmpv6)
            .map_err(|_| NetError::Enobufs)?;
        packet.proto = crate::addr::eth_p::IPV6;
        packet.iface = Some(iface);
        packet.next_hop = Some(crate::pkt::TxNextHop::V6 { addr: dst, src: Ipv6Addr::ANY });
        let dev = self.ifaces.acquire_egress_in_ns(iface, lease.net_ns())
            .filter(|dev| dev.generation() == lease.generation())
            .ok_or(NetError::Enetunreach)?;
        if !nf_output(&packet, NFPROTO_IPV6) { return Ok(false); }
        dev.xmit(packet)?;
        Ok(true)
    }

    pub fn send_l4_over_ip(&self, src: IpAddr, dst: IpAddr, proto: IpProto, l4: &[u8]) -> NetResult<()> {
        self.send_l4_over_ip_tos(src, dst, proto, l4, 0)
    }

    pub fn send_l4_over_ip_tos(
        &self,
        src: IpAddr,
        dst: IpAddr,
        proto: IpProto,
        l4: &[u8],
        tos: u8,
    ) -> NetResult<()> {
        match (src, dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                if tos != 0 {
                    return self.send_l4_over_ipv4_tos(s, d, proto, l4, tos);
                }
                let _ = proto;
                self.send_l4_over_ipv4_pub(s, d, l4)
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => self.send_l4_over_ipv6(s, d, proto, l4),
            _ => Err(NetError::Einval),
        }
    }

    pub(crate) fn send_l4_over_ipv6(
        &self,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        proto: IpProto,
        l4: &[u8],
    ) -> NetResult<()> {
        self.send_l4_over_ipv6_in(0, src, dst, proto, l4)
    }

    /// Send IPv6 L4 payload through one network namespace. # C: O(payload + N)
    pub(crate) fn send_l4_over_ipv6_in(&self, net_ns: u64, src: Ipv6Addr,
        dst: Ipv6Addr, proto: IpProto, l4: &[u8]) -> NetResult<()>
    {
        let route = self.routes6.lookup_policy_in(net_ns, dst, self.policy_rules())
            .ok_or(NetError::Enetunreach)?;
        let iface = self.ifaces.acquire_egress_in_ns(route.iface, net_ns).ok_or(NetError::Enetunreach)?;
        let src = if src.is_unspecified() {
            self.v6_select_source(route.iface, dst, route.src_hint)
                .ok_or(NetError::Eaddrnotavail)?
        } else { src };
        self.xmit_ipv6_l4_on_iface(
            route.iface, iface, crate::route6::next_hop6_for(route.gateway, dst), src, dst, proto, l4,
        )
    }

    pub(crate) fn xmit_ipv6_l4_on_iface(
        &self,
        iface_id: NetIfaceId,
        iface: crate::EgressLease,
        next_hop: Ipv6Addr,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        proto: IpProto,
        l4: &[u8],
    ) -> NetResult<()> {
        self.xmit_ipv6_l4_on_iface_opts(
            iface_id, iface, next_hop, src, dst, proto, l4, crate::ipv6::IPV6_DEFAULT_HOP_LIMIT, 0,
        )
    }

    /// `xmit_ipv6_l4_on_iface` with an explicit hop limit (socket
    /// IPV6_UNICAST_HOPS / IPV6_MULTICAST_HOPS) and traffic class
    /// (IPV6_TCLASS). Mirrors the IPv4 `xmit_ipv4_l4_on_iface_opts`
    /// ttl/tos seam. # C: O(payload + N)
    pub(crate) fn xmit_ipv6_l4_on_iface_opts(
        &self,
        iface_id: NetIfaceId,
        iface: crate::EgressLease,
        next_hop: Ipv6Addr,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        proto: IpProto,
        l4: &[u8],
        hop_limit: u8,
        traffic_class: u8,
    ) -> NetResult<()> {
        self.xmit_ipv6_l4_with_policy(
            iface_id, iface, next_hop, src, dst, proto, l4, hop_limit, traffic_class,
            0, false, usize::MAX, true, None,
        ).map(|_| ())
    }

    pub(crate) fn xmit_ipv6_l4_with_policy(
        &self,
        iface_id: NetIfaceId,
        iface: crate::EgressLease,
        next_hop: Ipv6Addr,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        proto: IpProto,
        l4: &[u8],
        hop_limit: u8,
        traffic_class: u8,
        flow_label: u32,
        automatic_flow_label: bool,
        policy_mtu: usize,
        may_fragment: bool,
        owner: Option<&crate::SocketOwner>,
    ) -> NetResult<crate::cgroup_bpf::EgressVerdict> {
        self.xmit_ipv6_payload_with_policy(iface_id, iface, next_hop, src, dst,
            proto as u8, l4, hop_limit, traffic_class, flow_label, automatic_flow_label,
            policy_mtu, may_fragment, owner)
    }

    fn xmit_ipv6_payload_with_policy(
        &self,
        iface_id: NetIfaceId,
        iface: crate::EgressLease,
        next_hop: Ipv6Addr,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        next_header: u8,
        payload: &[u8],
        hop_limit: u8,
        traffic_class: u8,
        flow_label: u32,
        automatic_flow_label: bool,
        policy_mtu: usize,
        may_fragment: bool,
        owner: Option<&crate::SocketOwner>,
    ) -> NetResult<crate::cgroup_bpf::EgressVerdict> {
        let src = if src.is_unspecified() {
            self.v6_select_source(iface_id, dst, None).ok_or(NetError::Eaddrnotavail)?
        } else { src };
        let flow_label = crate::inet_tx::ipv6_flow_label(flow_label, automatic_flow_label,
            src, dst, next_header, payload);
        let mtu = core::cmp::min(iface.mtu() as usize, policy_mtu);
        let total = IPV6_HDR_LEN + payload.len();
        if payload.len() > u16::MAX as usize { return Err(NetError::Emsgsize); }
        let mut full = crate::pkt::Pkt::with_capacity(IPV6_HDR_LEN, total + IPV6_HDR_LEN);
        full.put(payload.len()).map_err(|_| NetError::Enobufs)?.copy_from_slice(payload);
        push_ipv6_raw_header(&mut full, src, dst, next_header, hop_limit, traffic_class)?;
        set_ipv6_flow_label(&mut full, traffic_class, flow_label);
        prepare_ipv6(iface_id, next_hop, src, &mut full);
        let net_ns = owner.map_or_else(crate::netdev::current_net_ns, crate::SocketOwner::net_ns);
        if !crate::netfilter_hook::nf_output_in(net_ns, &full, NFPROTO_IPV6) {
            return Ok(crate::cgroup_bpf::EgressVerdict::Allow);
        }
        let verdict = if let Some(owner) = owner {
            crate::cgroup_bpf::egress(
                owner, full.data(), crate::addr::eth_p::IPV6, iface_id,
            )?
        } else {
            crate::cgroup_bpf::EgressVerdict::Allow
        };
        if total <= mtu {
            iface.xmit(full)?;
            return Ok(verdict);
        }

        if !may_fragment { return Err(NetError::Emsgsize); }

        let max_payload = mtu.saturating_sub(IPV6_HDR_LEN + 8) & !7usize;
        if max_payload == 0 {
            return Err(NetError::Enobufs);
        }
        let frag_id = self.next_ipv6_frag_id();
        let mut off = 0usize;
        while off < payload.len() {
            let take = core::cmp::min(max_payload, payload.len() - off);
            let more = off + take < payload.len();
            let frag_off_units = (off / 8) as u16;
            let off_flags = (frag_off_units << 3) | if more { 1 } else { 0 };
            let frag_payload_len = 8 + take;
            let total = IPV6_HDR_LEN + frag_payload_len;
            let mut p = crate::pkt::Pkt::with_capacity(IPV6_HDR_LEN, total + IPV6_HDR_LEN);
            let body = p.put(frag_payload_len).map_err(|_| NetError::Enobufs)?;
            body[0] = next_header;
            body[1] = 0;
            body[2..4].copy_from_slice(&off_flags.to_be_bytes());
            body[4..8].copy_from_slice(&frag_id.to_be_bytes());
            body[8..].copy_from_slice(&payload[off..off + take]);
            push_ipv6_raw_header(&mut p, src, dst, IpProto::Fragment as u8, hop_limit, traffic_class)?;
            set_ipv6_flow_label(&mut p, traffic_class, flow_label);
            emit_ipv6_fragment(iface_id, iface.clone(), next_hop, src, p)?;
            off += take;
        }
        Ok(verdict)
    }

    pub(crate) fn next_ipv6_frag_id(&self) -> u32 {
        let mut s = self.next_ip_id.lock();
        *s = s.wrapping_add(1);
        *s as u32
    }

    /// Build and transmit UDP/IPv6 using Linux `IPV6_MTU_DISCOVER` policy. # C: O(payload + N)
    pub fn send_udp6_pmtu_to_bound_opts(&self, src: Ipv6Addr, src_port: u16,
        dst: Ipv6Addr, dst_port: u16, payload: &[u8], bound: Option<NetIfaceId>,
        hop_limit: u8, traffic_class: u8, mode: i32) -> NetResult<()>
    {
        self.send_udp6_pmtu_to_bound_opts_in(
            0, src, src_port, dst, dst_port, payload, bound, hop_limit, traffic_class, mode,
        )
    }

    /// Build and transmit UDP/IPv6 in one network namespace. # C: O(payload + N)
    pub fn send_udp6_pmtu_to_bound_opts_in(&self, net_ns: u64, src: Ipv6Addr, src_port: u16,
        dst: Ipv6Addr, dst_port: u16, payload: &[u8], bound: Option<NetIfaceId>,
        hop_limit: u8, traffic_class: u8, mode: i32) -> NetResult<()>
    {
        self.send_udp6_pmtu_to_bound_opts_owner(None, net_ns, src, src_port, dst, dst_port,
            payload, bound, hop_limit, traffic_class, mode, 0, false, 0, false)
    }

    /// Build and transmit socket-owned UDP/IPv6. # C: O(payload + N)
    pub fn send_udp6_pmtu_to_bound_opts_owned(&self, owner: &crate::SocketOwner,
        src: Ipv6Addr, src_port: u16, dst: Ipv6Addr, dst_port: u16, payload: &[u8],
        bound: Option<NetIfaceId>, hop_limit: u8, traffic_class: u8, mode: i32,
        frag_size: i32, no_check: bool, flow_label: u32, automatic_flow_label: bool) -> NetResult<()> {
        self.send_udp6_pmtu_to_bound_opts_owner(Some(owner), owner.net_ns(), src, src_port,
            dst, dst_port, payload, bound, hop_limit, traffic_class, mode, frag_size, no_check,
            flow_label, automatic_flow_label)
    }

    fn send_udp6_pmtu_to_bound_opts_owner(&self, owner: Option<&crate::SocketOwner>,
        net_ns: u64, src: Ipv6Addr, src_port: u16, dst: Ipv6Addr, dst_port: u16,
        payload: &[u8], bound: Option<NetIfaceId>, hop_limit: u8, traffic_class: u8,
        mode: i32, frag_size: i32, no_check: bool, flow_label: u32,
        automatic_flow_label: bool) -> NetResult<()> {
        let src = if src == Ipv6Addr::ANY && dst == Ipv6Addr::LOOPBACK {
            Ipv6Addr::LOOPBACK
        } else { src };
        let (iface_id, iface, next_hop) = self.route_v6_iface_in(net_ns, dst, bound)?;
        let src_hint = self.routes6.lookup_policy_iface_in(
            net_ns, dst, iface_id, self.policy_rules()).and_then(|route| route.src_hint);
        let src = if src.is_unspecified() {
            self.v6_select_source(iface_id, dst, src_hint).ok_or(NetError::Eaddrnotavail)?
        } else { src };
        let use_iface = crate::uapi::ipv6_pmtudisc_uses_interface(mode);
        let mtu = ipv6_output_mtu(self.path_mtu_in(net_ns, IpAddr::V6(dst), Some(iface_id),
            use_iface)? as usize, frag_size);
        let l4_len = crate::udp::UDP_HDR_LEN + payload.len();
        let mut packet = crate::pkt::Pkt::with_capacity(0, l4_len);
        let body = packet.put(l4_len).map_err(|_| NetError::Enobufs)?;
        crate::udp::build_into_v6_opts(src_port, dst_port, src, dst, payload, body, no_check);
        self.xmit_ipv6_l4_with_policy(
            iface_id, iface, next_hop, src, dst, IpProto::Udp, packet.data(), hop_limit,
            traffic_class, flow_label, automatic_flow_label, mtu,
            crate::uapi::ipv6_pmtudisc_allows_fragmentation(mode),
            owner,
        ).map(|_| ())
    }

    pub(crate) fn handle_v6_packet_too_big(&self, net_ns: u64, mtu: u32, invoking: &[u8]) {
        let h = match Ipv6Hdr::parse(invoking) {
            Ok(h) => h,
            Err(_) => return,
        };
        let body = match invoking.get(IPV6_HDR_LEN..) { Some(body) => body, None => return };
        let l4 = match crate::ipv6_ext::walk(h.next_header, body) {
            Ok(crate::ipv6_ext::ExtWalk::Done { next_header, payload })
                if next_header == IpProto::Tcp as u8 => payload,
            Ok(crate::ipv6_ext::ExtWalk::Fragment { next_header, offset: 0, payload, .. }) => {
                match crate::ipv6_ext::walk(next_header, payload) {
                    Ok(crate::ipv6_ext::ExtWalk::Done { next_header, payload })
                        if next_header == IpProto::Tcp as u8 => payload,
                    _ => return,
                }
            }
            _ => return,
        };
        if l4.len() < 4 { return; }
        let src_port = u16::from_be_bytes([l4[0], l4[1]]);
        let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
        const IPV6_BASE_AND_TCP: usize = IPV6_HDR_LEN + 20;
        let ext_len = body.len().saturating_sub(l4.len());
        let overhead = IPV6_BASE_AND_TCP.saturating_add(ext_len).min(u16::MAX as usize) as u16;
        let path_mtu = mtu.max(1280).min(u16::MAX as u32) as u16;
        let new_mss = path_mtu.saturating_sub(overhead);
        let key = TcpKey {
            local_ip: crate::addr::IpAddr::V6(h.src),
            local_port: src_port,
            remote_ip: crate::addr::IpAddr::V6(h.dst),
            remote_port: dst_port,
        };
        if let Some(entry) = self.inet_tables(net_ns).tcp_conns.lock().get(&key).cloned() {
            let mut c = entry.conn.lock();
            if c.peer_mss == 0 || new_mss < c.peer_mss {
                c.peer_mss = new_mss;
            }
        }
    }

    pub(crate) fn xmit_ipv6(
        &self,
        iface: NetIfaceId,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        proto: IpProto,
        body: &[u8],
    ) -> NetResult<()> {
        let total = IPV6_HDR_LEN + body.len();
        let mut p = crate::pkt::Pkt::with_capacity(IPV6_HDR_LEN, total);
        p.put(body.len()).map_err(|_| NetError::Enobufs)?
            .copy_from_slice(body);
        push_ipv6_header(&mut p, src, dst, proto).map_err(|_| NetError::Enobufs)?;
        p.proto = crate::addr::eth_p::IPV6;
        p.iface = Some(iface);
        p.next_hop = Some(crate::pkt::TxNextHop::V6 { addr: dst, src });
        let net_ns = self.ifaces.namespace(iface).ok_or(NetError::Enetunreach)?;
        let dev = self.ifaces.acquire_egress_in_ns(iface, net_ns).ok_or(NetError::Enetunreach)?;
        if !nf_output(&p, NFPROTO_IPV6) {
            return Ok(());
        }
        dev.xmit(p)
    }

}

pub(super) fn push_ipv6_raw_header(p: &mut crate::pkt::Pkt, src: Ipv6Addr, dst: Ipv6Addr,
                        next_header: u8, hop_limit: u8, traffic_class: u8) -> NetResult<()> {
    if p.len() > u16::MAX as usize { return Err(NetError::Emsgsize); }
    let header = Ipv6Hdr { flow_label: 0, traffic_class, payload_length: p.len() as u16,
        next_header, hop_limit, src, dst };
    let slot = p.push(IPV6_HDR_LEN).map_err(|_| NetError::Enobufs)?;
    header.write_to(slot);
    Ok(())
}

fn set_ipv6_flow_label(p: &mut crate::pkt::Pkt, traffic_class: u8, flow_label: u32) {
    let bits = (6u32 << 28) | ((traffic_class as u32) << 20) | (flow_label & 0x000f_ffff);
    p.data_mut()[..4].copy_from_slice(&bits.to_be_bytes());
}

pub(super) fn admit_ipv6_owned(owner: &crate::SocketOwner, iface_id: NetIfaceId,
             next_hop: Ipv6Addr, src: Ipv6Addr, mut p: crate::pkt::Pkt) -> NetResult<bool> {
    prepare_ipv6(iface_id, next_hop, src, &mut p);
    if !crate::netfilter_hook::nf_output_in(owner.net_ns(), &p, NFPROTO_IPV6) {
        return Ok(false);
    }
    let _ = crate::cgroup_bpf::egress(
        owner, p.data(), crate::addr::eth_p::IPV6, iface_id,
    )?;
    Ok(true)
}

pub(super) fn emit_ipv6_fragment(iface_id: NetIfaceId, iface: crate::EgressLease, next_hop: Ipv6Addr,
             src: Ipv6Addr, mut p: crate::pkt::Pkt) -> NetResult<()> {
    prepare_ipv6(iface_id, next_hop, src, &mut p);
    iface.xmit(p)
}

fn prepare_ipv6(iface_id: NetIfaceId, next_hop: Ipv6Addr, src: Ipv6Addr,
                p: &mut crate::pkt::Pkt) {
    p.proto = crate::addr::eth_p::IPV6;
    p.iface = Some(iface_id);
    p.next_hop = Some(crate::pkt::TxNextHop::V6 { addr: next_hop, src });
}
