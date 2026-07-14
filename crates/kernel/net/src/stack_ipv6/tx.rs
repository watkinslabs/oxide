use alloc::sync::Arc;

use crate::addr::{IpAddr, IpProto, Ipv6Addr, NetIfaceId};
use crate::ipv6::{Ipv6Hdr, IPV6_HDR_LEN, push_ipv6_header, push_ipv6_header_hop};
use crate::netdev::{NetDev, NetError, NetResult};
use crate::netfilter_hook::{nf_output, NFPROTO_IPV6};
use crate::stack::NetStack;
use crate::stack::TcpKey;

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
        let route = self.routes6.lookup_in(net_ns, dst).ok_or(NetError::Enetunreach)?;
        let iface = self.ifaces.lookup_in_ns(route.iface, net_ns).ok_or(NetError::Enetunreach)?;
        self.xmit_ipv6_l4_on_iface(
            route.iface, iface, route.gateway.unwrap_or(dst), src, dst, proto, l4,
        )
    }

    pub(crate) fn xmit_ipv6_l4_on_iface(
        &self,
        iface_id: NetIfaceId,
        iface: Arc<dyn NetDev>,
        next_hop: Ipv6Addr,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        proto: IpProto,
        l4: &[u8],
    ) -> NetResult<()> {
        self.xmit_ipv6_l4_on_iface_opts(
            iface_id, iface, next_hop, src, dst, proto, l4, crate::ipv6::IPV6_DEFAULT_HOP_LIMIT,
        )
    }

    /// `xmit_ipv6_l4_on_iface` with an explicit hop limit (socket
    /// IPV6_UNICAST_HOPS / IPV6_MULTICAST_HOPS). Mirrors the IPv4
    /// `xmit_ipv4_l4_on_iface_opts` ttl seam. # C: O(payload + N)
    pub(crate) fn xmit_ipv6_l4_on_iface_opts(
        &self,
        iface_id: NetIfaceId,
        iface: Arc<dyn NetDev>,
        next_hop: Ipv6Addr,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        proto: IpProto,
        l4: &[u8],
        hop_limit: u8,
    ) -> NetResult<()> {
        self.xmit_ipv6_l4_with_policy(
            iface_id, iface, next_hop, src, dst, proto, l4, hop_limit, usize::MAX, true,
        )
    }

    fn xmit_ipv6_l4_with_policy(
        &self,
        iface_id: NetIfaceId,
        iface: Arc<dyn NetDev>,
        next_hop: Ipv6Addr,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        proto: IpProto,
        l4: &[u8],
        hop_limit: u8,
        policy_mtu: usize,
        may_fragment: bool,
    ) -> NetResult<()> {
        let mtu = core::cmp::min(iface.mtu() as usize, policy_mtu);
        let total = IPV6_HDR_LEN + l4.len();
        if l4.len() > u16::MAX as usize {
            return Err(NetError::Enobufs);
        }
        if total <= mtu {
            let mut p = crate::pkt::Pkt::with_capacity(IPV6_HDR_LEN, total + IPV6_HDR_LEN);
            p.put(l4.len()).map_err(|_| NetError::Enobufs)?
                .copy_from_slice(l4);
            push_ipv6_header_hop(&mut p, src, dst, proto, hop_limit).map_err(|_| NetError::Enobufs)?;
            p.proto = crate::addr::eth_p::IPV6;
            p.iface = Some(iface_id);
            p.next_hop = Some(crate::pkt::TxNextHop::V6 { addr: next_hop, src });
            if !nf_output(&p, NFPROTO_IPV6) {
                return Ok(());
            }
            return iface.xmit(p);
        }

        if !may_fragment { return Err(NetError::Emsgsize); }

        let max_payload = mtu.saturating_sub(IPV6_HDR_LEN + 8) & !7usize;
        if max_payload == 0 {
            return Err(NetError::Enobufs);
        }
        let frag_id = self.next_ipv6_frag_id();
        let mut off = 0usize;
        while off < l4.len() {
            let take = core::cmp::min(max_payload, l4.len() - off);
            let more = off + take < l4.len();
            let frag_off_units = (off / 8) as u16;
            let off_flags = (frag_off_units << 3) | if more { 1 } else { 0 };
            let frag_payload_len = 8 + take;
            let total = IPV6_HDR_LEN + frag_payload_len;
            let mut p = crate::pkt::Pkt::with_capacity(IPV6_HDR_LEN, total + IPV6_HDR_LEN);
            let body = p.put(frag_payload_len).map_err(|_| NetError::Enobufs)?;
            body[0] = proto as u8;
            body[1] = 0;
            body[2..4].copy_from_slice(&off_flags.to_be_bytes());
            body[4..8].copy_from_slice(&frag_id.to_be_bytes());
            body[8..].copy_from_slice(&l4[off..off + take]);
            push_ipv6_header_hop(&mut p, src, dst, IpProto::Fragment, hop_limit)
                .map_err(|_| NetError::Enobufs)?;
            p.proto = crate::addr::eth_p::IPV6;
            p.iface = Some(iface_id);
            p.next_hop = Some(crate::pkt::TxNextHop::V6 { addr: next_hop, src });
            if nf_output(&p, NFPROTO_IPV6) {
                iface.xmit(p)?;
            }
            off += take;
        }
        Ok(())
    }

    pub(crate) fn next_ipv6_frag_id(&self) -> u32 {
        let mut s = self.next_ip_id.lock();
        *s = s.wrapping_add(1);
        *s as u32
    }

    /// Build and transmit UDP/IPv6 using Linux `IPV6_MTU_DISCOVER` policy. # C: O(payload + N)
    pub fn send_udp6_pmtu_to_bound_opts(&self, src: Ipv6Addr, src_port: u16,
        dst: Ipv6Addr, dst_port: u16, payload: &[u8], bound: Option<NetIfaceId>,
        hop_limit: u8, mode: i32) -> NetResult<()>
    {
        self.send_udp6_pmtu_to_bound_opts_in(
            0, src, src_port, dst, dst_port, payload, bound, hop_limit, mode,
        )
    }

    /// Build and transmit UDP/IPv6 in one network namespace. # C: O(payload + N)
    pub fn send_udp6_pmtu_to_bound_opts_in(&self, net_ns: u64, src: Ipv6Addr, src_port: u16,
        dst: Ipv6Addr, dst_port: u16, payload: &[u8], bound: Option<NetIfaceId>,
        hop_limit: u8, mode: i32) -> NetResult<()>
    {
        let src = if src == Ipv6Addr::ANY && dst == Ipv6Addr::LOOPBACK {
            Ipv6Addr::LOOPBACK
        } else { src };
        let (iface_id, iface, next_hop) = self.route_v6_iface_in(net_ns, dst, bound)?;
        let use_iface = crate::uapi::ipv6_pmtudisc_uses_interface(mode);
        let mtu = self.path_mtu_in(net_ns, IpAddr::V6(dst), Some(iface_id), use_iface)? as usize;
        let l4_len = crate::udp::UDP_HDR_LEN + payload.len();
        let mut packet = crate::pkt::Pkt::with_capacity(0, l4_len);
        let body = packet.put(l4_len).map_err(|_| NetError::Enobufs)?;
        crate::udp::build_into_v6(src_port, dst_port, src, dst, payload, body);
        self.xmit_ipv6_l4_with_policy(
            iface_id, iface, next_hop, src, dst, IpProto::Udp, packet.data(), hop_limit, mtu,
            crate::uapi::ipv6_pmtudisc_allows_fragmentation(mode),
        )
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

    pub(crate) fn apply_router_advertisement(
        &self,
        net_ns: u64,
        iface: NetIfaceId,
        router: Ipv6Addr,
        ra: &crate::ndp::RouterAdvertisement,
    ) {
        if self.ifaces.lookup_in_ns(iface, net_ns).is_none() { return; }
        if let Some(mac) = ra.source_lladdr {
            self.ndp_insert(iface, router, mac);
        }

        let our_mac = match self.ifaces.lookup_in_ns(iface, net_ns) {
            Some(dev) => dev.mac(),
            None => return,
        };
        let mut src_hint = None;
        for p in &ra.prefixes {
            if p.prefix_len != 64 { continue; }
            self.routes6.retain_in(net_ns, |e| {
                !(e.iface == iface && e.prefix_len == p.prefix_len && e.dst == p.prefix)
            });
            if p.valid_lifetime == 0 { continue; }
            let autoconf = (p.flags & crate::ndp::NDP_PIO_FLAG_AUTO) != 0;
            let onlink = (p.flags & crate::ndp::NDP_PIO_FLAG_ONLINK) != 0;
            let addr = slaac_eui64_addr(p.prefix, our_mac);
            if autoconf {
                self.add_v6_addr_meta(
                    iface,
                    addr,
                    p.prefix_len,
                    p.valid_lifetime,
                    p.preferred_lifetime,
                );
                src_hint = Some(addr);
            }
            if onlink {
                self.routes6.add_in(net_ns, crate::route6::Route6Entry {
                    dst: p.prefix,
                    prefix_len: p.prefix_len,
                    iface,
                    gateway: None,
                    src_hint: if autoconf { Some(addr) } else { None },
                });
            }
        }

        self.routes6.retain_in(net_ns, |e| !(e.iface == iface && e.prefix_len == 0));
        if ra.router_lifetime != 0 {
            self.routes6.add_in(net_ns, crate::route6::Route6Entry {
                dst: Ipv6Addr::ANY,
                prefix_len: 0,
                iface,
                gateway: Some(router),
                src_hint,
            });
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
        let dev = self.ifaces.lookup_in_ns(iface, net_ns).ok_or(NetError::Enetunreach)?;
        if !nf_output(&p, NFPROTO_IPV6) {
            return Ok(());
        }
        dev.xmit(p)
    }

}

fn slaac_eui64_addr(prefix: Ipv6Addr, mac: crate::addr::MacAddr) -> Ipv6Addr {
    let mut out = prefix.0;
    out[8] = mac.0[0] ^ 0x02;
    out[9] = mac.0[1];
    out[10] = mac.0[2];
    out[11] = 0xff;
    out[12] = 0xfe;
    out[13] = mac.0[3];
    out[14] = mac.0[4];
    out[15] = mac.0[5];
    Ipv6Addr(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ra(prefix: Ipv6Addr, valid_lifetime: u32, router_lifetime: u16)
        -> crate::ndp::RouterAdvertisement
    {
        crate::ndp::RouterAdvertisement {
            hop_limit: 64,
            flags: 0,
            router_lifetime,
            reachable_time: 0,
            retrans_timer: 0,
            source_lladdr: None,
            prefixes: alloc::vec![crate::ndp::PrefixInfo {
                prefix_len: 64,
                flags: crate::ndp::NDP_PIO_FLAG_ONLINK | crate::ndp::NDP_PIO_FLAG_AUTO,
                valid_lifetime,
                preferred_lifetime: valid_lifetime,
                prefix,
            }],
        }
    }

    #[test]
    fn router_advertisement_mutations_are_namespace_scoped() {
        let stack = NetStack::new();
        let ns_a = 61;
        let ns_b = 62;
        let (iface_a, _) = stack.register_loopback_in(ns_a);
        let (iface_b, _) = stack.register_loopback_in(ns_b);
        let router_a = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
        let router_b = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,2]);
        let prefix = Ipv6Addr::from_segments([0x2001,0xdb8,0x825,0,0,0,0,0]);
        let outside = Ipv6Addr::from_segments([0x2001,0xdb8,0x999,0,0,0,0,1]);
        stack.apply_router_advertisement(ns_a, iface_a, router_a, &ra(prefix, 300, 60));
        stack.apply_router_advertisement(ns_b, iface_b, router_b, &ra(prefix, 300, 60));
        assert_eq!(stack.routes6.lookup_in(ns_a, outside).and_then(|r| r.gateway), Some(router_a));
        assert_eq!(stack.routes6.lookup_in(ns_b, outside).and_then(|r| r.gateway), Some(router_b));
        stack.apply_router_advertisement(ns_a, iface_a, router_a, &ra(prefix, 0, 0));
        assert!(stack.routes6.snapshot_in(ns_a).iter().all(|r| r.prefix_len == 128));
        assert!(stack.routes6.snapshot_in(ns_b).iter().any(|r| r.prefix_len == 64));
        assert_eq!(stack.routes6.lookup_in(ns_b, outside).and_then(|r| r.gateway), Some(router_b));
        let before = stack.routes6.snapshot_in(ns_a);
        stack.apply_router_advertisement(ns_a, iface_b, router_b, &ra(prefix, 300, 60));
        assert_eq!(stack.routes6.snapshot_in(ns_a), before);
    }
}
