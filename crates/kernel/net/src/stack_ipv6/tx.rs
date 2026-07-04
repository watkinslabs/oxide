use alloc::sync::Arc;

use crate::addr::{IpAddr, IpProto, Ipv6Addr, NetIfaceId};
use crate::ipv6::{Ipv6Hdr, IPV6_HDR_LEN, push_ipv6_header};
use crate::netdev::{NetDev, NetError, NetResult};
use crate::netfilter_hook::{nf_output, NFPROTO_IPV6};
use crate::stack::NetStack;
use crate::stack::TcpKey;

impl NetStack {
    pub fn send_router_solicitation(&self, iface: NetIfaceId, src: Ipv6Addr) -> NetResult<()> {
        let our_mac = if src.is_unspecified() {
            None
        } else {
            Some(self.ifaces.lookup(iface).ok_or(NetError::Enetunreach)?.mac())
        };
        let body = crate::ndp::NdpMsg::build_rs(
            src,
            crate::ndp::IPV6_ALL_ROUTERS,
            our_mac,
        );
        self.xmit_ipv6(iface, src, crate::ndp::IPV6_ALL_ROUTERS, IpProto::Icmpv6, &body)
    }

    pub fn join_ipv6_multicast(
        &self,
        iface: NetIfaceId,
        group: Ipv6Addr,
        src: Ipv6Addr,
    ) -> NetResult<()> {
        if !group.is_multicast() {
            return Err(NetError::Einval);
        }
        let fresh = {
            let mut g = self.v6_mcast.lock();
            let groups = g.entry(iface).or_default();
            if groups.iter().any(|m| *m == group) {
                false
            } else {
                groups.push(group);
                true
            }
        };
        if fresh && group != crate::ndp::IPV6_ALL_NODES {
            let body = crate::icmpv6::build_mldv2_report(
                src,
                crate::icmpv6::MLDV2_RECORD_CHANGE_TO_EXCLUDE,
                group,
                &[],
            );
            self.xmit_ipv6(iface, src, crate::icmpv6::IPV6_MLDV2_ROUTERS, IpProto::Icmpv6, &body)?;
        }
        Ok(())
    }

    pub fn leave_ipv6_multicast(
        &self,
        iface: NetIfaceId,
        group: Ipv6Addr,
        src: Ipv6Addr,
    ) -> NetResult<()> {
        let removed = {
            let mut g = self.v6_mcast.lock();
            if let Some(groups) = g.get_mut(&iface) {
                let before = groups.len();
                groups.retain(|m| *m != group);
                before != groups.len()
            } else {
                false
            }
        };
        if removed && group != crate::ndp::IPV6_ALL_NODES {
            let body = crate::icmpv6::build_mldv2_report(
                src,
                crate::icmpv6::MLDV2_RECORD_CHANGE_TO_INCLUDE,
                group,
                &[],
            );
            self.xmit_ipv6(iface, src, crate::icmpv6::IPV6_MLDV2_ROUTERS, IpProto::Icmpv6, &body)?;
        }
        Ok(())
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
        let (iface_id, iface) = self.route6_iface(dst).ok_or(NetError::Enetunreach)?;
        self.xmit_ipv6_l4_on_iface(iface_id, iface, src, dst, proto, l4)
    }

    pub(crate) fn xmit_ipv6_l4_on_iface(
        &self,
        iface_id: NetIfaceId,
        iface: Arc<dyn NetDev>,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        proto: IpProto,
        l4: &[u8],
    ) -> NetResult<()> {
        let mtu = iface.mtu() as usize;
        let total = IPV6_HDR_LEN + l4.len();
        if l4.len() > u16::MAX as usize {
            return Err(NetError::Enobufs);
        }
        if total <= mtu {
            let mut p = crate::pkt::Pkt::with_capacity(IPV6_HDR_LEN, total + IPV6_HDR_LEN);
            p.put(l4.len()).map_err(|_| NetError::Enobufs)?
                .copy_from_slice(l4);
            push_ipv6_header(&mut p, src, dst, proto).map_err(|_| NetError::Enobufs)?;
            p.proto = crate::addr::eth_p::IPV6;
            p.iface = Some(iface_id);
            if !nf_output(&p, NFPROTO_IPV6) {
                return Ok(());
            }
            return iface.xmit(p);
        }

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
            push_ipv6_header(&mut p, src, dst, IpProto::Fragment)
                .map_err(|_| NetError::Enobufs)?;
            p.proto = crate::addr::eth_p::IPV6;
            p.iface = Some(iface_id);
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

    pub(crate) fn handle_v6_packet_too_big(&self, mtu: u32, invoking: &[u8]) {
        let h = match Ipv6Hdr::parse(invoking) {
            Ok(h) => h,
            Err(_) => return,
        };
        if h.next_header != IpProto::Tcp as u8 {
            return;
        }
        if invoking.len() < IPV6_HDR_LEN + 4 {
            return;
        }
        let l4 = &invoking[IPV6_HDR_LEN..];
        let src_port = u16::from_be_bytes([l4[0], l4[1]]);
        let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
        let new_mss = (mtu as u16).saturating_sub(40);
        if new_mss < 1280u16.saturating_sub(40) {
            return;
        }
        let key = TcpKey {
            local_ip: crate::addr::IpAddr::V6(h.src),
            local_port: src_port,
            remote_ip: crate::addr::IpAddr::V6(h.dst),
            remote_port: dst_port,
        };
        if let Some(entry) = self.tcp_conns_map().lock().get(&key).cloned() {
            let mut c = entry.conn.lock();
            if c.peer_mss == 0 || new_mss < c.peer_mss {
                c.peer_mss = new_mss;
            }
        }
    }

    pub fn respond_mld_query(
        &self,
        iface: NetIfaceId,
        q: crate::icmpv6::Mldv1Query,
    ) -> NetResult<()> {
        let groups = {
            let g = self.v6_mcast.lock();
            g.get(&iface).cloned().unwrap_or_default()
        };
        let src = self.v6_src_on_iface(iface).unwrap_or(Ipv6Addr::ANY);
        for group in groups {
            if group == crate::ndp::IPV6_ALL_NODES {
                continue;
            }
            if !q.group.is_unspecified() && q.group != group {
                continue;
            }
            let body = crate::icmpv6::build_mldv2_report(
                src,
                crate::icmpv6::MLDV2_RECORD_MODE_IS_EXCLUDE,
                group,
                &q.sources,
            );
            self.xmit_ipv6(iface, src, crate::icmpv6::IPV6_MLDV2_ROUTERS, IpProto::Icmpv6, &body)?;
        }
        Ok(())
    }

    pub(crate) fn apply_router_advertisement(
        &self,
        iface: NetIfaceId,
        router: Ipv6Addr,
        ra: &crate::ndp::RouterAdvertisement,
    ) {
        if let Some(mac) = ra.source_lladdr {
            self.ndp_insert(iface, router, mac);
        }

        let our_mac = match self.ifaces.lookup(iface) {
            Some(dev) => dev.mac(),
            None => return,
        };
        let mut src_hint = None;
        for p in &ra.prefixes {
            if p.prefix_len != 64 || p.valid_lifetime == 0 {
                continue;
            }
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
                self.routes6.retain(|e| !(e.iface == iface && e.prefix_len == p.prefix_len && e.dst == p.prefix));
                self.routes6.add(crate::route6::Route6Entry {
                    dst: p.prefix,
                    prefix_len: p.prefix_len,
                    iface,
                    gateway: None,
                    src_hint: if autoconf { Some(addr) } else { None },
                });
            }
        }

        self.routes6.retain(|e| !(e.iface == iface && e.prefix_len == 0));
        if ra.router_lifetime != 0 {
            self.routes6.add(crate::route6::Route6Entry {
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
        let dev = self.ifaces.lookup(iface).ok_or(NetError::Enetunreach)?;
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
