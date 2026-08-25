use super::*;

impl NetStack {
    pub(super) fn emit_mldv2(&self, net_ns: u64, iface: NetIfaceId, src: Ipv6Addr,
                             records: &[(u8, Ipv6Addr, &[Ipv6Addr])]) -> NetResult<()> {
        let body = crate::icmpv6::build_mldv2_records(src, records);
        self.emit_mld_body(net_ns, iface, src, crate::icmpv6::IPV6_MLDV2_ROUTERS, &body)
    }

    /// Keep output construction at the packet-output boundary. Linux's
    /// `NF_HOOK` path is `noinline_for_stack`: receive-side protocol locals
    /// must not remain live while output builds packet state.
    #[inline(never)]
    pub(super) fn emit_mld_body(&self, net_ns: u64, iface: NetIfaceId,
                                src: Ipv6Addr, dst: Ipv6Addr, body: &[u8]) -> NetResult<()> {
        let dev = self.ifaces.acquire_egress_in_ns(iface, net_ns).ok_or(NetError::Enetunreach)?;
        let extension_len = 8usize;
        let payload_len = extension_len + body.len();
        let total = crate::ipv6::IPV6_HDR_LEN + payload_len;
        if total > dev.mtu() as usize || payload_len > u16::MAX as usize { return Err(NetError::Enobufs); }
        let mut packet = crate::Pkt::with_capacity(crate::ipv6::IPV6_HDR_LEN, total);
        let payload = packet.put(payload_len).map_err(|_| NetError::Enobufs)?;
        payload[..8].copy_from_slice(&[58, 0, 5, 2, 0, 0, 1, 0]);
        payload[8..].copy_from_slice(body);
        let header = packet.push(crate::ipv6::IPV6_HDR_LEN).map_err(|_| NetError::Enobufs)?;
        let mut ipv6 = crate::ipv6::Ipv6Hdr::build(src, dst,
            crate::addr::IpProto::Raw, payload_len as u16);
        ipv6.next_header = 0;
        ipv6.hop_limit = 1;
        ipv6.write_to(header);
        packet.proto = crate::addr::eth_p::IPV6;
        packet.iface = Some(iface);
        if !crate::netfilter_hook::nf_output(&mut packet, crate::netfilter_hook::NFPROTO_IPV6) { return Ok(()); }
        dev.xmit(packet)
    }
}
