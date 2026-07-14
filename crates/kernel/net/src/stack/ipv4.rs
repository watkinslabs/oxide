use super::*;

impl NetStack {
    /// Wrap an L4 segment in IPv4 + xmit it via the routing table.
    /// # C: O(payload)
    pub(crate) fn send_l4_over_ipv4(&self, src: Ipv4Addr, dst: Ipv4Addr,
                          proto: IpProto, l4: &[u8]) -> NetResult<()>
    {
        self.send_l4_over_ipv4_tos(src, dst, proto, l4, 0)
    }

    /// F190: ECN TOS variant. # C: O(payload)
    pub(crate) fn send_l4_over_ipv4_tos(&self, src: Ipv4Addr, dst: Ipv4Addr,
                          proto: IpProto, l4: &[u8], tos: u8) -> NetResult<()>
    {
        let route = self.routes.lookup(dst).ok_or(NetError::Enetunreach)?;
        let iface = self.ifaces.lookup(route.iface).ok_or(NetError::Enetunreach)?;
        let id = { let mut s = self.next_ip_id.lock(); *s = s.wrapping_add(1); *s };
        self.xmit_ipv4_l4_on_iface(route.iface, iface, src, dst, proto, l4, tos, id)
    }

    /// Emit one IPv4 L4 payload on a selected iface, fragmenting when
    /// `IP header + payload` exceeds the iface MTU. # C: O(payload)
    pub(crate) fn xmit_ipv4_l4_on_iface(&self, iface_id: NetIfaceId,
        iface: Arc<dyn NetDev>, src: Ipv4Addr, dst: Ipv4Addr, proto: IpProto,
        l4: &[u8], tos: u8, id: u16) -> NetResult<()>
    {
        self.xmit_ipv4_l4_on_iface_opts(
            iface_id, iface, src, dst, proto, l4, tos, crate::ipv4::IPV4_DEFAULT_TTL, id,
        )
    }

    /// Emit one IPv4 L4 payload with explicit TOS and TTL on a selected iface,
    /// fragmenting when `IP header + payload` exceeds the iface MTU. # C: O(payload)
    pub(crate) fn xmit_ipv4_l4_on_iface_opts(&self, iface_id: NetIfaceId,
        iface: Arc<dyn NetDev>, src: Ipv4Addr, dst: Ipv4Addr, proto: IpProto,
        l4: &[u8], tos: u8, ttl: u8, id: u16) -> NetResult<()>
    {
        let mtu = iface.mtu() as usize;
        self.xmit_ipv4_l4_with_policy(
            iface_id, iface, src, dst, proto, l4, tos, ttl, id, mtu, false, true,
        )
    }

    fn xmit_ipv4_l4_with_policy(&self, iface_id: NetIfaceId,
        iface: Arc<dyn NetDev>, src: Ipv4Addr, dst: Ipv4Addr, proto: IpProto,
        l4: &[u8], tos: u8, ttl: u8, id: u16, mtu: usize, df: bool,
        may_fragment: bool) -> NetResult<()>
    {
        if l4.len() + IPV4_HDR_LEN <= mtu {
            let total = IPV4_HDR_LEN + l4.len();
            let mut p = Pkt::with_capacity(IPV4_HDR_LEN, total + IPV4_HDR_LEN);
            p.put(l4.len()).map_err(|_| NetError::Enobufs)?.copy_from_slice(l4);
            if df {
                const IPV4_DF: u16 = 0x4000;
                crate::ipv4::push_ipv4_header_tos_ttl_frag(
                    &mut p, src, dst, proto, id, tos, ttl, IPV4_DF,
                ).map_err(|_| NetError::Enobufs)?;
            } else {
                crate::ipv4::push_ipv4_header_tos_ttl(&mut p, src, dst, proto, id, tos, ttl)
                    .map_err(|_| NetError::Enobufs)?;
            }
            p.proto = crate::addr::eth_p::IPV4;
            p.iface = Some(iface_id);
            if !nf_output(&p, NFPROTO_IPV4) { return Ok(()); }
            return iface.xmit(p);
        }

        if !may_fragment { return Err(NetError::Emsgsize); }
        let max_payload = mtu.saturating_sub(IPV4_HDR_LEN) & !7usize;
        if max_payload == 0 { return Err(NetError::Emsgsize); }
        let mut off = 0usize;
        while off < l4.len() {
            let take = ::core::cmp::min(max_payload, l4.len() - off);
            let more = off + take < l4.len();
            let frag_off_units = (off / 8) as u16;
            let flags_frag = if more { 0x2000 } else { 0 } | frag_off_units;
            let total = IPV4_HDR_LEN + take;
            let mut p = Pkt::with_capacity(IPV4_HDR_LEN, total + IPV4_HDR_LEN);
            p.put(take).map_err(|_| NetError::Enobufs)?.copy_from_slice(&l4[off..off + take]);
            crate::ipv4::push_ipv4_header_tos_ttl_frag(&mut p, src, dst, proto, id, tos, ttl, flags_frag)
                .map_err(|_| NetError::Enobufs)?;
            p.proto = crate::addr::eth_p::IPV4;
            p.iface = Some(iface_id);
            if nf_output(&p, NFPROTO_IPV4) {
                iface.xmit(p)?;
            }
            off += take;
        }
        Ok(())
    }

    /// Build and transmit UDP/IPv4 using Linux `IP_MTU_DISCOVER` policy. # C: O(payload + N)
    pub fn send_udp_pmtu_to_bound_opts(&self, src: Ipv4Addr, src_port: u16,
        dst: Ipv4Addr, dst_port: u16, payload: &[u8], bound: Option<NetIfaceId>,
        tos: u8, ttl: u8, mode: i32) -> NetResult<()>
    {
        let (iface_id, iface) = match bound {
            Some(id) => (id, self.ifaces.lookup(id).ok_or(NetError::Enetunreach)?),
            None => {
                let route = self.routes.lookup(dst).ok_or(NetError::Enetunreach)?;
                (route.iface, self.ifaces.lookup(route.iface).ok_or(NetError::Enetunreach)?)
            }
        };
        let probe = mode >= crate::uapi::IP_PMTUDISC_PROBE;
        let mtu = self.path_mtu(IpAddr::V4(dst), Some(iface_id), probe)? as usize;
        let may_fragment = mode != crate::uapi::IP_PMTUDISC_DO
            && mode != crate::uapi::IP_PMTUDISC_PROBE
            && mode != crate::uapi::IP_PMTUDISC_INTERFACE;
        let df = mode == crate::uapi::IP_PMTUDISC_WANT
            || mode == crate::uapi::IP_PMTUDISC_DO
            || mode == crate::uapi::IP_PMTUDISC_PROBE;
        let udp_len = crate::udp::UDP_HDR_LEN + payload.len();
        let mut packet = Pkt::with_capacity(0, udp_len);
        let udp = packet.put(udp_len).map_err(|_| NetError::Enobufs)?;
        UdpHdr::build_into(src_port, dst_port, src, dst, payload, udp);
        let id = { let mut next = self.next_ip_id.lock(); *next = next.wrapping_add(1); *next };
        self.xmit_ipv4_l4_with_policy(
            iface_id, iface, src, dst, IpProto::Udp, packet.data(), tos, ttl, id,
            mtu, df, may_fragment,
        )
    }

    // F180b: send_l4 in stack_ipv6.rs.

    /// Demux IPv4 → ICMP/UDP/TCP. # C: O(payload)
    pub fn deliver_rx(&self, iface: NetIfaceId, l3: &[u8]) -> NetResult<()> {
        // PRE_ROUTING fires on every received packet before the routing
        // decision. Non-local destinations are forwarded only when
        // `net.ipv4.ip_forward` enables router mode.
        if nf_hook_eval(NF_INET_PRE_ROUTING, l3, NFPROTO_IPV4) == 0 { return Ok(()); }
        let hdr = Ipv4Hdr::parse(l3).map_err(|_| NetError::Einval)?;
        if !self.ipv4_dst_is_local(hdr.dst) {
            return self.forward_ipv4(iface, l3);
        }
        if nf_hook_eval(NF_INET_LOCAL_IN, l3, NFPROTO_IPV4) == 0 { return Ok(()); }
        let total = hdr.total_len as usize;
        if total > l3.len() { return Err(NetError::Einval); }
        let frag_payload = &l3[hdr.ihl_bytes() .. total];
        let assembled;
        let mf = (hdr.flags_frag & 0x2000) != 0;
        let off8 = (hdr.flags_frag & 0x1FFF) as usize;
        let payload: &[u8] = if mf || off8 != 0 {
            let k = crate::ipv4_reasm::ReasmKey { src: hdr.src, dst: hdr.dst, proto: hdr.proto, id: hdr.id };
            match self.ipv4_reasm.push(k, net_now_ns(), off8 * 8, frag_payload, mf) {
                Some(b) => { assembled = b; &assembled[..] }
                None    => return Ok(()),
            }
        } else { frag_payload };
        match hdr.proto {
            p if p == IpProto::Icmp as u8 => {
                let echo = match icmp::IcmpEcho::parse(payload) {
                    Ok(h) => h, Err(_) => return Ok(()),
                };
                if echo.typ == ICMP_TYPE_ECHO_REQUEST {
                    let reply = match icmp::build_echo_reply(payload) {
                        Ok(r) => r, Err(_) => return Ok(()),
                    };
                    let total = IPV4_HDR_LEN + reply.len();
                    let mut p = Pkt::with_capacity(IPV4_HDR_LEN, total + IPV4_HDR_LEN);
                    p.put(reply.len()).map_err(|_| NetError::Enobufs)?
                        .copy_from_slice(&reply);
                    let id = { let mut s = self.next_ip_id.lock(); *s = s.wrapping_add(1); *s };
                    push_ipv4_header(&mut p, hdr.dst, hdr.src, IpProto::Icmp, id)
                        .map_err(|_| NetError::Enobufs)?;
                    p.proto = crate::addr::eth_p::IPV4;
                    p.iface = Some(iface);
                    let dev = self.ifaces.lookup(iface).ok_or(NetError::Enetunreach)?;
                    // ICMP echo reply is kernel-generated → LOCAL_OUT + POST_ROUTING.
                    if nf_output(&p, NFPROTO_IPV4) { dev.xmit(p)?; }
                } else if echo.typ == icmp::ICMP_TYPE_DEST_UNREACH
                    || echo.typ == icmp::ICMP_TYPE_TIME_EXC || echo.typ == 12
                {
                    self.handle_icmp_error(iface, hdr.src, echo.typ, echo.code, payload);
                }
            }
            p if p == IpProto::Udp as u8 => {
                let udp = UdpHdr::parse(payload, hdr.src, hdr.dst)
                    .map_err(|_| NetError::Einval)?;
                // Clone the queue Arc out of the map then drop the
                // map lock before touching the queue itself. wake_all
                // takes the waitlist lock + runqueue inner; we must
                // not hold the udp-map lock across either.
                let endpoints = self.udp_demux(hdr.src, udp.src_port, hdr.dst, udp.dst_port, iface);
                let has_v4 = !endpoints.is_empty();
                for q in endpoints {
                    if hdr.dst.is_multicast() {
                        if !q.mcast.accept_v4(iface, hdr.dst, hdr.src) { continue; }
                    }
                    let packet = &payload[..udp.length as usize];
                    let body = &packet[crate::udp::UDP_HDR_LEN..];
                    let Some(keep) = crate::bpf_filter::retained_payload_len(
                        q.bpf_filter.verdict(packet), body.len(),
                    ) else { continue; };
                    let _ = q.enqueue((
                        hdr.src, udp.src_port, hdr.dst, iface, hdr.ttl, body[..keep].to_vec(),
                    ));
                }
                let endpoints6 = if !has_v4 || hdr.dst.is_multicast() || hdr.dst.is_broadcast() {
                    self.udp6_demux_v4(hdr.src, udp.src_port, hdr.dst, udp.dst_port, iface)
                } else { Vec::new() };
                for q in endpoints6 {
                    let packet = &payload[..udp.length as usize];
                    let body = &packet[crate::udp::UDP_HDR_LEN..];
                    let Some(keep) = crate::bpf_filter::retained_payload_len(
                        q.bpf_filter.verdict(packet), body.len(),
                    ) else { continue; };
                    let _ = q.enqueue((
                        Ipv6Addr::from_v4_mapped(hdr.src), udp.src_port,
                        Ipv6Addr::from_v4_mapped(hdr.dst), iface, hdr.ttl, body[..keep].to_vec(),
                    ));
                }
            }
            p if p == IpProto::Tcp as u8 =>
                self.deliver_tcp(iface, IpAddr::V4(hdr.src), IpAddr::V4(hdr.dst), payload)?,
            p if p == IpProto::Igmp as u8 => self.handle_igmp(iface, hdr.src, hdr.dst, payload)?,
            _ => {}
        }
        Ok(())
    }

    /// Drain lo xmit → deliver_rx; v6 frames route to deliver_rx_ipv6.
    /// # C: O(N pending)
    pub fn drain_loopback(&self, iface: NetIfaceId, lo: &LoopbackDev) {
        while let Some(p) = lo.rx_pop() {
            // F180b: dispatch by ethertype so v6 lo round-trips work.
            if p.proto == crate::addr::eth_p::IPV6 {
                let _ = self.deliver_rx_ipv6(iface, p.data());
            } else {
                let _ = self.deliver_rx(iface, p.data());
            }
        }
    }
}
