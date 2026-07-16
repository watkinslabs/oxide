use super::*;

impl NetStack {
    /// Resolve canonical IPv4 PMTU transmit policy for one selected route. # C: O(log N)
    pub(crate) fn ipv4_pmtu_policy(&self, net_ns: u64, iface: NetIfaceId,
        dst: Ipv4Addr, link_mtu: u32, mode: i32) -> (usize, bool, bool) {
        let state = if crate::uapi::ip_pmtudisc_uses_interface(mode) {
            super::pmtu_cache::PmtuLookup { mtu: link_mtu, locked: false }
        } else {
            self.inet_tables(net_ns).pmtu.lookup(iface, IpAddr::V4(dst), link_mtu)
        };
        let df = mode == crate::uapi::IP_PMTUDISC_DO
            || mode == crate::uapi::IP_PMTUDISC_PROBE
            || mode == crate::uapi::IP_PMTUDISC_WANT && !state.locked;
        (state.mtu as usize, df, crate::uapi::ip_pmtudisc_allows_fragmentation(mode))
    }

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
        self.send_l4_over_ipv4_tos_in(0, src, dst, proto, l4, tos)
    }

    /// Wrap an L4 segment in IPv4 using one namespace's route table. # C: O(payload + N)
    pub(crate) fn send_l4_over_ipv4_tos_in(&self, net_ns: u64, src: Ipv4Addr, dst: Ipv4Addr,
                          proto: IpProto, l4: &[u8], tos: u8) -> NetResult<()> {
        let route = self.routes.lookup_result_in(net_ns, dst)?;
        let iface = self.ifaces.acquire_egress_in_ns(route.iface, net_ns).ok_or(NetError::Enetunreach)?;
        let id = { let mut s = self.next_ip_id.lock(); *s = s.wrapping_add(1); *s };
        self.xmit_ipv4_l4_on_iface(
            route.iface, iface, route.gateway.unwrap_or(dst), src, dst, proto, l4, tos, id,
        )
    }

    /// Emit one IPv4 L4 payload on a selected iface, fragmenting when
    /// `IP header + payload` exceeds the iface MTU. # C: O(payload)
    pub(crate) fn xmit_ipv4_l4_on_iface(&self, iface_id: NetIfaceId,
        iface: crate::EgressLease, next_hop: Ipv4Addr, src: Ipv4Addr, dst: Ipv4Addr, proto: IpProto,
        l4: &[u8], tos: u8, id: u16) -> NetResult<()>
    {
        self.xmit_ipv4_l4_on_iface_opts(
            iface_id, iface, next_hop, src, dst, proto, l4, tos, crate::ipv4::IPV4_DEFAULT_TTL, id,
        )
    }

    /// Emit one IPv4 L4 payload with explicit TOS and TTL on a selected iface,
    /// fragmenting when `IP header + payload` exceeds the iface MTU. # C: O(payload)
    pub(crate) fn xmit_ipv4_l4_on_iface_opts(&self, iface_id: NetIfaceId,
        iface: crate::EgressLease, next_hop: Ipv4Addr, src: Ipv4Addr, dst: Ipv4Addr, proto: IpProto,
        l4: &[u8], tos: u8, ttl: u8, id: u16) -> NetResult<()>
    {
        let mtu = iface.mtu() as usize;
        self.xmit_ipv4_l4_with_policy(
            iface_id, iface, next_hop, src, dst, proto, l4, tos, ttl, id, mtu, false, true,
        )
    }

    fn xmit_ipv4_l4_with_policy(&self, iface_id: NetIfaceId,
        iface: crate::EgressLease, next_hop: Ipv4Addr, src: Ipv4Addr, dst: Ipv4Addr, proto: IpProto,
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
                crate::ipv4::push_ipv4_header_tos_ttl_frag(
                    &mut p, src, dst, proto, id, tos, ttl, 0,
                ).map_err(|_| NetError::Enobufs)?;
            }
            p.proto = crate::addr::eth_p::IPV4;
            p.iface = Some(iface_id);
            p.next_hop = Some(crate::pkt::TxNextHop::V4(next_hop));
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
            p.next_hop = Some(crate::pkt::TxNextHop::V4(next_hop));
            if nf_output(&p, NFPROTO_IPV4) {
                iface.xmit(p)?;
            }
            off += take;
        }
        Ok(())
    }

    /// Transmit one TCP/IPv4 segment using the selected socket PMTU mode. # C: O(payload + N)
    pub(super) fn send_tcp_ipv4_segment_in(&self, net_ns: u64, src: Ipv4Addr,
        dst: Ipv4Addr, l4: &[u8], tos: u8, bound: Option<NetIfaceId>, mode: i32)
        -> NetResult<()>
    {
        let (iface_id, iface, next_hop) = self.route_v4_iface_in(net_ns, dst, bound)?;
        let (mtu, df, may_fragment) = self.ipv4_pmtu_policy(
            net_ns, iface_id, dst, iface.mtu(), mode,
        );
        self.xmit_ipv4_l4_with_policy(
            iface_id, iface, next_hop, src, dst, IpProto::Tcp, l4, tos,
            crate::ipv4::IPV4_DEFAULT_TTL, self.next_ipv4_id(), mtu, df, may_fragment,
        )
    }

    /// Build and transmit UDP/IPv4 using Linux `IP_MTU_DISCOVER` policy. # C: O(payload + N)
    pub fn send_udp_pmtu_to_bound_opts(&self, src: Ipv4Addr, src_port: u16,
        dst: Ipv4Addr, dst_port: u16, payload: &[u8], bound: Option<NetIfaceId>,
        tos: u8, ttl: u8, mode: i32) -> NetResult<()>
    {
        self.send_udp_pmtu_to_bound_opts_in(0, src, src_port, dst, dst_port, payload,
            bound, tos, ttl, mode)
    }

    /// Build and transmit UDP/IPv4 using one namespace's PMTU and routes. # C: O(payload + N)
    pub fn send_udp_pmtu_to_bound_opts_in(&self, net_ns: u64, src: Ipv4Addr, src_port: u16,
        dst: Ipv4Addr, dst_port: u16, payload: &[u8], bound: Option<NetIfaceId>,
        tos: u8, ttl: u8, mode: i32) -> NetResult<()> {
        let (iface_id, iface, next_hop) = self.route_v4_iface_in(net_ns, dst, bound)?;
        let (mtu, df, may_fragment) = self.ipv4_pmtu_policy(
            net_ns, iface_id, dst, iface.mtu(), mode,
        );
        let udp_len = crate::udp::UDP_HDR_LEN + payload.len();
        let mut packet = Pkt::with_capacity(0, udp_len);
        let udp = packet.put(udp_len).map_err(|_| NetError::Enobufs)?;
        UdpHdr::build_into(src_port, dst_port, src, dst, payload, udp);
        let id = { let mut next = self.next_ip_id.lock(); *next = next.wrapping_add(1); *next };
        self.xmit_ipv4_l4_with_policy(
            iface_id, iface, next_hop, src, dst, IpProto::Udp, packet.data(), tos, ttl, id,
            mtu, df, may_fragment,
        )
    }

    // F180b: send_l4 in stack_ipv6.rs.

    /// Demux IPv4 → ICMP/UDP/TCP. # C: O(payload)
    pub fn deliver_rx(&self, iface: NetIfaceId, l3: &[u8]) -> NetResult<()> {
        let lease = self.ifaces.acquire_ingress(iface).ok_or(NetError::Enodev)?;
        self.deliver_rx_in(&lease, l3)
    }

    /// Demux IPv4 under one immutable ingress ownership lease. # C: O(payload)
    pub fn deliver_rx_in(&self, lease: &crate::IngressLease, l3: &[u8]) -> NetResult<()> {
        let net_ns = lease.net_ns();
        let iface = lease.iface();
        // PRE_ROUTING fires on every received packet before the routing
        // decision. Non-local destinations are forwarded only when
        // `net.ipv4.ip_forward` enables router mode.
        if nf_hook_eval(NF_INET_PRE_ROUTING, l3, NFPROTO_IPV4) == 0 { return Ok(()); }
        let hdr = Ipv4Hdr::parse(l3).map_err(|_| NetError::Einval)?;
        if !self.ipv4_dst_is_local_in(net_ns, hdr.dst) {
            return self.forward_ipv4_in(net_ns, iface, l3);
        }
        if nf_hook_eval(NF_INET_LOCAL_IN, l3, NFPROTO_IPV4) == 0 { return Ok(()); }
        let total = hdr.total_len as usize;
        if total > l3.len() { return Err(NetError::Einval); }
        let frag_payload = &l3[hdr.ihl_bytes() .. total];
        let assembled;
        let mf = (hdr.flags_frag & 0x2000) != 0;
        let off8 = (hdr.flags_frag & 0x1FFF) as usize;
        let payload: &[u8] = if mf || off8 != 0 {
            self.deliver_raw4(net_ns, iface, &l3[..total], hdr, net_now_ns());
            let k = crate::ipv4_reasm::ReasmKey {
                net_ns, src: hdr.src, dst: hdr.dst, proto: hdr.proto, id: hdr.id,
            };
            match self.ipv4_reasm.push(k, net_now_ns(), off8 * 8, frag_payload, mf) {
                Some(b) => { assembled = b; &assembled[..] }
                None    => return Ok(()),
            }
        } else {
            self.deliver_raw4(net_ns, iface, &l3[..total], hdr, net_now_ns());
            frag_payload
        };
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
                    p.next_hop = Some(crate::pkt::TxNextHop::V4(hdr.src));
                    let dev = self.ifaces.acquire_egress_in_ns(iface, net_ns)
                        .ok_or(NetError::Enetunreach)?;
                    // ICMP echo reply is kernel-generated → LOCAL_OUT + POST_ROUTING.
                    if nf_output(&p, NFPROTO_IPV4) { dev.xmit(p)?; }
                } else if echo.typ == icmp::ICMP_TYPE_DEST_UNREACH
                    || echo.typ == icmp::ICMP_TYPE_TIME_EXC || echo.typ == 12
                {
                    self.handle_icmp_error(net_ns, iface, hdr.src, echo.typ, echo.code, payload);
                }
            }
            p if p == IpProto::Udp as u8 => {
                let udp = UdpHdr::parse(payload, hdr.src, hdr.dst)
                    .map_err(|_| NetError::Einval)?;
                // Clone the queue Arc out of the map then drop the
                // map lock before touching the queue itself. wake_all
                // takes the waitlist lock + runqueue inner; we must
                // not hold the udp-map lock across either.
                let endpoints = self.udp_demux_in(net_ns, hdr.src, udp.src_port, hdr.dst, udp.dst_port, iface);
                let has_v4 = !endpoints.is_empty();
                for q in endpoints {
                    if hdr.dst.is_multicast() {
                        if !q.mcast.accept_v4(iface, hdr.dst, hdr.src) { continue; }
                    }
                    let packet = &payload[..udp.length as usize];
                    let body = &packet[crate::udp::UDP_HDR_LEN..];
                    let Some(keep) = crate::bpf_filter::retained_payload_len(
                        q.bpf_filter.verdict_with_context(crate::bpf_filter::FilterContext {
                            packet, protocol: crate::addr::eth_p::IPV4,
                            ifindex: Some(iface.raw()),
                            pay_offset: crate::udp::UDP_HDR_LEN as u32,
                            hatype: self.ifaces.lookup_in_ns(iface, net_ns)
                                .map_or(0, |dev| dev.hardware_type()),
                        }), body.len(),
                    ) else { continue; };
                    let _ = q.enqueue((
                        hdr.src, udp.src_port, hdr.dst, iface, hdr.ttl, body[..keep].to_vec(),
                    ));
                }
                let endpoints6 = if !has_v4 || hdr.dst.is_multicast() || hdr.dst.is_broadcast() {
                    self.udp6_demux_v4_in(net_ns, hdr.src, udp.src_port, hdr.dst, udp.dst_port, iface)
                } else { Vec::new() };
                for q in endpoints6 {
                    let packet = &payload[..udp.length as usize];
                    let body = &packet[crate::udp::UDP_HDR_LEN..];
                    let Some(keep) = crate::bpf_filter::retained_payload_len(
                        q.bpf_filter.verdict_with_context(crate::bpf_filter::FilterContext {
                            packet, protocol: crate::addr::eth_p::IPV4,
                            ifindex: Some(iface.raw()),
                            pay_offset: crate::udp::UDP_HDR_LEN as u32,
                            hatype: self.ifaces.lookup_in_ns(iface, net_ns)
                                .map_or(0, |dev| dev.hardware_type()),
                        }), body.len(),
                    ) else { continue; };
                    let _ = q.enqueue((
                        Ipv6Addr::from_v4_mapped(hdr.src), udp.src_port,
                        Ipv6Addr::from_v4_mapped(hdr.dst), iface, hdr.ttl, body[..keep].to_vec(),
                    ));
                }
            }
            p if p == IpProto::Tcp as u8 =>
                self.deliver_tcp(net_ns, iface, IpAddr::V4(hdr.src), IpAddr::V4(hdr.dst), payload)?,
            p if p == IpProto::Igmp as u8 => {
                if hdr.ttl == 1 && ipv4_has_router_alert(&l3[IPV4_HDR_LEN..hdr.ihl_bytes()]) {
                    self.handle_igmp(iface, hdr.src, hdr.dst, payload)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Drain lo xmit → deliver_rx; v6 frames route to deliver_rx_ipv6.
    /// # C: O(N pending)
    pub fn drain_loopback(&self, iface: NetIfaceId, lo: &LoopbackDev) {
        let Some(lease) = self.ifaces.acquire_ingress(iface) else { return };
        self.drain_loopback_in(&lease, lo);
    }

    /// Drain one loopback queue under its exact admitted interface generation. # C: O(N pending)
    pub(crate) fn drain_loopback_in(&self, lease: &crate::IngressLease, lo: &LoopbackDev) {
        while let Some(p) = lo.rx_pop() {
            #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
            crate::sock::deliver_packet_loopback_in(lease, p.data(), p.proto);
            // F180b: dispatch by ethertype so v6 lo round-trips work.
            let delivered = if p.proto == crate::addr::eth_p::IPV6 {
                self.deliver_rx_ipv6_in(lease, p.data())
            } else {
                self.deliver_rx_in(lease, p.data())
            };
            if delivered.is_err() { lo.record_rx_error(); }
        }
    }
}

fn ipv4_has_router_alert(options: &[u8]) -> bool {
    let mut offset = 0usize;
    while offset < options.len() {
        match options[offset] {
            0 => return false,
            1 => { offset += 1; }
            typ => {
                if offset + 2 > options.len() { return false; }
                let len = options[offset + 1] as usize;
                if len < 2 || offset + len > options.len() { return false; }
                if typ == 0x94 && len == 4 && options[offset + 2] == 0
                    && options[offset + 3] == 0 { return true; }
                offset += len;
            }
        }
    }
    false
}
