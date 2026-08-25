use super::*;

mod tx;

impl NetStack {

    /// Demux IPv4 → ICMP/UDP/TCP. # C: O(payload)
    pub fn deliver_rx(&self, iface: NetIfaceId, l3: &[u8]) -> NetResult<()> {
        let lease = self.ifaces.acquire_ingress(iface).ok_or(NetError::Enodev)?;
        self.deliver_rx_in(&lease, l3)
    }

    /// Demux IPv4 under one immutable ingress ownership lease. # C: O(payload)
    pub fn deliver_rx_in(&self, lease: &crate::IngressLease, l3: &[u8]) -> NetResult<()> {
        let net_ns = lease.net_ns();
        let iface = lease.iface();
        let Some((reassembled, frag_max)) = account_ingress_copy(net_ns,
            self.ipv4_nf_defrag_ingress(net_ns, iface, l3))?
            else { return Ok(()); };
        let mut ingress_pkt = Pkt::from_owned(reassembled);
        // PRE_ROUTING fires on every received packet before the routing
        // decision. Non-local destinations are forwarded only when
        // `net.ipv4.ip_forward` enables router mode.
        let pre_routing = crate::netfilter_hook::nf_hook_packet_in(
            net_ns, NF_INET_PRE_ROUTING, &mut ingress_pkt, NFPROTO_IPV4, Some(iface), 0);
        if !pre_routing.accepted() { return Ok(()); }
        let l3 = ingress_pkt.data();
        crate::mib::bump(net_ns, crate::mib::Mib::IpInReceives);
        let hdr = Ipv4Hdr::parse(l3).map_err(|e| {
            crate::mib::bump(net_ns, crate::mib::Mib::IpInHdrErrors);
            let _ = e; NetError::Einval
        })?;
        if hdr.dst.is_multicast()
            && !self.v4_mcast_owned_by(net_ns, iface, hdr.dst, hdr.src, hdr.proto)
        { return Ok(()); }
        if !self.ipv4_dst_is_local_mark_in(net_ns, hdr.dst, pre_routing.mark) {
            crate::mib::bump(net_ns, crate::mib::Mib::IpForwDatagrams);
            return self.forward_ipv4_mark_in(net_ns, iface, l3, pre_routing.mark, Some(&ingress_pkt));
        }
        if !crate::netfilter_hook::nf_hook_packet_in(
            net_ns, NF_INET_LOCAL_IN, &mut ingress_pkt, NFPROTO_IPV4, Some(iface), pre_routing.mark).accepted() { return Ok(()); }
        let l3 = ingress_pkt.data();
        let tproxy = ingress_pkt.tproxy_target().and_then(|target| {
            (target.addr.0[4..] == [0; 12]).then(|| (
                if target.addr.0[..4] == [0; 4] { hdr.dst } else {
                    Ipv4Addr::new(target.addr.0[0], target.addr.0[1],
                        target.addr.0[2], target.addr.0[3])
                }, target.port))
        });
        let total = hdr.total_len as usize;
        if total > l3.len() { return Err(NetError::Einval); }
        // A delivered header's option area is compiled and PAID before
        // anything sees it, and an area that does not compile is a header
        // error. The filled area then replaces the received one, so a raw
        // receiver and the area IP_RETOPTS echoes carry the same bytes.
        let rx_options = crate::ipv4_options::rx::delivered(
            net_ns, iface, hdr.dst, &l3[IPV4_HDR_LEN..hdr.ihl_bytes()])
            .map_err(|_| NetError::Einval)?;
        let filled;
        let l3: &[u8] = if rx_options.data != l3[IPV4_HDR_LEN..hdr.ihl_bytes()] {
            let mut v = l3.to_vec();
            v[IPV4_HDR_LEN..hdr.ihl_bytes()].copy_from_slice(&rx_options.data);
            filled = v;
            &filled[..]
        } else { l3 };
        let raw_delivered = self.deliver_raw4(net_ns, iface, &l3[..total], hdr, net_now_ns(), &rx_options);
        let payload = &l3[hdr.ihl_bytes() .. total];
        let full_packet = &l3[..total];
        match hdr.proto {
            p if p == IpProto::Icmp as u8 => {
                crate::mib::bump(net_ns, crate::mib::Mib::IpInDelivers);
                crate::mib::bump(net_ns, crate::mib::Mib::IcmpInMsgs);
                let echo = match icmp::IcmpEcho::parse(payload) {
                    Ok(h) => h,
                    Err(_) => {
                        crate::mib::bump(net_ns, crate::mib::Mib::IcmpInErrors);
                        return Ok(());
                    }
                };
                // Both arms name the constant through its owning module. An
                // unqualified name that is not in scope is a binding pattern,
                // not a comparison: it matches every value, shadows the
                // scrutinee, and makes the arms after it unreachable.
                match echo.typ {
                    icmp::ICMP_TYPE_ECHO_REQUEST =>
                        crate::mib::bump(net_ns, crate::mib::Mib::IcmpInEchos),
                    icmp::ICMP_TYPE_ECHO_REPLY =>
                        crate::mib::bump(net_ns, crate::mib::Mib::IcmpInEchoReps),
                    _ => {}
                }
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
                    if nf_output(&mut p, NFPROTO_IPV4) { dev.xmit(p)?; }
                } else if crate::ping::is_reply(crate::ping::PingFamily::V4, echo.typ) {
                    let hatype = self.ifaces.lookup_in_ns(iface, net_ns)
                        .map_or(0, |dev| dev.hardware_type());
                    self.deliver_ping_v4(net_ns, iface, &hdr, payload, full_packet, hatype,
                        &rx_options);
                } else if echo.typ == icmp::ICMP_TYPE_DEST_UNREACH
                    || echo.typ == icmp::ICMP_TYPE_TIME_EXC || echo.typ == 12
                {
                    self.handle_icmp_error(net_ns, iface, hdr.src, echo.typ, echo.code, payload);
                }
            }
            p if p == IpProto::Udp as u8 => {
                crate::mib::bump(net_ns, crate::mib::Mib::IpInDelivers);
                crate::mib::bump(net_ns, crate::mib::Mib::UdpInDatagrams);
                let rx = crate::udp::parse_rx(payload, hdr.src, hdr.dst)
                    .map_err(|_| {
                        crate::mib::bump(net_ns, crate::mib::Mib::UdpInErrors);
                        NetError::Einval
                    })?;
                let udp = rx.hdr;
                // Clone the queue Arc out of the map then drop the
                // map lock before touching the queue itself. wake_all
                // takes the waitlist lock + runqueue inner; we must
                // not hold the udp-map lock across either.
                // A reuseport selection program sees the datagram from its
                // transport header, so resolve it once before the demux
                // rather than per selected endpoint.
                let datagram = payload.get(..udp.length as usize).unwrap_or(payload);
                let (demux_dst, demux_port) = tproxy
                    .map(|(dst, port)| (dst, if port == 0 { udp.dst_port } else { port }))
                    .unwrap_or((hdr.dst, udp.dst_port));
                let endpoints = self.udp_demux_in(net_ns, hdr.src, udp.src_port, demux_dst,
                    demux_port, iface, datagram);
                let hatype = self.ifaces.lookup_in_ns(iface, net_ns)
                    .map_or(0, |dev| dev.hardware_type());
                let gro_offered = crate::udp_gro::device_offers_gro(hatype);
                let has_v4 = !endpoints.is_empty();
                for q in endpoints {
                    if hdr.dst.is_multicast() {
                        if !q.mcast.accept_v4(iface, hdr.dst, hdr.src) { continue; }
                    }
                    if !crate::cgroup_bpf::ingress(
                        &q.owner, full_packet, crate::addr::eth_p::IPV4, iface,
                    ) { continue; }
                    let packet = &payload[..udp.length as usize];
                    let body = &packet[crate::udp::UDP_HDR_LEN..];
                    // Linux runs the socket's installed `UDP_ENCAP` receive
                    // handler before the datagram is queued: a handler that
                    // takes the datagram (NAT keepalive, encapsulated
                    // security payload) leaves the socket with nothing to
                    // read, while a key-exchange control packet falls through
                    // to ordinary delivery.
                    if crate::sock_opts::sol_udp::rx_verdict(
                        q.encap_type.load(::core::sync::atomic::Ordering::Acquire), body,
                    ).consumed() { continue; }
                    let Some(keep) = crate::bpf_filter::retained_payload_len(
                        q.bpf_filter.verdict_with_context(crate::bpf_filter::FilterContext {
                            packet, protocol: crate::addr::eth_p::IPV4,
                            ifindex: Some(iface.raw()),
                            pay_offset: crate::udp::UDP_HDR_LEN as u32,
                            hatype: self.ifaces.lookup_in_ns(iface, net_ns)
                                .map_or(0, |dev| dev.hardware_type()),
                        }), body.len(),
                    ) else { continue; };
                    let _ = q.enqueue_gro(crate::stack::UdpDatagram {
                        src: hdr.src, sport: udp.src_port, dst: hdr.dst,
                        dport: udp.dst_port, iface, ttl: hdr.ttl, tos: hdr.tos,
                        options: rx_options.clone(), frag_max,
                        dont_fragment: hdr.flags_frag & crate::ipv4::IPV4_FLAG_DONT_FRAGMENT != 0,
                        checksum: rx.complete,
                        payload: body[..keep].to_vec(),
                    }, udp.checksum == 0, gro_offered);
                }
                let endpoints6 = if !has_v4 || hdr.dst.is_multicast() || hdr.dst.is_broadcast() {
                    self.udp6_demux_v4_in(net_ns, hdr.src, udp.src_port, hdr.dst, udp.dst_port,
                        iface, datagram)
                } else { Vec::new() };
                let has_v6 = !endpoints6.is_empty();
                for q in endpoints6 {
                    if !crate::cgroup_bpf::ingress(
                        &q.owner, full_packet, crate::addr::eth_p::IPV4, iface,
                    ) { continue; }
                    let packet = &payload[..udp.length as usize];
                    let body = &packet[crate::udp::UDP_HDR_LEN..];
                    // Linux runs the socket's installed `UDP_ENCAP` receive
                    // handler before the datagram is queued: a handler that
                    // takes the datagram (NAT keepalive, encapsulated
                    // security payload) leaves the socket with nothing to
                    // read, while a key-exchange control packet falls through
                    // to ordinary delivery.
                    if crate::sock_opts::sol_udp::rx_verdict(
                        q.encap_type.load(::core::sync::atomic::Ordering::Acquire), body,
                    ).consumed() { continue; }
                    let Some(keep) = crate::bpf_filter::retained_payload_len(
                        q.bpf_filter.verdict_with_context(crate::bpf_filter::FilterContext {
                            packet, protocol: crate::addr::eth_p::IPV4,
                            ifindex: Some(iface.raw()),
                            pay_offset: crate::udp::UDP_HDR_LEN as u32,
                            hatype: self.ifaces.lookup_in_ns(iface, net_ns)
                                .map_or(0, |dev| dev.hardware_type()),
                        }), body.len(),
                    ) else { continue; };
                    let _ = q.enqueue_gro(crate::stack_ipv6::Udp6Datagram {
                        src: Ipv6Addr::from_v4_mapped(hdr.src), sport: udp.src_port,
                        dst: Ipv6Addr::from_v4_mapped(hdr.dst), dport: udp.dst_port,
                        iface, hop_limit: hdr.ttl, traffic_class: hdr.tos,
                        flowinfo: 0, ext_headers: alloc::vec::Vec::new(), frag_max,
                        ipv4: Some(crate::stack_ipv6::MappedIpv4Ancillary {
                            src: hdr.src, dst: hdr.dst, ttl: hdr.ttl, tos: hdr.tos,
                            options: rx_options.clone(),
                        }),
                        checksum: rx.complete,
                        payload: body[..keep].to_vec(),
                    }, udp.checksum == 0, gro_offered);
                }
                // Linux answers an otherwise valid unicast UDP datagram for
                // which no IPv4 or v4-mapped IPv6 endpoint exists with ICMP
                // destination-unreachable/port-unreachable. Loopback takes
                // the same queued transmit path as every other interface, so
                // the quoted packet is subsequently demultiplexed back to the
                // originating socket's IP_RECVERR queue.
                if !has_v4 && !has_v6 && !hdr.dst.is_multicast() && !hdr.dst.is_broadcast() {
                    crate::mib::bump(net_ns, crate::mib::Mib::UdpNoPorts);
                    self.send_ipv4_error(iface, hdr.dst, hdr.src,
                        icmp::ICMP_TYPE_DEST_UNREACH, icmp::unreach_code::PORT, full_packet)?;
                }
            }
            p if p == IpProto::Tcp as u8 => {
                crate::mib::bump(net_ns, crate::mib::Mib::IpInDelivers);
                crate::mib::bump(net_ns, crate::mib::Mib::TcpInSegs);
                self.deliver_tcp_packet_hop(net_ns, iface, IpAddr::V4(hdr.src), IpAddr::V4(hdr.dst),
                    payload, full_packet, hdr.ttl, ingress_pkt.tproxy_target())?
            }
            p if p == IpProto::Igmp as u8 => {
                crate::mib::bump(net_ns, crate::mib::Mib::IpInDelivers);
                if hdr.ttl == 1 && ipv4_has_router_alert(&l3[IPV4_HDR_LEN..hdr.ihl_bytes()]) {
                    self.handle_igmp(lease, hdr.src, hdr.dst, payload)?;
                }
            }
            _ if raw_delivered => crate::mib::bump(net_ns, crate::mib::Mib::IpInDelivers),
            _ => {
                crate::mib::bump(net_ns, crate::mib::Mib::IpInUnknownProtos);
                self.send_ipv4_error(iface, hdr.dst, hdr.src, icmp::ICMP_TYPE_DEST_UNREACH,
                    icmp::unreach_code::PROTOCOL, full_packet)?;
            }
        }
        Ok(())
    }

    /// Receive processing for one dequeued loopback frame, under its exact
    /// admitted interface generation. The sole delivery body: both the NET_RX
    /// backlog drain and the hosted fixtures below reach protocol delivery
    /// through here and nowhere else.
    /// # Ctx: NET_RX bottom half
    /// # C: O(1) + protocol delivery
    pub(crate) fn deliver_loopback_pkt_in(&self, lease: &crate::IngressLease, p: Pkt) {
        #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
        if p.mac_frame().is_none() {
            crate::sock::deliver_packet_loopback_in(lease, p.data(), p.proto);
        }
        // F180b: dispatch by ethertype so v6 lo round-trips work.
        let delivered = if p.proto == crate::addr::eth_p::IPV6 {
            self.deliver_rx_ipv6_in(lease, p.data())
        } else {
            self.deliver_rx_in(lease, p.data())
        };
        if delivered.is_err() { lease.device().record_rx_error(); }
    }

    /// Hosted fixture: enqueue everything a loopback holds and run the drain to
    /// completion, synchronously, against this stack.
    ///
    /// Test-build only. In a running kernel there is exactly one route from a
    /// queued frame to protocol delivery — raise NET_RX and let the bottom half
    /// take it (`backlog::net_rx_schedule`) — and a second, synchronous route
    /// compiled into the kernel is what the ledger row this replaced was about:
    /// it puts the whole receive subtree back on the caller's stack.
    /// # C: O(N pending)
    #[cfg(any(test, feature = "hosted"))]
    pub fn drain_loopback(&self, iface: NetIfaceId, lo: &LoopbackDev) {
        while let Some(p) = lo.rx_pop() {
            if self.netif_rx(iface, p) == crate::backlog::RxVerdict::Drop {
                lo.record_rx_dropped();
            }
        }
        while self.do_net_rx() {}
    }

    /// Hosted fixture: drain one loopback queue under a caller-supplied lease.
    /// Test-build only, for the same reason as [`Self::drain_loopback`].
    /// # C: O(N pending)
    #[cfg(any(test, feature = "hosted"))]
    pub(crate) fn drain_loopback_in(&self, lease: &crate::IngressLease, lo: &LoopbackDev) {
        while let Some(p) = lo.rx_pop() { self.deliver_loopback_pkt_in(lease, p); }
    }
}

fn account_ingress_copy<T>(net_ns: u64, result: NetResult<T>) -> NetResult<T> {
    if matches!(result, Err(NetError::Enobufs)) {
        crate::mib::bump(net_ns, crate::mib::Mib::IpInDiscards);
    }
    result
}

#[cfg(test)]
mod discard_tests {
    use super::*;

    #[test]
    fn exhausted_ipv4_copy_is_counted_as_an_input_discard() {
        const NS: u64 = 0x837;
        crate::mib::forget(NS);
        assert_eq!(account_ingress_copy(NS, Err::<(), _>(NetError::Enobufs)), Err(NetError::Enobufs));
        assert_eq!(crate::mib::get(NS, crate::mib::Mib::IpInDiscards), 1);
        crate::mib::forget(NS);
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
