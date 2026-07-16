use crate::addr::{IpAddr, IpProto, Ipv6Addr, NetIfaceId};
use crate::ipv6::Ipv6Hdr;
use crate::netdev::NetResult;
use crate::stack::NetStack;
use crate::stack_ipv6::Udp6RxQueue;
use crate::ndp;
use crate::netfilter_hook::{nf_hook_eval, NFPROTO_IPV6, NF_INET_LOCAL_IN, NF_INET_PRE_ROUTING};

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
        if nf_hook_eval(NF_INET_PRE_ROUTING, l3, NFPROTO_IPV6) == 0 {
            return Ok(());
        }
        let hdr = Ipv6Hdr::parse(l3).map_err(|_| crate::netdev::NetError::Einval)?;
        if !self.v6_dst_is_local_in(net_ns, iface, hdr.dst) { return Ok(()); }
        if nf_hook_eval(NF_INET_LOCAL_IN, l3, NFPROTO_IPV6) == 0 { return Ok(()); }
        let payload_end = crate::ipv6::IPV6_HDR_LEN + hdr.payload_length as usize;
        if payload_end > l3.len() {
            return Err(crate::netdev::NetError::Einval);
        }
        let payload = &l3[crate::ipv6::IPV6_HDR_LEN..payload_end];
        let mld_router_alert = hbh_has_mld_router_alert(hdr.next_header, payload);
        let assembled;
        let (next_header, payload) = match crate::ipv6_ext::walk(hdr.next_header, payload)
            .map_err(|_| crate::netdev::NetError::Einval)?
        {
            crate::ipv6_ext::ExtWalk::Done { next_header, payload } => (next_header, payload),
            crate::ipv6_ext::ExtWalk::Fragment {
                next_header,
                offset,
                more,
                id,
                payload,
            } => {
                let k = crate::ipv6_reasm::ReasmKey {
                    net_ns,
                    src: hdr.src,
                    dst: hdr.dst,
                    next_header,
                    id,
                };
                match self.ipv6_reasm.push(k, crate::stack::net_now_ns(), offset, payload, more) {
                    Some(bytes) => {
                        assembled = bytes;
                        match crate::ipv6_ext::walk(next_header, &assembled[..])
                            .map_err(|_| crate::netdev::NetError::Einval)?
                        {
                            crate::ipv6_ext::ExtWalk::Done { next_header, payload } => {
                                (next_header, payload)
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
            net_ns, iface, hdr.src, hdr.dst, hdr.hop_limit, hdr.traffic_class,
            hdr.flow_label, mld_router_alert, next_header, payload,
        )
    }

    fn v6_dst_is_local_in(&self, net_ns: u64, iface: NetIfaceId, ip: Ipv6Addr) -> bool {
        if ip.is_multicast() || ip.is_link_local() { return self.v6_dst_is_local(iface, ip); }
        self.v6_addrs.lock().iter().any(|(id, addrs)| {
            self.ifaces.lookup_in_ns(*id, net_ns).is_some()
                && addrs.iter().any(|addr| addr.addr == ip && addr.usable_at(self.ra_now_ns()))
        })
    }

    fn deliver_rx_ipv6_payload(
        &self,
        net_ns: u64,
        iface: NetIfaceId,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        hop_limit: u8,
        traffic_class: u8,
        flow_label: u32,
        mld_router_alert: bool,
        next_header: u8,
        payload: &[u8],
    ) -> NetResult<()> {
        let hatype = self.ifaces.lookup_in_ns(iface, net_ns)
            .map_or(0, |dev| dev.hardware_type());
        for endpoint in self.inet_tables(net_ns).raw6.endpoints(next_header) {
            let _ = endpoint.receive(crate::raw6::Raw6RxPacket {
                net_ns, protocol: next_header, src, dst, iface, hop_limit,
                traffic_class, flow_label, hatype, payload,
            });
        }
        match next_header {
            n if n == IpProto::Icmpv6 as u8 => {
                self.deliver_rx_icmpv6(
                    net_ns, iface, src, dst, hop_limit, mld_router_alert, payload,
                )?;
            }
            n if n == IpProto::Udp as u8 => {
                let udp = match crate::udp::parse_v6(payload, src, dst) {
                    Ok(h) => h,
                    Err(_) => return Ok(()),
                };
                let endpoints = self.udp6_demux_in(net_ns, src, udp.src_port, dst, udp.dst_port, iface);
                for q in endpoints {
                    let packet = &payload[..udp.length as usize];
                    let body = &packet[crate::udp::UDP_HDR_LEN..];
                    let Some(keep) = crate::bpf_filter::retained_payload_len(
                        q.bpf_filter.verdict_with_context(crate::bpf_filter::FilterContext {
                            packet, protocol: crate::addr::eth_p::IPV6,
                            ifindex: Some(iface.raw()),
                            pay_offset: crate::udp::UDP_HDR_LEN as u32,
                            hatype: self.ifaces.lookup_in_ns(iface, net_ns)
                                .map_or(0, |dev| dev.hardware_type()),
                        }), body.len(),
                    ) else { continue; };
                    let _ = q.enqueue((
                        src, udp.src_port, dst, iface, hop_limit, body[..keep].to_vec(),
                    ));
                }
            }
            n if n == IpProto::Tcp as u8 => {
                let src = IpAddr::V6(src);
                let dst = IpAddr::V6(dst);
                let _ = self.deliver_tcp(net_ns, iface, src, dst, payload);
            }
            _ => {}
        }
        Ok(())
    }

    fn deliver_rx_icmpv6(
        &self,
        net_ns: u64,
        iface: NetIfaceId,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        hop_limit: u8,
        mld_router_alert: bool,
        payload: &[u8],
    ) -> NetResult<()> {
        if payload.len() < crate::icmpv6::ICMPV6_HDR_LEN
            || !icmpv6_checksum_valid(payload, src, dst)
        {
            return Ok(());
        }
        let typ = payload[0];
        if matches!(typ, ICMPV6_TYPE_DEST_UNREACHABLE | ICMPV6_TYPE_TIME_EXCEEDED
            | ICMPV6_TYPE_PARAMETER_PROBLEM | crate::icmpv6::ICMPV6_TYPE_PACKET_TOO_BIG)
        {
            let info = if typ == crate::icmpv6::ICMPV6_TYPE_PACKET_TOO_BIG {
                u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]])
            } else { 0 };
            self.deliver_raw6_error(net_ns, iface, src, typ, payload[1], info, &payload[8..]);
        }
        match typ {
            t if t == ICMPV6_TYPE_DEST_UNREACHABLE => {
                self.handle_v6_dest_unreachable(net_ns, iface, src, payload[1], &payload[8..]);
            }
            t if t == ICMPV6_TYPE_TIME_EXCEEDED => {
                self.handle_v6_simple_error(net_ns, iface, src, t, payload[1], &payload[8..]);
            }
            t if t == ICMPV6_TYPE_PARAMETER_PROBLEM => {
                self.handle_v6_simple_error(net_ns, iface, src, t, payload[1], &payload[8..]);
            }
            t if t == crate::icmpv6::ICMPV6_TYPE_PACKET_TOO_BIG => {
                if payload.len() >= 8 + crate::ipv6::IPV6_HDR_LEN + 4 {
                    let mtu = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
                    let invoking = &payload[8..];
                    let mut update_cache = true;
                    if let Some((local, lport, remote, rport, body)) = quoted_udp6(invoking) {
                        if let Some(endpoint) = self.udp6_error_endpoint(
                            net_ns, iface, local, lport, remote, rport,
                        ) {
                            let mode = endpoint.ipv6_mtu_discover
                                .load(core::sync::atomic::Ordering::Acquire);
                            let accept_pmtu = mode != crate::uapi::IPV6_PMTUDISC_INTERFACE
                                && mode != crate::uapi::IPV6_PMTUDISC_OMIT;
                            update_cache = accept_pmtu;
                            if accept_pmtu {
                                let (errno, _) = icmpv6_error(crate::icmpv6::ICMPV6_TYPE_PACKET_TOO_BIG, 0);
                                endpoint.publish_error(crate::SocketErrorEntry {
                                    errno,
                                    origin: crate::socket_error::SO_EE_ORIGIN_ICMP6,
                                    kind: crate::icmpv6::ICMPV6_TYPE_PACKET_TOO_BIG,
                                    code: 0, info: mtu, data: 0,
                                    offender: IpAddr::V6(src),
                                    destination: IpAddr::V6(remote), destination_port: rport,
                                    ifindex: iface.raw(),
                                    payload: body.to_vec(),
                                }, mode != crate::uapi::IPV6_PMTUDISC_DONT);
                            }
                        }
                    } else {
                        self.handle_v6_packet_too_big(net_ns, mtu, invoking);
                    }
                    if update_cache {
                        if let Ok(invoking_hdr) = crate::ipv6::Ipv6Hdr::parse(invoking) {
                            self.update_pmtu_v6_in(net_ns, iface, invoking_hdr.dst, mtu);
                        }
                    }
                }
            }
            t if t == crate::icmpv6::ICMPV6_TYPE_ECHO_REQUEST => {
                let reply = match crate::icmpv6::build_echo_reply(src, dst, payload) {
                    Ok(r) => r,
                    Err(_) => return Ok(()),
                };
                self.xmit_ipv6(iface, dst, src, IpProto::Icmpv6, &reply)?;
            }
            t if t == crate::icmpv6::ICMPV6_TYPE_MLD_QUERY => {
                if src.is_link_local() && hop_limit == 1 && mld_router_alert {
                    if let Ok(q) = crate::icmpv6::Mldv1Query::parse(payload, src, dst) {
                        self.respond_mld_query(iface, dst, q, payload.len() == 24)?;
                    }
                }
            }
            t if t == ndp::NDP_NS => {
                if hop_limit == u8::MAX && payload[1] == 0 {
                  if let Ok(msg) = ndp::NdpMsg::parse(payload, src, dst) {
                    self.dad_duplicate_ingress(iface, msg.target);
                    if let Some(mac) = msg.lladdr {
                        self.ndp_insert(iface, src, mac);
                    }
                    if self.v6_addr_owned_by(iface, msg.target) {
                        let our_mac = self
                            .ifaces
                            .lookup_in_ns(iface, net_ns)
                            .map(|d| d.mac())
                            .unwrap_or(crate::addr::MacAddr::ZERO);
                        if src.is_unspecified() {
                            let na = ndp::NdpMsg::build_dad_defense_na(
                                msg.target, our_mac, msg.target);
                            self.xmit_ipv6(iface, msg.target, ndp::IPV6_ALL_NODES,
                                IpProto::Icmpv6, &na)?;
                        } else {
                            let na = ndp::NdpMsg::build_na(msg.target, src, our_mac,
                                msg.target, ndp::NDP_NA_FLAG_OVERRIDE);
                            self.xmit_ipv6(iface, msg.target, src, IpProto::Icmpv6, &na)?;
                        }
                    }
                  }
                }
            }
            t if t == ndp::NDP_NA => {
                if hop_limit == u8::MAX && payload[1] == 0 {
                  if let Ok(msg) = ndp::NdpMsg::parse(payload, src, dst) {
                    self.dad_duplicate_ingress(iface, msg.target);
                    if let Some(mac) = msg.lladdr {
                        self.ndp_insert(iface, msg.target, mac);
                    }
                  }
                }
            }
            t if t == ndp::NDP_RA => {
                if hop_limit == u8::MAX && src.is_link_local() && payload[1] == 0 {
                    if let Ok(ra) = ndp::RouterAdvertisement::parse(payload, src, dst) {
                        self.queue_router_advertisement_ingress(net_ns, iface, src, ra);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_v6_dest_unreachable(&self, net_ns: u64, iface: NetIfaceId, offender: Ipv6Addr,
                                  code: u8, invoking: &[u8]) {
        let (errno, hard) = icmpv6_error(ICMPV6_TYPE_DEST_UNREACHABLE, code);
        let (src, sport, dst, dport, body) = match quoted_udp6(invoking) {
            Some(tuple) => tuple,
            None => return,
        };
        if let Some(endpoint) = self.udp6_error_endpoint(net_ns, iface, src, sport, dst, dport) {
            endpoint.publish_error(crate::SocketErrorEntry {
                errno, origin: crate::socket_error::SO_EE_ORIGIN_ICMP6,
                kind: ICMPV6_TYPE_DEST_UNREACHABLE, code, info: 0, data: 0,
                offender: IpAddr::V6(offender), destination: IpAddr::V6(dst),
                destination_port: dport, ifindex: iface.raw(), payload: body.to_vec(),
            }, hard);
        }
    }

    fn handle_v6_simple_error(&self, net_ns: u64, iface: NetIfaceId, offender: Ipv6Addr,
                              kind: u8, code: u8, invoking: &[u8]) {
        let (errno, hard) = icmpv6_error(kind, code);
        let Some((src, sport, dst, dport, body)) = quoted_udp6(invoking) else { return; };
        if let Some(endpoint) = self.udp6_error_endpoint(net_ns, iface, src, sport, dst, dport) {
            endpoint.publish_error(crate::SocketErrorEntry {
                errno, origin: crate::socket_error::SO_EE_ORIGIN_ICMP6,
                kind, code, info: 0, data: 0, offender: IpAddr::V6(offender),
                destination: IpAddr::V6(dst), destination_port: dport,
                ifindex: iface.raw(),
                payload: body.to_vec(),
            }, hard);
        }
    }

    fn udp6_error_endpoint(&self, net_ns: u64, iface: NetIfaceId, src: Ipv6Addr, sport: u16,
                           dst: Ipv6Addr, dport: u16) -> Option<alloc::sync::Arc<Udp6RxQueue>> {
        self.udp6_demux_in(net_ns, dst, dport, src, sport, iface).pop()
    }

    fn deliver_raw6_error(&self, net_ns: u64, iface: NetIfaceId, offender: Ipv6Addr,
                          kind: u8, code: u8, info: u32, invoking: &[u8]) {
        let Some((hdr, protocol, body)) = quoted_raw6(invoking) else { return };
        let (errno, hard) = icmpv6_error(kind, code);
        let entry = crate::SocketErrorEntry {
            errno, origin: crate::socket_error::SO_EE_ORIGIN_ICMP6,
            kind, code, info, data: 0, offender: IpAddr::V6(offender),
            destination: IpAddr::V6(hdr.dst), destination_port: 0,
            ifindex: iface.raw(), payload: body.to_vec(),
        };
        for endpoint in self.inet_tables(net_ns).raw6.endpoints(protocol) {
            if endpoint.matches_error(iface, hdr.src, hdr.dst) {
                endpoint.publish_error(entry.clone(), hard);
            }
        }
    }
}

fn hbh_has_mld_router_alert(next_header: u8, payload: &[u8]) -> bool {
    if next_header != 0 || payload.len() < 8 { return false; }
    let len = ((payload[1] as usize) + 1) * 8;
    if len > payload.len() { return false; }
    let mut offset = 2usize;
    while offset < len {
        let typ = payload[offset];
        if typ == 0 { offset += 1; continue; }
        if offset + 2 > len { return false; }
        let option_len = payload[offset + 1] as usize;
        if offset + 2 + option_len > len { return false; }
        if typ == 5 && option_len == 2 && payload[offset + 2] == 0
            && payload[offset + 3] == 0 { return true; }
        offset += 2 + option_len;
    }
    false
}

const ICMPV6_TYPE_DEST_UNREACHABLE: u8 = 1;
const ICMPV6_TYPE_TIME_EXCEEDED: u8 = 3;
const ICMPV6_TYPE_PARAMETER_PROBLEM: u8 = 4;
const ICMPV6_DEST_NO_ROUTE: u8 = 0;
const ICMPV6_DEST_ADMIN_PROHIBITED: u8 = 1;
const ICMPV6_DEST_BEYOND_SCOPE: u8 = 2;
const ICMPV6_DEST_ADDR_UNREACHABLE: u8 = 3;
const ICMPV6_DEST_PORT_UNREACHABLE: u8 = 4;
const ICMPV6_DEST_POLICY_FAIL: u8 = 5;
const ICMPV6_DEST_REJECT_ROUTE: u8 = 6;

fn icmpv6_error(kind: u8, code: u8) -> (i32, bool) {
    use syscall::errno::Errno;
    match (kind, code) {
        (ICMPV6_TYPE_DEST_UNREACHABLE, ICMPV6_DEST_NO_ROUTE) =>
            (Errno::Enetunreach as i32, false),
        (ICMPV6_TYPE_DEST_UNREACHABLE, ICMPV6_DEST_BEYOND_SCOPE)
        | (ICMPV6_TYPE_DEST_UNREACHABLE, ICMPV6_DEST_ADDR_UNREACHABLE) =>
            (Errno::Ehostunreach as i32, false),
        (ICMPV6_TYPE_DEST_UNREACHABLE, ICMPV6_DEST_ADMIN_PROHIBITED)
        | (ICMPV6_TYPE_DEST_UNREACHABLE, ICMPV6_DEST_POLICY_FAIL)
        | (ICMPV6_TYPE_DEST_UNREACHABLE, ICMPV6_DEST_REJECT_ROUTE) =>
            (Errno::Eacces as i32, true),
        (ICMPV6_TYPE_DEST_UNREACHABLE, ICMPV6_DEST_PORT_UNREACHABLE) =>
            (Errno::Econnrefused as i32, true),
        (ICMPV6_TYPE_TIME_EXCEEDED, _) => (Errno::Ehostunreach as i32, false),
        (ICMPV6_TYPE_PARAMETER_PROBLEM, _) => (Errno::Eproto as i32, true),
        (crate::icmpv6::ICMPV6_TYPE_PACKET_TOO_BIG, _) => (Errno::Emsgsize as i32, false),
        _ => (Errno::Eproto as i32, true),
    }
}

fn quoted_udp6(invoking: &[u8]) -> Option<(Ipv6Addr, u16, Ipv6Addr, u16, &[u8])> {
    let hdr = Ipv6Hdr::parse(invoking).ok()?;
    let payload = invoking.get(crate::ipv6::IPV6_HDR_LEN..)?;
    let l4 = match crate::ipv6_ext::walk(hdr.next_header, payload).ok()? {
        crate::ipv6_ext::ExtWalk::Done { next_header, payload }
            if next_header == IpProto::Udp as u8 => payload,
        crate::ipv6_ext::ExtWalk::Fragment { next_header, offset: 0, payload, .. } => {
            match crate::ipv6_ext::walk(next_header, payload).ok()? {
                crate::ipv6_ext::ExtWalk::Done { next_header, payload }
                    if next_header == IpProto::Udp as u8 => payload,
                _ => return None,
            }
        }
        _ => return None,
    };
    if l4.len() < crate::udp::UDP_HDR_LEN { return None; }
    Some((
        hdr.src,
        u16::from_be_bytes([l4[0], l4[1]]),
        hdr.dst,
        u16::from_be_bytes([l4[2], l4[3]]),
        &l4[crate::udp::UDP_HDR_LEN..],
    ))
}

fn quoted_raw6(invoking: &[u8]) -> Option<(Ipv6Hdr, u8, &[u8])> {
    let hdr = Ipv6Hdr::parse(invoking).ok()?;
    let payload = invoking.get(crate::ipv6::IPV6_HDR_LEN..)?;
    match crate::ipv6_ext::walk(hdr.next_header, payload).ok()? {
        crate::ipv6_ext::ExtWalk::Done { next_header, payload } =>
            Some((hdr, next_header, payload)),
        crate::ipv6_ext::ExtWalk::Fragment { next_header, offset: 0, payload, .. } => {
            match crate::ipv6_ext::walk(next_header, payload).ok()? {
                crate::ipv6_ext::ExtWalk::Done { next_header, payload } =>
                    Some((hdr, next_header, payload)),
                crate::ipv6_ext::ExtWalk::Fragment { .. } => None,
            }
        }
        crate::ipv6_ext::ExtWalk::Fragment { next_header, payload, .. } =>
            Some((hdr, next_header, payload)),
    }
}

fn quoted_udp6_tuple(invoking: &[u8]) -> Option<(Ipv6Addr, u16, Ipv6Addr, u16)> {
    quoted_udp6(invoking).map(|(src, sport, dst, dport, _)| (src, sport, dst, dport))
}

fn icmpv6_checksum_valid(payload: &[u8], src: Ipv6Addr, dst: Ipv6Addr) -> bool {
    fn add_bytes(mut sum: u32, bytes: &[u8]) -> u32 {
        let mut chunks = bytes.chunks_exact(2);
        for word in &mut chunks {
            sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
        }
        if let Some(byte) = chunks.remainder().first() { sum += u32::from(*byte) << 8; }
        sum
    }
    let mut sum = add_bytes(0, &src.0);
    sum = add_bytes(sum, &dst.0);
    sum += (payload.len() as u32 >> 16) + (payload.len() as u32 & 0xffff);
    sum += u32::from(IpProto::Icmpv6 as u8);
    sum = add_bytes(sum, payload);
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16); }
    sum == 0xffff
}
