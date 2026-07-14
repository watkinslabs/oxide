use crate::addr::{IpAddr, IpProto, Ipv6Addr, NetIfaceId};
use crate::ipv6::Ipv6Hdr;
use crate::netdev::NetResult;
use crate::stack::NetStack;
use crate::stack_ipv6::Udp6RxQueue;
use crate::ndp;
use crate::netfilter_hook::{nf_hook_eval, NFPROTO_IPV6, NF_INET_LOCAL_IN, NF_INET_PRE_ROUTING};

impl NetStack {
    pub fn deliver_rx_ipv6(&self, iface: NetIfaceId, l3: &[u8]) -> NetResult<()> {
        if nf_hook_eval(NF_INET_PRE_ROUTING, l3, NFPROTO_IPV6) == 0 {
            return Ok(());
        }
        let hdr = Ipv6Hdr::parse(l3).map_err(|_| crate::netdev::NetError::Einval)?;
        if !self.v6_dst_is_local(iface, hdr.dst) { return Ok(()); }
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
            iface, hdr.src, hdr.dst, hdr.hop_limit, mld_router_alert, next_header, payload,
        )
    }

    fn deliver_rx_ipv6_payload(
        &self,
        iface: NetIfaceId,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        hop_limit: u8,
        mld_router_alert: bool,
        next_header: u8,
        payload: &[u8],
    ) -> NetResult<()> {
        match next_header {
            n if n == IpProto::Icmpv6 as u8 => {
                self.deliver_rx_icmpv6(
                    iface, src, dst, hop_limit, mld_router_alert, payload,
                )?;
            }
            n if n == IpProto::Udp as u8 => {
                let udp = match crate::udp::parse_v6(payload, src, dst) {
                    Ok(h) => h,
                    Err(_) => return Ok(()),
                };
                let endpoints = self.udp6_demux(src, udp.src_port, dst, udp.dst_port, iface);
                for q in endpoints {
                    let packet = &payload[..udp.length as usize];
                    let body = &packet[crate::udp::UDP_HDR_LEN..];
                    let Some(keep) = crate::bpf_filter::retained_payload_len(
                        q.bpf_filter.verdict(packet), body.len(),
                    ) else { continue; };
                    let _ = q.enqueue((
                        src, udp.src_port, dst, iface, hop_limit, body[..keep].to_vec(),
                    ));
                }
            }
            n if n == IpProto::Tcp as u8 => {
                let src = IpAddr::V6(src);
                let dst = IpAddr::V6(dst);
                let _ = self.deliver_tcp(iface, src, dst, payload);
            }
            _ => {}
        }
        Ok(())
    }

    fn deliver_rx_icmpv6(
        &self,
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
        match typ {
            t if t == ICMPV6_TYPE_DEST_UNREACHABLE => {
                self.handle_v6_dest_unreachable(iface, src, payload[1], &payload[8..]);
            }
            t if t == ICMPV6_TYPE_TIME_EXCEEDED => {
                self.handle_v6_simple_error(iface, src, t, payload[1], &payload[8..]);
            }
            t if t == ICMPV6_TYPE_PARAMETER_PROBLEM => {
                self.handle_v6_simple_error(iface, src, t, payload[1], &payload[8..]);
            }
            t if t == crate::icmpv6::ICMPV6_TYPE_PACKET_TOO_BIG => {
                if payload.len() >= 8 + crate::ipv6::IPV6_HDR_LEN + 4 {
                    let mtu = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
                    let invoking = &payload[8..];
                    let mut update_cache = true;
                    if let Some((local, lport, remote, rport, body)) = quoted_udp6(invoking) {
                        if let Some(endpoint) = self.udp6_error_endpoint(
                            iface, local, lport, remote, rport,
                        ) {
                            let mode = endpoint.ipv6_mtu_discover
                                .load(core::sync::atomic::Ordering::Acquire);
                            update_cache = mode != crate::uapi::IPV6_PMTUDISC_INTERFACE
                                && mode != crate::uapi::IPV6_PMTUDISC_OMIT;
                            endpoint.publish_error(crate::SocketErrorEntry {
                                errno: syscall::errno::Errno::Emsgsize as i32,
                                origin: crate::socket_error::SO_EE_ORIGIN_ICMP6,
                                kind: crate::icmpv6::ICMPV6_TYPE_PACKET_TOO_BIG,
                                code: 0, info: mtu, data: 0,
                                offender: IpAddr::V6(src),
                                destination: IpAddr::V6(remote), destination_port: rport,
                                ifindex: iface.raw(),
                                payload: body.to_vec(),
                            }, true);
                        }
                    } else {
                        self.handle_v6_packet_too_big(mtu, invoking);
                    }
                    if update_cache {
                        if let Ok(invoking_hdr) = crate::ipv6::Ipv6Hdr::parse(invoking) {
                            self.update_pmtu_v6(iface, invoking_hdr.dst, mtu);
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
                if hop_limit == 1 && mld_router_alert {
                    if let Ok(q) = crate::icmpv6::Mldv1Query::parse(payload, src, dst) {
                        self.respond_mld_query(iface, q, payload.len() == 24)?;
                    }
                }
            }
            t if t == ndp::NDP_NS => {
                if let Ok(msg) = ndp::NdpMsg::parse(payload, src, dst) {
                    if let Some(mac) = msg.lladdr {
                        self.ndp_insert(iface, src, mac);
                    }
                    if self.v6_addr_owned_by(iface, msg.target) {
                        let our_mac = self
                            .ifaces
                            .lookup(iface)
                            .map(|d| d.mac())
                            .unwrap_or(crate::addr::MacAddr::ZERO);
                        let na = ndp::NdpMsg::build_na(
                            msg.target,
                            src,
                            our_mac,
                            msg.target,
                            0x2000_0000,
                        );
                        self.xmit_ipv6(iface, msg.target, src, IpProto::Icmpv6, &na)?;
                    }
                }
            }
            t if t == ndp::NDP_NA => {
                if let Ok(msg) = ndp::NdpMsg::parse(payload, src, dst) {
                    if let Some(mac) = msg.lladdr {
                        self.ndp_insert(iface, msg.target, mac);
                    }
                }
            }
            t if t == ndp::NDP_RA => {
                if let Ok(ra) = ndp::RouterAdvertisement::parse(payload, src, dst) {
                    self.apply_router_advertisement(iface, src, &ra);
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_v6_dest_unreachable(&self, iface: NetIfaceId, offender: Ipv6Addr,
                                  code: u8, invoking: &[u8]) {
        let (errno, hard) = match code {
            ICMPV6_DEST_NO_ROUTE => (syscall::errno::Errno::Enetunreach as i32, false),
            ICMPV6_DEST_BEYOND_SCOPE | ICMPV6_DEST_ADDR_UNREACHABLE =>
                (syscall::errno::Errno::Ehostunreach as i32, false),
            ICMPV6_DEST_ADMIN_PROHIBITED | ICMPV6_DEST_POLICY_FAIL | ICMPV6_DEST_REJECT_ROUTE =>
                (syscall::errno::Errno::Eacces as i32, true),
            ICMPV6_DEST_PORT_UNREACHABLE => (syscall::errno::Errno::Econnrefused as i32, true),
            _ => return,
        };
        let (src, sport, dst, dport, body) = match quoted_udp6(invoking) {
            Some(tuple) => tuple,
            None => return,
        };
        if let Some(endpoint) = self.udp6_error_endpoint(iface, src, sport, dst, dport) {
            endpoint.publish_error(crate::SocketErrorEntry {
                errno, origin: crate::socket_error::SO_EE_ORIGIN_ICMP6,
                kind: ICMPV6_TYPE_DEST_UNREACHABLE, code, info: 0, data: 0,
                offender: IpAddr::V6(offender), destination: IpAddr::V6(dst),
                destination_port: dport, ifindex: iface.raw(), payload: body.to_vec(),
            }, hard);
        }
    }

    fn handle_v6_simple_error(&self, iface: NetIfaceId, offender: Ipv6Addr,
                              kind: u8, code: u8, invoking: &[u8]) {
        let (errno, hard) = if kind == ICMPV6_TYPE_PARAMETER_PROBLEM {
            (syscall::errno::Errno::Eproto as i32, true)
        } else { (syscall::errno::Errno::Ehostunreach as i32, false) };
        let Some((src, sport, dst, dport, body)) = quoted_udp6(invoking) else { return; };
        if let Some(endpoint) = self.udp6_error_endpoint(iface, src, sport, dst, dport) {
            endpoint.publish_error(crate::SocketErrorEntry {
                errno, origin: crate::socket_error::SO_EE_ORIGIN_ICMP6,
                kind, code, info: 0, data: 0, offender: IpAddr::V6(offender),
                destination: IpAddr::V6(dst), destination_port: dport,
                ifindex: iface.raw(),
                payload: body.to_vec(),
            }, hard);
        }
    }

    fn udp6_error_endpoint(&self, iface: NetIfaceId, src: Ipv6Addr, sport: u16,
                           dst: Ipv6Addr, dport: u16) -> Option<alloc::sync::Arc<Udp6RxQueue>> {
        self.udp6_demux(dst, dport, src, sport, iface).pop()
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
