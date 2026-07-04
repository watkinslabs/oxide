use crate::addr::{IpAddr, IpProto, Ipv6Addr, NetIfaceId};
use crate::ipv6::Ipv6Hdr;
use crate::netdev::NetResult;
use crate::stack::NetStack;
use crate::ndp;
use crate::netfilter_hook::{nf_hook_eval, NFPROTO_IPV6, NF_INET_LOCAL_IN, NF_INET_PRE_ROUTING};

impl NetStack {
    pub fn deliver_rx_ipv6(&self, iface: NetIfaceId, l3: &[u8]) -> NetResult<()> {
        if nf_hook_eval(NF_INET_PRE_ROUTING, l3, NFPROTO_IPV6) == 0 {
            return Ok(());
        }
        if nf_hook_eval(NF_INET_LOCAL_IN, l3, NFPROTO_IPV6) == 0 {
            return Ok(());
        }
        let hdr = Ipv6Hdr::parse(l3).map_err(|_| crate::netdev::NetError::Einval)?;
        let payload_end = crate::ipv6::IPV6_HDR_LEN + hdr.payload_length as usize;
        if payload_end > l3.len() {
            return Err(crate::netdev::NetError::Einval);
        }
        let payload = &l3[crate::ipv6::IPV6_HDR_LEN..payload_end];
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
        self.deliver_rx_ipv6_payload(iface, hdr.src, hdr.dst, next_header, payload)
    }

    fn deliver_rx_ipv6_payload(
        &self,
        iface: NetIfaceId,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        next_header: u8,
        payload: &[u8],
    ) -> NetResult<()> {
        match next_header {
            n if n == IpProto::Icmpv6 as u8 => {
                self.deliver_rx_icmpv6(iface, src, dst, payload)?;
            }
            n if n == IpProto::Udp as u8 => {
                let udp = match crate::udp::parse_v6(payload, src, dst) {
                    Ok(h) => h,
                    Err(_) => return Ok(()),
                };
                let q_arc = { self.udp6_map().lock().get(&udp.dst_port).cloned() };
                if let Some(q) = q_arc {
                    let bound = q
                        .bound_ifindex
                        .load(core::sync::atomic::Ordering::Acquire);
                    if bound != 0 && bound != iface.raw() {
                        return Ok(());
                    }
                    let body = &payload[crate::udp::UDP_HDR_LEN..udp.length as usize];
                    q.q.lock().push_back((src, udp.src_port, body.to_vec()));
                    #[cfg(target_os = "oxide-kernel")]
                    {
                        q.waiters.wake_all();
                        let slot = q.poll_subs.lock().clone();
                        if let Some(weak) = slot {
                            if let Some(s) = weak.upgrade() {
                                s.notify();
                            }
                        }
                    }
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
        payload: &[u8],
    ) -> NetResult<()> {
        if payload.is_empty() {
            return Ok(());
        }
        let typ = payload[0];
        match typ {
            t if t == crate::icmpv6::ICMPV6_TYPE_PACKET_TOO_BIG => {
                if payload.len() >= 8 + crate::ipv6::IPV6_HDR_LEN + 4 {
                    let mtu = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
                    self.handle_v6_packet_too_big(mtu, &payload[8..]);
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
                if let Ok(q) = crate::icmpv6::Mldv1Query::parse(payload, src, dst) {
                    self.respond_mld_query(iface, q)?;
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
}
