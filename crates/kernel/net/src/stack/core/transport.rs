#![allow(unused_imports)]
use super::super::*;

impl NetStack {
    /// Remove exactly one IPv4 UDP endpoint, preserving port peers. # C: O(N_port)
    pub fn unbind_udp_endpoint(&self, endpoint: &Arc<UdpRxQueue>) {
        let port = endpoint.bound_port;
        let Some(tables) = self.try_inet_tables(endpoint.net_ns()) else {
            endpoint.deactivate();
            return;
        };
        let mut map = tables.udp.lock();
        if let Some(group) = map.get_mut(&port) {
            group.retain(|q| !Arc::ptr_eq(q, endpoint));
            if group.is_empty() { map.remove(&port); }
        }
        crate::reuseport::slot::set_endpoint_group(&endpoint.reuseport_group, None);
        endpoint.deactivate();
    }

    /// Atomically change one endpoint's device scope after conflict validation. # C: O(N_port)
    pub fn rebind_udp_endpoint_iface(&self, endpoint: &Arc<UdpRxQueue>, iface: Option<NetIfaceId>)
        -> NetResult<()> {
        let tables = self.inet_tables(endpoint.net_ns());
        let map = tables.udp.lock();
        let map6 = tables.udp6.lock();
        let group = map.get(&endpoint.bound_port).ok_or(NetError::Einval)?;
        let new_iface = iface.map(|i| i.raw()).unwrap_or(0);
        if let Some(group6) = map6.get(&endpoint.bound_port) {
            for old in group6 {
                if old.v6only.load(::core::sync::atomic::Ordering::Acquire) != 0 { continue; }
                let addr_overlap = old.bound_ip == Ipv6Addr::ANY
                    || old.bound_ip.to_v4_mapped().is_some_and(|ip| {
                        endpoint.bound_ip.is_unspecified() || ip == endpoint.bound_ip
                    });
                if !addr_overlap { continue; }
                let old_iface = old.bound_ifindex.load(::core::sync::atomic::Ordering::Acquire);
                let iface_overlap = old_iface == 0 || new_iface == 0 || old_iface == new_iface;
                let shared = old.reuseport_member() && endpoint.reuseport_member()
                        && old.owner_uid == endpoint.owner_uid
                    || old.reuseaddr.load(::core::sync::atomic::Ordering::Acquire) != 0
                        && endpoint.reuseaddr.load(::core::sync::atomic::Ordering::Acquire) != 0;
                if iface_overlap && !shared { return Err(NetError::Eaddrinuse); }
            }
        }
        for old in group {
            if Arc::ptr_eq(old, endpoint) { continue; }
            let old_iface = old.bound_ifindex.load(::core::sync::atomic::Ordering::Acquire);
            let iface_overlap = old_iface == 0 || new_iface == 0 || old_iface == new_iface;
            let addr_overlap = old.bound_ip.is_unspecified() || endpoint.bound_ip.is_unspecified()
                || old.bound_ip == endpoint.bound_ip;
            let shared = old.reuseport_member() && endpoint.reuseport_member()
                    && old.owner_uid == endpoint.owner_uid
                || old.reuseaddr.load(::core::sync::atomic::Ordering::Acquire) != 0
                    && endpoint.reuseaddr.load(::core::sync::atomic::Ordering::Acquire) != 0;
            if iface_overlap && addr_overlap && !shared { return Err(NetError::Eaddrinuse); }
        }
        endpoint.bound_ifindex.store(new_iface, ::core::sync::atomic::Ordering::Release);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn udp_map(&self) -> Arc<super::super::inet_tables::InetTableLock<BTreeMap<u16, Vec<Arc<UdpRxQueue>>>>> {
        self.inet_tables(0).udp.clone()
    }

    #[cfg(test)]
    pub(crate) fn udp6_map(&self) -> Arc<super::super::inet_tables::InetTableLock<BTreeMap<u16, Vec<Arc<crate::stack_ipv6::Udp6RxQueue>>>>> {
        self.inet_tables(0).udp6.clone()
    }

    /// The connection table of the initial namespace, for tests that assert
    /// what a handshake left in it. # C: O(1)
    #[cfg(test)]
    pub(crate) fn tcp_conns_map(&self)
        -> Arc<super::super::inet_tables::InetTableLock<BTreeMap<TcpKey, super::super::TcpSlot>>> {
        self.inet_tables(0).tcp_conns.clone()
    }

    /// F161: pub TCP-over-IPv4 send wrapper. # C: O(payload + route)
    pub fn send_l4_over_ipv4_pub(&self, src: Ipv4Addr, dst: Ipv4Addr, l4: &[u8])
        -> NetResult<()>
    {
        self.send_tcp_ipv4_segment_in(
            0, src, dst, l4, 0, None, crate::uapi::IP_PMTUDISC_WANT, None, None,
            crate::stack_binddev::UNMARKED,
        ).map(|_| ())
    }

    /// Send the RFC 9293 reset response for an IPv4 segment rejected by
    /// nftables. An incoming ACK produces an unacknowledged RST; every other
    /// segment produces RST|ACK acknowledging its sequence space. # C: O(N)
    pub(crate) fn send_tcp_reset_ipv4(&self, net_ns: u64, packet: &[u8], mark: u32) -> NetResult<()> {
        if packet.len() < crate::ipv4::IPV4_HDR_LEN || packet[0] >> 4 != 4 { return Ok(()); }
        let ihl = (packet[0] & 0x0f) as usize * 4;
        if ihl < crate::ipv4::IPV4_HDR_LEN || packet.len() < ihl + crate::tcp_hdr::TCP_HDR_MIN_LEN {
            return Ok(());
        }
        let tcp = &packet[ihl..];
        let data_offset = (tcp[12] >> 4) as usize * 4;
        if data_offset < crate::tcp_hdr::TCP_HDR_MIN_LEN || tcp.len() < data_offset { return Ok(()); }
        let total = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        let payload_len = total.saturating_sub(ihl).saturating_sub(data_offset).min(
            tcp.len().saturating_sub(data_offset));
        let seq = u32::from_be_bytes(tcp[4..8].try_into().unwrap());
        let ack = u32::from_be_bytes(tcp[8..12].try_into().unwrap());
        let flags = tcp[13];
        let (reply_seq, reply_ack, reply_flags) = if flags & crate::tcp_hdr::flags::ACK != 0 {
            (ack, 0, crate::tcp_hdr::flags::RST)
        } else {
            let advance = payload_len as u32
                + u32::from((flags & crate::tcp_hdr::flags::SYN) != 0)
                + u32::from((flags & crate::tcp_hdr::flags::FIN) != 0);
            (0, seq.wrapping_add(advance),
             crate::tcp_hdr::flags::RST | crate::tcp_hdr::flags::ACK)
        };
        let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        let mut out = alloc::vec![0u8; crate::tcp_hdr::TCP_HDR_MIN_LEN];
        let mut header = crate::tcp_hdr::TcpHdr {
            src_port: u16::from_be_bytes([tcp[2], tcp[3]]),
            dst_port: u16::from_be_bytes([tcp[0], tcp[1]]),
            seq: reply_seq, ack: reply_ack, data_offset: 5, flags: reply_flags,
            window: 0, checksum: 0, urg_ptr: 0,
        };
        header.build_into(dst, src, &mut out);
        self.send_tcp_ipv4_segment_in(
            net_ns, dst, src, &out, 0, None, crate::uapi::IP_PMTUDISC_WANT,
            None, None, mark).map(|_| ())
    }

    /// Build + xmit UDP datagram. # C: O(payload + route lookup)
    pub fn send_udp_to(&self, src_ip: Ipv4Addr, src_port: u16,
                        dst_ip: Ipv4Addr, dst_port: u16, payload: &[u8])
        -> NetResult<()>
    {
        // F122: 255.255.255.255 has no specific route entry (DHCP
        // DISCOVER fires before any route is installed). Fall back
        // to the first non-loopback iface so the broadcast lands.
        // Once route tables track scope (LOCAL_BROADCAST etc.), the
        // fallback retires.
        let (route, iface, next_hop) = self.route_v4_xmit_in(0, dst_ip, None, crate::stack_binddev::UNMARKED)?;
        let total = crate::udp::UDP_HDR_LEN + payload.len();
        let mut p = Pkt::with_capacity(IPV4_HDR_LEN, total + IPV4_HDR_LEN);
        let udp_total = crate::udp::UDP_HDR_LEN + payload.len();
        let slot = p.put(udp_total).map_err(|_| NetError::Enobufs)?;
        UdpHdr::build_into(src_port, dst_port, src_ip, dst_ip, payload, slot);
        let id = {
            let mut s = self.next_ip_id.lock();
            *s = s.wrapping_add(1);
            *s
        };
        self.xmit_ipv4_l4_on_iface(
            route, iface, next_hop, src_ip, dst_ip, IpProto::Udp, p.data(), 0, id,
        )
    }
}

