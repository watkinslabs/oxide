use alloc::vec::Vec;

use super::{Raw4Endpoint, Raw4TxOptions};
use crate::sock_opts::sol_ip::options::Compiled;
use crate::addr::{eth_p, Ipv4Addr, NetIfaceId};
use crate::ipv4::{ip_checksum, IPV4_HDR_LEN, IPV4_VERSION};
use crate::netdev::{NetError, NetResult};
use crate::netfilter_hook::{nf_output_in, NFPROTO_IPV4};
use crate::pkt::{Pkt, TxNextHop};
use crate::stack::NetStack;

const IPV4_DF: u16 = 0x4000;
const IPV4_MF: u16 = 0x2000;
const IPV4_OFFSET_MASK: u16 = 0x1fff;
const IPV4_MAX_PACKET: usize = u16::MAX as usize;

impl NetStack {
    /// Send one raw IPv4 message using endpoint-owned protocol and scope. # C: O(packet + route)
    pub fn send_raw4(&self, endpoint: &Raw4Endpoint, dst: Ipv4Addr,
                     payload: &[u8], options: Raw4TxOptions,
                     control: &crate::send_control::Raw4Control) -> NetResult<()> {
        let state = endpoint.snapshot();
        if !state.accepting { return Err(NetError::Enoent); }
        if dst.is_unspecified() { return Err(NetError::Edestaddrreq); }
        if dst.is_broadcast() && !options.broadcast { return Err(NetError::Eacces); }
        let bound = control.iface.or(options.iface).or(state.bound_iface);
        if let Some(id) = bound {
            if self.ifaces.lookup_in_ns(id, endpoint.net_ns()).is_none() { return Err(NetError::Enodev); }
        }
        let route_dst = crate::ipv4_options::wire_dst(control.options.as_ref(), dst);
        let (route, iface, next_hop) = if control.dont_route && bound.is_some() {
            let iface_id = bound.unwrap();
            let iface = self.ifaces.acquire_egress_in_ns(iface_id, endpoint.net_ns())
                .ok_or(NetError::Enodev)?;
            (crate::ResolvedRoute {
                iface: iface_id,
                gateway: None,
                src_hint: None,
                table: crate::policy_rule::RT_TABLE_MAIN,
                priority: 0,
                metrics: crate::RouteMetrics::NONE,
            }, iface, route_dst)
        } else { self.route_v4_iface_in(endpoint.net_ns(), route_dst, bound)? };
        let iface_id = route.iface;
        if (control.dont_route && bound.is_none()
            || crate::ipv4_options::is_strict_route(control.options.as_ref()))
            && (next_hop != route_dst || !self.raw4_link_route(endpoint.net_ns(), route_dst, iface_id))
        { return Err(NetError::Enetunreach); }
        let route_source = self.routes.lookup_in(endpoint.net_ns(), route_dst).and_then(|r| r.src_hint)
            .or_else(|| crate::iface_addr::primary(endpoint.net_ns(), iface_id).map(|v| v.0));
        let source = control.source.or(options.source).filter(|src| !src.is_unspecified())
            .or_else(|| (!state.local.is_unspecified()).then_some(state.local))
            .or(route_source).unwrap_or(Ipv4Addr::ANY);
        if control.source.is_some() && !crate::iface_addr::snapshot_ns(endpoint.net_ns()).iter()
            .any(|row| row.addr == source)
        { return Err(NetError::Eaddrnotavail); }
        let (mtu, df, may_fragment) = self.ipv4_route_pmtu_policy(
            endpoint.net_ns(), route, route_dst, iface.mtu(), options.pmtudisc,
        );
        if dst.is_multicast() && control.multicast_loop == Some(false)
            && iface.hardware_type() == crate::uapi::ARPHRD_LOOPBACK
        {
            return Ok(());
        }
        if state.hdrincl {
            if control.options.is_some() { return Err(NetError::Einval); }
            return self.send_raw4_hdrincl(endpoint, iface_id, iface, next_hop,
                source, payload, mtu);
        }
        let id = self.next_raw4_id();
        self.send_raw4_payload(endpoint, iface_id, iface, next_hop, source, dst,
            endpoint.protocol(),
            payload, control.tos.unwrap_or(options.tos), control.ttl.unwrap_or(options.ttl),
            id, mtu, df, may_fragment,
            control.options.as_ref())
    }

    fn send_raw4_hdrincl(&self, endpoint: &Raw4Endpoint, iface_id: NetIfaceId,
                         iface: crate::EgressLease,
                         next_hop: Ipv4Addr, source: Ipv4Addr,
                         packet: &[u8], mtu: usize) -> NetResult<()> {
        if packet.len() < IPV4_HDR_LEN || packet.len() > IPV4_MAX_PACKET {
            return Err(NetError::Einval);
        }
        let ihl = ((packet[0] & 0x0f) as usize) * 4;
        if packet[0] >> 4 != IPV4_VERSION || ihl < IPV4_HDR_LEN || ihl > packet.len() {
            return Err(NetError::Einval);
        }
        let mut bytes = packet.to_vec();
        let packet_len = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&packet_len.to_be_bytes());
        if bytes[12..16] == [0, 0, 0, 0] { bytes[12..16].copy_from_slice(&source.octets()); }
        if bytes[4..6] == [0, 0] {
            bytes[4..6].copy_from_slice(&self.next_raw4_id().to_be_bytes());
        }
        bytes[10..12].copy_from_slice(&0u16.to_be_bytes());
        let checksum = ip_checksum(&bytes[..ihl]);
        bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
        if !self.admit_raw4(endpoint, iface_id, next_hop, &bytes)? { return Ok(()); }
        if bytes.len() > mtu { return Err(NetError::Emsgsize); }
        self.emit_raw4_fragment(iface_id, iface, next_hop, &bytes)
    }

    fn send_raw4_payload(&self, endpoint: &Raw4Endpoint, iface_id: NetIfaceId,
                         iface: crate::EgressLease,
                         next_hop: Ipv4Addr, src: Ipv4Addr, final_dst: Ipv4Addr, protocol: u8,
                         payload: &[u8], tos: u8, ttl: u8, id: u16, mtu: usize,
                         df: bool, may_fragment: bool,
        options: Option<&Compiled>) -> NetResult<()> {
        let header_len = crate::ipv4_options::header_len(options);
        if payload.len() + header_len > IPV4_MAX_PACKET { return Err(NetError::Emsgsize); }
        let full_flags = if df { IPV4_DF } else { 0 };
        let full = raw4_packet(src, final_dst, protocol, payload,
            tos, ttl, id, full_flags, options)?;
        if !self.admit_raw4(endpoint, iface_id, next_hop, &full)? { return Ok(()); }
        if payload.len() + header_len <= mtu {
            return self.emit_raw4_fragment(iface_id, iface, next_hop, &full);
        }
        if !may_fragment { return Err(NetError::Emsgsize); }
        let max_payload = mtu.saturating_sub(header_len) & !7usize;
        if max_payload == 0 { return Err(NetError::Emsgsize); }
        let later = options.map(crate::ipv4_options::fragmented);
        let mut offset = 0usize;
        while offset < payload.len() {
            let take = max_payload.min(payload.len() - offset);
            let more = offset + take < payload.len();
            let flags = ((offset / 8) as u16 & IPV4_OFFSET_MASK)
                | if more { IPV4_MF } else { 0 };
            let options = if offset == 0 { options } else { later.as_ref() };
            let bytes = raw4_packet(src, final_dst, protocol,
                &payload[offset..offset + take], tos, ttl, id, flags, options)?;
            self.emit_raw4_fragment(iface_id, iface.clone(), next_hop, &bytes)?;
            offset += take;
        }
        Ok(())
    }

    fn admit_raw4(&self, endpoint: &Raw4Endpoint, iface_id: NetIfaceId,
                  next_hop: Ipv4Addr, bytes: &[u8]) -> NetResult<bool> {
        let mut packet = Pkt::with_capacity(0, bytes.len());
        packet.put(bytes.len()).map_err(|_| NetError::Enobufs)?.copy_from_slice(bytes);
        packet.proto = eth_p::IPV4;
        packet.iface = Some(iface_id);
        packet.next_hop = Some(TxNextHop::V4(next_hop));
        if !nf_output_in(endpoint.net_ns(), &packet, NFPROTO_IPV4) { return Ok(false); }
        let _ = crate::cgroup_bpf::egress(
            &endpoint.owner, packet.data(), eth_p::IPV4, iface_id,
        )?;
        Ok(true)
    }

    fn emit_raw4_fragment(&self, iface_id: NetIfaceId, iface: crate::EgressLease,
                          next_hop: Ipv4Addr, bytes: &[u8]) -> NetResult<()> {
        let mut packet = Pkt::with_capacity(0, bytes.len());
        packet.put(bytes.len()).map_err(|_| NetError::Enobufs)?.copy_from_slice(bytes);
        packet.proto = eth_p::IPV4;
        packet.iface = Some(iface_id);
        packet.next_hop = Some(TxNextHop::V4(next_hop));
        iface.xmit(packet)
    }

    fn next_raw4_id(&self) -> u16 {
        let mut next = self.next_ip_id.lock();
        *next = next.wrapping_add(1);
        *next
    }

    fn raw4_link_route(&self, net_ns: u64, dst: Ipv4Addr, iface: NetIfaceId) -> bool {
        self.routes.lookup_record_in(net_ns, dst).is_some_and(|record| {
            record.route.iface == iface && record.route.gateway.is_none() && record.scope >= 253
        })
    }
}

/// Serialize one raw IPv4 datagram. `final_dst` is the caller's destination;
/// a compiled source route puts its first hop in the header instead and
/// carries this address in the option area's last slot. # C: O(packet)
fn raw4_packet(src: Ipv4Addr, final_dst: Ipv4Addr,
               protocol: u8, payload: &[u8], tos: u8, ttl: u8, id: u16, flags_frag: u16,
               options: Option<&Compiled>) -> NetResult<Vec<u8>> {
    let header_len = crate::ipv4_options::header_len(options);
    let total = header_len + payload.len();
    if total > IPV4_MAX_PACKET { return Err(NetError::Emsgsize); }
    let mut bytes = alloc::vec![0u8; total];
    let header = crate::ipv4_options::Header {
        src, dst: final_dst, proto: protocol, tos, ttl, id, flags_frag,
    };
    crate::ipv4_options::write_header(&mut bytes[..header_len], &header, options,
        payload.len(), crate::ipv4_options::timestamp());
    bytes[header_len..].copy_from_slice(payload);
    Ok(bytes)
}
