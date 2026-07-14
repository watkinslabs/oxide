use alloc::vec::Vec;

use super::{Raw4Endpoint, Raw4TxOptions};
use crate::addr::{eth_p, IpAddr, Ipv4Addr, NetIfaceId};
use crate::ipv4::{ip_checksum, IPV4_HDR_LEN, IPV4_VERSION};
use crate::netdev::{NetDev, NetError, NetResult};
use crate::netfilter_hook::{nf_output, NFPROTO_IPV4};
use crate::pkt::{Pkt, TxNextHop};
use crate::stack::NetStack;

const IPV4_DF: u16 = 0x4000;
const IPV4_MF: u16 = 0x2000;
const IPV4_OFFSET_MASK: u16 = 0x1fff;
const IPV4_MAX_PACKET: usize = u16::MAX as usize;

impl NetStack {
    /// Send one raw IPv4 message using endpoint-owned protocol and scope. # C: O(packet + route)
    pub fn send_raw4(&self, endpoint: &Raw4Endpoint, dst: Ipv4Addr,
                     payload: &[u8], options: Raw4TxOptions) -> NetResult<()> {
        let state = endpoint.snapshot();
        if !state.accepting { return Err(NetError::Enoent); }
        if dst.is_unspecified() { return Err(NetError::Edestaddrreq); }
        if dst.is_broadcast() && !options.broadcast { return Err(NetError::Eacces); }
        let bound = options.iface.or(state.bound_iface);
        let (iface_id, iface, next_hop) = self.route_v4_iface_in(endpoint.net_ns(), dst, bound)?;
        let route_source = self.routes.lookup_in(endpoint.net_ns(), dst).and_then(|r| r.src_hint)
            .or_else(|| crate::iface_addr::primary(endpoint.net_ns(), iface_id).map(|v| v.0));
        let source = options.source.filter(|src| !src.is_unspecified())
            .or_else(|| (!state.local.is_unspecified()).then_some(state.local))
            .or(route_source).unwrap_or(Ipv4Addr::ANY);
        let probe = options.pmtudisc >= crate::uapi::IP_PMTUDISC_PROBE;
        let mtu = self.path_mtu_in(endpoint.net_ns(), IpAddr::V4(dst), Some(iface_id), probe)? as usize;
        if state.hdrincl {
            return self.send_raw4_hdrincl(iface_id, iface, next_hop, source, dst, payload, mtu);
        }
        let may_fragment = options.pmtudisc != crate::uapi::IP_PMTUDISC_DO
            && options.pmtudisc != crate::uapi::IP_PMTUDISC_PROBE
            && options.pmtudisc != crate::uapi::IP_PMTUDISC_INTERFACE;
        let df = options.pmtudisc == crate::uapi::IP_PMTUDISC_WANT
            || options.pmtudisc == crate::uapi::IP_PMTUDISC_DO
            || options.pmtudisc == crate::uapi::IP_PMTUDISC_PROBE;
        let id = self.next_raw4_id();
        self.send_raw4_payload(iface_id, iface, next_hop, source, dst, endpoint.protocol(),
            payload, options.tos, options.ttl, id, mtu, df, may_fragment)
    }

    fn send_raw4_hdrincl(&self, iface_id: NetIfaceId, iface: alloc::sync::Arc<dyn NetDev>,
                         next_hop: Ipv4Addr, source: Ipv4Addr, route_dst: Ipv4Addr,
                         packet: &[u8], mtu: usize) -> NetResult<()> {
        if packet.len() < IPV4_HDR_LEN || packet.len() > IPV4_MAX_PACKET {
            return Err(NetError::Einval);
        }
        let ihl = ((packet[0] & 0x0f) as usize) * 4;
        if packet[0] >> 4 != IPV4_VERSION || ihl < IPV4_HDR_LEN || ihl > packet.len() {
            return Err(NetError::Einval);
        }
        if packet.len() > mtu { return Err(NetError::Emsgsize); }
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
        self.emit_raw4(iface_id, iface, next_hop, route_dst, &bytes)
    }

    fn send_raw4_payload(&self, iface_id: NetIfaceId, iface: alloc::sync::Arc<dyn NetDev>,
                         next_hop: Ipv4Addr, src: Ipv4Addr, dst: Ipv4Addr, protocol: u8,
                         payload: &[u8], tos: u8, ttl: u8, id: u16, mtu: usize,
                         df: bool, may_fragment: bool) -> NetResult<()> {
        if payload.len() + IPV4_HDR_LEN > IPV4_MAX_PACKET { return Err(NetError::Emsgsize); }
        if payload.len() + IPV4_HDR_LEN <= mtu {
            let flags = if df { IPV4_DF } else { 0 };
            let bytes = raw4_packet(src, dst, protocol, payload, tos, ttl, id, flags)?;
            return self.emit_raw4(iface_id, iface, next_hop, dst, &bytes);
        }
        if !may_fragment { return Err(NetError::Emsgsize); }
        let max_payload = mtu.saturating_sub(IPV4_HDR_LEN) & !7usize;
        if max_payload == 0 { return Err(NetError::Emsgsize); }
        let mut offset = 0usize;
        while offset < payload.len() {
            let take = max_payload.min(payload.len() - offset);
            let more = offset + take < payload.len();
            let flags = ((offset / 8) as u16 & IPV4_OFFSET_MASK)
                | if more { IPV4_MF } else { 0 };
            let bytes = raw4_packet(src, dst, protocol, &payload[offset..offset + take],
                tos, ttl, id, flags)?;
            self.emit_raw4(iface_id, iface.clone(), next_hop, dst, &bytes)?;
            offset += take;
        }
        Ok(())
    }

    fn emit_raw4(&self, iface_id: NetIfaceId, iface: alloc::sync::Arc<dyn NetDev>,
                 next_hop: Ipv4Addr, _dst: Ipv4Addr, bytes: &[u8]) -> NetResult<()> {
        let mut packet = Pkt::with_capacity(0, bytes.len());
        packet.put(bytes.len()).map_err(|_| NetError::Enobufs)?.copy_from_slice(bytes);
        packet.proto = eth_p::IPV4;
        packet.iface = Some(iface_id);
        packet.next_hop = Some(TxNextHop::V4(next_hop));
        if !nf_output(&packet, NFPROTO_IPV4) { return Ok(()); }
        iface.xmit(packet)
    }

    fn next_raw4_id(&self) -> u16 {
        let mut next = self.next_ip_id.lock();
        *next = next.wrapping_add(1);
        *next
    }
}

fn raw4_packet(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload: &[u8], tos: u8,
               ttl: u8, id: u16, flags_frag: u16) -> NetResult<Vec<u8>> {
    let total = IPV4_HDR_LEN + payload.len();
    if total > IPV4_MAX_PACKET { return Err(NetError::Emsgsize); }
    let mut bytes = alloc::vec![0u8; total];
    bytes[0] = (IPV4_VERSION << 4) | (IPV4_HDR_LEN as u8 / 4);
    bytes[1] = tos;
    bytes[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    bytes[4..6].copy_from_slice(&id.to_be_bytes());
    bytes[6..8].copy_from_slice(&flags_frag.to_be_bytes());
    bytes[8] = ttl;
    bytes[9] = protocol;
    bytes[12..16].copy_from_slice(&src.octets());
    bytes[16..20].copy_from_slice(&dst.octets());
    let checksum = ip_checksum(&bytes[..IPV4_HDR_LEN]);
    bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
    bytes[IPV4_HDR_LEN..].copy_from_slice(payload);
    Ok(bytes)
}
