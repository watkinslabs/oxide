use alloc::vec::Vec;

use super::{Raw4Endpoint, Raw4TxOptions};
use crate::addr::{eth_p, Ipv4Addr, NetIfaceId};
use crate::ipv4::{ip_checksum, IPV4_HDR_LEN, IPV4_VERSION};
use crate::netdev::{NetError, NetResult};
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
        let route_dst = control.options.as_ref().and_then(|opt| opt.first_hop).unwrap_or(dst);
        let (iface_id, iface, next_hop) = if control.dont_route && bound.is_some() {
            let iface_id = bound.unwrap();
            let iface = self.ifaces.acquire_egress_in_ns(iface_id, endpoint.net_ns())
                .ok_or(NetError::Enodev)?;
            (iface_id, iface, route_dst)
        } else { self.route_v4_iface_in(endpoint.net_ns(), route_dst, bound)? };
        if (control.dont_route && bound.is_none()
            || control.options.as_ref().is_some_and(|opt| opt.strict_route))
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
        let (mtu, df, may_fragment) = self.ipv4_pmtu_policy(
            endpoint.net_ns(), iface_id, route_dst, iface.mtu(), options.pmtudisc,
        );
        if dst.is_multicast() && control.multicast_loop == Some(false)
            && iface.hardware_type() == crate::uapi::ARPHRD_LOOPBACK
        {
            return Ok(());
        }
        if state.hdrincl {
            if control.options.is_some() { return Err(NetError::Einval); }
            return self.send_raw4_hdrincl(iface_id, iface, next_hop, source, dst, payload, mtu);
        }
        let id = self.next_raw4_id();
        self.send_raw4_payload(endpoint.net_ns(), iface_id, iface, next_hop, source, route_dst, dst,
            endpoint.protocol(),
            payload, control.tos.unwrap_or(options.tos), control.ttl.unwrap_or(options.ttl),
            id, mtu, df, may_fragment,
            control.options.as_ref())
    }

    fn send_raw4_hdrincl(&self, iface_id: NetIfaceId, iface: crate::EgressLease,
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

    fn send_raw4_payload(&self, net_ns: u64, iface_id: NetIfaceId, iface: crate::EgressLease,
                         next_hop: Ipv4Addr, src: Ipv4Addr, wire_dst: Ipv4Addr,
                         final_dst: Ipv4Addr, protocol: u8,
                         payload: &[u8], tos: u8, ttl: u8, id: u16, mtu: usize,
                         df: bool, may_fragment: bool,
                         options: Option<&crate::send_control::Ipv4Options>) -> NetResult<()> {
        let header_len = IPV4_HDR_LEN + options.map_or(0, |opt| opt.bytes.len());
        if payload.len() + header_len > IPV4_MAX_PACKET { return Err(NetError::Emsgsize); }
        if payload.len() + header_len <= mtu {
            let flags = if df { IPV4_DF } else { 0 };
            let bytes = raw4_packet(net_ns, src, wire_dst, final_dst, protocol, payload,
                tos, ttl, id, flags, options)?;
            return self.emit_raw4(iface_id, iface, next_hop, wire_dst, &bytes);
        }
        if !may_fragment { return Err(NetError::Emsgsize); }
        let max_payload = mtu.saturating_sub(header_len) & !7usize;
        if max_payload == 0 { return Err(NetError::Emsgsize); }
        let mut offset = 0usize;
        while offset < payload.len() {
            let take = max_payload.min(payload.len() - offset);
            let more = offset + take < payload.len();
            let flags = ((offset / 8) as u16 & IPV4_OFFSET_MASK)
                | if more { IPV4_MF } else { 0 };
            let fragment_options = if offset == 0 { None } else { options.map(copied_fragment_options) };
            let options = fragment_options.as_ref().or(options);
            let bytes = raw4_packet(net_ns, src, wire_dst, final_dst, protocol,
                &payload[offset..offset + take], tos, ttl, id, flags, options)?;
            self.emit_raw4(iface_id, iface.clone(), next_hop, wire_dst, &bytes)?;
            offset += take;
        }
        Ok(())
    }

    fn emit_raw4(&self, iface_id: NetIfaceId, iface: crate::EgressLease,
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

    fn raw4_link_route(&self, net_ns: u64, dst: Ipv4Addr, iface: NetIfaceId) -> bool {
        self.routes.lookup_record_in(net_ns, dst).is_some_and(|record| {
            record.route.iface == iface && record.route.gateway.is_none() && record.scope >= 253
        })
    }
}

fn raw4_packet(net_ns: u64, src: Ipv4Addr, wire_dst: Ipv4Addr, final_dst: Ipv4Addr,
               protocol: u8, payload: &[u8], tos: u8, ttl: u8, id: u16, flags_frag: u16,
               options: Option<&crate::send_control::Ipv4Options>) -> NetResult<Vec<u8>> {
    let option_len = options.map_or(0, |opt| opt.bytes.len());
    let header_len = IPV4_HDR_LEN + option_len;
    let total = header_len + payload.len();
    if total > IPV4_MAX_PACKET { return Err(NetError::Emsgsize); }
    let mut bytes = alloc::vec![0u8; total];
    bytes[0] = (IPV4_VERSION << 4) | (header_len as u8 / 4);
    bytes[1] = tos;
    bytes[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    bytes[4..6].copy_from_slice(&id.to_be_bytes());
    bytes[6..8].copy_from_slice(&flags_frag.to_be_bytes());
    bytes[8] = ttl;
    bytes[9] = protocol;
    bytes[12..16].copy_from_slice(&src.octets());
    bytes[16..20].copy_from_slice(&wire_dst.octets());
    if let Some(options) = options {
        bytes[IPV4_HDR_LEN..header_len].copy_from_slice(&options.bytes);
        build_ipv4_options(&mut bytes[IPV4_HDR_LEN..header_len], net_ns, src, final_dst);
    }
    let checksum = ip_checksum(&bytes[..header_len]);
    bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
    bytes[header_len..].copy_from_slice(payload);
    Ok(bytes)
}

fn build_ipv4_options(options: &mut [u8], net_ns: u64, src: Ipv4Addr, dst: Ipv4Addr) {
    let mut off = 0usize;
    while off < options.len() {
        match options[off] {
            0 => return,
            1 => off += 1,
            131 | 137 => {
                let len = options[off + 1] as usize;
                options[off + len - 4..off + len].copy_from_slice(&dst.octets());
                off += len;
            }
            7 => {
                let len = options[off + 1] as usize;
                let pointer = options[off + 2] as usize;
                if pointer <= len {
                    options[off + pointer - 1..off + pointer + 3].copy_from_slice(&src.octets());
                    options[off + 2] += 4;
                }
                off += len;
            }
            68 => {
                let len = options[off + 1] as usize;
                let pointer = options[off + 2] as usize;
                let mode = options[off + 3] & 0x0f;
                let stamp = ipv4_timestamp().to_be_bytes();
                if pointer <= len && mode == 0 {
                    options[off + pointer - 1..off + pointer + 3].copy_from_slice(&stamp);
                    options[off + 2] += 4;
                } else if pointer <= len && mode == 1 {
                    options[off + pointer - 1..off + pointer + 3].copy_from_slice(&src.octets());
                    options[off + pointer + 3..off + pointer + 7].copy_from_slice(&stamp);
                    options[off + 2] += 8;
                } else if pointer <= len && mode == 3
                    && prespecified_local(net_ns, &options[off..off + len], pointer)
                {
                    options[off + pointer + 3..off + pointer + 7].copy_from_slice(&stamp);
                    options[off + 2] += 8;
                }
                off += len;
            }
            _ => off += options[off + 1] as usize,
        }
    }
}

fn prespecified_local(net_ns: u64, option: &[u8], pointer: usize) -> bool {
    let addr = Ipv4Addr::new(option[pointer - 1], option[pointer], option[pointer + 1], option[pointer + 2]);
    crate::iface_addr::snapshot_ns(net_ns).iter().any(|row| row.addr == addr)
}

fn ipv4_timestamp() -> u32 {
    const DAY_MS: u64 = 86_400_000;
    ((vfs::inode_times::realtime_now_ns() / 1_000_000) % DAY_MS) as u32
}

fn copied_fragment_options(options: &crate::send_control::Ipv4Options)
    -> crate::send_control::Ipv4Options
{
    let mut out = options.clone();
    let mut off = 0usize;
    while off < out.bytes.len() {
        let kind = out.bytes[off];
        if kind == 0 { break; }
        if kind == 1 { off += 1; continue; }
        let len = out.bytes[off + 1] as usize;
        if kind & 0x80 == 0 { for byte in &mut out.bytes[off..off + len] { *byte = 1; } }
        off += len;
    }
    out
}
