use alloc::vec::Vec;

use crate::{IpAddr, Ipv6Addr, NetIfaceId};
use crate::ipv6::IPV6_HDR_LEN;
use crate::netdev::{NetError, NetResult};
use crate::send_control::Raw6Control;
use crate::stack::NetStack;

use super::tx::{admit_ipv6_owned, emit_ipv6_fragment, push_ipv6_raw_header};

const NH_HOP: u8 = 0;
const NH_ROUTING: u8 = 43;
const NH_FRAGMENT: u8 = 44;
const NH_ESP: u8 = 50;
const NH_AH: u8 = 51;
const NH_NONE: u8 = 59;
const NH_DEST: u8 = 60;

impl NetStack {
    /// Route and transmit one raw IPv6 message with immutable per-message controls. # C: O(payload + N)
    pub fn send_raw6(&self, endpoint: &crate::raw6::Raw6Endpoint, final_dst: Ipv6Addr,
        scoped: Option<NetIfaceId>, protocol_override: Option<u8>, payload: &[u8],
        hop_limit: u8, pmtudisc: i32, control: &Raw6Control) -> NetResult<()>
    {
        self.send_raw6_with_frag_size(endpoint, final_dst, scoped, protocol_override, payload,
            hop_limit, pmtudisc, 0, control)
    }

    /// Route and transmit one socket-owned raw IPv6 message. # C: O(payload + N)
    pub fn send_raw6_with_frag_size(&self, endpoint: &crate::raw6::Raw6Endpoint,
        final_dst: Ipv6Addr, scoped: Option<NetIfaceId>, protocol_override: Option<u8>,
        payload: &[u8], hop_limit: u8, pmtudisc: i32, frag_size: i32,
        control: &Raw6Control) -> NetResult<()>
    {
        if final_dst.is_unspecified() { return Err(NetError::Edestaddrreq); }
        let route_dst = control.route_destination(final_dst);
        let (local, endpoint_iface) = endpoint.tx_binding();
        let local_iface = (local.scope_id != 0).then(|| NetIfaceId::from_raw(local.scope_id));
        let bound = merge_iface(scoped, control.iface, endpoint_iface, local_iface)?;
        if let Some(id) = bound {
            if self.ifaces.lookup_in_ns(id, endpoint.net_ns()).is_none() { return Err(NetError::Enodev); }
        }
        let controlled_route = match control.iface {
            Some(id) => Some(self.longest_prefix_route6_on_iface(endpoint.net_ns(), id, route_dst)
                .ok_or(NetError::Enetunreach)?),
            None => None,
        };
        let (iface_id, iface, next_hop) = if let Some(route) = controlled_route {
            let iface = self.ifaces.acquire_egress_in_ns(route.iface, endpoint.net_ns())
                .ok_or(NetError::Enetunreach)?;
            (route.iface, iface, crate::route6::next_hop6_for(route.gateway, route_dst))
        } else { self.route_v6_iface_in(endpoint.net_ns(), route_dst, bound)? };
        if let Some(source) = control.source {
            if !self.v6_addr_owned_by(iface_id, source) { return Err(NetError::Einval); }
        }
        if control.source.is_none() && !local.addr.is_unspecified()
            && !self.v6_addr_owned_by(iface_id, local.addr)
        {
            return Err(NetError::Eaddrnotavail);
        }
        let route_hint = controlled_route.and_then(|route| route.src_hint)
            .or_else(|| self.routes6.lookup_in(endpoint.net_ns(), route_dst)
                .filter(|route| route.iface == iface_id).and_then(|route| route.src_hint));
        let source = control.source.or((!local.addr.is_unspecified()).then_some(local.addr))
            .or_else(|| self.v6_select_source(iface_id, final_dst, route_hint))
            .unwrap_or(Ipv6Addr::ANY);
        let prepared = endpoint.prepare_send(source, final_dst, protocol_override, payload)?;
        if prepared.mode == crate::raw6::Raw6SendMode::KernelHeader
            && prepared.src.is_unspecified()
        {
            return Err(NetError::Eaddrnotavail);
        }
        let use_iface = crate::uapi::ipv6_pmtudisc_uses_interface(pmtudisc);
        let mtu = super::tx::ipv6_output_mtu(self.path_mtu_in(endpoint.net_ns(),
            IpAddr::V6(route_dst), Some(iface_id), use_iface)? as usize, frag_size);
        if final_dst.is_multicast() && control.multicast_loop == Some(false)
            && iface.hardware_type() == crate::uapi::ARPHRD_LOOPBACK
        {
            return Ok(());
        }
        if prepared.mode == crate::raw6::Raw6SendMode::CallerHeader {
            return emit_raw6_caller_header(&endpoint.owner, iface_id, iface, next_hop,
                prepared.src, &prepared.bytes, mtu);
        }
        let hop = match control.hop_limit { Some(value) if value >= 0 => value as u8, _ => hop_limit };
        let flowinfo = control.flowinfo.unwrap_or(0);
        let tclass = match control.traffic_class {
            Some(value) if value >= 0 => value as u8,
            _ => ((flowinfo >> 20) & 0xff) as u8,
        };
        let flow = flowinfo & 0x000f_ffff;
        let may_fragment = crate::uapi::ipv6_pmtudisc_allows_fragmentation(pmtudisc)
            && control.dontfrag != Some(true);
        self.xmit_raw6_controlled(endpoint, iface_id, iface, next_hop, prepared.src, final_dst,
            route_dst, prepared.next_header, &prepared.bytes, hop, tclass, flow, mtu,
            may_fragment, control)
    }

    /// Best route to `dst` restricted to one interface, longest prefix wins.
    ///
    /// `#[inline(never)]`: this materialises the whole route table snapshot, and only a
    /// message carrying an explicit `IPV6_PKTINFO` interface takes it. Every other raw
    /// send would otherwise reserve the vector on a frame deep in the transmit chain.
    /// # C: O(N routes)
    #[inline(never)]
    fn longest_prefix_route6_on_iface(&self, net_ns: u64, id: NetIfaceId, dst: Ipv6Addr)
        -> Option<crate::route6::Route6Entry>
    {
        self.routes6.snapshot_in(net_ns).into_iter()
            .filter(|route| route.iface == id && route.matches(dst))
            .reduce(|best, route| if route.prefix_len > best.prefix_len { route } else { best })
    }

    fn xmit_raw6_controlled(&self, endpoint: &crate::raw6::Raw6Endpoint,
        iface_id: NetIfaceId, iface: crate::EgressLease,
        next_hop: Ipv6Addr, src: Ipv6Addr, final_dst: Ipv6Addr, base_dst: Ipv6Addr,
        upper: u8, payload: &[u8], hop: u8, tclass: u8, flow: u32, policy_mtu: usize,
        may_fragment: bool, control: &Raw6Control) -> NetResult<()>
    {
        let mtu = core::cmp::min(iface.mtu() as usize, policy_mtu);
        let (base_next, wire) = wire_payload(control, final_dst, upper, payload, None)?;
        if wire.len() > u16::MAX as usize { return Err(NetError::Emsgsize); }
        let full = build_packet(src, base_dst, base_next, &wire, hop, tclass, flow)?;
        if !admit_ipv6_owned(&endpoint.owner, iface_id, next_hop, src, full)? {
            return Ok(());
        }
        if IPV6_HDR_LEN + wire.len() <= mtu {
            return emit_packet_fragment(iface_id, iface, next_hop, src, base_dst,
                base_next, &wire, hop, tclass, flow);
        }
        if !may_fragment { return Err(NetError::Emsgsize); }
        let nonfrag_len = nonfragment_len(control);
        let max = mtu.saturating_sub(IPV6_HDR_LEN + nonfrag_len + 8) & !7usize;
        if max == 0 { return Err(NetError::Emsgsize); }
        let chain_len = post_fragment_chain_len(control, upper, payload)
            .ok_or(NetError::Emsgsize)?;
        if chain_len > max { return Err(NetError::Emsgsize); }
        let fragmentable = fragmentable_payload(control, upper, payload);
        let id = self.next_ipv6_frag_id();
        let mut off = 0usize;
        while off < fragmentable.len() {
            let take = core::cmp::min(max, fragmentable.len() - off);
            let more = off + take < fragmentable.len();
            let frag_next = if control.dst_after_routing.is_some() { NH_DEST } else { upper };
            let mut fragment = Vec::with_capacity(8 + take);
            fragment.push(frag_next); fragment.push(0);
            let flags = (((off / 8) as u16) << 3) | if more { 1 } else { 0 };
            fragment.extend_from_slice(&flags.to_be_bytes());
            fragment.extend_from_slice(&id.to_be_bytes());
            fragment.extend_from_slice(&fragmentable[off..off + take]);
            let (base_next, wire) = wire_payload(control, final_dst, NH_FRAGMENT, &fragment, Some(false))?;
            emit_packet_fragment(iface_id, iface.clone(), next_hop, src, base_dst, base_next,
                &wire, hop, tclass, flow)?;
            off += take;
        }
        Ok(())
    }
}

fn merge_iface(a: Option<NetIfaceId>, b: Option<NetIfaceId>, c: Option<NetIfaceId>,
    d: Option<NetIfaceId>) -> NetResult<Option<NetIfaceId>>
{
    let selected = a.or(b).or(c).or(d);
    if [a, b, c, d].iter().flatten().any(|iface| Some(*iface) != selected) {
        return Err(NetError::Einval);
    }
    Ok(selected)
}

fn wire_payload(control: &Raw6Control, final_dst: Ipv6Addr, upper: u8, payload: &[u8],
    include_after: Option<bool>) -> NetResult<(u8, Vec<u8>)>
{
    let include_after = include_after.unwrap_or(true);
    let mut headers: Vec<(u8, Vec<u8>)> = Vec::new();
    if let Some(h) = &control.hop_options { headers.push((NH_HOP, h.clone())); }
    if control.routing.is_some() {
        if let Some(h) = &control.dst_before_routing { headers.push((NH_DEST, h.clone())); }
        let mut routing = control.routing.clone().unwrap();
        routing[8..24].copy_from_slice(&final_dst.0);
        headers.push((NH_ROUTING, routing));
    }
    if include_after { if let Some(h) = &control.dst_after_routing { headers.push((NH_DEST, h.clone())); } }
    let base = headers.first().map_or(upper, |entry| entry.0);
    let mut out = Vec::new();
    for index in 0..headers.len() {
        let mut bytes = headers[index].1.clone();
        bytes[0] = headers.get(index + 1).map_or(upper, |entry| entry.0);
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(payload);
    Ok((base, out))
}

fn nonfragment_len(control: &Raw6Control) -> usize {
    control.hop_options.as_ref().map_or(0, Vec::len)
        + if control.routing.is_some() {
            control.dst_before_routing.as_ref().map_or(0, Vec::len)
                + control.routing.as_ref().map_or(0, Vec::len)
        } else { 0 }
}

fn fragmentable_payload(control: &Raw6Control, upper: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(header) = &control.dst_after_routing {
        let mut header = header.clone(); header[0] = upper; out.extend_from_slice(&header);
    }
    out.extend_from_slice(payload);
    out
}

fn post_fragment_chain_len(control: &Raw6Control, mut next: u8, mut payload: &[u8])
    -> Option<usize>
{
    let mut total = control.dst_after_routing.as_ref().map_or(0, Vec::len);
    loop {
        let len = match next {
            NH_HOP | NH_ROUTING | NH_DEST => {
                if payload.len() < 2 { return None; }
                (payload[1] as usize + 1) * 8
            }
            NH_FRAGMENT => 8,
            NH_AH => {
                if payload.len() < 2 { return None; }
                (payload[1] as usize + 2) * 4
            }
            NH_ESP => 8,
            NH_NONE => 0,
            p if p == crate::addr::IpProto::Udp as u8 => crate::udp::UDP_HDR_LEN,
            p if p == crate::addr::IpProto::Tcp as u8 => {
                if payload.len() < crate::tcp_hdr::TCP_HDR_MIN_LEN { return None; }
                let len = (payload[12] >> 4) as usize * 4;
                if len < crate::tcp_hdr::TCP_HDR_MIN_LEN { return None; }
                len
            }
            p if p == crate::icmpv6::IPPROTO_ICMPV6 => crate::icmpv6::ICMPV6_HDR_LEN,
            _ => 0,
        };
        if len > payload.len() { return None; }
        total = total.checked_add(len)?;
        if !matches!(next, NH_HOP | NH_ROUTING | NH_FRAGMENT | NH_AH | NH_DEST) {
            return Some(total);
        }
        next = payload[0];
        payload = &payload[len..];
    }
}

fn build_packet(src: Ipv6Addr, dst: Ipv6Addr, next: u8, payload: &[u8],
    hop: u8, tclass: u8, flow: u32) -> NetResult<crate::pkt::Pkt>
{
    if payload.len() > u16::MAX as usize { return Err(NetError::Emsgsize); }
    let mut p = crate::pkt::Pkt::with_capacity(IPV6_HDR_LEN, IPV6_HDR_LEN + payload.len());
    p.put(payload.len()).map_err(|_| NetError::Enobufs)?.copy_from_slice(payload);
    push_ipv6_raw_header(&mut p, src, dst, next, hop, tclass)?;
    let bits = (6u32 << 28) | ((tclass as u32) << 20) | flow;
    p.data_mut()[..4].copy_from_slice(&bits.to_be_bytes());
    Ok(p)
}

fn emit_packet_fragment(iface_id: NetIfaceId, iface: crate::EgressLease,
    next_hop: Ipv6Addr, src: Ipv6Addr, dst: Ipv6Addr, next: u8, payload: &[u8],
    hop: u8, tclass: u8, flow: u32) -> NetResult<()> {
    let p = build_packet(src, dst, next, payload, hop, tclass, flow)?;
    emit_ipv6_fragment(iface_id, iface, next_hop, src, p)
}

/// Transmit an `IPV6_HDRINCL` message whose caller already built the whole packet.
///
/// `#[inline(never)]`: this arm builds two `Pkt` buffers that the kernel-header arm —
/// the one every ordinary raw send takes, already deep in a transmit chain — never
/// touches, and LLVM otherwise reserves both sets of locals in one frame.
/// # C: O(packet)
#[inline(never)]
fn emit_raw6_caller_header(owner: &crate::SocketOwner, iface_id: NetIfaceId,
    iface: crate::EgressLease, next_hop: Ipv6Addr, src: Ipv6Addr, bytes: &[u8], mtu: usize)
    -> NetResult<()>
{
    let mut p = crate::pkt::Pkt::with_capacity(0, bytes.len());
    p.put(bytes.len()).map_err(|_| NetError::Enobufs)?.copy_from_slice(bytes);
    if !admit_ipv6_owned(owner, iface_id, next_hop, src, p)? { return Ok(()); }
    if bytes.len() > core::cmp::min(iface.mtu() as usize, mtu) { return Err(NetError::Emsgsize); }
    let mut p = crate::pkt::Pkt::with_capacity(0, bytes.len());
    p.put(bytes.len()).map_err(|_| NetError::Enobufs)?.copy_from_slice(bytes);
    emit_ipv6_fragment(iface_id, iface, next_hop, src, p)
}
