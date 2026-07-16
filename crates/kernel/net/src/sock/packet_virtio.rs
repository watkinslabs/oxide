use super::*;

pub(crate) const VNET_HEADER_LEN: u32 = crate::uapi::VIRTIO_NET_HDR_LEN;
pub(crate) const VNET_MRG_HEADER_LEN: u32 = crate::uapi::VIRTIO_NET_HDR_MRG_RXBUF_LEN;

use crate::uapi::{VIRTIO_NET_HDR_F_NEEDS_CSUM as F_NEEDS_CSUM,
    VIRTIO_NET_HDR_GSO_ECN as GSO_ECN, VIRTIO_NET_HDR_GSO_NONE as GSO_NONE,
    VIRTIO_NET_HDR_GSO_TCPV4 as GSO_TCPV4, VIRTIO_NET_HDR_GSO_TCPV6 as GSO_TCPV6,
    VIRTIO_NET_HDR_GSO_UDP as GSO_UDP, VIRTIO_NET_HDR_GSO_UDP_L4 as GSO_UDP_L4};
const GSO_BY_FRAGS: u16 = u16::MAX;
const UDP_MAX_SEGMENTS: usize = 128;
use crate::eth_p::{IPV4 as ETH_IPV4, IPV6 as ETH_IPV6, VLAN as ETH_VLAN,
                   VLAN_AD as ETH_VLAN_AD};
const IP_TCP: u8 = crate::IpProto::Tcp as u8;
const IP_UDP: u8 = crate::IpProto::Udp as u8;
const IP6_HOP: u8 = 0;
const IP6_ROUTING: u8 = 43;
const IP6_FRAGMENT: u8 = 44;
const IP6_ESP: u8 = 50;
const IP6_AUTH: u8 = 51;
const IP6_NONE: u8 = 59;
const IP6_DEST: u8 = 60;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct VirtioHeader {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
}

impl VirtioHeader {
    pub(crate) fn parse(bytes: &[u8]) -> crate::NetResult<Self> {
        if bytes.len() < VNET_HEADER_LEN as usize { return Err(crate::NetError::Einval); }
        Ok(Self {
            flags: bytes[0], gso_type: bytes[1],
            hdr_len: u16::from_le_bytes([bytes[2], bytes[3]]),
            gso_size: u16::from_le_bytes([bytes[4], bytes[5]]),
            csum_start: u16::from_le_bytes([bytes[6], bytes[7]]),
            csum_offset: u16::from_le_bytes([bytes[8], bytes[9]]),
        })
    }

    pub(crate) fn encode(self, size: u32) -> Vec<u8> {
        let mut bytes = alloc::vec![0; size as usize];
        if bytes.len() < VNET_HEADER_LEN as usize { return bytes; }
        bytes[0] = self.flags; bytes[1] = self.gso_type;
        bytes[2..4].copy_from_slice(&self.hdr_len.to_le_bytes());
        bytes[4..6].copy_from_slice(&self.gso_size.to_le_bytes());
        bytes[6..8].copy_from_slice(&self.csum_start.to_le_bytes());
        bytes[8..10].copy_from_slice(&self.csum_offset.to_le_bytes());
        bytes
    }
}

pub(crate) struct PreparedFrames {
    pub frames: Vec<Vec<u8>>,
    pub payload_len: usize,
}

#[derive(Clone, Copy)]
struct Network {
    ip: usize,
    eth: u16,
    transport: usize,
    next: u8,
    frag_at: usize,
    frag_next: usize,
}

fn l3(frame: &[u8]) -> crate::NetResult<(usize, u16)> {
    if frame.len() < crate::ethernet::ETH_HDR_LEN { return Err(crate::NetError::Einval); }
    let mut off = crate::ethernet::ETH_HDR_LEN;
    let mut protocol = u16::from_be_bytes([frame[12], frame[13]]);
    while matches!(protocol, ETH_VLAN | ETH_VLAN_AD) {
        if frame.len() < off + 4 { return Err(crate::NetError::Einval); }
        protocol = u16::from_be_bytes([frame[off + 2], frame[off + 3]]);
        off += 4;
    }
    Ok((off, protocol))
}

fn network(frame: &[u8]) -> crate::NetResult<Network> {
    let (ip, eth) = l3(frame)?;
    match eth {
        ETH_IPV4 => {
            if frame.len() < ip + 20 || frame[ip] >> 4 != 4 { return Err(crate::NetError::Einval); }
            let ihl = ((frame[ip] & 0x0f) as usize) * 4;
            if ihl < 20 || frame.len() < ip + ihl { return Err(crate::NetError::Einval); }
            let fragment = u16::from_be_bytes([frame[ip + 6], frame[ip + 7]]);
            if fragment & 0x3fff != 0 { return Err(crate::NetError::Einval); }
            Ok(Network { ip, eth, transport: ip + ihl, next: frame[ip + 9],
                frag_at: 0, frag_next: 0 })
        }
        ETH_IPV6 => network_v6(frame, ip),
        _ => Err(crate::NetError::Einval),
    }
}

fn network_v6(frame: &[u8], ip: usize) -> crate::NetResult<Network> {
    if frame.len() < ip + 40 || frame[ip] >> 4 != 6 { return Err(crate::NetError::Einval); }
    let mut off = ip + 40;
    let mut next = frame[ip + 6];
    let mut next_field = ip + 6;
    let mut frag_at = off;
    let mut frag_next = next_field;
    let mut found_routing = false;
    loop {
        let length = match next {
            IP6_HOP | IP6_ROUTING | IP6_DEST => {
                if next == IP6_HOP && off != ip + 40 { return Err(crate::NetError::Einval); }
                if next == IP6_DEST && found_routing && frag_at == ip + 40 {
                    frag_at = off; frag_next = next_field;
                }
                if next == IP6_ROUTING { found_routing = true; }
                if frame.len() < off + 2 { return Err(crate::NetError::Einval); }
                ((frame[off + 1] as usize) + 1) * 8
            }
            IP6_AUTH => {
                if frame.len() < off + 2 { return Err(crate::NetError::Einval); }
                ((frame[off + 1] as usize) + 2) * 4
            }
            IP6_FRAGMENT | IP6_ESP | IP6_NONE => return Err(crate::NetError::Einval),
            _ => {
                if frag_at == ip + 40 { frag_at = off; frag_next = next_field; }
                return Ok(Network { ip, eth: ETH_IPV6, transport: off, next,
                    frag_at, frag_next });
            }
        };
        if length < 8 || frame.len() < off + length { return Err(crate::NetError::Einval); }
        next_field = off; next = frame[off]; off += length;
    }
}

fn sum(mut value: u32, bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for pair in &mut chunks { value += u16::from_be_bytes([pair[0], pair[1]]) as u32; }
    if let Some(byte) = chunks.remainder().first() { value += (*byte as u32) << 8; }
    while value >> 16 != 0 { value = (value & 0xffff) + (value >> 16); }
    value
}

fn finish(value: u32) -> u16 { !(sum(value, &[]) as u16) }
fn checksum(bytes: &[u8]) -> u16 { finish(sum(0, bytes)) }
fn mangled(value: u16) -> u16 { if value == 0 { u16::MAX } else { value } }

fn partial_checksum(frame: &mut [u8], start: usize, offset: usize) -> crate::NetResult<()> {
    let field = start.checked_add(offset).ok_or(crate::NetError::Einval)?;
    if field + 2 > frame.len() { return Err(crate::NetError::Einval); }
    let value = mangled(checksum(&frame[start..]));
    frame[field..field + 2].copy_from_slice(&value.to_be_bytes());
    Ok(())
}

fn update_ip(frame: &mut [u8], net: Network, id_add: u16) -> crate::NetResult<()> {
    match net.eth {
        ETH_IPV4 => {
            let ihl = net.transport - net.ip;
            let length = frame.len() - net.ip;
            if length > u16::MAX as usize { return Err(crate::NetError::Einval); }
            frame[net.ip + 2..net.ip + 4].copy_from_slice(&(length as u16).to_be_bytes());
            let id = u16::from_be_bytes([frame[net.ip + 4], frame[net.ip + 5]]).wrapping_add(id_add);
            frame[net.ip + 4..net.ip + 6].copy_from_slice(&id.to_be_bytes());
            frame[net.ip + 10..net.ip + 12].fill(0);
            let value = checksum(&frame[net.ip..net.ip + ihl]);
            frame[net.ip + 10..net.ip + 12].copy_from_slice(&value.to_be_bytes());
        }
        ETH_IPV6 => {
            let length = frame.len() - net.ip - 40;
            if length > u16::MAX as usize { return Err(crate::NetError::Einval); }
            frame[net.ip + 4..net.ip + 6]
                .copy_from_slice(&(length as u16).to_be_bytes());
        }
        _ => return Err(crate::NetError::Einval),
    }
    Ok(())
}

fn transport_checksum(frame: &mut [u8], net: Network, field: usize) -> crate::NetResult<()> {
    if field + 2 > frame.len() || net.transport > frame.len() { return Err(crate::NetError::Einval); }
    frame[field..field + 2].fill(0);
    let length = frame.len() - net.transport;
    let mut value = match net.eth {
        ETH_IPV4 => {
            if length > u16::MAX as usize { return Err(crate::NetError::Einval); }
            let mut value = sum(0, &frame[net.ip + 12..net.ip + 20]);
            value = sum(value, &[0, net.next]); sum(value, &(length as u16).to_be_bytes())
        }
        ETH_IPV6 => {
            let mut value = sum(0, &frame[net.ip + 8..net.ip + 40]);
            value = sum(value, &(length as u32).to_be_bytes()); sum(value, &[0, 0, 0, net.next])
        }
        _ => return Err(crate::NetError::Einval),
    };
    value = sum(value, &frame[net.transport..]);
    frame[field..field + 2].copy_from_slice(&mangled(finish(value)).to_be_bytes());
    Ok(())
}

fn validate_partial(header: VirtioHeader, net: Network, offset: u16) -> crate::NetResult<()> {
    if header.flags & F_NEEDS_CSUM != 0 &&
        (header.csum_start as usize != net.transport || header.csum_offset != offset) {
        return Err(crate::NetError::Einval);
    }
    Ok(())
}

fn one_frame(body: &[u8], header: VirtioHeader, net: Network, field: usize)
    -> crate::NetResult<Vec<Vec<u8>>>
{
    let mut frame = body.to_vec();
    if header.flags & F_NEEDS_CSUM != 0 { transport_checksum(&mut frame, net, field)?; }
    Ok(alloc::vec![frame])
}

fn segment_transport(body: &[u8], header: VirtioHeader, net: Network, tcp: bool)
    -> crate::NetResult<Vec<Vec<u8>>>
{
    let transport = net.transport;
    let boundary = if tcp {
        if net.next != IP_TCP || body.len() < transport + 20 { return Err(crate::NetError::Einval); }
        validate_partial(header, net, 16)?;
        let length = ((body[transport + 12] >> 4) as usize) * 4;
        if length < 20 || body.len() < transport + length { return Err(crate::NetError::Einval); }
        transport + length
    } else {
        if net.next != IP_UDP || body.len() < transport + 8 || header.flags & F_NEEDS_CSUM == 0 {
            return Err(crate::NetError::Einval);
        }
        validate_partial(header, net, 6)?; transport + 8
    };
    let step = header.gso_size as usize;
    let data = &body[boundary..];
    if !tcp && data.len() > step.saturating_mul(UDP_MAX_SEGMENTS) {
        return Err(crate::NetError::Einval);
    }
    let field = transport + if tcp { 16 } else { 6 };
    if data.len() <= step { return one_frame(body, header, net, field); }
    let count = data.len().div_ceil(step);
    let mut frames = Vec::new();
    frames.try_reserve_exact(count).map_err(|_| crate::NetError::Enobufs)?;
    for (index, chunk) in data.chunks(step).enumerate() {
        let mut frame = body[..boundary].to_vec(); frame.extend_from_slice(chunk);
        update_ip(&mut frame, net, index as u16)?;
        if tcp {
            let sequence = u32::from_be_bytes(frame[transport + 4..transport + 8].try_into().unwrap())
                .wrapping_add((index * step) as u32);
            frame[transport + 4..transport + 8].copy_from_slice(&sequence.to_be_bytes());
            if index + 1 != count { frame[transport + 13] &= !(0x01 | 0x08); }
            if index != 0 { frame[transport + 13] &= !0x80; }
        } else {
            let length = frame.len() - transport;
            frame[transport + 4..transport + 6]
                .copy_from_slice(&(length as u16).to_be_bytes());
        }
        transport_checksum(&mut frame, net, field)?; frames.push(frame);
    }
    Ok(frames)
}

fn segment_ufo(body: &[u8], header: VirtioHeader, net: Network) -> crate::NetResult<Vec<Vec<u8>>> {
    if net.next != IP_UDP || body.len() < net.transport + 8 { return Err(crate::NetError::Einval); }
    validate_partial(header, net, 6)?;
    let total = body.len() - net.transport;
    let requested = header.gso_size as usize;
    if total <= requested { return one_frame(body, header, net, net.transport + 6); }
    let step = requested & !7;
    if step == 0 { return Err(crate::NetError::Einval); }
    let mut complete = body.to_vec();
    transport_checksum(&mut complete, net, net.transport + 6)?;
    match net.eth {
        ETH_IPV4 => fragment_v4(&complete, net, step),
        ETH_IPV6 => fragment_v6(&complete, net, step),
        _ => Err(crate::NetError::Einval),
    }
}

fn fragment_v4(body: &[u8], net: Network, step: usize) -> crate::NetResult<Vec<Vec<u8>>> {
    let prefix = &body[..net.transport];
    let data = &body[net.transport..];
    let mut frames = Vec::new();
    for (index, chunk) in data.chunks(step).enumerate() {
        let mut frame = prefix.to_vec(); frame.extend_from_slice(chunk);
        let more = (index + 1) * step < data.len();
        let fragment = (((index * step) / 8) as u16) | if more { 0x2000 } else { 0 };
        frame[net.ip + 6..net.ip + 8].copy_from_slice(&fragment.to_be_bytes());
        update_ip(&mut frame, net, 0)?; frames.push(frame);
    }
    Ok(frames)
}

fn fragment_v6(body: &[u8], net: Network, step: usize) -> crate::NetResult<Vec<Vec<u8>>> {
    let data = &body[net.frag_at..];
    let mut id = 0u32;
    for chunk in body[net.ip + 8..net.ip + 40].chunks_exact(4) {
        id ^= u32::from_be_bytes(chunk.try_into().unwrap());
    }
    let mut frames = Vec::new();
    for (index, chunk) in data.chunks(step).enumerate() {
        let mut frame = body[..net.frag_at].to_vec();
        frame[net.frag_next] = IP6_FRAGMENT;
        frame.extend_from_slice(&[body[net.frag_next], 0, 0, 0]);
        frame.extend_from_slice(&id.to_be_bytes()); frame.extend_from_slice(chunk);
        let more = (index + 1) * step < data.len();
        let fragment = ((index * step) as u16) | if more { 1 } else { 0 };
        frame[net.frag_at + 2..net.frag_at + 4].copy_from_slice(&fragment.to_be_bytes());
        update_ip(&mut frame, net, 0)?; frames.push(frame);
    }
    Ok(frames)
}

/// Parse one optional virtio header and produce device-sized software segments. # C: O(payload)
pub(crate) fn prepare(payload: &[u8], header_size: u32, max_frame: usize)
    -> crate::NetResult<PreparedFrames>
{
    if header_size == 0 {
        if payload.len() > max_frame { return Err(crate::NetError::Emsgsize); }
        return Ok(PreparedFrames { frames: alloc::vec![payload.to_vec()], payload_len: payload.len() });
    }
    if payload.len() < header_size as usize { return Err(crate::NetError::Einval); }
    let mut header = VirtioHeader::parse(payload)?;
    let body = &payload[header_size as usize..];
    if header.flags & F_NEEDS_CSUM != 0 {
        let required = (header.csum_start as usize).checked_add(header.csum_offset as usize)
            .and_then(|value| value.checked_add(2)).ok_or(crate::NetError::Einval)?;
        header.hdr_len = core::cmp::max(header.hdr_len as usize, required)
            .try_into().map_err(|_| crate::NetError::Einval)?;
    }
    if header.hdr_len as usize > body.len() { return Err(crate::NetError::Einval); }
    let kind = header.gso_type & !GSO_ECN;
    let mut frames = if header.gso_type == GSO_ECN {
        return Err(crate::NetError::Einval);
    } else if kind == GSO_NONE {
        let mut frame = body.to_vec();
        if header.flags & F_NEEDS_CSUM != 0 {
            partial_checksum(&mut frame, header.csum_start as usize, header.csum_offset as usize)?;
        }
        alloc::vec![frame]
    } else {
        if matches!(header.gso_size, 0 | GSO_BY_FRAGS) { return Err(crate::NetError::Einval); }
        if kind == GSO_UDP_L4 && header.gso_type & GSO_ECN != 0 {
            return Err(crate::NetError::Einval);
        }
        let net = network(body)?;
        match kind {
            GSO_TCPV4 if net.eth == ETH_IPV4 => segment_transport(body, header, net, true)?,
            GSO_TCPV6 if net.eth == ETH_IPV6 => segment_transport(body, header, net, true)?,
            GSO_UDP_L4 => segment_transport(body, header, net, false)?,
            GSO_UDP => segment_ufo(body, header, net)?,
            _ => return Err(crate::NetError::Einval),
        }
    };
    if frames.iter().any(|frame| frame.len() > max_frame) {
        return Err(crate::NetError::Emsgsize);
    }
    Ok(PreparedFrames { frames: core::mem::take(&mut frames), payload_len: body.len() })
}

#[cfg(test)]
#[path = "packet_virtio/tests.rs"]
mod tests;
