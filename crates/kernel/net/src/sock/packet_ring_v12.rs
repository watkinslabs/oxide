use super::*;

const ROOM_SHIFT: u32 = 2;
const HEADER_GAP: u32 = 16;
const NS_PER_SEC: u64 = 1_000_000_000;
const NS_PER_USEC: u64 = 1_000;

pub(crate) struct PacketRingInput<'a> {
    pub payload: &'a [u8],
    pub addr: PacketAddr,
    pub aux: PacketAuxData,
    pub datagram: bool,
    pub rxhash: u32,
}

fn align(value: u32) -> Option<u32> {
    value.checked_add(crate::uapi::TPACKET_ALIGNMENT - 1)
        .map(|v| v & !(crate::uapi::TPACKET_ALIGNMENT - 1))
}

fn room(ring: &PacketRingMemory) -> PacketRoom {
    let count = ring.frame_count();
    if count == 0 { return PacketRoom::None; }
    let head = ring.head();
    let future = head.wrapping_add(count >> ROOM_SHIFT) % count;
    if ring.status(future) == Some(crate::uapi::TP_STATUS_KERNEL) { PacketRoom::Normal }
    else if ring.status(head) == Some(crate::uapi::TP_STATUS_KERNEL) { PacketRoom::Low }
    else { PacketRoom::None }
}

fn readable(ring: &PacketRingMemory) -> bool {
    let count = ring.frame_count();
    if count == 0 { return false; }
    let previous = if ring.head() == 0 { count - 1 } else { ring.head() - 1 };
    ring.status(previous).is_some_and(|status| status != crate::uapi::TP_STATUS_KERNEL)
}

fn write_u16(ring: &PacketRingMemory, off: u64, value: u16) -> bool {
    ring.write(off, &value.to_ne_bytes())
}

fn write_u32(ring: &PacketRingMemory, off: u64, value: u32) -> bool {
    ring.write(off, &value.to_ne_bytes())
}

fn write_v1(ring: &PacketRingMemory, frame: u64, input: &PacketRingInput<'_>,
            snaplen: u32, mac: u16, net: u16, now_ns: u64) -> bool {
    write_u32(ring, frame + 8, input.aux.len)
        && write_u32(ring, frame + 12, snaplen)
        && write_u16(ring, frame + 16, mac)
        && write_u16(ring, frame + 18, net)
        && write_u32(ring, frame + 20, (now_ns / NS_PER_SEC) as u32)
        && write_u32(ring, frame + 24, ((now_ns % NS_PER_SEC) / NS_PER_USEC) as u32)
}

fn write_v2(ring: &PacketRingMemory, frame: u64, input: &PacketRingInput<'_>,
            snaplen: u32, mac: u16, net: u16, now_ns: u64) -> bool {
    write_u32(ring, frame + 4, input.aux.len)
        && write_u32(ring, frame + 8, snaplen)
        && write_u16(ring, frame + 12, mac)
        && write_u16(ring, frame + 14, net)
        && write_u32(ring, frame + 16, (now_ns / NS_PER_SEC) as u32)
        && write_u32(ring, frame + 20, (now_ns % NS_PER_SEC) as u32)
        && write_u16(ring, frame + 24, input.aux.vlan_tci)
        && write_u16(ring, frame + 26, input.aux.vlan_tpid)
        && ring.write(frame + 28, &[0; 4])
}

fn write_sockaddr(ring: &PacketRingMemory, frame: u64, input: &PacketRingInput<'_>) -> bool {
    let mut address = [0u8; crate::uapi::SOCKADDR_LL_LEN as usize];
    address[0..2].copy_from_slice(&AF_PACKET.to_ne_bytes());
    address[2..4].copy_from_slice(&input.addr.protocol.to_be_bytes());
    address[4..8].copy_from_slice(&input.addr.ifindex.to_ne_bytes());
    address[8..10].copy_from_slice(&input.addr.hatype.to_ne_bytes());
    address[10] = input.addr.pkttype;
    address[11] = input.addr.halen;
    address[12..20].copy_from_slice(&input.addr.addr);
    ring.write(frame + crate::uapi::TPACKET_V1_HEADER_LEN as u64, &address)
}

fn offsets(ring_header: u32, mac_len: u32, reserve: u32, datagram: bool)
    -> Option<(u32, u32)> {
    let net = if datagram {
        align(ring_header)?.checked_add(HEADER_GAP)?.checked_add(reserve)?
    } else {
        align(ring_header.checked_add(mac_len.max(HEADER_GAP))?)?.checked_add(reserve)?
    };
    Some((net.checked_sub(if datagram { 0 } else { mac_len })?, net))
}

struct PublishResult { published: bool, copied: bool }

struct CopyInput<'a> {
    queue: &'a mut PacketRxQueue,
    addr: PacketAddr,
    aux: PacketAuxData,
    payload: &'a [u8],
    limit: usize,
}

fn admit_copy(copy: CopyInput<'_>) -> bool {
    let mut aux = copy.aux;
    aux.snaplen = copy.payload.len().min(u32::MAX as usize) as u32;
    let mut payload = Vec::with_capacity(aux.vnet_hdr_size as usize + copy.payload.len());
    payload.extend_from_slice(&aux.vnet_header[..aux.vnet_hdr_size as usize]);
    payload.extend_from_slice(copy.payload);
    let frame = PacketFrame { payload, addr: copy.addr, aux,
        charge: core::mem::size_of::<PacketFrame>().saturating_add(copy.payload.len())
            .saturating_add(aux.vnet_hdr_size as usize) };
    copy.queue.admit_copy(frame, copy.limit)
}

fn publish(ring: &PacketRingMemory, input: &PacketRingInput<'_>, losing: bool,
           now_ns: u64, copy: Option<CopyInput<'_>>)
    -> PublishResult {
    let failed = PublishResult { published: false, copied: false };
    if !matches!(ring.layout().version, crate::uapi::TPACKET_V1 | crate::uapi::TPACKET_V2)
        || room(ring) == PacketRoom::None { return failed; }
    let layout = ring.layout();
    let ring_header = align(crate::uapi::TPACKET_V1_HEADER_LEN)
        .and_then(|header| header.checked_add(crate::uapi::SOCKADDR_LL_LEN));
    let Some(ring_header) = ring_header else { return failed; };
    let mac_len = if input.datagram { 0 } else { input.aux.net as u32 };
    let Some((base_mac, base_net)) = offsets(ring_header, mac_len, layout.reserve, input.datagram)
        else { return failed; };
    let vnet = input.aux.vnet_hdr_size as u32;
    let Some(mac) = base_mac.checked_add(vnet) else { return failed; };
    let Some(net) = base_net.checked_add(vnet) else { return failed; };
    if net > u16::MAX as u32 { return failed; }
    if mac > u16::MAX as u32 { return failed; }
    let available = layout.request.frame_size.saturating_sub(mac);
    let snaplen = (input.payload.len().min(input.aux.snaplen as usize) as u32).min(available);
    let index = ring.head();
    if ring.status(index) != Some(crate::uapi::TP_STATUS_KERNEL) { return failed; }
    ring.advance_head();
    let Some(frame) = ring.frame_offset(index) else { return failed; };
    let timestamp_ns = input.aux.timestamp_ns.unwrap_or(now_ns);
    let header = if layout.version == crate::uapi::TPACKET_V1 {
        write_v1(ring, frame, input, snaplen, mac as u16, net as u16, timestamp_ns)
    } else {
        write_v2(ring, frame, input, snaplen, mac as u16, net as u16, timestamp_ns)
    };
    if !header || !write_sockaddr(ring, frame, input)
        || (vnet != 0 && !ring.write(frame + (mac - VNET_HDR_SIZE as u32) as u64,
            &input.aux.vnet_header[..VNET_HDR_SIZE]))
        || !ring.write(frame + mac as u64, &input.payload[..snaplen as usize]) { return failed; }
    let copied = if snaplen < input.payload.len() as u32 && input.aux.copy_thresh {
        copy.is_some_and(admit_copy)
    } else { false };
    let mut status = input.aux.status | input.aux.timestamp_status;
    if layout.version == crate::uapi::TPACKET_V1 {
        status &= !(crate::uapi::TP_STATUS_VLAN_VALID | crate::uapi::TP_STATUS_VLAN_TPID_VALID);
    }
    if losing { status |= crate::uapi::TP_STATUS_LOSING; }
    if copied { status |= TP_STATUS_COPY; }
    PublishResult { published: ring.publish_status(index, status), copied }
}

impl InetSocket {
    #[cfg(test)]
    /// Publish one frame directly for deterministic ABI tests. # C: O(payload)
    pub(crate) fn publish_packet_ring_v12(&self, input: PacketRingInput<'_>, now_ns: u64)
        -> Option<bool> {
        let rings = self.packet_rings.lock();
        let ring = rings.rx()?.clone();
        let kind = self.kind.lock();
        let SockKind::Packet { rx, .. } = &*kind else { return Some(false); };
        let mut queue = rx.lock();
        let result = publish(&ring, &input, queue.has_drops(), now_ns, None);
        queue.account_ring(result.published);
        Some(result.published)
    }

    /// Select exactly one ring or queue receive destination. # C: O(payload)
    pub(crate) fn route_packet_receive(&self, input: PacketRingInput<'_>, queued: PacketFrame,
                                       limit: usize, now_ns: u64) -> bool {
        let full = input.payload;
        self.route_packet_receive_full(input, queued, full, limit, now_ns)
    }

    /// Route receive while retaining the unclamped packet for V1/V2 copy fallback. # C: O(payload)
    pub(crate) fn route_packet_receive_full(&self, input: PacketRingInput<'_>,
        queued: PacketFrame, full: &[u8], limit: usize, now_ns: u64) -> bool
    {
        let mut rings = self.packet_rings.lock();
        let kind = self.kind.lock();
        let SockKind::Packet { rx, .. } = &*kind else { return false; };
        let mut queue = rx.lock();
        route_packet_receive_locked(&mut rings, &mut queue, input, queued, full, limit, now_ns)
    }

    /// Classify Linux V1/V2 fanout rollover room. # C: O(1)
    pub(crate) fn packet_ring_room(&self) -> Option<PacketRoom> {
        let rings = self.packet_rings.lock();
        let ring = rings.rx()?;
        if ring.layout().version == crate::uapi::TPACKET_V3 {
            Some(room_v3(rings.rx_v3.as_ref()?, ring))
        } else { Some(room(ring)) }
    }

    /// Report previous-frame receive-ring poll readiness. # C: O(1)
    pub(crate) fn packet_ring_readable(&self) -> bool {
        let rings = self.packet_rings.lock();
        rings.rx().is_some_and(|ring| {
            if ring.layout().version == crate::uapi::TPACKET_V3 {
                rings.rx_v3.as_ref().is_some_and(|state| readable_v3(state, ring))
            } else { readable(ring) }
        })
    }
}

/// Commit one receive record under the socket's ring/configuration transaction. # C: O(payload)
pub(crate) fn route_packet_receive_locked(rings: &mut PacketRings, queue: &mut PacketRxQueue,
    input: PacketRingInput<'_>, queued: PacketFrame, full: &[u8], limit: usize, now_ns: u64) -> bool
{
    if let Some(ring) = rings.rx.clone() {
        let published = if ring.layout().version == crate::uapi::TPACKET_V3 {
            let result = publish_v3(&mut rings.rx_v3, &ring, &input,
                queue.has_drops(), now_ns);
            if result.froze { queue.account_freeze(); }
            result.published
        } else {
            let losing = queue.has_drops();
            let result = publish(&ring, &input, losing, now_ns,
                Some(CopyInput { queue, addr: queued.addr, aux: queued.aux,
                    payload: full, limit }));
            if !result.copied { queue.account_ring(result.published); }
            return true;
        };
        queue.account_ring(published);
        return true;
    }
    queue.admit(queued, limit)
}
