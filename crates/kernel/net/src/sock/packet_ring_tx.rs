use super::*;
use core::sync::atomic::{AtomicBool, Ordering};

pub(crate) struct PacketTxGate(AtomicBool);

pub(crate) struct PacketTxGuard<'a>(&'a PacketTxGate);

impl PacketTxGate {
    pub(crate) const fn new() -> Self { Self(AtomicBool::new(false)) }

    pub(crate) fn lock(&self) -> PacketTxGuard<'_> {
        while self.0.compare_exchange_weak(false, true, Ordering::Acquire,
            Ordering::Relaxed).is_err()
        { core::hint::spin_loop(); }
        PacketTxGuard(self)
    }
}

impl Drop for PacketTxGuard<'_> {
    fn drop(&mut self) { self.0.0.store(false, Ordering::Release); }
}

fn read_u32(ring: &PacketRingMemory, off: u64) -> Option<u32> {
    let mut bytes = [0u8; 4];
    ring.copy(off, &mut bytes).then(|| u32::from_ne_bytes(bytes))
}

fn read_u16(ring: &PacketRingMemory, off: u64) -> Option<u16> {
    let mut bytes = [0u8; 2];
    ring.copy(off, &mut bytes).then(|| u16::from_ne_bytes(bytes))
}

fn frame_len(ring: &PacketRingMemory, frame: u64) -> crate::NetResult<u32> {
    match ring.layout().version {
        crate::uapi::TPACKET_V1 => read_u32(ring, frame + 8),
        crate::uapi::TPACKET_V2 => read_u32(ring, frame + 4),
        crate::uapi::TPACKET_V3 => {
            if read_u32(ring, frame) != Some(0) { return Err(crate::NetError::Einval); }
            read_u32(ring, frame + 16)
        }
        _ => None,
    }.ok_or(crate::NetError::Einval)
}

fn frame_payload(ring: &PacketRingMemory, target: &PacketTxTarget, index: u32,
                 has_offset: bool)
    -> crate::NetResult<Vec<u8>>
{
    let frame = ring.frame_offset(index).ok_or(crate::NetError::Einval)?;
    let length = frame_len(ring, frame)? as usize;
    let minimum = packet_header_len(ring.layout().version)?;
    let offset = if has_offset {
        let field = match (ring.layout().version, target.datagram()) {
            (crate::uapi::TPACKET_V1, false) => 16,
            (crate::uapi::TPACKET_V1, true) => 18,
            (crate::uapi::TPACKET_V2, false) => 12,
            (crate::uapi::TPACKET_V2, true) => 14,
            (crate::uapi::TPACKET_V3, false) => 24,
            (crate::uapi::TPACKET_V3, true) => 26,
            _ => return Err(crate::NetError::Einval),
        };
        read_u16(ring, frame + field).ok_or(crate::NetError::Einval)? as u32
    } else { minimum };
    let maximum = ring.layout().request.frame_size.checked_sub(length as u32)
        .ok_or(crate::NetError::Emsgsize)?;
    if offset < minimum || offset > maximum { return Err(crate::NetError::Einval); }
    let mut payload = Vec::new();
    payload.try_reserve_exact(length).map_err(|_| crate::NetError::Enobufs)?;
    payload.resize(length, 0);
    if !ring.copy(frame + offset as u64, &mut payload) { return Err(crate::NetError::Einval); }
    Ok(payload)
}

impl InetSocket {
    /// Report whether sendmsg must kick a configured packet TX ring. # C: O(1)
    pub fn has_packet_tx_ring(&self) -> bool { self.packet_rings.lock().tx().is_some() }

    /// Consume all consecutive SEND_REQUEST frames from one packet TX ring. # C: O(frames * transmit)
    pub fn kick_packet_tx_ring(&self, address: Option<PacketTxAddress>) -> crate::NetResult<usize> {
        let _tx = self.packet_tx.lock();
        if self.released.load(Ordering::Acquire) { return Err(crate::NetError::Ebusy); }
        let ring = self.packet_rings.lock().tx.clone().ok_or(crate::NetError::Ebusy)?;
        let target = resolve_packet_tx(self, address)?;
        let loss = self.packet_loss()?;
        let has_offset = self.packet_tx_has_off()?;
        let mut total = 0usize;
        for _ in 0..ring.frame_count() {
            let index = ring.head();
            if ring.status(index) != Some(crate::uapi::TP_STATUS_SEND_REQUEST) { break; }
            if !ring.claim_status(index, crate::uapi::TP_STATUS_SEND_REQUEST,
                crate::uapi::TP_STATUS_SENDING) { break; }
            let payload = match frame_payload(&ring, &target, index, has_offset) {
                Ok(payload) => payload,
                Err(crate::NetError::Enobufs) => {
                    let _ = ring.publish_status(index, crate::uapi::TP_STATUS_SEND_REQUEST);
                    self.poll_subs.notify();
                    return if total == 0 { Err(crate::NetError::Enobufs) } else { Ok(total) };
                }
                Err(_) if loss => {
                    let _ = ring.publish_status(index, crate::uapi::TP_STATUS_AVAILABLE);
                    ring.advance_head();
                    continue;
                }
                Err(error) => {
                    let _ = ring.publish_status(index, crate::uapi::TP_STATUS_WRONG_FORMAT);
                    self.poll_subs.notify();
                    return Err(error);
                }
            };
            match target.transmit(self, &payload) {
                Ok(length) => {
                    let _ = ring.publish_status(index, crate::uapi::TP_STATUS_AVAILABLE);
                    ring.advance_head();
                    total = total.saturating_add(length);
                }
                Err(error) if matches!(error, crate::NetError::Einval
                    | crate::NetError::Emsgsize) && loss => {
                    let _ = ring.publish_status(index, crate::uapi::TP_STATUS_AVAILABLE);
                    ring.advance_head();
                    continue;
                }
                Err(error) if matches!(error, crate::NetError::Einval
                    | crate::NetError::Emsgsize) => {
                    let _ = ring.publish_status(index, crate::uapi::TP_STATUS_WRONG_FORMAT);
                    self.poll_subs.notify();
                    return Err(error);
                }
                Err(error) => {
                    let _ = ring.publish_status(index, crate::uapi::TP_STATUS_SEND_REQUEST);
                    self.poll_subs.notify();
                    return if error == crate::NetError::Enobufs && total != 0 {
                        Ok(total)
                    } else { Err(error) };
                }
            }
        }
        self.poll_subs.notify();
        Ok(total)
    }

    /// Report Linux packet TX-ring current-frame writability. # C: O(1)
    pub(crate) fn packet_tx_ring_writable(&self) -> Option<bool> {
        let rings = self.packet_rings.lock();
        let ring = rings.tx()?;
        Some(ring.status(ring.head()) == Some(crate::uapi::TP_STATUS_AVAILABLE))
    }
}
