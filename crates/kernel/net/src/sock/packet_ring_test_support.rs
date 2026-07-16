use super::*;

impl PacketRingMmap {
    pub(crate) fn read(&self, mut off: u64, bytes: &mut [u8]) -> bool {
        for ring in &self.rings {
            if off < ring.len() { return ring.copy(off, bytes); }
            off -= ring.len();
        }
        false
    }

    pub(crate) fn release_rx_frame(&self, index: u32) -> bool {
        self.rings.first().is_some_and(|ring| ring.publish_status(index,
            crate::uapi::TP_STATUS_KERNEL))
    }

    pub(crate) fn release_rx_block(&self, index: u32) -> bool {
        let Some(ring) = self.rings.first() else { return false; };
        let off = index as u64 * ring.layout().request.block_size as u64 + 8;
        ring.store_u32(off, crate::uapi::TP_STATUS_KERNEL)
    }

    pub(crate) fn write_test(&self, mut off: u64, bytes: &[u8]) -> bool {
        for ring in &self.rings {
            if off < ring.len() { return ring.write(off, bytes); }
            off -= ring.len();
        }
        false
    }

    pub(crate) fn tx_test(&self) -> Option<&Arc<PacketRingMemory>> {
        self.rings.iter().find(|ring| ring.layout().kind == PacketRingKind::Tx)
    }
}
