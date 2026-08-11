//! Retained controller DMA ownership for one Address Device operation.

use crate::context;
use crate::platform::DmaPage;
use crate::platform::Mmio;
use crate::ring::{CommandRing, Trb, TRB_BYTES, TRBS_PER_SEGMENT};

/// Input context, output device context, and endpoint-zero transfer ring.
pub struct AddressDeviceDma { input: DmaPage, output: DmaPage, ep0: DmaPage, ep0_ring: CommandRing }

impl AddressDeviceDma {
    /// Allocate and construct every DMA object required by Address Device. # C: O(page bytes)
    pub fn allocate(context_bytes: u8, port: u8, portsc: u32) -> Option<Self> {
        let input = DmaPage::allocate()?;
        let output = DmaPage::allocate()?;
        let ep0 = DmaPage::allocate()?;
        let words = context::address_device_words(context_bytes, port, portsc, ep0.pa())?;
        for word in words { if !input.write32(word.offset as u64, word.value) { return None; } }
        let link = Trb::link(ep0.pa(), true)?;
        for (word, value) in link.dword.iter().enumerate() {
            if !ep0.write32(((TRBS_PER_SEGMENT - 1) * 16 + word * 4) as u64, *value) { return None; }
        }
        input.clean_to_device(); output.clean_to_device(); ep0.clean_to_device();
        let ep0_ring = CommandRing::new(ep0.pa())?;
        Some(Self { input, output, ep0, ep0_ring })
    }

    /// Input-context physical address for Address Device. # C: O(1)
    pub fn input_pa(&self) -> u64 { self.input.pa() }
    /// Endpoint-zero transfer-ring physical address. # C: O(1)
    pub fn ep0_pa(&self) -> u64 { self.ep0.pa() }
    /// Publish one complete EP0 control-transfer TD and ring endpoint zero. # C: O(TRBs)
    pub fn submit_ep0(&mut self, mmio: &Mmio, slot: u8, trbs: &[Trb]) -> Option<u64> {
        if !(2..=3).contains(&trbs.len()) { return None; }
        let mut completion = 0;
        for trb in trbs {
            let (pa, _) = self.ep0_ring.push(*trb);
            let index = pa.checked_sub(self.ep0.pa())?.checked_div(TRB_BYTES as u64)? as usize;
            let written = self.ep0_ring.trb(index)?;
            for (word, value) in written.dword.iter().enumerate() {
                if !self.ep0.write32((index * TRB_BYTES + word * 4) as u64, *value) { return None; }
            }
            completion = pa;
        }
        self.ep0.clean_to_device();
        mmio.ring_endpoint_doorbell(slot, 1).then_some(completion)
    }
    /// Publish the output device context in a valid nonzero DCBAA slot. # C: O(1)
    pub fn publish_dcbaa(&self, dcbaa: &DmaPage, slot: u8) -> bool {
        if slot == 0 || (slot as usize) * 8 + 8 > 4096 { return false; }
        let offset = slot as u64 * 8;
        if !dcbaa.write32(offset, self.output.pa() as u32) || !dcbaa.write32(offset + 4, (self.output.pa() >> 32) as u32) { return false; }
        dcbaa.clean_to_device();
        true
    }
}
