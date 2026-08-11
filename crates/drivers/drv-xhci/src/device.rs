//! Retained controller DMA ownership for one Address Device operation.

use crate::context;
use crate::platform::DmaPage;
use crate::ring::{Trb, TRBS_PER_SEGMENT};

/// Input context, output device context, and endpoint-zero transfer ring.
pub struct AddressDeviceDma { input: DmaPage, output: DmaPage, ep0: DmaPage }

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
        Some(Self { input, output, ep0 })
    }

    /// Input-context physical address for Address Device. # C: O(1)
    pub fn input_pa(&self) -> u64 { self.input.pa() }
    /// Endpoint-zero transfer-ring physical address. # C: O(1)
    pub fn ep0_pa(&self) -> u64 { self.ep0.pa() }
    /// Publish the output device context in a valid nonzero DCBAA slot. # C: O(1)
    pub fn publish_dcbaa(&self, dcbaa: &DmaPage, slot: u8) -> bool {
        if slot == 0 || (slot as usize) * 8 + 8 > 4096 { return false; }
        let offset = slot as u64 * 8;
        if !dcbaa.write32(offset, self.output.pa() as u32) || !dcbaa.write32(offset + 4, (self.output.pa() >> 32) as u32) { return false; }
        dcbaa.clean_to_device();
        true
    }
}
