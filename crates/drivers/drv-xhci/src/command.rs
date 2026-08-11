//! Controller-owned command-ring DMA publication.

use crate::platform::{DmaPage, Mmio};
use crate::ring::{CommandRing, Trb, TRB_BYTES};

/// Retained command-ring page and its software producer cursor.
pub struct CommandTransport { page: DmaPage, ring: CommandRing }

impl CommandTransport {
    /// Take ownership of the page already named by CRCR. # C: O(1)
    pub fn new(page: DmaPage) -> Option<Self> { Some(Self { ring: CommandRing::new(page.dma())?, page }) }
    /// Submit exactly one command after writing and synchronizing its TRB. # C: O(1)
    pub fn submit(&mut self, mmio: &Mmio, trb: Trb) -> Option<u64> {
        let (pa, _) = self.ring.push(trb);
        let index = pa.checked_sub(self.page.dma())?.checked_div(TRB_BYTES as u64)? as usize;
        let trb = self.ring.trb(index)?;
        for (word, value) in trb.dword.iter().enumerate() {
            if !self.page.write32((index * TRB_BYTES + word * 4) as u64, *value) { return None; }
        }
        self.page.clean_to_device();
        mmio.ring_command_doorbell().then_some(pa)
    }
}
