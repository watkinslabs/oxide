use super::*;

pub(super) fn transfer_ring(bdf: pci::Bdf, dma_mask: u64) -> Option<(DmaPage, CommandRing)> {
    let ring = DmaPage::allocate(bdf, dma_mask)?;
    let link = Trb::link(ring.dma(), true)?;
    for (word, value) in link.dword.iter().enumerate() {
        if !ring.write32(((TRBS_PER_SEGMENT - 1) * TRB_BYTES + word * 4) as u64, *value) { return None; }
    }
    ring.clean_to_device();
    let producer = CommandRing::new(ring.dma())?;
    Some((ring, producer))
}

pub(super) fn submit_transfer(mmio: &Mmio, slot: u8, endpoint: u8, producer: &mut CommandRing, ring: &DmaPage, buffer: u64, length: u32) -> Option<u64> {
    let endpoint_id = (endpoint & 0x0f).checked_mul(2)?.checked_add(u8::from(endpoint & 0x80 != 0))?;
    let trb = Trb::normal(buffer, length)?;
    let (pa, _) = producer.push(trb);
    let index = pa.checked_sub(ring.dma())?.checked_div(TRB_BYTES as u64)? as usize;
    let written = producer.trb(index)?;
    for (word, value) in written.dword.iter().enumerate() { if !ring.write32((index * TRB_BYTES + word * 4) as u64, *value) { return None; } }
    ring.clean_to_device();
    mmio.ring_endpoint_doorbell(slot, endpoint_id).then_some(pa)
}

pub(super) fn pages_for(length: usize) -> Option<usize> {
    length.checked_add(DmaPage::BYTES - 1)?.checked_div(DmaPage::BYTES)
}

pub(super) fn ensure_storage_pages(bdf: pci::Bdf, dma_mask: u64, pages: &mut Vec<DmaPage>, length: usize) -> Option<()> {
    let needed = pages_for(length)?;
    if needed > crate::ring::COMMAND_USABLE_TRBS { return None; }
    while pages.len() < needed { pages.push(DmaPage::allocate(bdf, dma_mask)?); }
    Some(())
}

pub(super) fn submit_transfer_pages(mmio: &Mmio, slot: u8, endpoint: u8, producer: &mut CommandRing, ring: &DmaPage, pages: &[DmaPage], length: usize) -> Option<u64> {
    let endpoint_id = (endpoint & 0x0f).checked_mul(2)?.checked_add(u8::from(endpoint & 0x80 != 0))?;
    let count = pages_for(length)?;
    if count == 0 || count > pages.len() || count > producer.capacity() { return None; }
    let mut remaining = length;
    let mut completion = None;
    for (index, page) in pages.iter().take(count).enumerate() {
        let bytes = remaining.min(DmaPage::BYTES) as u32;
        let last = index + 1 == count;
        let trb = Trb::normal_chain(page.dma(), bytes, !last, last)?;
        let (pa, _) = producer.push(trb);
        let ring_index = pa.checked_sub(ring.dma())?.checked_div(TRB_BYTES as u64)? as usize;
        let written = producer.trb(ring_index)?;
        for (word, value) in written.dword.iter().enumerate() { if !ring.write32((ring_index * TRB_BYTES + word * 4) as u64, *value) { return None; } }
        remaining = remaining.checked_sub(bytes as usize)?;
        completion = Some(pa);
    }
    if remaining != 0 { return None; }
    ring.clean_to_device();
    mmio.ring_endpoint_doorbell(slot, endpoint_id).then_some(completion?)
}
