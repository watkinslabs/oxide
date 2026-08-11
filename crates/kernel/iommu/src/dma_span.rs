/// Normalize one byte DMA request to the page interval the IOMMU must own.
/// # C: O(1)
pub(crate) fn normalize_dma_span(pa: u64, len: usize) -> Option<(u64, u64, u64)> {
    if len == 0 { return None; }
    let page = pci::IOVA_PAGE_SIZE;
    let base = pa & !(page - 1);
    let offset = pa - base;
    let bytes = offset.checked_add(len as u64)?.checked_add(page - 1)? & !(page - 1);
    base.checked_add(bytes)?;
    Some((base, bytes, offset))
}

#[cfg(test)] mod tests {
    use super::*;

    #[test] fn preserves_subpage_offset_and_rejects_overflow() {
        assert_eq!(normalize_dma_span(0x1234, 0x2345), Some((0x1000, 0x3000, 0x234)));
        assert_eq!(normalize_dma_span(0x1000, 0), None);
        assert_eq!(normalize_dma_span(u64::MAX, 2), None);
    }
}
