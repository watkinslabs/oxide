use alloc::vec::Vec;

use pci::Bdf;
use sync::{Devices, Spinlock};

/// One live DMA mapping owned by the requester and selected IOMMU backend.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct Mapping { requester: Bdf, iova: u64, pa: u64, len: usize }

static MAPPINGS: Spinlock<Vec<Mapping>, Devices> = Spinlock::new(Vec::new());

/// Install a DMA mapping for a PCI requester in its established IOMMU domain.
///
/// The selected IOMMU owner assigns device-visible IOVA space. It is recorded
/// under the full requester identity; callers must unmap before memory reuse.
/// # C: O(live mappings)
pub fn map_dma(requester: Bdf, pa: u64, len: usize) -> Option<u64> {
    map_dma_below(requester, pa, len, u64::MAX)
}

/// Install a DMA mapping constrained by the requester's inclusive DMA mask.
/// # C: O(live mappings)
pub fn map_dma_below(requester: Bdf, pa: u64, len: usize, mask: u64) -> Option<u64> {
    if len == 0 || !super::bus_master_admitted(requester) { return None; }
    let _ = pa.checked_add(len as u64 - 1)?;
    let iova = if super::amd_vi_manager::owns(requester) {
        super::amd_vi_manager::map_dma_below(requester, pa, len, mask)?
    } else if super::vtd_manager::owns(requester) {
        super::vtd_manager::map_dma_below(requester, pa, len, mask)?
    } else if pa.checked_add(len as u64 - 1)? <= mask { pa } else { return None };
    let mapping = Mapping { requester, iova, pa, len };
    MAPPINGS.lock().push(mapping);
    Some(mapping.iova)
}

/// Retire one exact DMA mapping before the backing memory can be reused.
/// # C: O(live mappings)
pub fn unmap_dma(requester: Bdf, iova: u64, len: usize) -> bool {
    if len == 0 { return false; }
    let mapping = {
        let mappings = MAPPINGS.lock();
        mappings.iter().copied().find(|mapping| mapping.requester == requester && mapping.iova == iova && mapping.len == len)
    };
    let Some(mapping) = mapping else { return false; };
    if super::amd_vi_manager::owns(requester) && !super::amd_vi_manager::unmap_dma(requester, iova, len) { return false; }
    if super::vtd_manager::owns(requester) && !super::vtd_manager::unmap_dma(requester, iova, len) { return false; }
    let mut mappings = MAPPINGS.lock();
    let Some(index) = mappings.iter().position(|candidate| *candidate == mapping) else { return false; };
    mappings.swap_remove(index);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_identity_retains_the_full_requester_key() {
        let first = Bdf { segment: 1, bus: 2, device: 3, function: 4 };
        let other_segment = Bdf { segment: 2, ..first };
        super::super::admit_boot_requesters(&[first]);
        let iova = map_dma(first, 0x4000, 4096).expect("admitted requester maps");
        assert_eq!(iova, 0x4000);
        assert!(!unmap_dma(other_segment, iova, 4096));
        assert!(unmap_dma(first, iova, 4096));
    }
}
