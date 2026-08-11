use alloc::vec::Vec;

use pci::Bdf;
use sync::{Devices, Spinlock};

/// One live DMA mapping through the boot identity domain.
///
/// The address is intentionally retained as an IOVA rather than treated as a
/// bare physical address.  The initial domains are identity mapped, but this
/// ownership record is the common ABI boundary for a later non-identity IOVA
/// allocator and prevents one PCI requester from unmapping another's DMA.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct Mapping { requester: Bdf, iova: u64, pa: u64, len: usize }

static MAPPINGS: Spinlock<Vec<Mapping>, Devices> = Spinlock::new(Vec::new());

/// Install a DMA mapping for a PCI requester in its established IOMMU domain.
///
/// Boot domains deliberately map PMM RAM at equal IOVA and physical addresses,
/// so the address returned now is `pa`.  It is nevertheless recorded under the
/// full requester identity; callers must use `unmap_dma` before memory is
/// reused.
/// # C: O(live mappings)
pub fn map_dma(requester: Bdf, pa: u64, len: usize) -> Option<u64> {
    if len == 0 || !super::bus_master_admitted(requester) { return None; }
    let _ = pa.checked_add(len as u64 - 1)?;
    let mapping = Mapping { requester, iova: pa, pa, len };
    MAPPINGS.lock().push(mapping);
    Some(mapping.iova)
}

/// Retire one exact DMA mapping before the backing memory can be reused.
/// # C: O(live mappings)
pub fn unmap_dma(requester: Bdf, iova: u64, len: usize) -> bool {
    if len == 0 { return false; }
    let mut mappings = MAPPINGS.lock();
    let Some(index) = mappings.iter().position(|mapping|
        mapping.requester == requester && mapping.iova == iova && mapping.len == len) else { return false; };
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
