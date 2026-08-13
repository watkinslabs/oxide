use alloc::vec::Vec;

use pci::Bdf;
use sync::{Devices, Spinlock};

/// Requesters whose boot-time DMA ownership has been established.
///
/// This is deliberately keyed by the full PCI address, not only the 16-bit
/// requester ID: a firmware IOMMU unit is segment-scoped and equal requester
/// IDs in distinct PCI segments are different devices.
static ADMITTED_REQUESTERS: Spinlock<Vec<Bdf>, Devices> = Spinlock::new(Vec::new());

/// Publish the requesters that were quiesced before IOMMU setup completed.
///
/// This is called exactly once, after AMD-Vi and VT-d activation have either
/// installed their domains or established that this platform has no IOMMU.
/// Later hotplug requesters remain denied until the owner that creates their
/// domain explicitly admits them.
/// # C: O(requesters^2)
pub fn admit_boot_requesters(requesters: &[Bdf]) {
    let translation_active = super::amd_vi_manager::active() || super::vtd_manager::active();
    let mut admitted = ADMITTED_REQUESTERS.lock();
    admitted.clear();
    for &bdf in requesters {
        let owned = super::amd_vi_manager::owns(bdf) || super::vtd_manager::owns(bdf);
        if admits(translation_active, owned) && !admitted.contains(&bdf) { admitted.push(bdf); }
    }
}

/// Return whether IOMMU bring-up has established DMA ownership for `bdf`.
/// # C: O(requesters)
pub fn bus_master_admitted(bdf: Bdf) -> bool {
    contains_exact(&ADMITTED_REQUESTERS.lock(), bdf)
}

fn contains_exact(admitted: &[Bdf], bdf: Bdf) -> bool {
    admitted.iter().any(|candidate| *candidate == bdf)
}

fn admits(translation_active: bool, owned: bool) -> bool { !translation_active || owned }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_keeps_pci_segment_in_the_requester_key() {
        let bdf = Bdf { segment: 1, bus: 2, device: 3, function: 4 };
        let same_rid_elsewhere = Bdf { segment: 2, ..bdf };
        assert!(contains_exact(&[bdf], bdf));
        assert!(!contains_exact(&[bdf], same_rid_elsewhere));
    }

    #[test]
    fn active_translation_rejects_an_unowned_requester() {
        assert!(!admits(true, false));
        assert!(admits(true, true));
        assert!(admits(false, false));
    }
}
