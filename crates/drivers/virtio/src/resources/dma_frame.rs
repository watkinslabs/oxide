use alloc::vec::Vec;

use crate::VirtioDmaFrame;

/// Every frame retained by a failed transport probe. Ring pages retain both
/// address domains so the transport can retire the device mapping before PMM
/// is allowed to reuse the physical page.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VirtioProbeFrameSet {
    pub vring_frames: Vec<VirtioDmaFrame>,
    pub payload_frames: Vec<VirtioDmaFrame>,
}

/// Allocate one PMM frame and establish the BDF-scoped DMA mapping before a
/// child can publish its IOVA in a virtqueue descriptor. # C: O(1)
pub fn allocate_dma_frame(bdf: pci::Bdf, len: usize) -> Option<VirtioDmaFrame> {
    let pa = pmm::setup::alloc_raw_frame()?;
    let Some(dma) = iommu::map_dma(bdf, pa, len) else {
        // SAFETY: map_dma failed before the frame reached device-visible state.
        unsafe { pmm::setup::free_one_frame(pa); }
        return None;
    };
    Some(VirtioDmaFrame { pa, dma })
}

/// Retire a DMA mapping before allowing PMM to reuse its frame. Failure leaks
/// the frame deliberately: an IOMMU invalidation that did not complete cannot
/// be followed by physical reuse. # C: O(1)
pub fn release_dma_frame(bdf: pci::Bdf, frame: &mut VirtioDmaFrame, len: usize) -> bool {
    let owned = core::mem::take(frame);
    if owned.pa == 0 || owned.dma == 0 { return true; }
    if !iommu::unmap_dma(bdf, owned.dma, len) { return false; }
    // SAFETY: unmap_dma completed before the PMM frame becomes reusable.
    unsafe { pmm::setup::free_one_frame(owned.pa); }
    true
}

/// Return the IOVA that is valid in a device-visible virtqueue descriptor.
/// # C: O(1)
pub const fn device_dma_addr(frame: VirtioDmaFrame) -> u64 { frame.dma }

impl VirtioProbeFrameSet {
    /// # C: O(1)
    pub fn is_empty(&self) -> bool {
        self.vring_frames.is_empty() && self.payload_frames.is_empty()
    }
}

/// # C: O(N)
pub fn push_unique_dma_frame(frames: &mut Vec<VirtioDmaFrame>, frame: VirtioDmaFrame) {
    if frame.pa != 0 && frame.dma != 0 && !frames.iter().any(|existing| *existing == frame) {
        frames.push(frame);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_descriptor_uses_dma_not_cpu_physical_address() {
        let frame = VirtioDmaFrame { pa: 0x1000, dma: 0x9000_1000 };
        assert_eq!(device_dma_addr(frame), 0x9000_1000);
        assert_ne!(device_dma_addr(frame), frame.pa);
    }
}
