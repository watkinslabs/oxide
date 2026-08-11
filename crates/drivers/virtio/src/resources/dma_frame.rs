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
