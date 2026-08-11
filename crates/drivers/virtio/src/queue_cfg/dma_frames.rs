use alloc::vec::Vec;

use super::{ProgrammedQueues, VirtioDmaFrame};

impl ProgrammedQueues {
    /// Return every ring page with its physical and device-visible address.
    /// # C: O(MAX_RESOURCE_QUEUES)
    pub fn dma_frames(&self) -> Vec<VirtioDmaFrame> {
        let mut frames = Vec::new();
        for ring in core::iter::once(self.q0).chain(self.extra.iter().flatten().copied()) {
            push_unique_dma_frame(&mut frames, VirtioDmaFrame { pa: ring.desc_pa, dma: ring.desc_dma });
            push_unique_dma_frame(&mut frames, VirtioDmaFrame { pa: ring.driver_pa, dma: ring.driver_dma });
            push_unique_dma_frame(&mut frames, VirtioDmaFrame { pa: ring.device_pa, dma: ring.device_dma });
        }
        frames
    }
}

fn push_unique_dma_frame(frames: &mut Vec<VirtioDmaFrame>, frame: VirtioDmaFrame) {
    if frame.pa != 0 && frame.dma != 0 && !frames.iter().any(|candidate| *candidate == frame) {
        frames.push(frame);
    }
}
