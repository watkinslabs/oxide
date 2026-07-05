use alloc::vec::Vec;

use super::{
    MsixBinding, TransportMappings, disable_pci_command, publish_transport_record,
    release_failed_probe, release_msix_bindings,
};

pub(crate) struct VirtioProbeDevres {
    bdf: pci::Bdf,
    bdf_word: u32,
    cfg_va: u64,
    mappings: TransportMappings,
    msix: Vec<MsixBinding>,
    frames: virtio::VirtioProbeOwnedFrames,
    lease: virtio::VirtioProbeLease,
}

impl VirtioProbeDevres {
    pub(crate) fn new(
        bdf: pci::Bdf,
        bdf_word: u32,
        cfg_va: u64,
        mappings: TransportMappings,
        msix: Vec<MsixBinding>,
        frames: virtio::VirtioProbeOwnedFrames,
    ) -> Self {
        Self {
            bdf,
            bdf_word,
            cfg_va,
            mappings,
            msix,
            frames,
            lease: virtio::VirtioProbeLease::live(),
        }
    }

    pub(crate) fn release_failed(&mut self) {
        if !self.lease.take() {
            return;
        }
        let frames = self.frames.take_all();
        release_failed_probe(self.cfg_va, &frames);
        release_msix_bindings(self.bdf, &mut self.msix);
        disable_pci_command(self.bdf);
        self.mappings.unmap_all();
    }

    pub(crate) fn publish(&mut self) {
        if !self.lease.take() {
            return;
        }
        publish_transport_record(
            self.bdf_word,
            core::mem::take(&mut self.mappings),
            self.frames.take_vring_frames(),
            core::mem::take(&mut self.msix),
        );
    }
}

impl Drop for VirtioProbeDevres {
    fn drop(&mut self) {
        self.release_failed();
    }
}
