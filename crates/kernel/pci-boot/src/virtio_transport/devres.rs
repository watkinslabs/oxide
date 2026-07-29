use alloc::vec::Vec;

use super::{
    MsixBinding, TransportMappings, publish_transport_record,
    release_failed_probe_frames, release_msix_bindings, reset_failed_probe,
    restore_pci_command,
};

pub(crate) struct VirtioProbeDevres {
    bdf: pci::Bdf,
    bdf_word: u32,
    command_orig: u16,
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
        command_orig: u16,
        cfg_va: u64,
        mappings: TransportMappings,
        msix: Vec<MsixBinding>,
        frames: virtio::VirtioProbeOwnedFrames,
    ) -> Self {
        Self {
            bdf,
            bdf_word,
            command_orig,
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
        let quiesced = reset_failed_probe(self.cfg_va);
        release_msix_bindings(self.bdf, &mut self.msix);
        restore_pci_command(self.bdf, self.command_orig);
        self.mappings.unmap_all();
        // Unconfirmed reset ⇒ the device may still hold these frames in a
        // descriptor; leak rather than hand them back to the buddy (the
        // documented contract on `virtio::reset_device`).
        if quiesced { release_failed_probe_frames(&frames); }
    }

    pub(crate) fn publish(&mut self, device_key: virtio::VirtioChildDeviceKey) {
        if !self.lease.take() {
            return;
        }
        publish_transport_record(
            device_key,
            self.bdf_word,
            self.command_orig,
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
