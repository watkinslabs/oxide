use super::probe_state::VirtioProbeState;
use super::runtime::VirtioPciRuntime;
use super::{unpublish_transport_record, unpublish_transport_record_by_bdf, VirtioProbeDevres};

pub(super) struct VirtioPciAcquisition {
    caps: pci::heapless_caps::CapVec,
    vcaps: virtio::pci::heapless_v::VCapVec,
    bars: [pci::Bar; 6],
    cmd_orig: u16,
    #[cfg(feature = "debug-boot")]
    cmd_new: u16,
}

impl VirtioPciAcquisition {
    pub(super) fn acquire(bdf: pci::Bdf) -> Option<Self> {
        let (caps, vcaps, bars, cmd_orig) = {
            #[cfg(target_arch = "x86_64")]
            {
                let r = hal_x86_64::pci::EcamPci::from_published()?;
                let caps = pci::capabilities(&r, bdf);
                let vcaps = virtio::decode_all(&r, bdf, &caps);
                let bars = pci::decode_bars(&r, bdf);
                let cmd_orig = pci::enable_mem_bus_master(&r, bdf) as u32;
                (caps, vcaps, bars, cmd_orig)
            }
            #[cfg(target_arch = "aarch64")]
            {
                let r = hal_aarch64::pci::EcamPci::from_published()?;
                let caps = pci::capabilities(&r, bdf);
                let vcaps = virtio::decode_all(&r, bdf, &caps);
                let bars = pci::decode_bars(&r, bdf);
                let cmd_orig = pci::enable_mem_bus_master(&r, bdf) as u32;
                (caps, vcaps, bars, cmd_orig)
            }
        };
        #[cfg(feature = "debug-boot")]
        let cmd_new = (cmd_orig & 0xFFFF)
            | (pci::COMMAND_MEMORY | pci::COMMAND_BUS_MASTER) as u32;
        Some(Self {
            caps,
            vcaps,
            bars,
            cmd_orig: (cmd_orig & 0xFFFF) as u16,
            #[cfg(feature = "debug-boot")]
            cmd_new: (cmd_new & 0xFFFF) as u16,
        })
    }

    pub(super) fn probe_child(
        self,
        d: &pci::PciDevice,
        profile: virtio::VirtioTransportProfile,
    ) -> Option<VirtioProbe> {
        let bdf = d.bdf;
        let mut state = VirtioProbeState::from_caps(bdf, &self.vcaps, &self.bars, self.cmd_orig)?;
        let runtime = VirtioPciRuntime::current();

        let bringup = state.negotiate_and_program(d, &self.caps, &self.bars, profile, runtime);
        #[cfg(feature = "debug-boot")]
        let dev_features = bringup.negotiated.dev_features;
        let drv_features = bringup.negotiated.drv_features;
        #[cfg(feature = "debug-boot")]
        let post_status = bringup.negotiated.post_status;
        #[cfg(feature = "debug-boot")]
        let features_ok = bringup.negotiated.features_ok;
        #[cfg(feature = "debug-boot")]
        let msix_cfg = bringup.negotiated.msix_cfg;
        #[cfg(feature = "debug-boot")]
        let num_queues = bringup.negotiated.num_queues;
        let queues = bringup.queues;
        let queues_len = bringup.queues_len;
        let notify_cap = self.vcaps.find(virtio::VIRTIO_PCI_CAP_NOTIFY_CFG);
        let final_status = bringup.final_status;
        let handoff = state.runtime_handoff(
            profile,
            runtime,
            final_status,
            &queues,
            queues_len,
            bringup.programmed_queues.as_ref(),
            notify_cap.as_ref(),
            self.vcaps.find(virtio::VIRTIO_PCI_CAP_ISR_CFG).as_ref(),
            &self.bars,
        );

        let transport_result = virtio::VirtioTransportProbeResult::new(
            runtime.hhdm,
            drv_features,
            final_status,
            state.cfg_va(),
            state.device_cfg_va(),
            handoff.queue_resources,
            handoff.net_boot_payloads,
        );
        #[cfg(feature = "debug-boot")]
        let trace = VirtioPciProbeTrace {
            cmd_orig: self.cmd_orig,
            cmd_new: self.cmd_new,
            cfg_va: state.cfg_va(),
            dev_features,
            drv_features,
            post_status,
            features_ok,
            msix_cfg,
            num_queues,
            queues,
            queues_len,
            queue_resources: handoff.queue_resources,
            final_status,
            post_notify_status: handoff.post_notify_status,
            avail_idx_posted: handoff.avail_idx_posted,
            used_idx_observed: handoff.used_idx_observed,
            isr_status: handoff.isr_status,
        };

        let child_facts = transport_result.child_facts();
        let devres = state.finish_devres(&transport_result, self.cmd_orig);
        Some(VirtioProbe {
            child_facts,
            #[cfg(feature = "debug-boot")]
            trace,
            devres,
        })
    }
}

/// Probe-time record consumed only by `virtio_trace::trace_probe`, whose every
/// read sits inside `debug_boot!`. The record therefore exists only when that
/// feature does: built unconditionally it was ~408 B of probe frame — its own
/// copy of the `MAX_RESOURCE_QUEUES` resource array included — written and
/// never read, on a boot path already close to the stack-depth ceiling.
#[cfg(feature = "debug-boot")]
pub(crate) struct VirtioPciProbeTrace {
    pub(crate) cmd_orig: u16,
    pub(crate) cmd_new: u16,
    pub(crate) cfg_va: u64,
    pub(crate) dev_features: u64,
    pub(crate) drv_features: u64,
    pub(crate) post_status: u32,
    pub(crate) features_ok: bool,
    pub(crate) msix_cfg: u16,
    pub(crate) num_queues: u16,
    pub(crate) queues: [(u16, u16); virtio::MAX_RESOURCE_QUEUES],
    pub(crate) queues_len: usize,
    pub(crate) queue_resources: [virtio::VirtQueueResource; virtio::MAX_RESOURCE_QUEUES],
    pub(crate) final_status: u8,
    pub(crate) post_notify_status: u8,
    pub(crate) avail_idx_posted: u16,
    pub(crate) used_idx_observed: u16,
    pub(crate) isr_status: u8,
}

pub(crate) struct VirtioProbe {
    pub(crate) child_facts: virtio::VirtioChildProbeFacts,
    #[cfg(feature = "debug-boot")]
    pub(crate) trace: VirtioPciProbeTrace,
    devres: VirtioProbeDevres,
}

impl VirtioProbe {
    pub(crate) fn child_resources(
        &self,
        requirements: virtio::VirtioChildRequirements,
    ) -> Option<virtio::VirtioResources> {
        self.child_facts.resources_for_child(requirements)
    }

    fn release_failed_transport(&mut self) {
        self.devres.release_failed();
    }

    pub(crate) fn release_failed_child(&mut self) {
        self.release_failed_transport();
    }
}

impl Drop for VirtioProbe {
    fn drop(&mut self) {
        self.release_failed_transport();
    }
}

pub(super) fn publish_transport_mmio(
    p: &mut VirtioProbe,
    device_key: virtio::VirtioChildDeviceKey,
) {
    p.devres.publish(device_key);
}

pub(super) fn unpublish_transport_mmio(device_key: virtio::VirtioChildDeviceKey) {
    unpublish_transport_record(device_key);
}

pub(super) fn unpublish_transport_mmio_bdf(bdf: u32) {
    unpublish_transport_record_by_bdf(bdf);
}
