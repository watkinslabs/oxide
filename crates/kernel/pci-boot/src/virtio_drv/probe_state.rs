use super::address::{bdf_from_word, bdf_word};
use super::runtime::VirtioPciRuntime;
use super::{
    bind_msix_vector, disable_pci_command, kick_queue_notify, unmask_msix_bindings, MsixBinding,
    NetRxBootBuffer, ProgrammedQueues, TransportMappings, VirtioProbeDevres, Vec,
};

const VIRTIO_MSIX_Q0_VECTOR: u16 = 0;

pub(super) struct VirtioProbeState {
    bdf_word: u32,
    mappings: TransportMappings,
    cfg_va: u64,
    device_cfg_va: u64,
    msix: Vec<MsixBinding>,
}

impl VirtioProbeState {
    fn new(bdf: pci::Bdf, mappings: TransportMappings, cfg_va: u64, device_cfg_va: u64) -> Self {
        Self {
            bdf_word: bdf_word(bdf),
            mappings,
            cfg_va,
            device_cfg_va,
            msix: Vec::new(),
        }
    }

    pub(super) fn from_caps(
        bdf: pci::Bdf,
        vcaps: &virtio::pci::heapless_v::VCapVec,
        bars: &[pci::Bar; 6],
    ) -> Option<Self> {
        let mut mappings = TransportMappings::default();
        let Some(common) = vcaps.find(virtio::VIRTIO_PCI_CAP_COMMON_CFG) else {
            return abandon_probe_transport(bdf, &mut mappings);
        };
        let Some(cfg_va) = map_cap_window(&mut mappings, common, bars) else {
            return abandon_probe_transport(bdf, &mut mappings);
        };
        let device_cfg_va = vcaps
            .find(virtio::VIRTIO_PCI_CAP_DEVICE_CFG)
            .and_then(|devcfg| map_cap_window(&mut mappings, devcfg, bars))
            .unwrap_or(0);
        Some(Self::new(bdf, mappings, cfg_va, device_cfg_va))
    }

    pub(super) fn cfg_va(&self) -> u64 {
        self.cfg_va
    }

    pub(super) fn device_cfg_va(&self) -> u64 {
        self.device_cfg_va
    }

    fn bind_msix_queue(
        &mut self,
        d: &pci::PciDevice,
        caps: &pci::heapless_caps::CapVec,
        bars: &[pci::Bar; 6],
        queue_vector: u16,
        handler: Option<fn()>,
    ) -> Option<u16> {
        let Some(handler) = handler else {
            return None;
        };
        if let Some(binding) = self
            .msix
            .iter()
            .find(|binding| binding.queue_vector == queue_vector)
        {
            return Some(binding.queue_vector);
        }
        if let Some(binding) = bind_msix_vector(d, caps, bars, &mut self.mappings, queue_vector, handler) {
            let queue_vector = binding.queue_vector;
            self.msix.push(binding);
            return Some(queue_vector);
        }
        None
    }

    fn bind_msix0(
        &mut self,
        d: &pci::PciDevice,
        caps: &pci::heapless_caps::CapVec,
        bars: &[pci::Bar; 6],
        handler: Option<fn()>,
    ) -> Option<u16> {
        self.bind_msix_queue(d, caps, bars, VIRTIO_MSIX_Q0_VECTOR, handler)
    }

    fn resolve_queue_plan_msix(
        &mut self,
        d: &pci::PciDevice,
        caps: &pci::heapless_caps::CapVec,
        bars: &[pci::Bar; 6],
        queue_plans: &[Option<virtio::VirtioQueuePlan>; virtio::MAX_RESOURCE_QUEUES],
    ) -> [Option<virtio::VirtioQueuePlan>; virtio::MAX_RESOURCE_QUEUES] {
        let mut resolved = *queue_plans;
        for plan in resolved.iter_mut().flatten() {
            let msix_vec = self
                .bind_msix_queue(d, caps, bars, plan.index, plan.msix_handler)
                .unwrap_or(virtio::VIRTIO_MSI_NO_VECTOR);
            *plan = plan.with_msix_vec(msix_vec);
        }
        resolved
    }

    pub(super) fn negotiate_and_program(
        &mut self,
        d: &pci::PciDevice,
        caps: &pci::heapless_caps::CapVec,
        bars: &[pci::Bar; 6],
        profile: virtio::VirtioTransportProfile,
        runtime: VirtioPciRuntime,
    ) -> virtio::CommonCfgBringup<ProgrammedQueues> {
        let bringup = virtio::bring_up_common_cfg(self.cfg_va, profile.drv_features, || {
            let q0_msix_vec = self
                .bind_msix0(d, caps, bars, profile.msix0_handler)
                .unwrap_or(virtio::VIRTIO_MSI_NO_VECTOR);
            let queue_plans = self.resolve_queue_plan_msix(d, caps, bars, &profile.queue_plans);
            runtime.program_queue_set(self.cfg_va, q0_msix_vec, &queue_plans)
        });
        if (bringup.final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0 {
            unmask_msix_bindings(d.bdf, &self.msix);
        }
        bringup
    }

    fn map_notify(
        &mut self,
        notify_cap: Option<&virtio::VirtioPciCap>,
        bars: &[pci::Bar; 6],
        notify_off: u16,
    ) -> u64 {
        self.mappings
            .map_queue_notify_va(notify_cap, bars, notify_off)
    }

    fn kick_queue(
        &mut self,
        notify_cap: Option<&virtio::VirtioPciCap>,
        bars: &[pci::Bar; 6],
        notify_off: u16,
        queue_index: u16,
    ) -> u64 {
        let notify_va = self.map_notify(notify_cap, bars, notify_off);
        if kick_queue_notify(notify_va, queue_index) {
            notify_va
        } else {
            0
        }
    }

    fn kick_queue_and_observe_status(
        &mut self,
        notify_cap: Option<&virtio::VirtioPciCap>,
        bars: &[pci::Bar; 6],
        notify_off: u16,
        queue_index: u16,
        fallback_status: u8,
    ) -> (u64, u8) {
        let kick_va = self.kick_queue(notify_cap, bars, notify_off, queue_index);
        if kick_va == 0 {
            return (0, fallback_status);
        }
        for _ in 0..1_000_000 {
            core::hint::spin_loop();
        }
        (kick_va, virtio::read_status(self.cfg_va))
    }

    fn read_isr_status(
        &mut self,
        isr_cap: Option<&virtio::VirtioPciCap>,
        bars: &[pci::Bar; 6],
    ) -> u8 {
        self.mappings.read_isr_status(isr_cap, bars)
    }

    pub(super) fn runtime_handoff(
        &mut self,
        profile: virtio::VirtioTransportProfile,
        runtime: VirtioPciRuntime,
        final_status: u8,
        queues: &[(u16, u16); virtio::MAX_RESOURCE_QUEUES],
        queues_len: usize,
        programmed_queues: Option<&ProgrammedQueues>,
        notify_cap: Option<&virtio::VirtioPciCap>,
        isr_cap: Option<&virtio::VirtioPciCap>,
        bars: &[pci::Bar; 6],
    ) -> virtio::VirtioRuntimeHandoff {
        let q0_ring = programmed_queues.and_then(|p| p.queue(0));
        let q1_ring = programmed_queues.and_then(|p| p.queue(1));
        let q0_notify_off = q0_ring.map(|q| q.notify_off).unwrap_or(0);

        let planned_notify_mappings = virtio::resolve_planned_notify_mappings(
            &profile.queue_plans,
            programmed_queues,
            |notify_off| self.map_notify(notify_cap, bars, notify_off),
        );

        let net_rx_boot = if profile.early_payload_policy.is_net()
            && (final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0
        {
            runtime.post_net_rx_boot_buffer(q0_ring)
        } else {
            NetRxBootBuffer::default()
        };

        let (q0_notify_va, post_notify_status) = if final_status & virtio::VIRTIO_STATUS_FAILED == 0
            && (final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0
        {
            self.kick_queue_and_observe_status(notify_cap, bars, q0_notify_off, 0, final_status)
        } else {
            (0u64, final_status)
        };

        let q1_notify_va = if (final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0 {
            planned_notify_mappings.get(1)
        } else {
            0
        };
        let tx0_buf_pa = if profile.early_payload_policy.is_net()
            && (final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0
        {
            runtime.alloc_net_tx_boot_buffer(q1_ring, q1_notify_va)
        } else {
            0
        };

        let isr_status = if net_rx_boot.avail_idx_posted > 0 {
            self.read_isr_status(isr_cap, bars)
        } else {
            0
        };
        let used_idx_observed = if net_rx_boot.avail_idx_posted > 0 {
            runtime.read_queue_used_idx(q0_ring)
        } else {
            0
        };

        virtio::build_runtime_handoff(virtio::VirtioRuntimeHandoffInput {
            scanned_queues: queues,
            scanned_len: queues_len,
            programmed_queues,
            planned_notify_mappings,
            q0_notify_va,
            q1_notify_va,
            post_notify_status,
            avail_idx_posted: net_rx_boot.avail_idx_posted,
            used_idx_observed,
            isr_status,
            net_boot_payloads: virtio::VirtioNetBootPayloads::from_rx_pool(
                net_rx_boot.bufs,
                net_rx_boot.bufs_len,
                tx0_buf_pa,
            ),
        })
    }

    pub(super) fn finish_devres(
        self,
        result: &virtio::VirtioTransportProbeResult,
    ) -> VirtioProbeDevres {
        let owned_frames = virtio::VirtioProbeOwnedFrames::from_probe_result(result);
        VirtioProbeDevres::new(
            bdf_from_word(self.bdf_word),
            self.bdf_word,
            self.cfg_va,
            self.mappings,
            self.msix,
            owned_frames,
        )
    }
}

fn abandon_probe_transport<T>(bdf: pci::Bdf, mappings: &mut TransportMappings) -> Option<T> {
    disable_pci_command(bdf);
    mappings.unmap_all();
    None
}

fn map_cap_window(
    mappings: &mut TransportMappings,
    cap: virtio::VirtioPciCap,
    bars: &[pci::Bar; 6],
) -> Option<u64> {
    let bar_pa = match bars.get(cap.bar as usize)? {
        pci::Bar::Mem32 { base, .. } => *base as u64,
        pci::Bar::Mem64 { base, .. } => *base,
        _ => return None,
    };
    let cap_pa = bar_pa.checked_add(cap.offset as u64)?;
    let page_pa = cap_pa & !0xFFF;
    let page_off = cap_pa - page_pa;
    Some(mappings.map_page(page_pa) + page_off)
}
