// Modern virtio-pci transport bring-up. Split from pci_boot/mod.rs.
// klog calls gated under debug_boot! per R06.

use super::virtio_transport::{
    alloc_net_tx_boot_buffer, bind_msix_vector, disable_pci_command, kick_queue_notify,
    post_net_rx_boot_buffer, program_queue_set, publish_transport_record, read_queue_used_idx,
    release_failed_probe, release_msix_bindings, unpublish_transport_record, MsixBinding,
    NetRxBootBuffer, ProgrammedQueues, QueueRing, TransportMappings,
};
use alloc::sync::Arc;
use alloc::vec::Vec;

struct VirtioPciDrv;
impl drv::Driver for VirtioPciDrv {
    fn name(&self) -> &'static str { "virtio-pci" }

    fn matches(&self, dev: &drv::Device) -> bool {
        dev.bus == "pci" && virtio::is_modern(dev.vendor_id, dev.device_id)
    }

    fn probe(&self, dev: &Arc<drv::Device>) -> drv::KResult<()> {
        let Some(d) = pci_device_from_pci_model(dev) else { return Err(drv::Error::ProbeFailed); };
        if !virtio::is_modern(d.vendor_id, d.device_id) {
            return Err(drv::Error::NoMatch);
        }

        let Some(child) = virtio::VirtioChildModelIdentity::modern_from_pci(
            d.vendor_id,
            d.device_id,
            super::virtio_seq(),
        ) else {
            return Err(drv::Error::NoMatch);
        };
        drv::try_device_add(Arc::new(
            drv::Device::new(
                child.bus,
                child.addr,
                child.vendor_id,
                child.device_id,
                child.class,
            )
                .with_parent("pci", dev.addr.clone()),
        ))?;
        Ok(())
    }

    fn remove(&self, dev: &drv::Device) {
        let children: Vec<Arc<drv::Device>> = drv::devices()
            .into_iter()
            .filter(|child| virtio::virtio_child_has_parent(&child.bus, child.parent(), "pci", &dev.addr))
            .collect();
        let mut bdfs: Vec<u32> = Vec::new();
        for child in children {
            if let Some((_, parent_addr)) = child.parent() {
                if let Some(parent_bdf) = parse_pci_addr(&parent_addr) {
                    bdfs.push(bdf_word(parent_bdf));
                }
            }
            drv::device_del(&child);
        }

        bdfs.sort_unstable();
        bdfs.dedup();
        for bdf_word in bdfs {
            unpublish_transport_mmio(bdf_word);
        }
    }

    fn shutdown(&self, dev: &drv::Device) {
        let Some(d) = pci_device_from_pci_model(dev) else { return };
        disable_pci_command(d.bdf);
    }
}
static VIRTIO_PCI_DRV: VirtioPciDrv = VirtioPciDrv;

fn bdf_word(bdf: pci::Bdf) -> u32 {
    (bdf.bus as u32) << 16 | (bdf.device as u32) << 8 | (bdf.function as u32)
}

fn bdf_from_word(word: u32) -> pci::Bdf {
    pci::Bdf {
        bus: ((word >> 16) & 0xFF) as u8,
        device: ((word >> 8) & 0xFF) as u8,
        function: (word & 0xFF) as u8,
    }
}

const VIRTIO_MSIX_Q0_VECTOR: u16 = 0;

#[derive(Copy, Clone, Default)]
pub(super) struct VirtioPciTransport;

impl VirtioPciTransport {
    pub(super) fn probe_child(
        self,
        d: &pci::PciDevice,
        profile: virtio::VirtioTransportProfile,
    ) -> Option<VirtioProbe> {
        if !virtio::is_modern(d.vendor_id, d.device_id) {
            return None;
        }
        VirtioPciAcquisition::acquire(d.bdf)?.probe_child(d, profile)
    }

    pub(super) fn publish(self, p: &mut VirtioProbe) {
        publish_transport_mmio(p);
    }

    pub(super) fn unpublish_key(self, device_key: virtio::VirtioChildDeviceKey) {
        unpublish_transport_mmio(device_key.raw());
    }
}

fn release_probe_msix(p: &mut VirtioProbe) {
    release_msix_bindings(bdf_from_word(p.bdf_word), &mut p.msix);
}

fn publish_transport_mmio(p: &mut VirtioProbe) {
    publish_transport_record(
        p.bdf_word,
        core::mem::take(&mut p.mappings),
        p.owned_frames.take_vring_frames(),
        core::mem::take(&mut p.msix),
    );
}

fn abandon_probe_transport<T>(bdf: pci::Bdf, mappings: &mut TransportMappings) -> Option<T> {
    disable_pci_command(bdf);
    mappings.unmap_all();
    None
}

fn unpublish_transport_mmio(bdf: u32) {
    unpublish_transport_record(bdf);
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn hex_byte(s: &[u8]) -> Option<u8> {
    Some((hex_nibble(*s.first()?)? << 4) | hex_nibble(*s.get(1)?)?)
}

fn parse_pci_addr(addr: &str) -> Option<pci::Bdf> {
    let b = addr.as_bytes();
    if b.len() != 12 || b[4] != b':' || b[7] != b':' || b[10] != b'.' {
        return None;
    }
    Some(pci::Bdf {
        bus: hex_byte(&b[5..7])?,
        device: hex_byte(&b[8..10])?,
        function: hex_nibble(b[11])?,
    })
}

fn pci_device_from_pci_model(dev: &drv::Device) -> Option<pci::PciDevice> {
    if dev.bus != "pci" {
        return None;
    }
    pci_device_from_bdf(parse_pci_addr(&dev.addr)?)
}

fn pci_device_from_bdf(bdf: pci::Bdf) -> Option<pci::PciDevice> {
    #[cfg(target_arch = "x86_64")]
    {
        let r = hal_x86_64::pci::LegacyPci;
        pci::PciDevice::from_config(&r, bdf)
    }
    #[cfg(target_arch = "aarch64")]
    {
        match hal_aarch64::pci::EcamPci::from_published() {
            Some(r) => pci::PciDevice::from_config(&r, bdf),
            None => None,
        }
    }
}

/// Register virtio drivers whose bring-up is owned by `Driver::probe`.
/// # C: O(N_drivers)
pub(super) fn register_model_drivers() {
    drv::register_driver(&VIRTIO_PCI_DRV);
    super::virtio_child::register_model_drivers();
}

// pub(super) so the trace (virtio_trace.rs) can read the fields without
// re-deriving them; virtio model-driver probes are the producers.
struct VirtioProbeState {
    bdf_word: u32,
    mappings: TransportMappings,
    cfg_va: u64,
    device_cfg_va: u64,
    msix: Vec<MsixBinding>,
}

#[derive(Clone, Copy)]
struct VirtioPciRuntime {
    hhdm: u64,
}

impl VirtioPciRuntime {
    fn current() -> Self {
        Self {
            hhdm: {
                #[cfg(target_arch = "x86_64")]
                {
                    hal_x86_64::mmu_ops::hhdm_offset()
                }
                #[cfg(target_arch = "aarch64")]
                {
                    hal_aarch64::mmu_ops::hhdm_offset()
                }
            },
        }
    }

    fn program_queue_set(
        self,
        cfg_va: u64,
        q0_msix_vec: u16,
        queue_plans: &[Option<virtio::VirtioQueuePlan>],
    ) -> Option<ProgrammedQueues> {
        program_queue_set(cfg_va, self.hhdm, q0_msix_vec, queue_plans)
    }

    fn post_net_rx_boot_buffer(self, q0_ring: Option<QueueRing>) -> NetRxBootBuffer {
        post_net_rx_boot_buffer(self.hhdm, q0_ring)
    }

    fn alloc_net_tx_boot_buffer(self, q1_ring: Option<QueueRing>, q1_notify_va: u64) -> u64 {
        alloc_net_tx_boot_buffer(self.hhdm, q1_ring, q1_notify_va)
    }

    fn read_queue_used_idx(self, q0_ring: Option<QueueRing>) -> u16 {
        read_queue_used_idx(self.hhdm, q0_ring)
    }
}

struct VirtioPciAcquisition {
    caps: pci::heapless_caps::CapVec,
    vcaps: virtio::pci::heapless_v::VCapVec,
    bars: [pci::Bar; 6],
    cmd_orig: u16,
    cmd_new: u16,
}

impl VirtioPciAcquisition {
    fn acquire(bdf: pci::Bdf) -> Option<Self> {
        let (caps, vcaps, bars, cmd_orig) = {
            #[cfg(target_arch = "x86_64")]
            {
                let r = hal_x86_64::pci::LegacyPci;
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
        let cmd_new = (cmd_orig & 0xFFFF) | (pci::COMMAND_MEMORY | pci::COMMAND_BUS_MASTER) as u32;
        Some(Self {
            caps,
            vcaps,
            bars,
            cmd_orig: (cmd_orig & 0xFFFF) as u16,
            cmd_new: (cmd_new & 0xFFFF) as u16,
        })
    }

    fn probe_child(
        self,
        d: &pci::PciDevice,
        profile: virtio::VirtioTransportProfile,
    ) -> Option<VirtioProbe> {
        let bdf = d.bdf;
        let mut state = VirtioProbeState::from_caps(bdf, &self.vcaps, &self.bars)?;
        let runtime = VirtioPciRuntime::current();

        let bringup = state.negotiate_and_program(d, &self.caps, &self.bars, profile, runtime);
        let dev_features = bringup.negotiated.dev_features;
        let drv_features = bringup.negotiated.drv_features;
        let post_status = bringup.negotiated.post_status;
        let features_ok = bringup.negotiated.features_ok;
        let msix_cfg = bringup.negotiated.msix_cfg;
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
            state.cfg_va,
            state.device_cfg_va,
            handoff.queue_resources,
            handoff.net_boot_payloads,
        );
        let trace = VirtioPciProbeTrace {
            cmd_orig: self.cmd_orig,
            cmd_new: self.cmd_new,
            cfg_va: state.cfg_va,
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

        Some(state.finish(transport_result, trace))
    }
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

    fn from_caps(
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
        if let Some(binding) = bind_msix_vector(
                d,
                caps,
                bars,
                &mut self.mappings,
                queue_vector,
                handler,
        ) {
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

    fn negotiate_and_program(
        &mut self,
        d: &pci::PciDevice,
        caps: &pci::heapless_caps::CapVec,
        bars: &[pci::Bar; 6],
        profile: virtio::VirtioTransportProfile,
        runtime: VirtioPciRuntime,
    ) -> virtio::CommonCfgBringup<ProgrammedQueues> {
        virtio::bring_up_common_cfg(self.cfg_va, profile.drv_features, || {
            let q0_msix_vec = self
                .bind_msix0(d, caps, bars, profile.msix0_handler)
                .unwrap_or(virtio::VIRTIO_MSI_NO_VECTOR);
            let queue_plans = self.resolve_queue_plan_msix(d, caps, bars, &profile.queue_plans);
            runtime.program_queue_set(self.cfg_va, q0_msix_vec, &queue_plans)
        })
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
        // Brief observation window for device-driven completion. QEMU user-net
        // normally has no packet ready here, so q0 used.idx may stay 0.
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

    fn runtime_handoff(
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
            net_boot_payloads: virtio::VirtioNetBootPayloads::new(
                net_rx_boot.buf_pa,
                net_rx_boot.buf_len,
                tx0_buf_pa,
            ),
        })
    }

    fn finish(
        self,
        result: virtio::VirtioTransportProbeResult,
        trace: VirtioPciProbeTrace,
    ) -> VirtioProbe {
        let child_facts = result.child_facts();
        let owned_frames = virtio::VirtioProbeOwnedFrames::from_probe_result(&result);
        VirtioProbe {
            bdf_word: self.bdf_word,
            mappings: self.mappings,
            msix: self.msix,
            child_facts,
            trace,
            cfg_va: self.cfg_va,
            owned_frames,
        }
    }
}

pub(super) struct VirtioPciProbeTrace {
    pub(super) cmd_orig: u16,
    pub(super) cmd_new: u16,
    pub(super) cfg_va: u64,
    pub(super) dev_features: u64,
    pub(super) drv_features: u64,
    pub(super) post_status: u32,
    pub(super) features_ok: bool,
    pub(super) msix_cfg: u16,
    pub(super) num_queues: u16,
    pub(super) queues: [(u16, u16); virtio::MAX_RESOURCE_QUEUES],
    pub(super) queues_len: usize,
    pub(super) queue_resources: [virtio::VirtQueueResource; virtio::MAX_RESOURCE_QUEUES],
    pub(super) final_status: u8,
    pub(super) post_notify_status: u8,
    pub(super) avail_idx_posted: u16,
    pub(super) used_idx_observed: u16,
    pub(super) isr_status: u8,
}

pub(super) struct VirtioProbe {
    pub(super) bdf_word: u32,
    mappings: TransportMappings,
    msix: Vec<MsixBinding>,
    pub(super) child_facts: virtio::VirtioChildProbeFacts,
    pub(super) trace: VirtioPciProbeTrace,
    pub(super) cfg_va: u64,
    owned_frames: virtio::VirtioProbeOwnedFrames,
}

impl VirtioProbe {
    pub(super) fn child_resources(
        &self,
        requirements: virtio::VirtioChildRequirements,
    ) -> Option<virtio::VirtioResources> {
        self.child_facts.resources_for_child(requirements)
    }

    fn release_failed_transport(&mut self) {
        let frames = self.owned_frames.take_all();
        release_failed_probe(self.cfg_va, &frames);
        release_probe_msix(self);
        disable_pci_command(bdf_from_word(self.bdf_word));
        self.mappings.unmap_all();
    }

    pub(super) fn release_failed_child(&mut self) {
        self.release_failed_transport();
    }

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
