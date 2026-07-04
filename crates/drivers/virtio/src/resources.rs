//! Transport-owned resource descriptions handed from a virtio transport to a
//! child driver. These are plain descriptors; ownership and unmapping still
//! live with the transport until every child driver is converted to managed
//! resources.

use alloc::{format, string::String, vec::Vec};

use crate::{ProgrammedQueues, QueueRing};

/// Driver-model bus name used for virtio child devices.
pub const VIRTIO_CHILD_BUS: &str = "virtio";

/// Virtio vendor ID used by virtio child model devices.
pub const VIRTIO_VENDOR_ID: u16 = 0x1AF4;

/// Driver-model class used for synthetic virtio child devices.
pub const VIRTIO_CHILD_CLASS: u32 = 0;

/// Transport-neutral identity for a model-published virtio child device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VirtioChildModelIdentity {
    pub bus: &'static str,
    pub addr: String,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class: u32,
}

impl VirtioChildModelIdentity {
    /// # C: O(1)
    pub fn modern_from_pci(pci_vendor_id: u16, pci_device_id: u16, index: u32) -> Option<Self> {
        Some(Self {
            bus: VIRTIO_CHILD_BUS,
            addr: virtio_child_addr(index),
            vendor_id: pci_vendor_id,
            device_id: crate::modern_device_id(pci_device_id)?,
            class: VIRTIO_CHILD_CLASS,
        })
    }
}

/// Bus address for a model-published virtio child.
/// # C: O(log10(index))
pub fn virtio_child_addr(index: u32) -> String {
    format!("virtio{}", index)
}

/// True iff a model device is a virtio child of `parent_bus:parent_addr`.
/// # C: O(parent_addr.len())
pub fn virtio_child_has_parent(
    child_bus: &str,
    child_parent: Option<(&str, &str)>,
    parent_bus: &str,
    parent_addr: &str,
) -> bool {
    if child_bus != VIRTIO_CHILD_BUS {
        return false;
    }
    let Some((actual_parent_bus, actual_parent_addr)) = child_parent else {
        return false;
    };
    actual_parent_bus == parent_bus && actual_parent_addr == parent_addr
}

/// Model-driver identity for a virtio child driver. Child drivers own these
/// descriptors; the virtio bus wrapper uses them for driver/device matching.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VirtioChildDriverId {
    pub name: &'static str,
    pub device_id: u16,
}

impl VirtioChildDriverId {
    /// # C: O(1)
    pub const fn new(name: &'static str, device_id: u16) -> Self {
        Self { name, device_id }
    }

    /// # C: O(1)
    pub fn matches_device(&self, bus: &str, vendor_id: u16, device_id: u16) -> bool {
        bus == VIRTIO_CHILD_BUS
            && vendor_id == VIRTIO_VENDOR_ID
            && device_id == self.device_id
    }
}

/// Maximum virtqueues exposed through the staged resource object. Modern
/// virtio devices in this kernel currently use queues 0..=3.
pub const MAX_RESOURCE_QUEUES: usize = 8;

/// Child-driver transport requirements declared before a transport publishes
/// resources to the child. The transport owns validation against its concrete
/// bring-up result; the child owns device-specific parsing and registration.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VirtioChildRequirements {
    pub required_queues: [bool; MAX_RESOURCE_QUEUES],
    pub needs_device_cfg: bool,
    pub needs_net_boot_payloads: bool,
}

impl VirtioChildRequirements {
    /// # C: O(1)
    pub const fn new(
        required_queues: [bool; MAX_RESOURCE_QUEUES],
        needs_device_cfg: bool,
        needs_net_boot_payloads: bool,
    ) -> Self {
        Self {
            required_queues,
            needs_device_cfg,
            needs_net_boot_payloads,
        }
    }

    /// Require q0, the mandatory virtqueue for the active drivers here.
    /// # C: O(1)
    pub const fn q0() -> Self {
        Self::new(
            [true, false, false, false, false, false, false, false],
            false,
            false,
        )
    }

    /// Require q0 and a device-specific config window.
    /// # C: O(1)
    pub const fn q0_device_cfg() -> Self {
        Self::new(
            [true, false, false, false, false, false, false, false],
            true,
            false,
        )
    }

    /// Require q0/q1 and a device-specific config window.
    /// # C: O(1)
    pub const fn q0_q1_device_cfg() -> Self {
        Self::new(
            [true, true, false, false, false, false, false, false],
            true,
            false,
        )
    }

    /// Require virtio-net RX/TX queues plus boot payload buffers.
    /// # C: O(1)
    pub const fn net() -> Self {
        Self::new(
            [true, true, false, false, false, false, false, false],
            false,
            true,
        )
    }

    /// Require virtio-snd control, event, TX, and RX queues plus config.
    /// # C: O(1)
    pub const fn snd() -> Self {
        Self::new(
            [true, true, true, true, false, false, false, false],
            true,
            false,
        )
    }
}

/// Sentinel used by MSI-X capable transports when a queue is intentionally
/// left without a per-queue vector.
pub const VIRTIO_MSI_NO_VECTOR: u16 = 0xFFFF;

/// One extra virtqueue requested by a child profile. The child describes the
/// queue index and callback policy; the concrete transport resolves MSI-X
/// vectors and notify mappings during bring-up.
#[derive(Copy, Clone)]
pub struct VirtioQueuePlan {
    pub index: u16,
    pub msix_handler: Option<fn()>,
    pub msix_vec: u16,
    pub map_notify: bool,
}

impl VirtioQueuePlan {
    /// # C: O(1)
    pub const fn new(index: u16, msix_handler: Option<fn()>, map_notify: bool) -> Self {
        Self {
            index,
            msix_handler,
            msix_vec: VIRTIO_MSI_NO_VECTOR,
            map_notify,
        }
    }

    /// # C: O(1)
    pub const fn with_msix_vec(mut self, msix_vec: u16) -> Self {
        self.msix_vec = msix_vec;
        self
    }
}

/// Child-declared transport profile consumed by virtio transports. Device
/// drivers own feature policy and queue requirements; transports execute the
/// common status/feature/queue protocol and publish validated resources.
#[derive(Copy, Clone)]
pub struct VirtioTransportProfile {
    pub drv_features: u64,
    pub msix0_handler: Option<fn()>,
    pub queue_plans: [Option<VirtioQueuePlan>; MAX_RESOURCE_QUEUES],
    pub needs_net_boot_buffers: bool,
    pub child_requirements: VirtioChildRequirements,
}

impl VirtioTransportProfile {
    /// # C: O(1)
    pub const fn new(
        drv_features: u64,
        msix0_handler: Option<fn()>,
        queue_plans: [Option<VirtioQueuePlan>; MAX_RESOURCE_QUEUES],
        needs_net_boot_buffers: bool,
        child_requirements: VirtioChildRequirements,
    ) -> Self {
        Self {
            drv_features,
            msix0_handler,
            queue_plans,
            needs_net_boot_buffers,
            child_requirements,
        }
    }

    /// # C: O(1)
    pub const fn q0(drv_features: u64, msix0_handler: Option<fn()>) -> Self {
        Self::new(
            drv_features,
            msix0_handler,
            [None, None, None, None, None, None, None, None],
            false,
            VirtioChildRequirements::q0(),
        )
    }

    /// # C: O(1)
    pub const fn q0_device_cfg(drv_features: u64, msix0_handler: Option<fn()>) -> Self {
        Self::new(
            drv_features,
            msix0_handler,
            [None, None, None, None, None, None, None, None],
            false,
            VirtioChildRequirements::q0_device_cfg(),
        )
    }

    /// # C: O(1)
    pub const fn net(drv_features: u64, msix0_handler: Option<fn()>) -> Self {
        Self::new(
            drv_features,
            msix0_handler,
            [
                None,
                Some(VirtioQueuePlan::new(1, None, true)),
                None,
                None,
                None,
                None,
                None,
                None,
            ],
            true,
            VirtioChildRequirements::net(),
        )
    }

    /// # C: O(1)
    pub const fn vsock(drv_features: u64, msix0_handler: Option<fn()>) -> Self {
        Self::new(
            drv_features,
            msix0_handler,
            [
                None,
                Some(VirtioQueuePlan::new(1, None, true)),
                None,
                None,
                None,
                None,
                None,
                None,
            ],
            false,
            VirtioChildRequirements::q0_q1_device_cfg(),
        )
    }

    /// # C: O(1)
    pub const fn snd(
        drv_features: u64,
        msix0_handler: Option<fn()>,
        event_handler: Option<fn()>,
    ) -> Self {
        Self::new(
            drv_features,
            msix0_handler,
            [
                None,
                Some(VirtioQueuePlan::new(1, event_handler, true)),
                Some(VirtioQueuePlan::new(2, None, true)),
                Some(VirtioQueuePlan::new(3, None, true)),
                None,
                None,
                None,
                None,
            ],
            false,
            VirtioChildRequirements::snd(),
        )
    }
}

/// One programmed split virtqueue plus its notify window.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VirtQueueResource {
    pub index:      u16,
    pub size:       u16,
    pub desc_pa:    u64,
    pub driver_pa:  u64,
    pub device_pa:  u64,
    pub notify_va:  u64,
    pub notify_off: u16,
}

impl VirtQueueResource {
    /// # C: O(1)
    pub const fn new(
        index: u16,
        size: u16,
        desc_pa: u64,
        driver_pa: u64,
        device_pa: u64,
        notify_va: u64,
        notify_off: u16,
    ) -> Self {
        Self { index, size, desc_pa, driver_pa, device_pa, notify_va, notify_off }
    }

    /// True iff this queue has all runtime resources a child driver needs.
    /// # C: O(1)
    pub const fn is_runtime_valid(&self) -> bool {
        self.size != 0
            && self.desc_pa != 0
            && self.driver_pa != 0
            && self.device_pa != 0
            && self.notify_va != 0
    }
}

/// Queue notify VAs resolved by a concrete transport. The shared handoff
/// builder consumes this indexed table so resource assembly is not tied to a
/// PCI-specific q0/q1/q2/q3 shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtioQueueNotifyMappings {
    by_queue: [u64; MAX_RESOURCE_QUEUES],
}

impl VirtioQueueNotifyMappings {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self {
            by_queue: [0; MAX_RESOURCE_QUEUES],
        }
    }

    /// # C: O(1)
    pub fn set(&mut self, queue_index: u16, notify_va: u64) {
        let index = queue_index as usize;
        if index < MAX_RESOURCE_QUEUES {
            self.by_queue[index] = notify_va;
        }
    }

    /// # C: O(1)
    pub const fn get(&self, queue_index: u16) -> u64 {
        let index = queue_index as usize;
        if index < MAX_RESOURCE_QUEUES {
            self.by_queue[index]
        } else {
            0
        }
    }
}

impl Default for VirtioQueueNotifyMappings {
    fn default() -> Self {
        Self::new()
    }
}

/// Assemble child-visible queue resources from the transport's programmed
/// queues, scanned queue-size table, and resolved notify mappings.
/// # C: O(MAX_RESOURCE_QUEUES * N_scanned)
pub fn build_queue_resources(
    scanned_queues: &[(u16, u16); MAX_RESOURCE_QUEUES],
    scanned_len: usize,
    programmed_queues: Option<&ProgrammedQueues>,
    notify_mappings: &VirtioQueueNotifyMappings,
) -> [VirtQueueResource; MAX_RESOURCE_QUEUES] {
    core::array::from_fn(|index| {
        let index = index as u16;
        queue_resource(
            index,
            programmed_queues.and_then(|queues| queues.queue(index)),
            scanned_queue_size(scanned_queues, scanned_len, index),
            notify_mappings.get(index),
        )
    })
}

/// Transport observations needed to assemble the completed runtime handoff.
///
/// Concrete transports still own hardware actions such as mapping notify
/// windows, kicking queues, sampling ISR state, and allocating boot buffers.
/// Shared virtio owns converting those observations into child-visible queue
/// resources and transport-neutral boot payload descriptors.
pub struct VirtioRuntimeHandoffInput<'a> {
    pub scanned_queues: &'a [(u16, u16); MAX_RESOURCE_QUEUES],
    pub scanned_len: usize,
    pub programmed_queues: Option<&'a ProgrammedQueues>,
    pub planned_notify_mappings: VirtioQueueNotifyMappings,
    pub q0_notify_va: u64,
    pub q1_notify_va: u64,
    pub post_notify_status: u8,
    pub avail_idx_posted: u16,
    pub used_idx_observed: u16,
    pub isr_status: u8,
    pub net_boot_payloads: VirtioNetBootPayloads,
}

/// Transport-neutral facts handed from completed transport bring-up to the
/// child publication and trace paths.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VirtioRuntimeHandoff {
    pub queue_resources: [VirtQueueResource; MAX_RESOURCE_QUEUES],
    pub post_notify_status: u8,
    pub avail_idx_posted: u16,
    pub used_idx_observed: u16,
    pub isr_status: u8,
    pub net_boot_payloads: VirtioNetBootPayloads,
}

/// Assemble the final runtime handoff from transport-provided observations.
/// # C: O(MAX_RESOURCE_QUEUES * N_scanned)
pub fn build_runtime_handoff(input: VirtioRuntimeHandoffInput<'_>) -> VirtioRuntimeHandoff {
    let mut notify_mappings = input.planned_notify_mappings;
    notify_mappings.set(0, input.q0_notify_va);
    notify_mappings.set(1, input.q1_notify_va);

    VirtioRuntimeHandoff {
        queue_resources: build_queue_resources(
            input.scanned_queues,
            input.scanned_len,
            input.programmed_queues,
            &notify_mappings,
        ),
        post_notify_status: input.post_notify_status,
        avail_idx_posted: input.avail_idx_posted,
        used_idx_observed: input.used_idx_observed,
        isr_status: input.isr_status,
        net_boot_payloads: input.net_boot_payloads,
    }
}

/// Resolve notify mappings requested by child queue plans.
///
/// The concrete transport owns converting a programmed queue's
/// `queue_notify_off` into a usable notify address; shared virtio owns the
/// child-profile policy for which planned queues require persistent notify
/// mappings.
/// # C: O(MAX_RESOURCE_QUEUES)
pub fn resolve_planned_notify_mappings<F>(
    queue_plans: &[Option<VirtioQueuePlan>; MAX_RESOURCE_QUEUES],
    programmed_queues: Option<&ProgrammedQueues>,
    mut map_notify: F,
) -> VirtioQueueNotifyMappings
where
    F: FnMut(u16) -> u64,
{
    let mut mappings = VirtioQueueNotifyMappings::new();
    let Some(programmed) = programmed_queues else {
        return mappings;
    };

    for queue in queue_plans {
        let Some(queue) = queue else { continue };
        if !queue.map_notify {
            continue;
        }
        let Some(ring) = programmed.queue(queue.index) else {
            continue;
        };
        mappings.set(queue.index, map_notify(ring.notify_off));
    }

    mappings
}

fn scanned_queue_size(
    scanned_queues: &[(u16, u16); MAX_RESOURCE_QUEUES],
    scanned_len: usize,
    index: u16,
) -> u16 {
    scanned_queues
        .iter()
        .take(scanned_len)
        .find(|queue| queue.0 == index)
        .map(|queue| queue.1)
        .unwrap_or(0)
}

fn queue_resource(
    index: u16,
    ring: Option<QueueRing>,
    fallback_size: u16,
    notify_va: u64,
) -> VirtQueueResource {
    let size = ring.map(|ring| ring.size).unwrap_or(fallback_size);
    VirtQueueResource::new(
        index,
        size,
        ring.map(|ring| ring.desc_pa).unwrap_or(0),
        ring.map(|ring| ring.driver_pa).unwrap_or(0),
        ring.map(|ring| ring.device_pa).unwrap_or(0),
        notify_va,
        ring.map(|ring| ring.notify_off).unwrap_or(0),
    )
}

/// Common transport state and the programmed queues visible to a child driver.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VirtioResources {
    pub cfg_va:        u64,
    pub device_cfg_va: u64,
    pub hhdm:          u64,
    queues:            [Option<VirtQueueResource>; MAX_RESOURCE_QUEUES],
}

impl VirtioResources {
    /// # C: O(1)
    pub const fn new(cfg_va: u64, hhdm: u64) -> Self {
        Self {
            cfg_va,
            device_cfg_va: 0,
            hhdm,
            queues: [None; MAX_RESOURCE_QUEUES],
        }
    }

    /// Attach the transport-mapped device-specific config window.
    /// # C: O(1)
    pub const fn with_device_cfg_va(mut self, device_cfg_va: u64) -> Self {
        self.device_cfg_va = device_cfg_va;
        self
    }

    /// Build a resource set from the transport's programmed queue list.
    /// Duplicate queue indices keep the last entry, matching `set_queue`.
    /// # C: O(N_queues)
    pub fn from_queues(cfg_va: u64, hhdm: u64, queues: &[VirtQueueResource]) -> Self {
        let mut resources = Self::new(cfg_va, hhdm);
        for queue in queues {
            resources.set_queue(*queue);
        }
        resources
    }

    /// # C: O(1)
    pub fn set_queue(&mut self, queue: VirtQueueResource) {
        let index = queue.index as usize;
        if index < MAX_RESOURCE_QUEUES {
            self.queues[index] = Some(queue);
        }
    }

    /// # C: O(1)
    pub const fn queue(&self, index: u16) -> Option<VirtQueueResource> {
        let index = index as usize;
        if index < MAX_RESOURCE_QUEUES {
            self.queues[index]
        } else {
            None
        }
    }

    /// Return a programmed runtime queue only when the resource slot contains
    /// the requested queue index and all fields required by a child driver are
    /// present.
    /// # C: O(1)
    pub const fn require_queue(&self, index: u16) -> Option<VirtQueueResource> {
        let Some(queue) = self.queue(index) else {
            return None;
        };
        if queue.index == index && queue.is_runtime_valid() {
            Some(queue)
        } else {
            None
        }
    }

    /// # C: O(1)
    pub const fn common_cfg_valid(&self) -> bool {
        self.cfg_va != 0 && self.hhdm != 0
    }

    /// True iff common transport state is present and every requested queue is
    /// present, index-matched, and runtime-valid.
    /// # C: O(N_required)
    pub fn require_common_and_queues(&self, queues: &[u16]) -> bool {
        if !self.common_cfg_valid() {
            return false;
        }
        for queue in queues {
            if self.require_queue(*queue).is_none() {
                return false;
            }
        }
        true
    }
}

/// Transport-neutral location for a virtio child. PCI transports fill these
/// fields from BDF; non-PCI transports can use the same tuple as a stable
/// controller-local location without pulling PCI types into child drivers.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct VirtioTransportLocation {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl VirtioTransportLocation {
    /// # C: O(1)
    pub const fn new(bus: u8, device: u8, function: u8) -> Self {
        Self {
            bus,
            device,
            function,
        }
    }
}

/// Early payload buffers a transport may prepare for a network child before
/// the child runtime takes over normal RX/TX ownership.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct VirtioNetBootPayloads {
    pub rx_buf_pa: u64,
    pub rx_buf_len: u16,
    pub tx_buf_pa: u64,
}

impl VirtioNetBootPayloads {
    /// # C: O(1)
    pub const fn new(rx_buf_pa: u64, rx_buf_len: u16, tx_buf_pa: u64) -> Self {
        Self {
            rx_buf_pa,
            rx_buf_len,
            tx_buf_pa,
        }
    }

    /// # C: O(1)
    pub const fn is_present(&self) -> bool {
        self.rx_buf_pa != 0 && self.rx_buf_len != 0 && self.tx_buf_pa != 0
    }
}

/// Transport-neutral state used to decide whether a completed transport
/// bring-up can hand resources to a virtio child driver.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VirtioChildResourceState {
    pub final_status: u8,
    pub cfg_va: u64,
    pub device_cfg_va: u64,
    pub hhdm: u64,
    pub net_boot_payloads: VirtioNetBootPayloads,
    queues: [Option<VirtQueueResource>; MAX_RESOURCE_QUEUES],
}

impl VirtioChildResourceState {
    /// # C: O(1)
    pub const fn new(final_status: u8, cfg_va: u64, hhdm: u64) -> Self {
        Self {
            final_status,
            cfg_va,
            device_cfg_va: 0,
            hhdm,
            net_boot_payloads: VirtioNetBootPayloads::new(0, 0, 0),
            queues: [None; MAX_RESOURCE_QUEUES],
        }
    }

    /// # C: O(1)
    pub const fn with_device_cfg_va(mut self, device_cfg_va: u64) -> Self {
        self.device_cfg_va = device_cfg_va;
        self
    }

    /// # C: O(1)
    pub const fn with_net_boot_payloads(mut self, payloads: VirtioNetBootPayloads) -> Self {
        self.net_boot_payloads = payloads;
        self
    }

    /// # C: O(1)
    pub fn set_queue(&mut self, queue: VirtQueueResource) {
        let index = queue.index as usize;
        if index < MAX_RESOURCE_QUEUES {
            self.queues[index] = Some(queue);
        }
    }

    /// # C: O(1)
    pub const fn queue(&self, index: u16) -> Option<VirtQueueResource> {
        let index = index as usize;
        if index < MAX_RESOURCE_QUEUES {
            self.queues[index]
        } else {
            None
        }
    }

    /// # C: O(N_required)
    pub fn ready_for_child(&self, requirements: VirtioChildRequirements) -> bool {
        if (self.final_status & crate::VIRTIO_STATUS_DRIVER_OK) == 0 || self.cfg_va == 0 {
            return false;
        }
        if requirements.needs_device_cfg && self.device_cfg_va == 0 {
            return false;
        }
        if requirements.needs_net_boot_payloads && !self.net_boot_payloads.is_present() {
            return false;
        }
        for (index, required) in requirements.required_queues.iter().copied().enumerate() {
            if !required {
                continue;
            }
            let Some(queue) = self.queue(index as u16) else {
                return false;
            };
            if queue.index != index as u16 || !queue.is_runtime_valid() {
                return false;
            }
        }
        true
    }

    /// # C: O(N_required)
    pub fn resources_for_child(
        &self,
        requirements: VirtioChildRequirements,
    ) -> Option<VirtioResources> {
        if !self.ready_for_child(requirements) {
            return None;
        }
        let mut resources =
            VirtioResources::new(self.cfg_va, self.hhdm).with_device_cfg_va(self.device_cfg_va);
        for (index, required) in requirements.required_queues.iter().copied().enumerate() {
            if required {
                resources.set_queue(self.queue(index as u16)?);
            }
        }
        Some(resources)
    }
}

/// Child-visible facts produced by a completed transport probe. The concrete
/// transport still owns MMIO/MSI lifetime and teardown records; this object
/// carries the transport-neutral facts child drivers need after bring-up.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VirtioChildProbeFacts {
    pub drv_features: u64,
    pub resources: VirtioChildResourceState,
}

impl VirtioChildProbeFacts {
    /// # C: O(1)
    pub const fn new(drv_features: u64, resources: VirtioChildResourceState) -> Self {
        Self {
            drv_features,
            resources,
        }
    }

    /// # C: O(1)
    pub const fn net_boot_payloads(&self) -> VirtioNetBootPayloads {
        self.resources.net_boot_payloads
    }

    /// # C: O(N_required)
    pub fn resources_for_child(
        &self,
        requirements: VirtioChildRequirements,
    ) -> Option<VirtioResources> {
        self.resources.resources_for_child(requirements)
    }
}

/// Transport-neutral result of a completed virtio transport bring-up.
///
/// Concrete transports still own MMIO mapping, IRQ/MSI binding, PCI command
/// lifetime, and debug trace data. This object owns the common child-facing
/// resource facts and the frame lists needed for failed-probe cleanup.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VirtioTransportProbeResult {
    pub hhdm: u64,
    pub drv_features: u64,
    pub final_status: u8,
    pub cfg_va: u64,
    pub device_cfg_va: u64,
    pub queue_resources: [VirtQueueResource; MAX_RESOURCE_QUEUES],
    pub net_boot_payloads: VirtioNetBootPayloads,
}

impl VirtioTransportProbeResult {
    /// # C: O(1)
    pub const fn new(
        hhdm: u64,
        drv_features: u64,
        final_status: u8,
        cfg_va: u64,
        device_cfg_va: u64,
        queue_resources: [VirtQueueResource; MAX_RESOURCE_QUEUES],
        net_boot_payloads: VirtioNetBootPayloads,
    ) -> Self {
        Self {
            hhdm,
            drv_features,
            final_status,
            cfg_va,
            device_cfg_va,
            queue_resources,
            net_boot_payloads,
        }
    }

    /// # C: O(MAX_RESOURCE_QUEUES)
    pub fn child_facts(&self) -> VirtioChildProbeFacts {
        let mut resources = VirtioChildResourceState::new(self.final_status, self.cfg_va, self.hhdm)
            .with_device_cfg_va(self.device_cfg_va)
            .with_net_boot_payloads(self.net_boot_payloads);
        for queue in self.queue_resources {
            resources.set_queue(queue);
        }
        VirtioChildProbeFacts::new(self.drv_features, resources)
    }

    /// # C: O(MAX_RESOURCE_QUEUES)
    pub fn vring_frames(&self) -> Vec<u64> {
        let mut frames = Vec::new();
        for queue in self.queue_resources {
            push_unique_frame(&mut frames, queue.desc_pa);
            push_unique_frame(&mut frames, queue.driver_pa);
            push_unique_frame(&mut frames, queue.device_pa);
        }
        frames
    }

    /// # C: O(1)
    pub const fn net_payload_frames(&self) -> [u64; 2] {
        [
            self.net_boot_payloads.rx_buf_pa,
            self.net_boot_payloads.tx_buf_pa,
        ]
    }
}

/// # C: O(N)
pub fn push_unique_frame(frames: &mut Vec<u64>, frame: u64) {
    if frame != 0 && !frames.iter().any(|existing| *existing == frame) {
        frames.push(frame);
    }
}

/// Common child-facing session contract implemented by concrete virtio
/// transports. Child drivers consume this shape; transport backends own how
/// bring-up, IRQ/vector binding, MMIO lifetime, and failed-probe release are
/// actually performed.
pub trait VirtioChildTransportSession {
    /// Stable key used by this kernel's per-device child runtime tables.
    /// # C: O(1)
    fn device_key(&self) -> u32;

    /// Controller-local address of the transport-owned child.
    /// # C: O(1)
    fn location(&self) -> VirtioTransportLocation;

    /// Negotiated driver feature mask after transport bring-up.
    /// # C: O(1)
    fn drv_features(&self) -> u64;

    /// Transport-prepared network boot payload buffers, if requested.
    /// # C: O(1)
    fn net_boot_payloads(&self) -> VirtioNetBootPayloads;

    /// Validated common/device config and queue resources for the child.
    /// # C: O(N_required)
    fn child_resources(&self) -> Option<VirtioResources>;

    /// Release transport-owned probe state after child install failure.
    /// # C: O(N_transport_resources)
    fn release_failed_child(&mut self);

    /// Publish persistent transport state after a child probe succeeds.
    /// # C: O(N_transport_resources)
    fn publish(self)
    where
        Self: Sized;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_driver_id_matches_virtio_child_devices() {
        let id = VirtioChildDriverId::new("virtio-test", 42);

        assert_eq!(id.name, "virtio-test");
        assert!(id.matches_device(VIRTIO_CHILD_BUS, VIRTIO_VENDOR_ID, 42));
        assert!(!id.matches_device("pci", VIRTIO_VENDOR_ID, 42));
        assert!(!id.matches_device(VIRTIO_CHILD_BUS, 0x1234, 42));
        assert!(!id.matches_device(VIRTIO_CHILD_BUS, VIRTIO_VENDOR_ID, 43));
    }

    #[test]
    fn child_model_identity_maps_modern_pci_device() {
        let child = VirtioChildModelIdentity::modern_from_pci(0x1AF4, 0x1041, 2)
            .expect("modern virtio block id");

        assert_eq!(child.bus, VIRTIO_CHILD_BUS);
        assert_eq!(child.addr, "virtio2");
        assert_eq!(child.vendor_id, 0x1AF4);
        assert_eq!(child.device_id, 1);
        assert_eq!(child.class, VIRTIO_CHILD_CLASS);
    }

    #[test]
    fn child_model_identity_rejects_non_modern_pci_device() {
        assert!(VirtioChildModelIdentity::modern_from_pci(0x1AF4, 0x1000, 0).is_none());
        assert!(VirtioChildModelIdentity::modern_from_pci(0x1AF4, 0x9999, 0).is_none());
    }

    #[test]
    fn child_parent_match_requires_virtio_bus_and_matching_parent() {
        assert!(virtio_child_has_parent(
            VIRTIO_CHILD_BUS,
            Some(("pci", "0000:00:01.0")),
            "pci",
            "0000:00:01.0",
        ));
        assert!(!virtio_child_has_parent(
            "pci",
            Some(("pci", "0000:00:01.0")),
            "pci",
            "0000:00:01.0",
        ));
        assert!(!virtio_child_has_parent(
            VIRTIO_CHILD_BUS,
            Some(("pci", "0000:00:02.0")),
            "pci",
            "0000:00:01.0",
        ));
        assert!(!virtio_child_has_parent(
            VIRTIO_CHILD_BUS,
            None,
            "pci",
            "0000:00:01.0",
        ));
    }

    const VALID_Q0: VirtQueueResource = VirtQueueResource {
        index:      0,
        size:       8,
        desc_pa:    0x1000,
        driver_pa:  0x2000,
        device_pa:  0x3000,
        notify_va:  0x4000,
        notify_off: 2,
    };

    #[test]
    fn require_queue_accepts_matching_runtime_queue() {
        let resources = VirtioResources::from_queues(0x10, 0x20, &[VALID_Q0]);

        assert_eq!(resources.require_queue(0), Some(VALID_Q0));
        assert!(resources.require_common_and_queues(&[0]));
    }

    #[test]
    fn require_queue_rejects_missing_or_invalid_queue() {
        let mut invalid = VALID_Q0;
        invalid.notify_va = 0;
        let resources = VirtioResources::from_queues(0x10, 0x20, &[invalid]);

        assert_eq!(resources.require_queue(0), None);
        assert_eq!(resources.require_queue(1), None);
        assert!(!resources.require_common_and_queues(&[0]));
        assert!(!resources.require_common_and_queues(&[1]));
    }

    #[test]
    fn require_common_and_queues_rejects_missing_common_state() {
        let resources = VirtioResources::from_queues(0, 0x20, &[VALID_Q0]);

        assert_eq!(resources.require_queue(0), Some(VALID_Q0));
        assert!(!resources.require_common_and_queues(&[0]));
    }

    #[test]
    fn notify_mappings_are_indexed_and_bounded() {
        let mut mappings = VirtioQueueNotifyMappings::new();
        mappings.set(1, 0x1000);
        mappings.set((MAX_RESOURCE_QUEUES + 1) as u16, 0x2000);

        assert_eq!(mappings.get(1), 0x1000);
        assert_eq!(mappings.get((MAX_RESOURCE_QUEUES + 1) as u16), 0);
    }

    #[test]
    fn build_queue_resources_uses_scanned_sizes_and_notify_mappings() {
        let mut mappings = VirtioQueueNotifyMappings::new();
        mappings.set(0, 0x1000);
        mappings.set(3, 0x3000);
        let scanned = [
            (0, 8),
            (3, 16),
            (0, 0),
            (0, 0),
            (0, 0),
            (0, 0),
            (0, 0),
            (0, 0),
        ];

        let resources = build_queue_resources(&scanned, 2, None, &mappings);

        assert_eq!(resources[0].index, 0);
        assert_eq!(resources[0].size, 8);
        assert_eq!(resources[0].notify_va, 0x1000);
        assert_eq!(resources[3].index, 3);
        assert_eq!(resources[3].size, 16);
        assert_eq!(resources[3].notify_va, 0x3000);
        assert_eq!(resources[2].size, 0);
    }

    #[test]
    fn build_runtime_handoff_applies_final_notify_observations() {
        let programmed = ProgrammedQueues::from_test_parts(
            QueueRing {
                desc_pa: 0x1000,
                driver_pa: 0x2000,
                device_pa: 0x3000,
                notify_off: 4,
                size: 8,
            },
            core::array::from_fn(|index| {
                if index == 1 {
                    Some(QueueRing {
                        desc_pa: 0x4000,
                        driver_pa: 0x5000,
                        device_pa: 0x6000,
                        notify_off: 8,
                        size: 16,
                    })
                } else {
                    None
                }
            }),
        );
        let scanned = [
            (0, 8),
            (1, 16),
            (0, 0),
            (0, 0),
            (0, 0),
            (0, 0),
            (0, 0),
            (0, 0),
        ];
        let mut planned = VirtioQueueNotifyMappings::new();
        planned.set(1, 0x1111);

        let handoff = build_runtime_handoff(VirtioRuntimeHandoffInput {
            scanned_queues: &scanned,
            scanned_len: 2,
            programmed_queues: Some(&programmed),
            planned_notify_mappings: planned,
            q0_notify_va: 0xaaa0,
            q1_notify_va: 0xbbb0,
            post_notify_status: crate::VIRTIO_STATUS_DRIVER_OK,
            avail_idx_posted: 1,
            used_idx_observed: 2,
            isr_status: 3,
            net_boot_payloads: VirtioNetBootPayloads::new(0x7000, 64, 0x8000),
        });

        assert_eq!(handoff.queue_resources[0].size, 8);
        assert_eq!(handoff.queue_resources[0].notify_va, 0xaaa0);
        assert_eq!(handoff.queue_resources[1].size, 16);
        assert_eq!(handoff.queue_resources[1].notify_va, 0xbbb0);
        assert_eq!(handoff.queue_resources[1].desc_pa, 0x4000);
        assert_eq!(handoff.post_notify_status, crate::VIRTIO_STATUS_DRIVER_OK);
        assert_eq!(handoff.avail_idx_posted, 1);
        assert_eq!(handoff.used_idx_observed, 2);
        assert_eq!(handoff.isr_status, 3);
        assert_eq!(
            handoff.net_boot_payloads,
            VirtioNetBootPayloads::new(0x7000, 64, 0x8000)
        );
    }

    #[test]
    fn resolve_planned_notify_mappings_uses_child_queue_policy() {
        let programmed = ProgrammedQueues::from_test_parts(
            QueueRing {
                desc_pa: 0x1000,
                driver_pa: 0x2000,
                device_pa: 0x3000,
                notify_off: 4,
                size: 8,
            },
            core::array::from_fn(|index| {
                if index == 1 {
                    Some(QueueRing {
                        desc_pa: 0x4000,
                        driver_pa: 0x5000,
                        device_pa: 0x6000,
                        notify_off: 8,
                        size: 8,
                    })
                } else if index == 2 {
                    Some(QueueRing {
                        desc_pa: 0x7000,
                        driver_pa: 0x8000,
                        device_pa: 0x9000,
                        notify_off: 12,
                        size: 8,
                    })
                } else {
                    None
                }
            }),
        );
        let mut plans = [None; MAX_RESOURCE_QUEUES];
        plans[1] = Some(VirtioQueuePlan::new(1, None, true));
        plans[2] = Some(VirtioQueuePlan::new(2, None, false));
        plans[3] = Some(VirtioQueuePlan::new(3, None, true));

        let mappings = resolve_planned_notify_mappings(&plans, Some(&programmed), |notify_off| {
            0x1000 + notify_off as u64
        });

        assert_eq!(mappings.get(1), 0x1008);
        assert_eq!(mappings.get(2), 0);
        assert_eq!(mappings.get(3), 0);
    }

    #[test]
    fn child_requirements_describe_transport_contracts() {
        let q0 = VirtioChildRequirements::q0();
        assert!(q0.required_queues[0]);
        assert!(!q0.needs_device_cfg);
        assert!(!q0.needs_net_boot_payloads);

        let net = VirtioChildRequirements::net();
        assert!(net.required_queues[0]);
        assert!(net.required_queues[1]);
        assert!(net.needs_net_boot_payloads);
        assert!(!net.needs_device_cfg);

        let snd = VirtioChildRequirements::snd();
        assert!(snd.required_queues[0]);
        assert!(snd.required_queues[1]);
        assert!(snd.required_queues[2]);
        assert!(snd.required_queues[3]);
        assert!(snd.needs_device_cfg);
        assert!(!snd.required_queues[4]);
    }

    #[test]
    fn transport_profiles_describe_child_queue_policy() {
        let net = VirtioTransportProfile::net(0x55, None);
        assert_eq!(net.drv_features, 0x55);
        assert!(net.needs_net_boot_buffers);
        assert_eq!(net.queue_plans[1].map(|q| q.index), Some(1));
        assert!(net.queue_plans[1].map(|q| q.map_notify).unwrap_or(false));
        assert!(net.child_requirements.needs_net_boot_payloads);

        let snd = VirtioTransportProfile::snd(0xaa, None, None);
        assert_eq!(snd.drv_features, 0xaa);
        assert_eq!(snd.queue_plans[1].map(|q| q.index), Some(1));
        assert_eq!(snd.queue_plans[2].map(|q| q.index), Some(2));
        assert_eq!(snd.queue_plans[3].map(|q| q.index), Some(3));
        assert!(snd.queue_plans[1].map(|q| q.map_notify).unwrap_or(false));
        assert!(snd.queue_plans[2].map(|q| q.map_notify).unwrap_or(false));
        assert!(snd.child_requirements.needs_device_cfg);
    }

    #[test]
    fn child_session_data_is_transport_neutral() {
        let loc = VirtioTransportLocation::new(0, 3, 1);
        assert_eq!(loc.bus, 0);
        assert_eq!(loc.device, 3);
        assert_eq!(loc.function, 1);

        let empty = VirtioNetBootPayloads::default();
        assert!(!empty.is_present());

        let payloads = VirtioNetBootPayloads::new(0x1000, 64, 0x2000);
        assert!(payloads.is_present());
    }

    #[test]
    fn child_resource_state_builds_required_resources() {
        let mut state =
            VirtioChildResourceState::new(crate::VIRTIO_STATUS_DRIVER_OK, 0x10, 0x20)
                .with_device_cfg_va(0x30);
        state.set_queue(VALID_Q0);

        let resources = state
            .resources_for_child(VirtioChildRequirements::q0_device_cfg())
            .unwrap();

        assert_eq!(resources.cfg_va, 0x10);
        assert_eq!(resources.device_cfg_va, 0x30);
        assert_eq!(resources.require_queue(0), Some(VALID_Q0));
    }

    #[test]
    fn child_resource_state_rejects_not_ready_transport() {
        let mut state = VirtioChildResourceState::new(0, 0x10, 0x20);
        state.set_queue(VALID_Q0);
        assert!(!state.ready_for_child(VirtioChildRequirements::q0()));

        let state = VirtioChildResourceState::new(crate::VIRTIO_STATUS_DRIVER_OK, 0x10, 0x20);
        assert!(!state.ready_for_child(VirtioChildRequirements::q0()));

        let mut state =
            VirtioChildResourceState::new(crate::VIRTIO_STATUS_DRIVER_OK, 0x10, 0x20);
        state.set_queue(VALID_Q0);
        assert!(!state.ready_for_child(VirtioChildRequirements::q0_device_cfg()));
        assert!(!state.ready_for_child(VirtioChildRequirements::net()));

        let state = state.with_net_boot_payloads(VirtioNetBootPayloads::new(0x1000, 64, 0x2000));
        assert!(!state.ready_for_child(VirtioChildRequirements::net()));
    }

    #[test]
    fn child_probe_facts_expose_features_payloads_and_resources() {
        let mut state =
            VirtioChildResourceState::new(crate::VIRTIO_STATUS_DRIVER_OK, 0x10, 0x20)
                .with_net_boot_payloads(VirtioNetBootPayloads::new(0x1000, 64, 0x2000));
        state.set_queue(VALID_Q0);
        let facts = VirtioChildProbeFacts::new(0x55, state);

        assert_eq!(facts.drv_features, 0x55);
        assert!(facts.net_boot_payloads().is_present());
        assert!(facts
            .resources_for_child(VirtioChildRequirements::q0())
            .is_some());
    }

    #[test]
    fn transport_probe_result_builds_child_facts_and_frame_lists() {
        let mut queues = core::array::from_fn(|index| {
            VirtQueueResource::new(index as u16, 0, 0, 0, 0, 0, 0)
        });
        queues[0] = VALID_Q0;
        queues[1] = VirtQueueResource {
            index:      1,
            size:       8,
            desc_pa:    0x5000,
            driver_pa:  0x6000,
            device_pa:  0x7000,
            notify_va:  0x8000,
            notify_off: 4,
        };
        let result = VirtioTransportProbeResult::new(
            0x20,
            0x55,
            crate::VIRTIO_STATUS_DRIVER_OK,
            0x10,
            0x30,
            queues,
            VirtioNetBootPayloads::new(0x9000, 64, 0xa000),
        );

        let facts = result.child_facts();
        assert_eq!(facts.drv_features, 0x55);
        assert_eq!(facts.net_boot_payloads().rx_buf_pa, 0x9000);
        let resources = facts.resources_for_child(VirtioChildRequirements::net()).unwrap();
        assert_eq!(resources.cfg_va, 0x10);
        assert_eq!(resources.device_cfg_va, 0x30);
        assert_eq!(resources.require_queue(0), Some(queues[0]));
        assert_eq!(resources.require_queue(1), Some(queues[1]));

        assert_eq!(
            result.vring_frames(),
            alloc::vec![0x1000, 0x2000, 0x3000, 0x5000, 0x6000, 0x7000]
        );
        assert_eq!(result.net_payload_frames(), [0x9000, 0xa000]);
    }
}
