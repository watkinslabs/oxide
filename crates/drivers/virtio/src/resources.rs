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

/// Stable transport-neutral key for a virtio child device.
///
/// The current PCI transport packs bus/device/function into the raw value, but
/// child-session users should not depend on that encoding.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct VirtioChildDeviceKey(u32);

impl VirtioChildDeviceKey {
    /// # C: O(1)
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// # C: O(1)
    pub const fn from_location(location: VirtioTransportLocation) -> Self {
        Self(
            ((location.bus as u32) << 16)
                | ((location.device as u32) << 8)
                | location.function as u32,
        )
    }

    /// # C: O(1)
    pub const fn raw(self) -> u32 {
        self.0
    }
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

/// Optional early payloads a child driver can request from the transport
/// before normal runtime ownership takes over.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VirtioEarlyPayloadPolicy {
    None,
    Net,
}

impl VirtioEarlyPayloadPolicy {
    /// # C: O(1)
    pub const fn is_net(self) -> bool {
        match self {
            Self::None => false,
            Self::Net => true,
        }
    }
}

/// Child-declared transport profile consumed by virtio transports. Device
/// drivers own feature policy, queue requirements, and any early boot payload
/// contract; transports execute those policies through concrete hardware ops.
#[derive(Copy, Clone)]
pub struct VirtioTransportProfile {
    pub drv_features: u64,
    pub msix0_handler: Option<fn()>,
    pub queue_plans: [Option<VirtioQueuePlan>; MAX_RESOURCE_QUEUES],
    pub early_payload_policy: VirtioEarlyPayloadPolicy,
    pub child_requirements: VirtioChildRequirements,
}

impl VirtioTransportProfile {
    /// # C: O(1)
    pub const fn new(
        drv_features: u64,
        msix0_handler: Option<fn()>,
        queue_plans: [Option<VirtioQueuePlan>; MAX_RESOURCE_QUEUES],
        early_payload_policy: VirtioEarlyPayloadPolicy,
        child_requirements: VirtioChildRequirements,
    ) -> Self {
        Self {
            drv_features,
            msix0_handler,
            queue_plans,
            early_payload_policy,
            child_requirements,
        }
    }

    /// # C: O(1)
    pub const fn q0(drv_features: u64, msix0_handler: Option<fn()>) -> Self {
        Self::new(
            drv_features,
            msix0_handler,
            [None, None, None, None, None, None, None, None],
            VirtioEarlyPayloadPolicy::None,
            VirtioChildRequirements::q0(),
        )
    }

    /// # C: O(1)
    pub const fn q0_device_cfg(drv_features: u64, msix0_handler: Option<fn()>) -> Self {
        Self::new(
            drv_features,
            msix0_handler,
            [None, None, None, None, None, None, None, None],
            VirtioEarlyPayloadPolicy::None,
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
            VirtioEarlyPayloadPolicy::Net,
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
            VirtioEarlyPayloadPolicy::None,
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
            VirtioEarlyPayloadPolicy::None,
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
pub struct VirtioNetRxBuffer {
    pub desc_id: u16,
    pub pa:      u64,
    pub len:     u16,
}

/// Number of RX buffers the PCI transport pre-posts for a virtio-net child.
pub const VIRTIO_NET_RX_BOOT_POOL: usize = 8;

/// Early payload buffers a transport may prepare for a network child before
/// the child runtime takes over normal RX/TX ownership.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct VirtioNetBootPayloads {
    pub rx_bufs:   [VirtioNetRxBuffer; VIRTIO_NET_RX_BOOT_POOL],
    pub rx_bufs_len: usize,
    pub tx_buf_pa: u64,
}

impl VirtioNetBootPayloads {
    /// # C: O(1)
    pub const fn new(rx_buf_pa: u64, rx_buf_len: u16, tx_buf_pa: u64) -> Self {
        let mut rx_bufs = [VirtioNetRxBuffer { desc_id: 0, pa: 0, len: 0 }; VIRTIO_NET_RX_BOOT_POOL];
        let rx_bufs_len = if rx_buf_pa != 0 && rx_buf_len != 0 {
            rx_bufs[0] = VirtioNetRxBuffer {
                desc_id: 0,
                pa: rx_buf_pa,
                len: rx_buf_len,
            };
            1
        } else {
            0
        };
        Self {
            rx_bufs,
            rx_bufs_len,
            tx_buf_pa,
        }
    }

    /// # C: O(1)
    pub const fn from_rx_pool(
        rx_bufs: [VirtioNetRxBuffer; VIRTIO_NET_RX_BOOT_POOL],
        rx_bufs_len: usize,
        tx_buf_pa: u64,
    ) -> Self {
        Self {
            rx_bufs,
            rx_bufs_len,
            tx_buf_pa,
        }
    }

    /// # C: O(1)
    pub const fn is_present(&self) -> bool {
        self.rx_bufs_len != 0 && self.rx_bufs_valid() && self.tx_buf_pa != 0
    }

    /// # C: O(VIRTIO_NET_RX_BOOT_POOL)
    pub const fn rx_bufs_valid(&self) -> bool {
        let mut i = 0;
        while i < self.rx_bufs_len {
            if i >= VIRTIO_NET_RX_BOOT_POOL
                || self.rx_bufs[i].pa == 0
                || self.rx_bufs[i].len == 0
            {
                return false;
            }
            i += 1;
        }
        true
    }
}

mod child;
pub use child::{
    push_unique_frame, run_child_probe, run_child_remove, run_child_shutdown,
    VirtioChildProbeFacts, VirtioChildResourceState, VirtioChildTransportSession,
    VirtioProbeLease, VirtioProbeOwnedFrames, VirtioTransportProbeResult,
};

#[cfg(test)]
mod tests;
