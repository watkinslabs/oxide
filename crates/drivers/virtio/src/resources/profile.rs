pub const MAX_RESOURCE_QUEUES: usize = 8;
pub const VIRTIO_MSI_NO_VECTOR: u16 = 0xFFFF;
/// Virtqueue index a single-poll-queue device profile dedicates to polling.
/// Polling queues occupy the TAIL of the queue array so interrupt-driven
/// default queues keep the low indexes; with one of each that tail is index 1.
pub const POLL_QUEUE_INDEX: u16 = 1;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VirtioChildRequirements {
    pub required_queues: [bool; MAX_RESOURCE_QUEUES],
    /// Queues the child USES when the device provides them and does without
    /// otherwise. Absence never fails the probe; a required queue's does.
    pub optional_queues: [bool; MAX_RESOURCE_QUEUES],
    pub needs_device_cfg: bool,
    pub needs_net_boot_payloads: bool,
}

const NO_QUEUES: [bool; MAX_RESOURCE_QUEUES] = [false; MAX_RESOURCE_QUEUES];

impl VirtioChildRequirements {
    pub const fn new(
        required_queues: [bool; MAX_RESOURCE_QUEUES],
        needs_device_cfg: bool,
        needs_net_boot_payloads: bool,
    ) -> Self {
        Self { required_queues, optional_queues: NO_QUEUES, needs_device_cfg, needs_net_boot_payloads }
    }

    /// Mark one virtqueue as usable-if-present. # C: O(1)
    pub const fn with_optional_queue(mut self, index: usize) -> Self {
        if index < MAX_RESOURCE_QUEUES { self.optional_queues[index] = true; }
        self
    }

    pub const fn q0() -> Self {
        Self::new([true, false, false, false, false, false, false, false], false, false)
    }

    pub const fn q0_device_cfg() -> Self {
        Self::new([true, false, false, false, false, false, false, false], true, false)
    }

    pub const fn q0_q1() -> Self {
        Self::new([true, true, false, false, false, false, false, false], false, false)
    }

    pub const fn q0_q1_device_cfg() -> Self {
        Self::new([true, true, false, false, false, false, false, false], true, false)
    }

    pub const fn net() -> Self {
        Self::new([true, true, false, false, false, false, false, false], true, true)
    }

    pub const fn snd() -> Self {
        Self::new([true, true, true, true, false, false, false, false], true, false)
    }
}

#[derive(Copy, Clone)]
pub struct VirtioQueuePlan {
    pub index: u16,
    pub msix_handler: Option<fn()>,
    pub msix_vec: u16,
    pub map_notify: bool,
}

impl VirtioQueuePlan {
    pub const fn new(index: u16, msix_handler: Option<fn()>, map_notify: bool) -> Self {
        Self { index, msix_handler, msix_vec: VIRTIO_MSI_NO_VECTOR, map_notify }
    }

    pub const fn with_msix_vec(mut self, msix_vec: u16) -> Self {
        self.msix_vec = msix_vec;
        self
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VirtioEarlyPayloadPolicy {
    None,
    Net,
}

impl VirtioEarlyPayloadPolicy {
    pub const fn is_net(self) -> bool {
        match self {
            Self::None => false,
            Self::Net => true,
        }
    }
}

#[derive(Copy, Clone)]
pub struct VirtioTransportProfile {
    pub drv_features: u64,
    pub msix0_handler: Option<fn()>,
    pub queue_plans: [Option<VirtioQueuePlan>; MAX_RESOURCE_QUEUES],
    pub early_payload_policy: VirtioEarlyPayloadPolicy,
    pub child_requirements: VirtioChildRequirements,
}

impl VirtioTransportProfile {
    pub const fn new(
        drv_features: u64,
        msix0_handler: Option<fn()>,
        queue_plans: [Option<VirtioQueuePlan>; MAX_RESOURCE_QUEUES],
        early_payload_policy: VirtioEarlyPayloadPolicy,
        child_requirements: VirtioChildRequirements,
    ) -> Self {
        // Ring features are transport capabilities. Keep them outside every
        // child driver's device-specific feature declaration.
        Self {
            drv_features: drv_features | crate::VIRTIO_F_RING_EVENT_IDX,
            msix0_handler,
            queue_plans,
            early_payload_policy,
            child_requirements,
        }
    }

    pub const fn q0(drv_features: u64, msix0_handler: Option<fn()>) -> Self {
        Self::new(
            drv_features,
            msix0_handler,
            [None, None, None, None, None, None, None, None],
            VirtioEarlyPayloadPolicy::None,
            VirtioChildRequirements::q0(),
        )
    }

    pub const fn q0_device_cfg(drv_features: u64, msix0_handler: Option<fn()>) -> Self {
        Self::new(
            drv_features,
            msix0_handler,
            [None, None, None, None, None, None, None, None],
            VirtioEarlyPayloadPolicy::None,
            VirtioChildRequirements::q0_device_cfg(),
        )
    }

    /// One interrupt-driven request queue plus an OPTIONAL polling queue at
    /// index 1. The poll queue registers no completion handler, so the
    /// transport binds it `VIRTIO_MSI_NO_VECTOR` and the device is left with
    /// no vector to raise for it. Its notify doorbell is still mapped: a
    /// poller must be able to kick. # C: O(1)
    pub const fn q0_device_cfg_poll_q1(drv_features: u64, msix0_handler: Option<fn()>) -> Self {
        Self::new(
            drv_features,
            msix0_handler,
            [None, Some(VirtioQueuePlan::new(POLL_QUEUE_INDEX, None, true)), None, None, None, None, None, None],
            VirtioEarlyPayloadPolicy::None,
            VirtioChildRequirements::q0_device_cfg()
                .with_optional_queue(POLL_QUEUE_INDEX as usize),
        )
    }

    pub const fn q0_q1(drv_features: u64, msix0_handler: Option<fn()>) -> Self {
        Self::new(
            drv_features,
            msix0_handler,
            [None, Some(VirtioQueuePlan::new(1, None, true)), None, None, None, None, None, None],
            VirtioEarlyPayloadPolicy::None,
            VirtioChildRequirements::q0_q1(),
        )
    }

    pub const fn net(drv_features: u64, msix0_handler: Option<fn()>) -> Self {
        Self::new(
            drv_features,
            msix0_handler,
            [None, Some(VirtioQueuePlan::new(1, None, true)), None, None, None, None, None, None],
            VirtioEarlyPayloadPolicy::Net,
            VirtioChildRequirements::net(),
        )
    }

    pub const fn vsock(drv_features: u64, msix0_handler: Option<fn()>) -> Self {
        Self::new(
            drv_features,
            msix0_handler,
            [None, Some(VirtioQueuePlan::new(1, None, true)), None, None, None, None, None, None],
            VirtioEarlyPayloadPolicy::None,
            VirtioChildRequirements::q0_q1_device_cfg(),
        )
    }

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
