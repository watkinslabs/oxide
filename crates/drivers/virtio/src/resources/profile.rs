pub const MAX_RESOURCE_QUEUES: usize = 8;
pub const VIRTIO_MSI_NO_VECTOR: u16 = 0xFFFF;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VirtioChildRequirements {
    pub required_queues: [bool; MAX_RESOURCE_QUEUES],
    pub needs_device_cfg: bool,
    pub needs_net_boot_payloads: bool,
}

impl VirtioChildRequirements {
    pub const fn new(
        required_queues: [bool; MAX_RESOURCE_QUEUES],
        needs_device_cfg: bool,
        needs_net_boot_payloads: bool,
    ) -> Self {
        Self { required_queues, needs_device_cfg, needs_net_boot_payloads }
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
        Self { drv_features, msix0_handler, queue_plans, early_payload_policy, child_requirements }
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
