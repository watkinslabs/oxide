//! Transport-owned resource descriptions handed from a virtio transport to a
//! child driver. These are plain descriptors; ownership and unmapping still
//! live with the transport until every child driver is converted to managed
//! resources.

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

/// Queue notification lifetime requested by the child profile. The transport
/// maps notify windows according to this policy after queue programming.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VirtioQ1NotifyPolicy {
    None,
    NetBootTx,
    PersistentTx,
    PersistentEvent,
}

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
    pub extra_queues: [Option<VirtioQueuePlan>; 3],
    pub q1_notify_policy: VirtioQ1NotifyPolicy,
    pub needs_net_boot_buffers: bool,
    pub child_requirements: VirtioChildRequirements,
}

impl VirtioTransportProfile {
    /// # C: O(1)
    pub const fn new(
        drv_features: u64,
        msix0_handler: Option<fn()>,
        extra_queues: [Option<VirtioQueuePlan>; 3],
        q1_notify_policy: VirtioQ1NotifyPolicy,
        needs_net_boot_buffers: bool,
        child_requirements: VirtioChildRequirements,
    ) -> Self {
        Self {
            drv_features,
            msix0_handler,
            extra_queues,
            q1_notify_policy,
            needs_net_boot_buffers,
            child_requirements,
        }
    }

    /// # C: O(1)
    pub const fn q0(drv_features: u64, msix0_handler: Option<fn()>) -> Self {
        Self::new(
            drv_features,
            msix0_handler,
            [None, None, None],
            VirtioQ1NotifyPolicy::None,
            false,
            VirtioChildRequirements::q0(),
        )
    }

    /// # C: O(1)
    pub const fn q0_device_cfg(drv_features: u64, msix0_handler: Option<fn()>) -> Self {
        Self::new(
            drv_features,
            msix0_handler,
            [None, None, None],
            VirtioQ1NotifyPolicy::None,
            false,
            VirtioChildRequirements::q0_device_cfg(),
        )
    }

    /// # C: O(1)
    pub const fn net(drv_features: u64, msix0_handler: Option<fn()>) -> Self {
        Self::new(
            drv_features,
            msix0_handler,
            [Some(VirtioQueuePlan::new(1, None, false)), None, None],
            VirtioQ1NotifyPolicy::NetBootTx,
            true,
            VirtioChildRequirements::net(),
        )
    }

    /// # C: O(1)
    pub const fn vsock(drv_features: u64, msix0_handler: Option<fn()>) -> Self {
        Self::new(
            drv_features,
            msix0_handler,
            [Some(VirtioQueuePlan::new(1, None, false)), None, None],
            VirtioQ1NotifyPolicy::PersistentTx,
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
                Some(VirtioQueuePlan::new(1, event_handler, false)),
                Some(VirtioQueuePlan::new(2, None, true)),
                Some(VirtioQueuePlan::new(3, None, true)),
            ],
            VirtioQ1NotifyPolicy::PersistentEvent,
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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(net.q1_notify_policy, VirtioQ1NotifyPolicy::NetBootTx);
        assert!(net.needs_net_boot_buffers);
        assert_eq!(net.extra_queues[0].map(|q| q.index), Some(1));
        assert!(net.child_requirements.needs_net_boot_payloads);

        let snd = VirtioTransportProfile::snd(0xaa, None, None);
        assert_eq!(snd.drv_features, 0xaa);
        assert_eq!(
            snd.q1_notify_policy,
            VirtioQ1NotifyPolicy::PersistentEvent
        );
        assert_eq!(snd.extra_queues[0].map(|q| q.index), Some(1));
        assert_eq!(snd.extra_queues[1].map(|q| q.index), Some(2));
        assert_eq!(snd.extra_queues[2].map(|q| q.index), Some(3));
        assert!(snd.extra_queues[1].map(|q| q.map_notify).unwrap_or(false));
        assert!(snd.child_requirements.needs_device_cfg);
    }
}
