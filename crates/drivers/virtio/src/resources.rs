//! Transport-owned resource descriptions handed from a virtio transport to a
//! child driver. These are plain descriptors; ownership and unmapping still
//! live with the transport until every child driver is converted to managed
//! resources.

/// Maximum virtqueues exposed through the staged resource object. Modern
/// virtio devices in this kernel currently use queues 0..=3.
pub const MAX_RESOURCE_QUEUES: usize = 8;

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
}
