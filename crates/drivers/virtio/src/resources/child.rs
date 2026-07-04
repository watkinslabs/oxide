use super::*;

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

    /// # C: O(VIRTIO_NET_RX_BOOT_POOL)
    pub fn net_payload_frames(&self) -> Vec<u64> {
        let mut frames = Vec::new();
        for i in 0..self.net_boot_payloads.rx_bufs_len.min(VIRTIO_NET_RX_BOOT_POOL) {
            push_unique_frame(&mut frames, self.net_boot_payloads.rx_bufs[i].pa);
        }
        push_unique_frame(&mut frames, self.net_boot_payloads.tx_buf_pa);
        frames
    }
}

/// Transport-owned frame list prepared during probe and either transferred to
/// the live transport record or released on child probe failure.
///
/// Keeping this as one owner avoids per-child conditional cleanup paths: if
/// the transport allocated a frame and child probe did not publish, the failed
/// probe owns releasing it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VirtioProbeOwnedFrames {
    vring_frames: Vec<u64>,
    payload_frames: Vec<u64>,
}

impl VirtioProbeOwnedFrames {
    /// # C: O(MAX_RESOURCE_QUEUES)
    pub fn from_probe_result(result: &VirtioTransportProbeResult) -> Self {
        Self {
            vring_frames: result.vring_frames(),
            payload_frames: result.net_payload_frames(),
        }
    }

    /// Drain every frame still owned by the failed transport probe.
    /// # C: O(N_frames)
    pub fn take_all(&mut self) -> Vec<u64> {
        let mut frames = core::mem::take(&mut self.vring_frames);
        for frame in core::mem::take(&mut self.payload_frames) {
            push_unique_frame(&mut frames, frame);
        }
        frames
    }

    /// Drain only the vring frames for publication into the live transport
    /// record. Payload buffers are handed to the child driver runtime through
    /// child probe facts and must not be transport-owned after publish.
    /// # C: O(1)
    pub fn take_vring_frames(&mut self) -> Vec<u64> {
        core::mem::take(&mut self.vring_frames)
    }

    /// # C: O(N_payload)
    pub fn payload_frames(&self) -> &[u64] {
        &self.payload_frames
    }

    /// # C: O(1)
    pub fn is_empty(&self) -> bool {
        self.vring_frames.is_empty() && self.payload_frames.is_empty()
    }
}

/// # C: O(N)
pub fn push_unique_frame(frames: &mut Vec<u64>, frame: u64) {
    if frame != 0 && !frames.iter().any(|existing| *existing == frame) {
        frames.push(frame);
    }
}

/// One-shot ownership marker for transport state prepared during child probe.
/// The holder must either publish the prepared transport state or release it;
/// `take` makes that ownership transfer idempotent across explicit error
/// paths and session drop.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VirtioProbeLease {
    live: bool,
}

impl VirtioProbeLease {
    /// # C: O(1)
    pub const fn live() -> Self {
        Self { live: true }
    }

    /// # C: O(1)
    pub const fn empty() -> Self {
        Self { live: false }
    }

    /// # C: O(1)
    pub const fn is_live(self) -> bool {
        self.live
    }

    /// Consume the outstanding lease once.
    /// # C: O(1)
    pub fn take(&mut self) -> bool {
        let was_live = self.live;
        self.live = false;
        was_live
    }
}

impl Default for VirtioProbeLease {
    fn default() -> Self {
        Self::empty()
    }
}

/// Common child-facing session contract implemented by concrete virtio
/// transports. Child drivers consume this shape; transport backends own how
/// bring-up, IRQ/vector binding, MMIO lifetime, and failed-probe release are
/// actually performed.
pub trait VirtioChildTransportSession {
    /// Stable key used by this kernel's per-device child runtime tables.
    /// # C: O(1)
    fn device_key(&self) -> VirtioChildDeviceKey;

    /// Controller-local address of the transport-owned child.
    /// # C: O(1)
    fn location(&self) -> VirtioTransportLocation;

    /// Device-model address of the child device being probed.
    /// # C: O(1)
    fn device_addr(&self) -> &str;

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

/// Run a child probe against a transport session, publishing transport-owned
/// state only after the child succeeds and releasing failed-probe resources on
/// child error.
/// # C: O(child_probe + N_transport_resources)
pub fn run_child_probe<S, E, F>(mut session: S, probe: F) -> Result<(), E>
where
    S: VirtioChildTransportSession,
    F: FnOnce(&mut dyn VirtioChildTransportSession) -> Result<(), E>,
{
    match probe(&mut session) {
        Ok(()) => {
            session.publish();
            Ok(())
        }
        Err(e) => {
            session.release_failed_child();
            Err(e)
        }
    }
}

/// Run child remove before unpublishing transport-owned state.
/// # C: O(child_remove + N_transport_resources)
pub fn run_child_remove<R, U>(device_key: VirtioChildDeviceKey, remove: R, unpublish: U)
where
    R: FnOnce(VirtioChildDeviceKey),
    U: FnOnce(VirtioChildDeviceKey),
{
    remove(device_key);
    unpublish(device_key);
}

/// Run child shutdown for a stable child key.
/// # C: O(child_shutdown)
pub fn run_child_shutdown<S>(device_key: VirtioChildDeviceKey, shutdown: S)
where
    S: FnOnce(VirtioChildDeviceKey),
{
    shutdown(device_key);
}
