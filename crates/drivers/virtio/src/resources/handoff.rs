use super::*;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VirtQueueResource {
    pub index: u16,
    pub size: u16,
    pub desc_pa: u64,
    pub driver_pa: u64,
    pub device_pa: u64,
    pub notify_va: u64,
    pub notify_off: u16,
}

impl VirtQueueResource {
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

    pub const fn is_runtime_valid(&self) -> bool {
        self.size != 0
            && self.desc_pa != 0
            && self.driver_pa != 0
            && self.device_pa != 0
            && self.notify_va != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtioQueueNotifyMappings {
    by_queue: [u64; MAX_RESOURCE_QUEUES],
}

impl VirtioQueueNotifyMappings {
    pub const fn new() -> Self {
        Self { by_queue: [0; MAX_RESOURCE_QUEUES] }
    }

    pub fn set(&mut self, queue_index: u16, notify_va: u64) {
        let index = queue_index as usize;
        if index < MAX_RESOURCE_QUEUES {
            self.by_queue[index] = notify_va;
        }
    }

    pub const fn get(&self, queue_index: u16) -> u64 {
        let index = queue_index as usize;
        if index < MAX_RESOURCE_QUEUES { self.by_queue[index] } else { 0 }
    }
}

impl Default for VirtioQueueNotifyMappings {
    fn default() -> Self { Self::new() }
}

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

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VirtioRuntimeHandoff {
    pub queue_resources: [VirtQueueResource; MAX_RESOURCE_QUEUES],
    pub post_notify_status: u8,
    pub avail_idx_posted: u16,
    pub used_idx_observed: u16,
    pub isr_status: u8,
    pub net_boot_payloads: VirtioNetBootPayloads,
}

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
