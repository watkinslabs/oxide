use super::*;

const VALID_Q0: VirtQueueResource = VirtQueueResource {
    index: 0,
    size: 8,
    desc_pa: 0x1000,
    driver_pa: 0x2000,
    device_pa: 0x3000,
    notify_va: 0x4000,
    notify_off: 2,
};

mod identity;
mod queue_handoff;
mod child_state;
