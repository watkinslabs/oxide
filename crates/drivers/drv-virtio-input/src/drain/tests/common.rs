use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicU32, Ordering};

use sync::{Spinlock, TaskList as DriverLockClass};

use super::super::*;

const TEST_QUEUE_SIZE: u16 = 8;

pub(super) static TEST_LOCK: Spinlock<(), DriverLockClass> = Spinlock::new(());
pub(super) static TEST_DRAINS: AtomicU32 = AtomicU32::new(0);

pub(super) fn test_handler() {
    TEST_DRAINS.fetch_add(1, Ordering::Relaxed);
}

pub(super) fn key(raw: u32) -> virtio::VirtioChildDeviceKey {
    virtio::VirtioChildDeviceKey::from_raw(raw)
}

pub(super) fn queue() -> virtio::VirtQueueResource {
    virtio::VirtQueueResource {
        index: 0,
        size: TEST_QUEUE_SIZE,
        desc_pa: 0,
        driver_pa: 0,
        device_pa: 0,
        notify_va: 0,
        notify_off: 0,
    }
}

pub(super) fn ctx(device_key: virtio::VirtioChildDeviceKey) -> QueueCtx {
    let statusq = virtio::VirtQueueResource { index: 1, ..queue() };
    QueueCtx {
        device_key,
        cfg_va: 0,
        hhdm: 0,
        eventq: queue(),
        buf_pa: 0,
        event_buffers: queue().size.min(super::super::queue::MAX_EVENT_BUFFERS),
        statusq,
        status_buf_pa: 0,
        status: super::super::status::StatusState::new(statusq.size)
            .expect("status state"),
        pending_output: VecDeque::new(),
        last_used: 0,
        avail_idx: 0,
        eventq_failed: false,
    }
}

pub(super) fn reset() {
    for slot in CTXS.lock().iter_mut() {
        *slot = None;
    }
    HANDLER_INSTALLED.store(false, Ordering::Release);
    TEST_DRAINS.store(0, Ordering::Relaxed);
    let _ = softirq::clear_handler(softirq::Slot::InputDrain);
}
