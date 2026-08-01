use super::super::*;
use crate::device::DeviceKey;
use core::sync::atomic::{AtomicU32, AtomicU64};
use sync::{Spinlock, TaskList as DriverLockClass};

pub(super) static TEST_LOCK: Spinlock<(), DriverLockClass> = Spinlock::new(());

pub(super) const fn key(raw: u32) -> DeviceKey {
    DeviceKey::from_raw(raw)
}

pub(super) fn test_ctrlq() -> virtio::VirtQueueResource {
    virtio::VirtQueueResource {
        index:      0,
        size:       1,
        desc_pa:    0,
        driver_pa:  0,
        device_pa:  0,
        notify_va:  0,
        notify_off: 0,
    }
}

pub(super) fn test_device(device_key: DeviceKey, bdf: u32) -> VirtioGpuDev {
    VirtioGpuDev {
        device_key,
        bdf,
        card_id: 0,
        cfg_va: 0,
        ctrlq: test_ctrlq(),
        cursorq: test_ctrlq(),
        features_negotiated: 0,
        display: DisplayInfo::default(),
        edid: None,
        resource_id_alloc: AtomicU32::new(1),
        blob_uuid_alloc: AtomicU64::new(1),
        capset_count: 0,
    }
}
