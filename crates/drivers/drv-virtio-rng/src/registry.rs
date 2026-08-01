use alloc::{string::String, sync::Arc, vec::Vec};

use sync::{Spinlock, TaskList as DriverLockClass};

use crate::{consts::{BOUNCE_FRAME_BYTES, HWRNG_MAJOR, HWRNG_MINOR}, fill::fill_from_device};

pub(crate) struct RngState {
    pub device_key: virtio::VirtioChildDeviceKey,
    pub cfg_va: u64,
    pub hhdm: u64,
    pub requestq: virtio::VirtQueueResource,
    pub avail_idx: u16,
    pub used_idx_seen: u16,
    pub bounce_pa: u64,
    pub hwrng_dev: Arc<drv::Device>,
    pub shutdown: bool,
}

pub(crate) type RngHandle = Arc<Spinlock<RngState, DriverLockClass>>;

pub(crate) struct RngRegistry {
    pub records: Vec<RngHandle>,
    pub active_key: Option<virtio::VirtioChildDeviceKey>,
}

pub(crate) static RNGS: Spinlock<RngRegistry, DriverLockClass> = Spinlock::new(RngRegistry {
    records: Vec::new(),
    active_key: None,
});

pub fn present() -> bool {
    !RNGS.lock().records.is_empty()
}

pub fn install(
    device_key: virtio::VirtioChildDeviceKey,
    resources: virtio::VirtioResources,
) -> Option<usize> {
    let Some(requestq) = resources.require_queue(0) else {
        return None;
    };
    if !resources.common_cfg_valid() || find_handle(device_key).is_some() {
        return None;
    }
    let bounce_pa = pmm::setup::alloc_one_frame()?;
    let va = resources.hhdm.wrapping_add(bounce_pa) as *mut u8;
    // SAFETY: HHDM view of the frame `alloc_one_frame` just returned, so this
    // code is its only owner and no other mapping exists yet; the loop clears
    // exactly the one PAGE_SIZE frame that was allocated.
    unsafe {
        for i in 0..BOUNCE_FRAME_BYTES {
            core::ptr::write_volatile(va.add(i), 0);
        }
    }
    let used = resources.hhdm.wrapping_add(requestq.device_pa) as *const u16;
    // SAFETY: HHDM-mapped q0 used ring (require_queue accepted device_pa);
    // aligned u16 load of used.idx at index 1, taken once so the driver's
    // avail counter starts from whatever the device has already consumed.
    let used_seen = unsafe { core::ptr::read_volatile(used.add(1)) };
    let hwrng_dev = Arc::new(
        drv::Device::new("misc", String::from("hwrng"), 0, 0, 0)
            .with_devnode("misc", String::from("hwrng"), Some((HWRNG_MAJOR, HWRNG_MINOR)))
            .with_node_factory(Arc::new(|| devfs::misc::make_hwrng_inode())),
    );
    let mut registry = RNGS.lock();
    if registry
        .records
        .iter()
        .any(|record| record.lock().device_key == device_key)
    {
        free_frame(bounce_pa);
        return None;
    }
    let publish_hwrng = registry.active_key.is_none();
    let record = Arc::new(Spinlock::new(RngState {
        device_key,
        cfg_va: resources.cfg_va,
        hhdm: resources.hhdm,
        requestq,
        avail_idx: used_seen,
        used_idx_seen: used_seen,
        bounce_pa,
        hwrng_dev: Arc::clone(&hwrng_dev),
        shutdown: false,
    }));
    if publish_hwrng {
        registry.active_key = Some(device_key);
    }
    registry.records.push(record);
    drop(registry);
    if publish_hwrng && !publish_hwrng_or_clear_active(device_key, hwrng_dev) {
        let record = {
            let mut registry = RNGS.lock();
            registry
                .records
                .iter()
                .position(|record| record.lock().device_key == device_key)
                .map(|idx| registry.records.remove(idx))
        };
        // The record was published under `active_key` before this point, so a
        // concurrent `fill` may hold a clone of it: disarm, never plain-free.
        if let Some(record) = record {
            disarm_and_free(&record);
        } else {
            free_frame(bounce_pa);
        }
        return None;
    }
    let mut seed = [0u8; 32];
    let n = fill_from_device(device_key, &mut seed);
    if n == 0 {
        let _ = uninstall(device_key);
        return None;
    }
    // A virtio-rng device IS a hardware generator: Linux credits it via
    // `add_hwgenerator_randomness`, which is what makes a cold pool ready.
    devfs::misc::add_hw_entropy(&seed[..n]);
    Some(n)
}

pub fn uninstall(device_key: virtio::VirtioChildDeviceKey) -> bool {
    let (record, was_active, promoted_hwrng_dev) = {
        let mut registry = RNGS.lock();
        let Some(idx) = registry
            .records
            .iter()
            .position(|record| record.lock().device_key == device_key)
        else {
            return false;
        };
        let was_active = registry.active_key == Some(device_key);
        let record = registry.records.remove(idx);
        let promoted_hwrng_dev = if was_active {
            promote_active_locked(&mut registry)
        } else {
            None
        };
        (record, was_active, promoted_hwrng_dev)
    };

    if was_active && promoted_hwrng_dev.is_none() {
        devfs::misc::clear_hwrng_source();
    }

    let (cfg_va, removed_hwrng_dev) = {
        let ctx = record.lock();
        (ctx.cfg_va, if was_active { Some(Arc::clone(&ctx.hwrng_dev)) } else { None })
    };
    let _ = virtio::reset_device(cfg_va);
    disarm_and_free(&record);
    if let Some(hwrng_dev) = removed_hwrng_dev {
        drv::device_del(&hwrng_dev);
        if let Some((promoted_key, promoted)) = promoted_hwrng_dev {
            let _ = publish_hwrng_or_clear_active(promoted_key, promoted);
        }
    }
    true
}

pub fn shutdown(device_key: virtio::VirtioChildDeviceKey) -> bool {
    let Some(record) = find_handle(device_key) else {
        return false;
    };
    let cfg_va = {
        let ctx = record.lock();
        if ctx.shutdown {
            return true;
        }
        ctx.cfg_va
    };
    let _ = virtio::reset_device(cfg_va);
    disarm_and_free(&record);
    true
}

/// Mark a record dead and hand its DMA frame back, in that order.
///
/// Removal from the registry alone does not disarm a record: `fill` and
/// `fill_from_device` clone the handle out of the registry, release the
/// registry lock, and only then take the record lock, so a clone can still be
/// in flight. Clearing `bounce_pa` under the record lock before the frame is
/// freed makes such a clone return 0 instead of publishing a freed frame to
/// the device as a WRITE descriptor.
/// # C: O(1)
pub(crate) fn disarm_and_free(record: &RngHandle) {
    let bounce_pa = {
        let mut ctx = record.lock();
        ctx.shutdown = true;
        core::mem::replace(&mut ctx.bounce_pa, 0)
    };
    free_frame(bounce_pa);
}

pub(crate) fn free_frame(pa: u64) {
    if pa != 0 {
        // SAFETY: `pa` came from `alloc_one_frame` for this record's bounce
        // buffer and reaches here only after the record was removed from the
        // registry (or marked shut down) with `bounce_pa` cleared under its
        // lock, so no descriptor and no clone of the handle still names it.
        unsafe { pmm::setup::free_one_frame(pa); }
    }
}

pub(crate) fn active_handle() -> Option<RngHandle> {
    let registry = RNGS.lock();
    let active = registry.active_key?;
    registry
        .records
        .iter()
        .find(|record| record.lock().device_key == active)
        .cloned()
}

pub(crate) fn find_handle(device_key: virtio::VirtioChildDeviceKey) -> Option<RngHandle> {
    RNGS.lock()
        .records
        .iter()
        .find(|record| record.lock().device_key == device_key)
        .cloned()
}

pub(crate) fn promote_active_locked(
    registry: &mut RngRegistry,
) -> Option<(virtio::VirtioChildDeviceKey, Arc<drv::Device>)> {
    let Some(next) = registry.records.iter().find(|record| !record.lock().shutdown) else {
        registry.active_key = None;
        return None;
    };
    let next = next.lock();
    registry.active_key = Some(next.device_key);
    Some((next.device_key, Arc::clone(&next.hwrng_dev)))
}

pub(crate) fn publish_hwrng_or_clear_active(
    device_key: virtio::VirtioChildDeviceKey,
    hwrng_dev: Arc<drv::Device>,
) -> bool {
    match drv::try_device_add(hwrng_dev) {
        Ok(_) => {
            devfs::misc::set_hwrng_source(crate::fill::fill);
            true
        }
        Err(_) => {
            let mut registry = RNGS.lock();
            if registry.active_key == Some(device_key) {
                registry.active_key = None;
            }
            drop(registry);
            devfs::misc::clear_hwrng_source();
            false
        }
    }
}
