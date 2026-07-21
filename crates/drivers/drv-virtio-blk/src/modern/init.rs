use super::*;

const BLK_CFG_CAPACITY_BYTES: usize = 8;
const BLK_CFG_BLK_SIZE_BYTES: usize = 4;
const DISK_NAME_BUF_BYTES: usize = 8;

fn read_device_config(resources: virtio::VirtioResources, drv_features: u64) -> Option<BlkDeviceConfig> {
    let cfg = resources.device_cfg_va;
    if cfg == 0 {
        return None;
    }

    let mut capb = [0u8; BLK_CFG_CAPACITY_BYTES];
    for i in 0..BLK_CFG_CAPACITY_BYTES {
        let off = virtio::BLK_CFG_OFF_CAPACITY + i as u64;
        // SAFETY: read_device_config uses a transport-mapped virtio device config byte address.
        capb[i] = unsafe { core::ptr::read_volatile((cfg + off) as *const u8) };
    }
    let capacity = u64::from_le_bytes(capb);

    let mut blk_size = blk::VIRTIO_BLK_SECTOR_BYTES;
    if drv_features & virtio::VIRTIO_BLK_F_BLK_SIZE != 0 {
        let mut bsb = [0u8; BLK_CFG_BLK_SIZE_BYTES];
        for i in 0..BLK_CFG_BLK_SIZE_BYTES {
            let off = virtio::BLK_CFG_OFF_BLK_SIZE + i as u64;
            // SAFETY: read_device_config uses a transport-mapped virtio device config byte address.
            bsb[i] = unsafe {
                core::ptr::read_volatile((cfg + off) as *const u8)
            };
        }
        let bs = u32::from_le_bytes(bsb);
        if bs != 0 {
            blk_size = bs;
        }
    }

    Some(BlkDeviceConfig { capacity, blk_size })
}

#[cfg(test)]
pub(crate) fn test_read_device_config(
    resources: virtio::VirtioResources,
    drv_features: u64,
) -> Option<(u64, u32)> {
    read_device_config(resources, drv_features).map(|cfg| (cfg.capacity, cfg.blk_size))
}

pub fn disk_name(index: u32) -> String {
    let mut buf = [0u8; DISK_NAME_BUF_BYTES];
    let n = blk::vd_name(index, &mut buf);
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

pub fn init_blk(init: BlkInit) -> u32 {
    let Some(requestq) = init.resources.require_queue(0) else {
        return 0;
    };
    if !init.resources.common_cfg_valid() {
        return 0;
    }
    let Some(device_cfg) = read_device_config(init.resources, init.drv_features) else {
        return 0;
    };
    if DEVICES.lock().iter().any(|d| same_device(d, init.device_key)) {
        return 0;
    }
    let bounce_pa = match pmm::setup::alloc_contig(pmm::Order(BOUNCE_ORDER)) {
        Some(pa) => pa,
        None => return 0,
    };
    let h = hhdm();
    if h != 0 {
        let va = h.wrapping_add(bounce_pa) as *mut u8;
        unsafe {
            for i in 0..BOUNCE_BYTES { core::ptr::write_volatile(va.add(i), 0); }
        }
    }
    let blk_size = blk::validate_blk_size(device_cfg.blk_size);
    let seed = if h != 0 && requestq.device_pa != 0 {
        let used = h.wrapping_add(requestq.device_pa) as *const u16;
        virtio::dma::invalidate_from_device(
            used as u64,
            2 * core::mem::size_of::<u16>(),
        );
        unsafe { core::ptr::read_volatile(used.add(1)) }
    } else { 0 };

    let mut state = BlkState {
        cfg_va: init.resources.cfg_va,
        requestq,
        capacity: device_cfg.capacity,
        blk_size,
        serial: [0u8; blk::BLK_SERIAL_LEN],
        bounce_pa,
        inflight: Spinlock::new(RingShadow { avail_idx: seed, used_seen: seed, busy: false }),
        poisoned: core::sync::atomic::AtomicBool::new(false),
    };

    if let Ok(raw) = state.get_id() {
        blk::trim_serial(&raw, &mut state.serial);
    }

    let disk_index = NEXT_DISK_INDEX.fetch_add(1, Ordering::Relaxed);
    let name = disk_name(disk_index);
    let serial_len = state.serial.iter().position(|&b| b == 0).unwrap_or(state.serial.len());
    let serial_str = String::from_utf8_lossy(&state.serial[..serial_len]).into_owned();
    let state: Arc<BlkState> = Arc::new(state);
    let serial_opt = if serial_str.is_empty() { None } else { Some(serial_str.as_str()) };
    let existed = block::registry::by_name(&name).is_some();
    let idx = block::registry::register_with_serial(&name, serial_opt, state.clone());
    let published = if idx != 0 && !existed {
        let mut devices = DEVICES.lock();
        if devices.iter().any(|d| same_device(d, init.device_key)) {
            false
        } else {
            devices.push(BlkRecord {
                device_key: init.device_key,
                name: name.clone(),
                state: state.clone(),
            });
            true
        }
    } else {
        false
    };
    if !published {
        if idx != 0 && !existed {
            let _ = block::registry::unregister(&name);
        }
        state.remove();
        return 0;
    }
    #[cfg(feature = "debug-boot")]
    {
        klog::write_raw(b"[INFO]  virtio-blk-modern key=");
        klog::write_hex_u64(key_raw(init.device_key) as u64);
        klog::write_raw(b" cap_sec=");
        klog::write_dec_u64(device_cfg.capacity);
        klog::write_raw(b" blk_size=");
        klog::write_dec_u64(blk_size as u64);
        klog::write_raw(b" idx=");
        klog::write_dec_u64(idx as u64);
        klog::write_raw(b"\n");
    }
    idx
}

pub fn remove_blk(device_key: virtio::VirtioChildDeviceKey) -> bool {
    let rec = {
        let mut devices = DEVICES.lock();
        match devices.iter().position(|d| same_device(d, device_key)) {
            Some(i) => devices.remove(i),
            None => return false,
        }
    };
    rec.state.remove();
    block::registry::unregister(&rec.name)
}

pub fn shutdown_blk(device_key: virtio::VirtioChildDeviceKey) -> bool {
    let state = {
        DEVICES.lock()
            .iter()
            .find(|d| same_device(d, device_key))
            .map(|d| d.state.clone())
    };
    let Some(state) = state else { return false; };
    state.shutdown();
    true
}

#[cfg(test)]
pub(crate) fn test_publish_record(bus: u8, device: u8, function: u8, name: &str) -> u32 {
    let device_key = child_key(bus, device, function);
    if DEVICES.lock().iter().any(|d| same_device(d, device_key)) {
        return 0;
    }
    let state = Arc::new(BlkState {
        cfg_va: 0,
        requestq: virtio::VirtQueueResource {
            index: 0,
            size: 0,
            desc_pa: 0,
            driver_pa: 0,
            device_pa: 0,
            notify_va: 0,
            notify_off: 0,
        },
        capacity: 8,
        blk_size: 512,
        serial: [0u8; blk::BLK_SERIAL_LEN],
        bounce_pa: 0,
        inflight: Spinlock::new(RingShadow { avail_idx: 0, used_seen: 0, busy: false }),
        poisoned: core::sync::atomic::AtomicBool::new(false),
    });
    let idx = block::registry::register_with_serial(name, None, state.clone());
    if idx != 0 {
        DEVICES.lock().push(BlkRecord {
            device_key,
            name: String::from(name),
            state,
        });
    }
    idx
}

#[cfg(test)]
pub(crate) fn test_has_record(bus: u8, device: u8, function: u8) -> bool {
    DEVICES.lock().iter().any(|d| same_device(d, child_key(bus, device, function)))
}
