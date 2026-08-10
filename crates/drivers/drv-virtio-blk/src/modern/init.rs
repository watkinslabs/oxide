use super::*;

const BLK_CFG_CAPACITY_BYTES: usize = 8;
const BLK_CFG_BLK_SIZE_BYTES: usize = 4;
const BLK_CFG_NUM_QUEUES_BYTES: usize = 2;
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

    let mut num_queues: u16 = 1;
    if drv_features & virtio::VIRTIO_BLK_F_MQ != 0 {
        let mut nqb = [0u8; BLK_CFG_NUM_QUEUES_BYTES];
        for i in 0..BLK_CFG_NUM_QUEUES_BYTES {
            let off = virtio::BLK_CFG_OFF_NUM_QUEUES + i as u64;
            // SAFETY: read_device_config uses a transport-mapped virtio device config byte address.
            nqb[i] = unsafe { core::ptr::read_volatile((cfg + off) as *const u8) };
        }
        num_queues = u16::from_le_bytes(nqb);
    }

    Some(BlkDeviceConfig { capacity, blk_size, num_queues })
}

/// The used-ring index the device left after reset, so the driver's cursor
/// starts where the device's does instead of at zero. # C: O(1)
fn seed_used_index(h: u64, res: &virtio::VirtQueueResource) -> u16 {
    if h == 0 || res.device_pa == 0 { return 0; }
    let used = h.wrapping_add(res.device_pa) as *const u16;
    virtio::dma::invalidate_from_device(used as u64, 2 * core::mem::size_of::<u16>());
    // SAFETY: `device_pa` is this queue's used frame (checked non-zero) via
    // HHDM; `used.add(1)` is the aligned u16 `used.idx` at byte 2, the first
    // four bytes of the frame. `invalidate_from_device` above dropped any
    // stale cache line so this reads what the device left after reset.
    unsafe { core::ptr::read_volatile(used.add(1)) }
}

/// Read back a queue's `avail.flags`. # C: O(1)
#[cfg(feature = "debug-boot")]
fn read_avail_flags(hhdm: u64, res: &virtio::VirtQueueResource) -> u16 {
    if hhdm == 0 || res.driver_pa == 0 { return 0; }
    let avail = hhdm.wrapping_add(res.driver_pa + virtio::VRING_AVAIL_FLAGS_OFF) as *const u16;
    // SAFETY: `driver_pa` is this queue's own avail frame via HHDM, checked
    // non-zero above; `flags` is its first, u16-aligned field (Virtio 1.2
    // §2.7.6).
    unsafe { core::ptr::read_volatile(avail) }
}

/// Build the interrupt-free polling queue when the device gave one to spare.
///
/// Setting `VRING_AVAIL_F_NO_INTERRUPT` here, before any buffer is made
/// available on the queue, is what makes a polled completion cost no
/// interrupt: the transport bound no MSI-X vector to this queue, and the
/// device is now told not to signal on it either.
fn build_poll_queue(
    resources: virtio::VirtioResources, drv_features: u64, num_queues: u16, h: u64,
) -> Option<BlkQueue> {
    let index = poll_queue_index(drv_features, num_queues, DEFAULT_POLL_QUEUES)?;
    let res = resources.require_queue_at_least(index, MAX_REQUEST_DESCRIPTORS)?;
    suppress_queue_interrupts(h, &res);
    Some(BlkQueue::new(res, seed_used_index(h, &res), true))
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
    #[cfg(target_os = "oxide-kernel")]
    if !block::completion::register(run_completion_bottom_half) {
        return 0;
    }
    let Some(requestq) = init.resources.require_queue_at_least(0, MAX_REQUEST_DESCRIPTORS) else {
        return 0;
    };
    if !init.resources.common_cfg_valid() {
        return 0;
    }
    let Some(device_cfg) = read_device_config(init.resources, init.drv_features) else {
        return 0;
    };
    if DEVICES.lock_bh::<sched::bh::SchedBh>().iter().any(|d| same_device(d, init.device_key)) {
        return 0;
    }
    let bounce_pa = match pmm::setup::alloc_contig(pmm::Order(BOUNCE_ORDER)) {
        Some(pa) => pa,
        None => return 0,
    };
    let h = hhdm();
    if h != 0 {
        let va = h.wrapping_add(bounce_pa) as *mut u8;
        // SAFETY: `bounce_pa` is the `alloc_contig(BOUNCE_ORDER)` block just
        // allocated above and owned solely by this probe; `BOUNCE_ORDER` is
        // derived from `BOUNCE_BYTES`, so the block covers every index written.
        // No descriptor references it yet, so the device cannot see the stores.
        unsafe {
            for i in 0..BOUNCE_BYTES { core::ptr::write_volatile(va.add(i), 0); }
        }
    }
    let blk_size = blk::validate_blk_size(device_cfg.blk_size);
    let seed = seed_used_index(h, &requestq);

    let mut state = BlkState {
        cfg_va: init.resources.cfg_va,
        requestq: BlkQueue::new(requestq, seed, false),
        pollq: build_poll_queue(init.resources, init.drv_features, device_cfg.num_queues, h),
        capacity: device_cfg.capacity,
        blk_size,
        serial: [0u8; blk::BLK_SERIAL_LEN],
        bounce_pa,
        // The reference derives the queue's write-cache mode straight from
        // the negotiated `F_FLUSH` bit: that bit IS the cache mode.
        write_cache: virtio::cache_mode_writeback(init.drv_features),
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
    let idx = block::registry::register_with_driver(
        block::registry::BlockDriver::fixed("virtblk", block::uapi::VIRTIO_BLK_MAJOR), &name, serial_opt, state.clone());
    let published = if idx != 0 && !existed {
        let mut devices = DEVICES.lock_bh::<sched::bh::SchedBh>();
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
    // Evidence, read back from the DEVICE and the driver area rather than
    // assumed, that this disk's polled ring really is interrupt-free: the
    // vector the device would raise for the poll queue, and the suppression
    // bit it was told to honour. `msix=ffff` is the no-vector sentinel.
    #[cfg(feature = "debug-boot")]
    {
        if let Some(poll) = state.pollq.as_ref() {
            klog::write_raw(b"[INFO]  virtio-blk poll queue idx=");
            klog::write_dec_u64(poll.res.index as u64);
            klog::write_raw(b" of ");
            klog::write_dec_u64(device_cfg.num_queues as u64);
            klog::write_raw(b" msix=");
            klog::write_hex_u64(
                virtio::read_queue_msix_vector(init.resources.cfg_va, poll.res.index) as u64);
            klog::write_raw(b" avail_flags=");
            klog::write_hex_u64(read_avail_flags(h, &poll.res) as u64);
            klog::write_raw(b"\n");
        }
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
        klog::write_raw(b" queues=");
        klog::write_dec_u64(device_cfg.num_queues as u64);
        klog::write_raw(b" pollq=");
        klog::write_dec_u64(state.pollq.as_ref().map(|q| q.res.index as u64 + 1).unwrap_or(0));
        klog::write_raw(b"\n");
    }
    idx
}

pub fn remove_blk(device_key: virtio::VirtioChildDeviceKey) -> bool {
    let rec = {
        let mut devices = DEVICES.lock_bh::<sched::bh::SchedBh>();
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
        DEVICES.lock_bh::<sched::bh::SchedBh>()
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
    if DEVICES.lock_bh::<sched::bh::SchedBh>().iter().any(|d| same_device(d, device_key)) {
        return 0;
    }
    let state = Arc::new(BlkState::for_test_cfg(0));
    let idx = block::registry::register_with_driver(
        block::registry::BlockDriver::fixed("virtblk", block::uapi::VIRTIO_BLK_MAJOR), name, None, state.clone());
    if idx != 0 {
        DEVICES.lock_bh::<sched::bh::SchedBh>().push(BlkRecord {
            device_key,
            name: String::from(name),
            state,
        });
    }
    idx
}

#[cfg(test)]
pub(crate) fn test_has_record(bus: u8, device: u8, function: u8) -> bool {
    DEVICES.lock_bh::<sched::bh::SchedBh>().iter().any(|d| same_device(d, child_key(bus, device, function)))
}
