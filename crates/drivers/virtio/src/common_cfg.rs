//! Modern virtio common-cfg register protocol helpers.
//!
//! These helpers own the device-status, feature-negotiation, and queue-size
//! register sequence. Concrete transports still own mapping the common-cfg
//! window and allocating/programming queue memory.

// common-cfg field offsets, Virtio 1.2 §4.1.4.3. u16-precise stores are
// required for queue fields; QEMU dispatches common-cfg writes by address.
pub const CFG_QUEUE_SELECT: u64 = 0x16; // u16
pub const CFG_QUEUE_SIZE: u64 = 0x18; // u16/read
pub const CFG_DEVICE_FEATURE_SELECT: u64 = 0x00; // u32
pub const CFG_DEVICE_FEATURE: u64 = 0x04; // u32
pub const CFG_DRIVER_FEATURE_SELECT: u64 = 0x08; // u32
pub const CFG_DRIVER_FEATURE: u64 = 0x0C; // u32
pub const CFG_MSIX_CONFIG_NUMQ: u64 = 0x10; // u16 msix_config + u16 num_queues
pub const CFG_DEVICE_STATUS: u64 = 0x14; // u8

#[derive(Clone, Copy)]
pub struct FeatureNegotiation {
    pub dev_features: u64,
    pub drv_features: u64,
    pub post_status: u32,
    pub features_ok: bool,
    pub msix_cfg: u16,
    pub num_queues: u16,
}

/// Execute the common virtio device reset + feature negotiation sequence on
/// the modern common-cfg window.
/// # SAFETY: caller mapped `cfg_va` as a Device-attr virtio common-cfg window.
/// # C: O(1)
pub fn negotiate_features(cfg_va: u64, wanted_features: u64) -> FeatureNegotiation {
    let r32 = |off: u64| -> u32 {
        // SAFETY: cfg_va is the Device-attr-mapped common-cfg window; aligned
        // u32 load of a common-cfg register.
        unsafe { core::ptr::read_volatile((cfg_va + off) as *const u32) }
    };
    let w32 = |off: u64, v: u32| {
        // SAFETY: cfg_va is the Device-attr-mapped common-cfg window; aligned
        // u32 store of a common-cfg register.
        unsafe { core::ptr::write_volatile((cfg_va + off) as *mut u32, v); }
    };
    let w8 = |off: u64, v: u8| {
        // SAFETY: cfg_va is the Device-attr-mapped common-cfg window; status
        // is the u8 field at CFG_DEVICE_STATUS.
        unsafe { core::ptr::write_volatile((cfg_va + off) as *mut u8, v); }
    };

    w8(CFG_DEVICE_STATUS, 0);
    let _ = r32(CFG_DEVICE_STATUS);
    w8(CFG_DEVICE_STATUS, crate::VIRTIO_STATUS_ACKNOWLEDGE);
    w8(
        CFG_DEVICE_STATUS,
        crate::VIRTIO_STATUS_ACKNOWLEDGE | crate::VIRTIO_STATUS_DRIVER,
    );

    w32(CFG_DEVICE_FEATURE_SELECT, 0);
    let dev_feat_lo = r32(CFG_DEVICE_FEATURE);
    w32(CFG_DEVICE_FEATURE_SELECT, 1);
    let dev_feat_hi = r32(CFG_DEVICE_FEATURE);
    let dev_features = ((dev_feat_hi as u64) << 32) | dev_feat_lo as u64;
    let drv_features = dev_features & wanted_features;

    w32(CFG_DRIVER_FEATURE_SELECT, 1);
    w32(CFG_DRIVER_FEATURE, (drv_features >> 32) as u32);
    w32(CFG_DRIVER_FEATURE_SELECT, 0);
    w32(CFG_DRIVER_FEATURE, (drv_features & 0xFFFF_FFFF) as u32);
    w8(
        CFG_DEVICE_STATUS,
        crate::VIRTIO_STATUS_ACKNOWLEDGE
            | crate::VIRTIO_STATUS_DRIVER
            | crate::VIRTIO_STATUS_FEATURES_OK,
    );

    let post_status = r32(CFG_DEVICE_STATUS) & 0xFF;
    let features_ok = post_status & crate::VIRTIO_STATUS_FEATURES_OK as u32 != 0;
    let w_msix_nq = r32(CFG_MSIX_CONFIG_NUMQ);
    FeatureNegotiation {
        dev_features,
        drv_features,
        post_status,
        features_ok,
        msix_cfg: (w_msix_nq & 0xFFFF) as u16,
        num_queues: (w_msix_nq >> 16) as u16,
    }
}

/// Scan modern common-cfg queue sizes into a compact `(index, size)` table.
/// # SAFETY: caller mapped `cfg_va` as a Device-attr virtio common-cfg window.
/// # C: O(min(num_queues, 8))
pub fn scan_queue_sizes(cfg_va: u64, num_queues: u16) -> ([(u16, u16); 8], usize) {
    let r32 = |off: u64| -> u32 {
        // SAFETY: cfg_va is the Device-attr-mapped common-cfg window; aligned
        // u32 load of a common-cfg register.
        unsafe { core::ptr::read_volatile((cfg_va + off) as *const u32) }
    };
    let w16 = |off: u64, v: u16| {
        // SAFETY: cfg_va is the Device-attr-mapped common-cfg window; queue
        // selection is the u16 field at CFG_QUEUE_SELECT.
        unsafe { core::ptr::write_volatile((cfg_va + off) as *mut u16, v); }
    };

    let mut queues = [(0u16, 0u16); 8];
    let mut queues_len = 0usize;
    let cap = if num_queues == 0 || num_queues > 8 {
        8
    } else {
        num_queues
    } as u16;
    for qi in 0..cap {
        w16(CFG_QUEUE_SELECT, qi);
        let queue_size = (r32(CFG_QUEUE_SIZE) & 0xFFFF) as u16;
        queues[queues_len] = (qi, queue_size);
        queues_len += 1;
        if queue_size == 0 {
            break;
        }
    }
    (queues, queues_len)
}

/// Read the modern common-cfg device status byte.
/// # SAFETY: caller mapped `cfg_va` as a Device-attr virtio common-cfg window.
/// # C: O(1)
pub fn read_status(cfg_va: u64) -> u8 {
    // SAFETY: cfg_va is the Device-attr-mapped common-cfg window; status is
    // the u8 field at CFG_DEVICE_STATUS.
    unsafe { core::ptr::read_volatile((cfg_va + CFG_DEVICE_STATUS) as *const u8) }
}

/// Reset a modern virtio device through the common-cfg status register.
/// # SAFETY: caller mapped `cfg_va` as a Device-attr virtio common-cfg window.
/// # C: O(1)
pub fn reset_device(cfg_va: u64) {
    if cfg_va == 0 {
        return;
    }
    // SAFETY: cfg_va is the Device-attr-mapped common-cfg window; status is
    // the u8 field at CFG_DEVICE_STATUS.
    unsafe { core::ptr::write_volatile((cfg_va + CFG_DEVICE_STATUS) as *mut u8, 0u8); }
}

/// Publish FAILED when the transport cannot complete feature or mandatory
/// queue bring-up.
/// # SAFETY: caller mapped `cfg_va` as a Device-attr virtio common-cfg window.
/// # C: O(1)
pub fn set_failed(cfg_va: u64) -> u8 {
    let status = read_status(cfg_va) | crate::VIRTIO_STATUS_FAILED;
    // SAFETY: cfg_va is the Device-attr-mapped common-cfg window; status is
    // the u8 field at CFG_DEVICE_STATUS.
    unsafe {
        core::ptr::write_volatile((cfg_va + CFG_DEVICE_STATUS) as *mut u8, status);
    }
    read_status(cfg_va)
}

/// Publish DRIVER_OK after features and queues are fully programmed.
/// # SAFETY: caller mapped `cfg_va` as a Device-attr virtio common-cfg window.
/// # C: O(1)
pub fn set_driver_ok(cfg_va: u64) -> u8 {
    // SAFETY: cfg_va is the Device-attr-mapped common-cfg window; status is
    // the u8 field at CFG_DEVICE_STATUS.
    unsafe {
        core::ptr::write_volatile(
            (cfg_va + CFG_DEVICE_STATUS) as *mut u8,
            crate::VIRTIO_STATUS_ACKNOWLEDGE
                | crate::VIRTIO_STATUS_DRIVER
                | crate::VIRTIO_STATUS_FEATURES_OK
                | crate::VIRTIO_STATUS_DRIVER_OK,
        );
    }
    read_status(cfg_va)
}
