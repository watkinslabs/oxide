// Generalized modern virtio-pci virtqueue setup, split out of
// `virtio_drv` so that file stays under the 1000-line cap (docs/08§7)
// and so every virtqueue is programmed uniformly (Virtio 1.2 §4.1.4.3
// virtio_pci_common_cfg), the way the Linux virtio core does — not q0/q1
// hand-coded per device. virtio-snd (4 queues: controlq0/eventq1/txq2/
// rxq3) and any future multi-queue device program q2/q3 by calling
// `program_queue` with the queue index.

// common-cfg field offsets, Virtio 1.2 §4.1.4.3. u16-precise stores per
// F59-09: QEMU's `virtio_pci_common_write` dispatches by `switch(addr)`,
// so a 4-byte store at a sub-field addr only triggers the field at that
// addr and silently drops the rest. queue_select / queue_msix_vector /
// queue_enable MUST be u16 stores at their exact offsets.
const CFG_QUEUE_SELECT: u64 = 0x16; // u16
const CFG_QUEUE_SIZE:   u64 = 0x18; // u16 (read)
const CFG_QUEUE_MSIX:   u64 = 0x1A; // u16
const CFG_QUEUE_ENABLE: u64 = 0x1C; // u16
const CFG_QUEUE_NOTIFY: u64 = 0x1E; // u16 (read: queue_notify_off)
const CFG_QUEUE_DESC:   u64 = 0x20; // le64
const CFG_QUEUE_DRIVER: u64 = 0x28; // le64
const CFG_QUEUE_DEVICE: u64 = 0x30; // le64
const CFG_DEVICE_FEATURE_SELECT: u64 = 0x00; // u32
const CFG_DEVICE_FEATURE:        u64 = 0x04; // u32
const CFG_DRIVER_FEATURE_SELECT: u64 = 0x08; // u32
const CFG_DRIVER_FEATURE:        u64 = 0x0C; // u32
const CFG_MSIX_CONFIG_NUMQ:      u64 = 0x10; // u16 msix_config + u16 num_queues
const CFG_DEVICE_STATUS:         u64 = 0x14; // u8

#[derive(Clone, Copy)]
pub(super) struct QueuePlan {
    pub(super) index: u16,
    pub(super) msix_vec: u16,
    pub(super) map_notify: bool,
}

impl QueuePlan {
    pub(super) const fn new(index: u16, msix_vec: u16, map_notify: bool) -> Self {
        Self {
            index,
            msix_vec,
            map_notify,
        }
    }
}

/// Programmed virtqueue: the three ring PAs handed to the device, the
/// per-queue `queue_notify_off`, and the negotiated `queue_size`.
pub(super) struct QueueRing {
    pub(super) desc_pa:    u64,
    pub(super) driver_pa:  u64,
    pub(super) device_pa:  u64,
    pub(super) notify_off: u16,
    pub(super) size:       u16,
}

#[derive(Clone, Copy)]
pub(super) struct FeatureNegotiation {
    pub(super) dev_features: u64,
    pub(super) drv_features: u64,
    pub(super) post_status:  u32,
    pub(super) features_ok:  bool,
    pub(super) msix_cfg:     u16,
    pub(super) num_queues:   u16,
}

/// Execute the common virtio device reset + feature negotiation sequence on
/// the modern PCI common-cfg window. This is transport/core work: child
/// drivers choose wanted feature bits, but the common config protocol owns the
/// register dance and FEATURES_OK validation.
/// # SAFETY: caller mapped `cfg_va` as a Device-attr virtio common-cfg window.
/// # C: O(1)
pub(super) fn negotiate_features(cfg_va: u64, wanted_features: u64) -> FeatureNegotiation {
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
    w8(CFG_DEVICE_STATUS, virtio::VIRTIO_STATUS_ACKNOWLEDGE);
    w8(
        CFG_DEVICE_STATUS,
        virtio::VIRTIO_STATUS_ACKNOWLEDGE | virtio::VIRTIO_STATUS_DRIVER,
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
        virtio::VIRTIO_STATUS_ACKNOWLEDGE
            | virtio::VIRTIO_STATUS_DRIVER
            | virtio::VIRTIO_STATUS_FEATURES_OK,
    );

    let post_status = r32(CFG_DEVICE_STATUS) & 0xFF;
    let features_ok = post_status & virtio::VIRTIO_STATUS_FEATURES_OK as u32 != 0;
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
/// Queue selection is u16-precise; see the comment above the common-cfg
/// offsets for why this must not use a wider write.
/// # SAFETY: caller mapped `cfg_va` as a Device-attr virtio common-cfg window.
/// # C: O(min(num_queues, 8))
pub(super) fn scan_queue_sizes(cfg_va: u64, num_queues: u16) -> ([(u16, u16); 8], usize) {
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
    let cap = if num_queues == 0 || num_queues > 8 { 8 } else { num_queues } as u16;
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
pub(super) fn read_status(cfg_va: u64) -> u8 {
    // SAFETY: cfg_va is the Device-attr-mapped common-cfg window; status is
    // the u8 field at CFG_DEVICE_STATUS.
    unsafe { core::ptr::read_volatile((cfg_va + CFG_DEVICE_STATUS) as *const u8) }
}

/// Reset a modern virtio device through the common-cfg status register.
/// # SAFETY: caller mapped `cfg_va` as a Device-attr virtio common-cfg window.
/// # C: O(1)
pub(super) fn reset_device(cfg_va: u64) {
    if cfg_va == 0 {
        return;
    }
    // SAFETY: cfg_va is the Device-attr-mapped common-cfg window; status is
    // the u8 field at CFG_DEVICE_STATUS.
    unsafe { core::ptr::write_volatile((cfg_va + CFG_DEVICE_STATUS) as *mut u8, 0u8); }
}

/// Publish DRIVER_OK after features and queues are fully programmed.
/// # SAFETY: caller mapped `cfg_va` as a Device-attr virtio common-cfg window.
/// # C: O(1)
pub(super) fn set_driver_ok(cfg_va: u64) -> u8 {
    // SAFETY: cfg_va is the Device-attr-mapped common-cfg window; status is
    // the u8 field at CFG_DEVICE_STATUS.
    unsafe {
        core::ptr::write_volatile(
            (cfg_va + CFG_DEVICE_STATUS) as *mut u8,
            virtio::VIRTIO_STATUS_ACKNOWLEDGE
                | virtio::VIRTIO_STATUS_DRIVER
                | virtio::VIRTIO_STATUS_FEATURES_OK
                | virtio::VIRTIO_STATUS_DRIVER_OK,
        );
    }
    read_status(cfg_va)
}

/// Program virtqueue `qi` on the modern common-cfg window at `cfg_va`:
/// select the queue, read its `queue_size` (0 → queue absent, returns
/// None), allocate + zero the three ring frames via `hhdm`, write the
/// ring PAs, bind `msix_vec` (0xFFFF = VIRTIO_MSI_NO_VECTOR for
/// poll-only queues), set queue_enable=1, and capture `queue_notify_off`.
/// Restores queue_select=0 on return so later q0-state reads are correct.
/// Virtio 1.2 §3.1.1 / §4.1.4.3.
/// # SAFETY: caller is the boot path; PMM ready; single-CPU; IRQs masked;
/// `cfg_va` is the Device-attr-mapped virtio_pci_common_cfg window.
/// # C: O(1) — 3 frame allocs + a fixed number of MMIO stores
pub(super) fn program_queue(cfg_va: u64, qi: u16, msix_vec: u16, hhdm: u64) -> Option<QueueRing> {
    let w16 = |off: u64, v: u16| {
        // SAFETY: cfg_va is the Device-attr-mapped common-cfg window; per
        // Virtio 1.2 §4.1.4.3 the field at `off` is u16-aligned within it.
        unsafe { core::ptr::write_volatile((cfg_va + off) as *mut u16, v); }
    };
    let w32 = |off: u64, v: u32| {
        // SAFETY: cfg_va common-cfg window; queue_desc/driver/device le64
        // fields are written as the two u32 halves at `off`/`off+4`.
        unsafe { core::ptr::write_volatile((cfg_va + off) as *mut u32, v); }
    };
    let r16 = |off: u64| -> u16 {
        // SAFETY: cfg_va common-cfg window; aligned u16 load of the
        // selected queue's field at `off`.
        unsafe { core::ptr::read_volatile((cfg_va + off) as *const u16) }
    };

    // Select qi and read its negotiated queue_size. 0 = the device has no
    // such queue (Virtio 1.2 §4.1.4.3.2) — nothing to program.
    w16(CFG_QUEUE_SELECT, qi);
    let size = r16(CFG_QUEUE_SIZE);
    if size == 0 { return None; }

    let desc_pa   = pmm::setup::alloc_raw_frame()?;
    let driver_pa = pmm::setup::alloc_raw_frame()?;
    let device_pa = pmm::setup::alloc_raw_frame()?;

    // Zero the 3 ring frames via HHDM BEFORE queue_enable so the device
    // sees deterministic ring state — PMM doesn't guarantee zero-init.
    if hhdm != 0 {
        for &pa in &[desc_pa, driver_pa, device_pa] {
            let va = hhdm.wrapping_add(pa) as *mut u64;
            // SAFETY: HHDM covers all RAM PMM hands out; single-CPU
            // pre-init; we own these freshly-allocated frames; aligned
            // u64 stores stay within the 4 KiB page.
            unsafe {
                for i in 0..(0x1000 / 8) { core::ptr::write_volatile(va.add(i), 0); }
            }
        }
    }

    // Re-select qi (defensive) and program the ring layout. notify_off is
    // captured while qi is selected — the correct per-queue value.
    w16(CFG_QUEUE_SELECT, qi);
    let notify_off = r16(CFG_QUEUE_NOTIFY);
    w16(CFG_QUEUE_MSIX, msix_vec);
    w32(CFG_QUEUE_DESC,        (desc_pa   & 0xFFFF_FFFF) as u32);
    w32(CFG_QUEUE_DESC + 4,    (desc_pa   >> 32)         as u32);
    w32(CFG_QUEUE_DRIVER,      (driver_pa & 0xFFFF_FFFF) as u32);
    w32(CFG_QUEUE_DRIVER + 4,  (driver_pa >> 32)         as u32);
    w32(CFG_QUEUE_DEVICE,      (device_pa & 0xFFFF_FFFF) as u32);
    w32(CFG_QUEUE_DEVICE + 4,  (device_pa >> 32)         as u32);
    w16(CFG_QUEUE_ENABLE, 1);
    // Restore queue_select=0 so subsequent reads in the kick path see q0.
    w16(CFG_QUEUE_SELECT, 0);

    Some(QueueRing { desc_pa, driver_pa, device_pa, notify_off, size })
}
