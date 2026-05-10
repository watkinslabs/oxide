// Modern virtio-pci transport bring-up. Split from pci_boot/mod.rs.
// klog calls gated under debug_boot! per R06.

use super::map_mmio_pages;

struct VirtioProbe {
    cmd_orig: u16,
    cmd_new:  u16,
    cfg_va:   u64,
    dev_features: u64,
    drv_features: u64,
    post_status: u32,
    features_ok: bool,
    msix_cfg:    u16,
    num_queues:  u16,
    queues: [(u16, u16); 8],
    queues_len: usize,
    q0_desc_pa:   u64,
    q0_driver_pa: u64,
    q0_device_pa: u64,
    final_status: u8,
    q0_notify_off: u16,
    q0_notify_va:  u64,
    post_notify_status: u8,
    avail_idx_posted: u16,
    used_idx_observed: u16,
    isr_status: u8,
    blk_id: [u8; 20],
    tx_used_idx: u16,
    q1_notify_va: u64,
    q1_notify_off: u16,
    blk_status: u8,
    q0_size: u16,
    q1_size: u16,
    q1_desc_pa:   u64,
    q1_driver_pa: u64,
    q1_device_pa: u64,
    rx0_buf_pa:  u64,
    rx0_buf_len: u16,
    mac:       [u8; 6],
    mac_valid: bool,
    tx0_buf_pa: u64,
}

/// Drive one modern virtio-pci device through FEATURES_OK and
/// scan its queue layout. Returns Some(probe) on success.
/// # SAFETY: caller is the boot path; PMM ready; single-CPU; IRQs masked.
/// # C: O(BAR pages mapped + ~num_queues u32 reads)
fn virtio_init_arch(d: &pci::PciDevice) -> Option<VirtioProbe> {
    if !virtio::is_modern(d.vendor_id, d.device_id) { return None; }
    let bdf = d.bdf;
    // Hoist device-class detection so queue 1 (TX) setup can hook in
    // alongside queue 0 inside the per-queue setup block below.
    let is_virtio_net_early = d.vendor_id == 0x1AF4
        && (d.device_id == 0x1000 || d.device_id == 0x1041);

    // Re-walk caps + decode virtio cfgs + decode BARs.
    let (vcaps, bars) = {
        #[cfg(target_arch = "x86_64")]
        {
            let r = hal_x86_64::pci::LegacyPci;
            let c = pci::capabilities(&r, bdf);
            let v = virtio::decode_all(&r, bdf, &c);
            let b = pci::decode_bars(&r, bdf);
            (v, b)
        }
        #[cfg(target_arch = "aarch64")]
        {
            match hal_aarch64::pci::EcamPci::from_published() {
                Some(r) => {
                    let c = pci::capabilities(&r, bdf);
                    let v = virtio::decode_all(&r, bdf, &c);
                    let b = pci::decode_bars(&r, bdf);
                    (v, b)
                }
                None => return None,
            }
        }
    };

    // Enable Memory + BusMaster in PCI cmd reg.
    let cmd_orig = {
        #[cfg(target_arch = "x86_64")]
        { let r = hal_x86_64::pci::LegacyPci;
          <hal_x86_64::pci::LegacyPci as pci::ConfigSpaceReader>::read32(&r, bdf, 0x04) }
        #[cfg(target_arch = "aarch64")]
        { match hal_aarch64::pci::EcamPci::from_published() {
            Some(r) => <hal_aarch64::pci::EcamPci as pci::ConfigSpaceReader>::read32(&r, bdf, 0x04),
            None => return None,
        } }
    };
    let cmd_new = (cmd_orig & 0xFFFF_0000) | ((cmd_orig & 0xFFFF) | 0x0006);
    if cmd_new != cmd_orig {
        #[cfg(target_arch = "x86_64")]
        { let r = hal_x86_64::pci::LegacyPci;
          <hal_x86_64::pci::LegacyPci as pci::ConfigSpaceReader>::write32(&r, bdf, 0x04, cmd_new); }
        #[cfg(target_arch = "aarch64")]
        { if let Some(r) = hal_aarch64::pci::EcamPci::from_published() {
            <hal_aarch64::pci::EcamPci as pci::ConfigSpaceReader>::write32(&r, bdf, 0x04, cmd_new);
        } }
    }

    // Locate COMMON cfg + map the BAR page.
    let common = vcaps.find(virtio::VIRTIO_PCI_CAP_COMMON_CFG)?;
    let bar_pa = match bars[common.bar as usize] {
        pci::Bar::Mem32 { base, .. } => base as u64,
        pci::Bar::Mem64 { base, .. } => base,
        _ => return None,
    };
    let common_pa = bar_pa + common.offset as u64;
    let page_pa = common_pa & !0xFFF;
    let page_off = (common_pa - page_pa) as u64;
    // SAFETY: BAR PA decoded from device BAR reg; bump VA is exclusive.
    let base_va = unsafe { map_mmio_pages(page_pa, 1) };
    let cfg_va = base_va + page_off;

    // u32 volatile R/W over the Device-attr MMIO window.
    let r32 = |off: u64| -> u32 {
        // SAFETY: cfg_va Device-attr mapped; off < 0x1000.
        unsafe { core::ptr::read_volatile((cfg_va + off) as *const u32) }
    };
    let w32 = |off: u64, v: u32| {
        // SAFETY: same window; writes drive device per spec.
        unsafe { core::ptr::write_volatile((cfg_va + off) as *mut u32, v); }
    };
    // F59-09: u16-precise writes for the byte/word fields in
    // virtio_pci_common_cfg. QEMU's `virtio_pci_common_write`
    // dispatches by `switch(addr)` — a 4-byte store at 0x14
    // only triggers the DEVSTATUS handler (byte 0); bytes 1-3
    // (config_generation @ 0x15 + queue_select @ 0x16) are
    // silently dropped. queue_select MUST be written as a u16
    // at 0x16 or it never takes effect.
    let w16 = |off: u64, v: u16| {
        // SAFETY: same window; per Virtio 1.2 §4.1.4.3 the field at `off` is u16-aligned.
        unsafe { core::ptr::write_volatile((cfg_va + off) as *mut u16, v); }
    };
    let w8 = |off: u64, v: u8| {
        // SAFETY: same window; per Virtio 1.2 §4.1.4.3 device_status is a u8 at +0x14.
        unsafe { core::ptr::write_volatile((cfg_va + off) as *mut u8, v); }
    };

    // Spec §3.1.1 driver init sequence.
    let st = |s: u8| -> u32 { s as u32 };
    w32(0x14, st(0));                                              // reset
    let _ = r32(0x14);
    w32(0x14, st(virtio::VIRTIO_STATUS_ACKNOWLEDGE));
    w32(0x14, st(virtio::VIRTIO_STATUS_ACKNOWLEDGE
               | virtio::VIRTIO_STATUS_DRIVER));

    // Feature negotiation. Insist on VIRTIO_F_VERSION_1 (bit 32) for
    // modern transport. F59-08: also accept VIRTIO_NET_F_MAC (bit 5)
    // + VIRTIO_NET_F_STATUS (bit 16) for virtio-net so QEMU's modern
    // virtio-net-pci queues actually start processing kicks. The
    // boot probe's q1 TX never advanced used.idx with only V1
    // negotiated; QEMU's virtio_net_set_status() gates queue
    // activation on a complete enough feature set for nets.
    w32(0x00, 0); let dev_feat_lo = r32(0x04);
    w32(0x00, 1); let dev_feat_hi = r32(0x04);
    let dev_features: u64 = ((dev_feat_hi as u64) << 32) | (dev_feat_lo as u64);
    let mut want = virtio::VIRTIO_F_VERSION_1;
    if d.vendor_id == 0x1AF4 && (d.device_id == 0x1000 || d.device_id == 0x1041) {
        want |= virtio::VIRTIO_NET_F_MAC | virtio::VIRTIO_NET_F_STATUS;
    }
    let drv_features: u64 = dev_features & want;
    w32(0x08, 1); w32(0x0C, (drv_features >> 32) as u32);
    w32(0x08, 0); w32(0x0C, (drv_features & 0xFFFF_FFFF) as u32);
    w32(0x14, st(virtio::VIRTIO_STATUS_ACKNOWLEDGE
               | virtio::VIRTIO_STATUS_DRIVER
               | virtio::VIRTIO_STATUS_FEATURES_OK));

    let post_status = r32(0x14) & 0xFF;
    let features_ok = post_status & virtio::VIRTIO_STATUS_FEATURES_OK as u32 != 0;

    let w_msix_nq = r32(0x10);
    let msix_cfg   = (w_msix_nq & 0xFFFF) as u16;
    let num_queues = (w_msix_nq >> 16) as u16;

    // Queue scan: iterate queue_select 0..min(num_queues, 8) reading
    // queue_size at +0x18. queue_size==0 means the queue is disabled
    // (per spec). queue_select sits in the high u16 of the same dword
    // as device_status; preserve status when writing.
    let mut queues = [(0u16, 0u16); 8];
    let mut queues_len = 0usize;
    let cap = if num_queues == 0 || num_queues > 8 { 8 } else { num_queues } as u16;
    for qi in 0..cap {
        // F59-09: queue_select is a u16 at +0x16 — must be a u16
        // store, not a u32 store at 0x14 (QEMU's switch-based
        // dispatcher would only update DEVSTATUS @ 0x14).
        w16(0x16, qi);
        let qs_data = r32(0x18);
        let queue_size = (qs_data & 0xFFFF) as u16;
        queues[queues_len] = (qi, queue_size);
        queues_len += 1;
        if queue_size == 0 { break; }
    }

    // queue_notify_off = hi-u16 of cfg+0x1C.
    let q0_notify_off = (r32(0x1C) >> 16) as u16;
    // queue 1 (TX) state captured via queue_select switch.
    let mut q1_desc_pa: u64 = 0;
    let mut q1_driver_pa: u64 = 0;
    let mut q1_device_pa: u64 = 0;
    let mut q1_notify_off_local: u16 = 0;
    let q0_size = if queues_len > 0 { queues[0].1 } else { 0 };
    let (q0_desc_pa, q0_driver_pa, q0_device_pa, final_status) = if q0_size != 0 && features_ok {
        let pa_desc   = pmm_setup::alloc_one_frame().unwrap_or(0);
        let pa_driver = pmm_setup::alloc_one_frame().unwrap_or(0);
        let pa_device = pmm_setup::alloc_one_frame().unwrap_or(0);
        if pa_desc != 0 && pa_driver != 0 && pa_device != 0 {
            //: zero the 3 ring frames via HHDM BEFORE programming
            // queue_enable so the device sees deterministic ring state.
            // PMM doesn't guarantee zero-init.
            let hhdm = {
                #[cfg(target_arch = "x86_64")]
                { hal_x86_64::mmu_ops::hhdm_offset() }
                #[cfg(target_arch = "aarch64")]
                { hal_aarch64::mmu_ops::hhdm_offset() }
            };
            if hhdm != 0 {
                for &pa in &[pa_desc, pa_driver, pa_device] {
                    let va = hhdm.wrapping_add(pa) as *mut u64;
                    // SAFETY: HHDM covers all RAM PMM hands out;
                    // single-CPU pre-init; we own these freshly-allocated
                    // frames; aligned u64 stores within a 4 KiB page.
                    unsafe {
                        for i in 0..(0x1000 / 8) {
                            core::ptr::write_volatile(va.add(i), 0);
                        }
                    }
                }
            }
            // F59-09: queue_select=0 via u16 store at +0x16.
            w16(0x16, 0);
            // queue_size at 0x18 (low u16) — leave as-is.
            //: bind queue_msix_vector at +0x1A to MSI-X table
            // F59-09: queue_msix_vector is u16 at +0x1A — must be a
            // u16 store (QEMU's switch dispatcher would drop a u32
            // store at 0x18, only triggering queue_size).
            w16(0x1A, 0);
            // queue_desc le64 at +0x20: separate u32 cases at 0x20/0x24.
            w32(0x20, (pa_desc & 0xFFFF_FFFF) as u32);
            w32(0x24, (pa_desc >> 32) as u32);
            // queue_driver (avail) le64 at +0x28:
            w32(0x28, (pa_driver & 0xFFFF_FFFF) as u32);
            w32(0x2C, (pa_driver >> 32) as u32);
            // queue_device (used) le64 at +0x30:
            w32(0x30, (pa_device & 0xFFFF_FFFF) as u32);
            w32(0x34, (pa_device >> 32) as u32);
            // F59-09: queue_enable is u16 at +0x1C — must be a u16 store.
            w16(0x1C, 1);

            //: for virtio-net, also stand up queue 1 (TX) so we
            // can post outgoing frames. queue 0 = RX, queue 1 = TX
            // by spec §5.1.6 Device Operation.
            if is_virtio_net_early {
                if let (Some(q1d), Some(q1v), Some(q1u)) = (
                    pmm_setup::alloc_one_frame(),
                    pmm_setup::alloc_one_frame(),
                    pmm_setup::alloc_one_frame(),
                ) {
                    let hhdm = {
                        #[cfg(target_arch = "x86_64")]
                        { hal_x86_64::mmu_ops::hhdm_offset() }
                        #[cfg(target_arch = "aarch64")]
                        { hal_aarch64::mmu_ops::hhdm_offset() }
                    };
                    if hhdm != 0 {
                        for &p in &[q1d, q1v, q1u] {
                            let v = hhdm.wrapping_add(p) as *mut u64;
                            // SAFETY: HHDM-mapped freshly-allocated frame; aligned u64 stores within the 4 KiB page bounds we own.
                            unsafe {
                                for i in 0..(0x1000 / 8) {
                                    core::ptr::write_volatile(v.add(i), 0);
                                }
                            }
                        }
                    }
                    // F59-09: queue_select=1 via u16 store at +0x16.
                    // The earlier u32 store at 0x14 was dropped by
                    // QEMU's switch-on-addr dispatcher, so q1's ring
                    // PA writes were silently going to q0 instead.
                    // Confirmed: with the u16 store, q1_notify_off
                    // reads back as 1 (was 0 with the bug), TX kicks
                    // reach the device, SLIRP replies to ARP.
                    w16(0x16, 1);
                    // Capture per-queue notify_off (u16 at +0x1E).
                    // SAFETY: cfg_va Device-attr-mapped above; aligned u16 load of queue_notify_off for the currently-selected queue (q1).
                    q1_notify_off_local = unsafe {
                        core::ptr::read_volatile((cfg_va + 0x1E) as *const u16)
                    };
                    // q1 polls used.idx, no MSI-X needed.
                    // F59-09: queue_msix_vector u16 at +0x1A.
                    w16(0x1A, 0xFFFF);
                    // queue_desc/driver/device for q1
                    w32(0x20, (q1d & 0xFFFF_FFFF) as u32);
                    w32(0x24, (q1d >> 32) as u32);
                    w32(0x28, (q1v & 0xFFFF_FFFF) as u32);
                    w32(0x2C, (q1v >> 32) as u32);
                    w32(0x30, (q1u & 0xFFFF_FFFF) as u32);
                    w32(0x34, (q1u >> 32) as u32);
                    // F59-09: queue_enable u16 at +0x1C.
                    w16(0x1C, 1);
                    // Stash for outer-scope use post-DRIVER_OK.
                    q1_desc_pa = q1d;
                    q1_driver_pa = q1v;
                    q1_device_pa = q1u;
                    // Restore queue_select=0 so subsequent reads in
                    // the kick path see q0 state.
                    w16(0x16, 0); // F59-09: restore queue_select=0 via u16 store
                }
            }

            // DRIVER_OK
            w32(0x14, st(virtio::VIRTIO_STATUS_ACKNOWLEDGE
                       | virtio::VIRTIO_STATUS_DRIVER
                       | virtio::VIRTIO_STATUS_FEATURES_OK
                       | virtio::VIRTIO_STATUS_DRIVER_OK));
            let final_status = (r32(0x14) & 0xFF) as u8;
            (pa_desc, pa_driver, pa_device, final_status)
        } else {
            (0, 0, 0, post_status as u8)
        }
    } else {
        (0, 0, 0, post_status as u8)
    };
    //: for virtio-blk (transitional 0x1001 or modern 0x1042),
    // issue a VIRTIO_BLK_T_IN read of sector 1 — the GPT primary
    // header on a GPT-partitioned disk. Header (16B) + data (512B) +
    // status (1B) in a 3-descriptor chain. Proves bidirectional DMA
    // roundtrip with real disk content; first 8 bytes of the data
    // buffer should be the ASCII "EFI PART" GPT signature.
    let mut blk_id = [0u8; 20];
    let mut blk_status: u8 = 0xFF;
    let is_virtio_blk = d.vendor_id == 0x1AF4
        && (d.device_id == 0x1001 || d.device_id == 0x1042);

    //: for virtio-net (transitional 0x1000 or modern 0x1041),
    // post one RX buffer descriptor on queue 0 and bump avail.idx
    // before kicking. For other devices the queue stays empty so the
    // kick is a no-op nudge.
    let mut avail_idx_posted = 0u16;
    // F59-02: persisted RX-buffer info for runtime rx_poll. Set when
    // the virtio-net branch below allocates the boot-time RX page;
    // 0/0 if no virtio-net device or DRIVER_OK didn't land.
    let mut rx0_buf_pa_local: u64 = 0;
    let mut rx0_buf_len_local: u16 = 0;
    let is_virtio_net = d.vendor_id == 0x1AF4
        && (d.device_id == 0x1000 || d.device_id == 0x1041);
    let is_virtio_gpu = d.vendor_id == 0x1AF4 && d.device_id == 0x1050;
    let is_virtio_input = d.vendor_id == 0x1AF4 && d.device_id == 0x1052;
    let bdf_word = (d.bdf.bus as u32) << 16
                 | (d.bdf.device as u32) << 8
                 | (d.bdf.function as u32);
    if is_virtio_gpu && (final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0 {
        use core::sync::atomic::{AtomicU32, AtomicU64};
        let card_id = drv_virtio_gpu::install_with_drm(drv_virtio_gpu::VirtioGpuDev {
            bdf: bdf_word, features_negotiated: drv_features as u64,
            display: drv_virtio_gpu::DisplayInfo::default(),
            resource_id_alloc: AtomicU32::new(1),
            blob_uuid_alloc: AtomicU64::new(1), capset_count: 0,
        });
        debug_boot! { klog::write_raw(b"[INFO]  virtio-gpu installed feat=");
            klog::write_hex_u64(drv_features); klog::write_raw(b" card=");
            klog::write_dec_u64(card_id as u64); klog::write_raw(b"\n"); }
    }
    if is_virtio_input && (final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0 {
        let evdev_id = drv_virtio_input::count() as u32;
        drv_virtio_input::install(drv_virtio_input::VirtioInputDev {
            bdf: bdf_word, evdev_id,
            name: [0; 128], name_len: 0, serial: [0; 128], serial_len: 0,
            ids: drv_virtio_input::VirtioInputDevIds::default(),
            ev_bits: [0; 32],
            key_bits: drv_virtio_input::CapBitmap::default(),
            rel_bits: drv_virtio_input::CapBitmap::default(),
            abs_bits: drv_virtio_input::CapBitmap::default(),
            led_bits: drv_virtio_input::CapBitmap::default(),
            abs_info: [None; 64],
        });
        debug_boot! { klog::write_raw(b"[INFO]  virtio-input installed evdev_id=");
            klog::write_dec_u64(evdev_id as u64); klog::write_raw(b"\n"); }
    }
    if is_virtio_blk && q0_desc_pa != 0 && (final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0 {
        let hhdm = {
            #[cfg(target_arch = "x86_64")]
            { hal_x86_64::mmu_ops::hhdm_offset() }
            #[cfg(target_arch = "aarch64")]
            { hal_aarch64::mmu_ops::hhdm_offset() }
        };
        if let Some(buf_pa) = pmm_setup::alloc_one_frame() {
            if hhdm != 0 {
                let buf_va = hhdm.wrapping_add(buf_pa) as *mut u8;
                // SAFETY: HHDM-mapped frame; aligned writes within 4 KiB.
                unsafe {
                    // Zero the buf first.
                    for i in 0..0x1000usize { core::ptr::write_volatile(buf_va.add(i), 0); }
                    //: VIRTIO_BLK_T_IN read of sector 1 (GPT primary
                    // header). Header layout (16B):
                    //   le32 type=0 (IN/read)
                    //   le32 reserved=0
                    //   le64 sector=1
                    core::ptr::write_volatile(buf_va.add(0) as *mut u32, 0);
                    core::ptr::write_volatile(buf_va.add(8) as *mut u64, 1u64);
                    // Pre-fill status byte at +0x600 with sentinel 0xFF.
                    core::ptr::write_volatile(buf_va.add(0x600), 0xFFu8);
                }
                // 3 descriptors at desc table:
                //   d0: { addr=buf+0x000, len=16,  flags=NEXT(1),       next=1 }
                //   d1: { addr=buf+0x200, len=512, flags=WRITE|NEXT(3), next=2 }
                //   d2: { addr=buf+0x600, len=1,   flags=WRITE(2),      next=0 }
                let desc0 = (hhdm.wrapping_add(q0_desc_pa)) as *mut u64;
                // SAFETY: HHDM-mapped virtio queue-0 descriptor table; aligned u64 stores within the frame the driver owns.
                unsafe {
                    // Descriptor 0
                    core::ptr::write_volatile(desc0.add(0), buf_pa);
                    let d0_lo = 16u64;
                    let d0_flags = (virtio::VRING_DESC_F_NEXT as u64) << 32;
                    let d0_next = 1u64 << 48;
                    core::ptr::write_volatile(desc0.add(1), d0_lo | d0_flags | d0_next);
                    // Descriptor 1: data buffer for the device's sector
                    // payload (512 bytes), positioned at buf+0x200 to
                    // leave header room at +0x000..+0x010.
                    core::ptr::write_volatile(desc0.add(2), buf_pa + 0x200);
                    let d1_lo = 512u64;
                    let d1_flags = ((virtio::VRING_DESC_F_NEXT
                                   | virtio::VRING_DESC_F_WRITE) as u64) << 32;
                    let d1_next = 2u64 << 48;
                    core::ptr::write_volatile(desc0.add(3), d1_lo | d1_flags | d1_next);
                    // Descriptor 2 — status byte at buf+0x600 (after the
                    // 512-byte sector payload at +0x200..+0x600).
                    core::ptr::write_volatile(desc0.add(4), buf_pa + 0x600);
                    let d2_lo = 1u64;
                    let d2_flags = (virtio::VRING_DESC_F_WRITE as u64) << 32;
                    core::ptr::write_volatile(desc0.add(5), d2_lo | d2_flags);
                }
                // avail.ring[0] = 0; avail.idx = 1.
                let avail = (hhdm.wrapping_add(q0_driver_pa)) as *mut u16;
                // SAFETY: HHDM-mapped virtio queue-0 avail ring; aligned u16 stores within the driver-owned frame.
                unsafe {
                    core::ptr::write_volatile(avail.add(2), 0u16); // ring[0]
                }
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                // SAFETY: same ring; idx at u16 offset 1.
                unsafe { core::ptr::write_volatile(avail.add(1), 1u16); }
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                avail_idx_posted = 1;
            }
        }
    } else if is_virtio_net && q0_desc_pa != 0 && (final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0 {
        let hhdm = {
            #[cfg(target_arch = "x86_64")]
            { hal_x86_64::mmu_ops::hhdm_offset() }
            #[cfg(target_arch = "aarch64")]
            { hal_aarch64::mmu_ops::hhdm_offset() }
        };
        if let Some(rx_pa) = pmm_setup::alloc_one_frame() {
            if hhdm != 0 {
                // F59-02: capture rx_pa for runtime rx_poll re-publish.
                rx0_buf_pa_local = rx_pa;
                rx0_buf_len_local = 2048;
                // Descriptor[0]: { addr=rx_pa; len=2048; flags=WRITE(2); next=0 }
                let desc0 = (hhdm.wrapping_add(q0_desc_pa)) as *mut u64;
                // SAFETY: HHDM-mapped, freshly-allocated frame, single-CPU.
                unsafe {
                    core::ptr::write_volatile(desc0, rx_pa);
                    // len=2048 (low 32) | flags=WRITE(2) << 32 | next=0 << 48
                    let lo32 = 2048u32 as u64;
                    let flags_next = (virtio::VRING_DESC_F_WRITE as u64) << 32;
                    core::ptr::write_volatile(desc0.add(1), lo32 | flags_next);
                }
                // avail.ring[0] = 0 at driver_pa+0x04
                let avail = (hhdm.wrapping_add(q0_driver_pa)) as *mut u16;
                // SAFETY: same frame, ring[0] at byte +4 = u16 offset 2.
                unsafe {
                    core::ptr::write_volatile(avail.add(2), 0u16);
                }
                // Memory barrier so the descriptor + ring writes are
                // observable before avail.idx bump.
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                // avail.idx = 1 at driver_pa+0x02 (u16 offset 1).
                // SAFETY: HHDM-mapped avail ring as above; this u16 store at idx publishes the descriptor we just wrote.
                unsafe { core::ptr::write_volatile(avail.add(1), 1u16); }
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                avail_idx_posted = 1;
            }
        }
    }

    //: kick the notify register for queue 0. Notify address per
    // Virtio 1.2 §4.1.4.4:
    //   notify_pa = NOTIFY_BAR_pa + notify_cap.offset + qoff * notify_mult
    // where qoff = the queue_notify_off captured above.
    let (q0_notify_va, post_notify_status) = if final_status & virtio::VIRTIO_STATUS_FAILED == 0
        && (final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0
    {
        if let Some(notify_cap) = vcaps.find(virtio::VIRTIO_PCI_CAP_NOTIFY_CFG) {
            let nbar_pa = match bars[notify_cap.bar as usize] {
                pci::Bar::Mem32 { base, .. } => base as u64,
                pci::Bar::Mem64 { base, .. } => base,
                _ => 0,
            };
            if nbar_pa != 0 {
                let nfy_pa = nbar_pa + notify_cap.offset as u64
                           + (q0_notify_off as u64) * (notify_cap.notify_off_multiplier as u64);
                let n_page_pa = nfy_pa & !0xFFF;
                let n_page_off = nfy_pa - n_page_pa;
                // SAFETY: NOTIFY BAR PA decoded from device cap; bump VA private.
                let n_va = unsafe { map_mmio_pages(n_page_pa, 1) };
                let kick_va = n_va + n_page_off;
                // Write queue index 0 as a u16 to the notify address.
                // SAFETY: kick_va Device-attr; aligned u16 write.
                unsafe { core::ptr::write_volatile(kick_va as *mut u16, 0u16); }
                // Brief observation window for any device-driven RX
                // completion (QEMU user-net delivers nothing without
                // packets, so used.idx will normally stay 0).
                for _ in 0..1_000_000 { core::hint::spin_loop(); }
                let st = (r32(0x14) & 0xFF) as u8;
                (kick_va, st)
            } else {
                (0u64, final_status)
            }
        } else {
            (0u64, final_status)
        }
    } else {
        (0u64, final_status)
    };

    //: virtio-net TX path. After DRIVER_OK + (existing F26) q0
    // kick, post one ethernet frame to queue 1, kick q1, observe
    // q1.used.idx. Frame = 12-byte virtio_net_hdr (zeros) + 60-byte
    // dummy ethernet broadcast frame. Single descriptor, flags=0
    // (driver-side only).
    let mut q1_notify_va_local: u64 = 0;
    let mut tx_used_idx_local: u16 = 0;
    // F59-05: persist TX scratch buffer PA so dev_virtio_net_modern::
    // tx_frame can rewrite + repost it after boot. 0 if no virtio-net
    // or DRIVER_OK didn't land or the q1 setup bailed before alloc.
    let mut tx0_buf_pa_local: u64 = 0;
    if is_virtio_net_early
        && q1_desc_pa != 0
        && (final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0
    {
        let hhdm = {
            #[cfg(target_arch = "x86_64")]
            { hal_x86_64::mmu_ops::hhdm_offset() }
            #[cfg(target_arch = "aarch64")]
            { hal_aarch64::mmu_ops::hhdm_offset() }
        };
        if let Some(tx_pa) = pmm_setup::alloc_one_frame() {
            tx0_buf_pa_local = tx_pa;
            if hhdm != 0 {
                let tx_va = hhdm.wrapping_add(tx_pa) as *mut u8;
                // SAFETY: HHDM-mapped freshly-allocated frame; bytes 0..72 stay within the 4 KiB page; we own this frame exclusively.
                unsafe {
                    // virtio_net_hdr: 12 bytes of zeros (no checksum, no GSO, num_buffers=0).
                    for i in 0..12usize { core::ptr::write_volatile(tx_va.add(i), 0); }
                    // 60-byte dummy ethernet frame at +12.
                    // dst MAC (broadcast) ff*6
                    for i in 0..6 { core::ptr::write_volatile(tx_va.add(12 + i), 0xFF); }
                    // src MAC 02:00:00:00:00:01
                    core::ptr::write_volatile(tx_va.add(18), 0x02);
                    for i in 19..24 { core::ptr::write_volatile(tx_va.add(i), 0); }
                    core::ptr::write_volatile(tx_va.add(23), 0x01);
                    // ethertype 0x0800 (IPv4)
                    core::ptr::write_volatile(tx_va.add(24), 0x08);
                    core::ptr::write_volatile(tx_va.add(25), 0x00);
                    // 46 bytes of pad (already zeroed via PMM in some
                    // setups; explicit for safety).
                    for i in 26..72 { core::ptr::write_volatile(tx_va.add(i), 0); }
                }
                // descriptor[0] for q1 = { addr=tx_pa, len=72, flags=0, next=0 }
                let q1_desc = (hhdm.wrapping_add(q1_desc_pa)) as *mut u64;
                // SAFETY: HHDM-mapped queue-1 descriptor table; aligned u64 stores within frame bounds; driver owns it.
                unsafe {
                    core::ptr::write_volatile(q1_desc, tx_pa);
                    core::ptr::write_volatile(q1_desc.add(1), 72u64);
                }
                // avail.ring[0] = 0; avail.idx = 1
                let q1_avail = (hhdm.wrapping_add(q1_driver_pa)) as *mut u16;
                // SAFETY: HHDM-mapped q1 avail ring frame; u16 offset 2 = ring[0], offset 1 = idx.
                unsafe {
                    core::ptr::write_volatile(q1_avail.add(2), 0u16);
                }
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                // SAFETY: same frame; published idx=1 after the desc and ring writes are observable.
                unsafe { core::ptr::write_volatile(q1_avail.add(1), 1u16); }
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                // Compute q1 notify VA from notify_cap + q1_off * mult.
                if let Some(notify_cap) = vcaps.find(virtio::VIRTIO_PCI_CAP_NOTIFY_CFG) {
                    let nbar_pa = match bars[notify_cap.bar as usize] {
                        pci::Bar::Mem32 { base, .. } => base as u64,
                        pci::Bar::Mem64 { base, .. } => base,
                        _ => 0,
                    };
                    if nbar_pa != 0 {
                        let nfy_pa = nbar_pa + notify_cap.offset as u64
                            + (q1_notify_off_local as u64)
                              * (notify_cap.notify_off_multiplier as u64);
                        let n_page_pa = nfy_pa & !0xFFF;
                        let n_page_off = nfy_pa - n_page_pa;
                        // SAFETY: NOTIFY BAR PA decoded from device cap; bump VA private to virtio.
                        let n_va = unsafe { super::map_mmio_pages(n_page_pa, 1) };
                        let kick_va = n_va + n_page_off;
                        q1_notify_va_local = kick_va;
                        // Write queue index 1 to the q1 notify VA.
                        // SAFETY: kick_va Device-attr mapped above; aligned u16 write.
                        unsafe { core::ptr::write_volatile(kick_va as *mut u16, 1u16); }
                        // Brief observation window for any TX completion.
                        for _ in 0..1_000_000 { core::hint::spin_loop(); }
                        let q1_used = (hhdm.wrapping_add(q1_device_pa)) as *const u16;
                        // SAFETY: HHDM-mapped q1 used ring; u16 idx at offset 1.
                        tx_used_idx_local = unsafe { core::ptr::read_volatile(q1_used.add(1)) };
                    }
                }
            }
        }
    }

    //: locate ISR cap, map its BAR page, and read the ISR byte
    // post-kick. Per Virtio 1.2 §4.1.4.5: ISR is a 1-byte read-to-clear
    // register; bit 0 = queue interrupt, bit 1 = config-change
    // interrupt. With MSI-X unbound the device would normally route via
    // INTx; we're not catching those yet but the ISR poll lets us see
    // whether the device attempted notification.
    let isr_status = if avail_idx_posted > 0 {
        if let Some(isr_cap) = vcaps.find(virtio::VIRTIO_PCI_CAP_ISR_CFG) {
            let ibar_pa = match bars[isr_cap.bar as usize] {
                pci::Bar::Mem32 { base, .. } => base as u64,
                pci::Bar::Mem64 { base, .. } => base,
                _ => 0,
            };
            if ibar_pa != 0 {
                let isr_pa = ibar_pa + isr_cap.offset as u64;
                let i_page_pa = isr_pa & !0xFFF;
                let i_page_off = isr_pa - i_page_pa;
                // SAFETY: ISR BAR PA decoded from device cap; bump VA private.
                let i_va = unsafe { map_mmio_pages(i_page_pa, 1) };
                let isr_va = i_va + i_page_off;
                // SAFETY: isr_va Device-attr; aligned u8 read clears it.
                unsafe { core::ptr::read_volatile(isr_va as *const u8) }
            } else { 0 }
        } else { 0 }
    } else { 0 };

    // F59-04: harvest virtio-net MAC from the device-cfg region. Per
    // Virtio 1.2 §5.1.4 `virtio_net_config`, the first 6 bytes of the
    // device-cfg space are the MAC address (when F_MAC negotiated;
    // QEMU's virtio-net always supports it). Layout: bar=N off=M from
    // the `VIRTIO_PCI_CAP_DEVICE_CFG` capability decoded above.
    let mut mac_local: [u8; 6] = [0; 6];
    let mut mac_valid_local: bool = false;
    if is_virtio_net {
        if let Some(devcfg_cap) = vcaps.find(virtio::VIRTIO_PCI_CAP_DEVICE_CFG) {
            let dbar_pa = match bars[devcfg_cap.bar as usize] {
                pci::Bar::Mem32 { base, .. } => base as u64,
                pci::Bar::Mem64 { base, .. } => base,
                _ => 0,
            };
            if dbar_pa != 0 {
                let d_pa = dbar_pa + devcfg_cap.offset as u64;
                let d_page_pa = d_pa & !0xFFF;
                let d_page_off = d_pa - d_page_pa;
                // SAFETY: device-cfg BAR PA decoded from device cap; bump VA private; one-page window covers the 6-byte MAC at offset 0.
                let d_va = unsafe { map_mmio_pages(d_page_pa, 1) };
                let mac_va = d_va + d_page_off;
                for i in 0..6 {
                    // SAFETY: mac_va Device-attr-mapped above via map_mmio_pages; aligned u8 read within the one-page MAC window.
                    mac_local[i] = unsafe {
                        core::ptr::read_volatile((mac_va + i as u64) as *const u8)
                    };
                }
                mac_valid_local = true;
            }
        }
    }

    //: harvest virtio-blk GET_ID result if we issued one. The data
    // descriptor's buffer pa = q0_desc_pa is encoded in desc[2*1+0] but
    // we already know it's `buf_pa+0x100`; rather than read the desc
    // back, walk the used ring to find the chain head, then dereference.
    if is_virtio_blk && avail_idx_posted > 0 {
        let hhdm = {
            #[cfg(target_arch = "x86_64")]
            { hal_x86_64::mmu_ops::hhdm_offset() }
            #[cfg(target_arch = "aarch64")]
            { hal_aarch64::mmu_ops::hhdm_offset() }
        };
        if hhdm != 0 {
            // Read used.idx at q0_device_pa+0x02 to confirm completion;
            // used.ring[0].id is at +0x04..+0x08 (le32 = chain head idx),
            // which we can use to recover the buffer PA via desc table.
            let used = (hhdm.wrapping_add(q0_device_pa)) as *const u16;
            // SAFETY: HHDM-mapped virtio queue-0 used ring; aligned u16 load at the idx field.
            let uidx = unsafe { core::ptr::read_volatile(used.add(1)) };
            if uidx > 0 {
                // descriptor-table is HHDM-mapped at q0_desc_pa
                let desc0 = (hhdm.wrapping_add(q0_desc_pa)) as *const u64;
                // SAFETY: HHDM-mapped virtio queue-0 descriptor table; aligned u64 load of the chain head's addr field.
                let d0_addr = unsafe { core::ptr::read_volatile(desc0.add(0)) };
                let buf_pa = d0_addr; // descriptor 0's addr is buf_pa + 0
                let buf_va = hhdm.wrapping_add(buf_pa) as *const u8;
                // SAFETY: HHDM-mapped data buf within the same page.
                unsafe {
                    //: data is at buf+0x200 (sector 1 contents).
                    // Capture first 20 bytes — first 8 are the GPT
                    // signature "EFI PART" if this is a GPT-partitioned
                    // disk. blk_id reuses the array for the dump.
                    for i in 0..20 {
                        blk_id[i] = core::ptr::read_volatile(buf_va.add(0x200 + i));
                    }
                    blk_status = core::ptr::read_volatile(buf_va.add(0x600));
                }
            }
        }
    }

    //: read used.idx after the kick.
    let used_idx_observed = if avail_idx_posted > 0 && q0_device_pa != 0 {
        let hhdm = {
            #[cfg(target_arch = "x86_64")]
            { hal_x86_64::mmu_ops::hhdm_offset() }
            #[cfg(target_arch = "aarch64")]
            { hal_aarch64::mmu_ops::hhdm_offset() }
        };
        if hhdm != 0 {
            let used = (hhdm.wrapping_add(q0_device_pa)) as *const u16;
            // used.idx at +0x02 (u16 offset 1).
            // SAFETY: HHDM-mapped frame; aligned u16 load.
            unsafe { core::ptr::read_volatile(used.add(1)) }
        } else { 0 }
    } else { 0 };

    Some(VirtioProbe {
        cmd_orig: (cmd_orig & 0xFFFF) as u16,
        cmd_new:  (cmd_new  & 0xFFFF) as u16,
        cfg_va,
        dev_features,
        drv_features,
        post_status,
        features_ok,
        msix_cfg,
        num_queues,
        queues,
        queues_len,
        q0_desc_pa,
        q0_driver_pa,
        q0_device_pa,
        final_status,
        q0_notify_off,
        q0_notify_va,
        post_notify_status,
        avail_idx_posted,
        used_idx_observed,
        isr_status,
        blk_id,
        blk_status,
        tx_used_idx: tx_used_idx_local,
        q1_notify_va: q1_notify_va_local,
        q1_notify_off: q1_notify_off_local,
        q0_size,
        q1_size: if queues_len > 1 { queues[1].1 } else { 0 },
        q1_desc_pa,
        q1_driver_pa,
        q1_device_pa,
        rx0_buf_pa:  rx0_buf_pa_local,
        rx0_buf_len: rx0_buf_len_local,
        mac:       mac_local,
        mac_valid: mac_valid_local,
        tx0_buf_pa: tx0_buf_pa_local,
    })
}

/// Drive one modern virtio-pci device + emit `[INFO] virtio-cfg ...`
/// + per-queue `[INFO] virtio-q ...` lines under `debug-boot`.
/// Side-effect work runs unconditionally; only the trace is gated.
/// # C: O(BAR pages mapped + ~num_queues u32 reads)
pub(super) fn virtio_probe_arch(d: &pci::PciDevice) {
    let p = match virtio_init_arch(d) { Some(p) => p, None => return };
    let bdf = d.bdf;
    debug_boot! {
        klog::write_raw(b"[INFO]  pci-cmd ");
        klog::write_dec_u64(bdf.bus as u64);
        klog::write_raw(b":");
        klog::write_dec_u64(bdf.device as u64);
        klog::write_raw(b".");
        klog::write_dec_u64(bdf.function as u64);
        klog::write_raw(b" was=");
        klog::write_hex_u64(p.cmd_orig as u64);
        klog::write_raw(b" now=");
        klog::write_hex_u64(p.cmd_new as u64);
        klog::write_raw(b"\n");

        klog::write_raw(b"[INFO]  virtio-cfg ");
        klog::write_dec_u64(bdf.bus as u64);
        klog::write_raw(b":");
        klog::write_dec_u64(bdf.device as u64);
        klog::write_raw(b".");
        klog::write_dec_u64(bdf.function as u64);
        klog::write_raw(b" common-va=");
        klog::write_hex_u64(p.cfg_va);
        klog::write_raw(b" feat=");
        klog::write_hex_u64(p.dev_features);
        klog::write_raw(b" drv_feat=");
        klog::write_hex_u64(p.drv_features);
        klog::write_raw(b" status=");
        klog::write_hex_u64(p.post_status as u64);
        klog::write_raw(b" features_ok=");
        klog::write_dec_u64(p.features_ok as u64);
        klog::write_raw(b" num_queues=");
        klog::write_dec_u64(p.num_queues as u64);
        klog::write_raw(b" msix_cfg=");
        klog::write_hex_u64(p.msix_cfg as u64);
        klog::write_raw(b"\n");

        for i in 0..p.queues_len {
            let (qi, qsz) = p.queues[i];
            klog::write_raw(b"[INFO]  virtio-q ");
            klog::write_dec_u64(bdf.bus as u64);
            klog::write_raw(b":");
            klog::write_dec_u64(bdf.device as u64);
            klog::write_raw(b".");
            klog::write_dec_u64(bdf.function as u64);
            klog::write_raw(b" idx=");
            klog::write_dec_u64(qi as u64);
            klog::write_raw(b" size=");
            klog::write_dec_u64(qsz as u64);
            klog::write_raw(b"\n");
        }
        if p.blk_status != 0xFF {
            klog::write_raw(b"[INFO]  virtio-blk-rd ");
            klog::write_dec_u64(bdf.bus as u64);
            klog::write_raw(b":");
            klog::write_dec_u64(bdf.device as u64);
            klog::write_raw(b".");
            klog::write_dec_u64(bdf.function as u64);
            klog::write_raw(b" status=");
            klog::write_hex_u64(p.blk_status as u64);
            klog::write_raw(b" id=\"");
            // Render printable bytes; replace non-printables with '.'
            let mut buf = [b'.'; 20];
            for i in 0..20 {
                let b = p.blk_id[i];
                buf[i] = if b >= 0x20 && b < 0x7f { b } else if b == 0 { b'.' } else { b'?' };
            }
            klog::write_raw(&buf);
            klog::write_raw(b"\"\n");
        }
        if p.avail_idx_posted > 0 {
            klog::write_raw(b"[INFO]  virtio-rx-post ");
            klog::write_dec_u64(bdf.bus as u64);
            klog::write_raw(b":");
            klog::write_dec_u64(bdf.device as u64);
            klog::write_raw(b".");
            klog::write_dec_u64(bdf.function as u64);
            klog::write_raw(b" avail_idx=");
            klog::write_dec_u64(p.avail_idx_posted as u64);
            klog::write_raw(b" used_idx=");
            klog::write_dec_u64(p.used_idx_observed as u64);
            klog::write_raw(b" isr=");
            klog::write_hex_u64(p.isr_status as u64);
            klog::write_raw(b"\n");
        }
        if p.q1_notify_va != 0 {
            klog::write_raw(b"[INFO]  virtio-tx ");
            klog::write_dec_u64(bdf.bus as u64);
            klog::write_raw(b":");
            klog::write_dec_u64(bdf.device as u64);
            klog::write_raw(b".");
            klog::write_dec_u64(bdf.function as u64);
            klog::write_raw(b" q1_notify_off=");
            klog::write_dec_u64(p.q1_notify_off as u64);
            klog::write_raw(b" q1_notify_va=");
            klog::write_hex_u64(p.q1_notify_va);
            klog::write_raw(b" tx_used_idx=");
            klog::write_dec_u64(p.tx_used_idx as u64);
            klog::write_raw(b"\n");
        }
        if p.q0_notify_va != 0 {
            klog::write_raw(b"[INFO]  virtio-notify ");
            klog::write_dec_u64(bdf.bus as u64);
            klog::write_raw(b":");
            klog::write_dec_u64(bdf.device as u64);
            klog::write_raw(b".");
            klog::write_dec_u64(bdf.function as u64);
            klog::write_raw(b" q=0 off=");
            klog::write_hex_u64(p.q0_notify_off as u64);
            klog::write_raw(b" va=");
            klog::write_hex_u64(p.q0_notify_va);
            klog::write_raw(b" post_status=");
            klog::write_hex_u64(p.post_notify_status as u64);
            klog::write_raw(b"\n");
        }
        //: read back queue_msix_vector (high u16 of dword at 0x18)
        // and report MSI delivery count seen by the IRQ dispatcher.
        // SAFETY: cfg_va Device-attr mapped during init; aligned u32 read.
        let qmv_word = unsafe {
            core::ptr::read_volatile((p.cfg_va + 0x18) as *const u32)
        };
        let qmv = (qmv_word >> 16) as u16;
        let fires = msi::MSI_FIRES.load(core::sync::atomic::Ordering::Acquire);
        klog::write_raw(b"[INFO]  virtio-msix ");
        klog::write_dec_u64(bdf.bus as u64);
        klog::write_raw(b":");
        klog::write_dec_u64(bdf.device as u64);
        klog::write_raw(b".");
        klog::write_dec_u64(bdf.function as u64);
        klog::write_raw(b" q0_msix_vec=");
        klog::write_hex_u64(qmv as u64);
        klog::write_raw(b" msi_fires=");
        klog::write_dec_u64(fires as u64);
        klog::write_raw(b"\n");
        if p.q0_desc_pa != 0 {
            klog::write_raw(b"[INFO]  virtio-q0-prog ");
            klog::write_dec_u64(bdf.bus as u64);
            klog::write_raw(b":");
            klog::write_dec_u64(bdf.device as u64);
            klog::write_raw(b".");
            klog::write_dec_u64(bdf.function as u64);
            klog::write_raw(b" desc_pa=");
            klog::write_hex_u64(p.q0_desc_pa);
            klog::write_raw(b" driver_pa=");
            klog::write_hex_u64(p.q0_driver_pa);
            klog::write_raw(b" device_pa=");
            klog::write_hex_u64(p.q0_device_pa);
            klog::write_raw(b" final_status=");
            klog::write_hex_u64(p.final_status as u64);
            klog::write_raw(b"\n");
        }
    }
    // F59-01: hand persistent runtime state for the modern virtio-net
    // device to dev_virtio_net so later phases (RX poll, TX, ARP) can
    // drive the queues post-boot. Only register if the device reached
    // virtio-gpu post-init: submit CMD_GET_DISPLAY_INFO over CTRLQ.
    let is_virtio_gpu_post = d.vendor_id == 0x1AF4 && d.device_id == 0x1050;
    if is_virtio_gpu_post
        && (p.final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0
        && p.q0_desc_pa != 0
        && p.q0_notify_va != 0
    {
        // SAFETY: caller is boot path; PMM up; q0 + notify VAs valid; single-CPU.
        let _ = unsafe {
            drv_virtio_gpu::post_init::get_display_info(
                bdf.bus, bdf.device, bdf.function,
                p.drv_features,
                p.q0_desc_pa, p.q0_driver_pa, p.q0_device_pa,
                p.q0_notify_va,
            )
        };
    }

    // DRIVER_OK with both queues programmed; ring PAs and notify VAs
    // are required for the runtime path.
    let is_virtio_net = d.vendor_id == 0x1AF4
        && (d.device_id == 0x1000 || d.device_id == 0x1041);
    if is_virtio_net
        && (p.final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0
        && p.q0_desc_pa != 0
        && p.q1_desc_pa != 0
        && p.q0_notify_va != 0
        && p.q1_notify_va != 0
    {
        crate::dev_virtio_net_modern::init_modern(
            crate::dev_virtio_net_modern::ModernNetState {
                bus:      bdf.bus,
                device:   bdf.device,
                function: bdf.function,
                cfg_va:        p.cfg_va,
                q0_notify_va:  p.q0_notify_va,
                q1_notify_va:  p.q1_notify_va,
                q0_desc_pa:    p.q0_desc_pa,
                q0_driver_pa:  p.q0_driver_pa,
                q0_device_pa:  p.q0_device_pa,
                q1_desc_pa:    p.q1_desc_pa,
                q1_driver_pa:  p.q1_driver_pa,
                q1_device_pa:  p.q1_device_pa,
                q0_size:       p.q0_size,
                q1_size:       p.q1_size,
                rx0_buf_pa:    p.rx0_buf_pa,
                rx0_buf_len:   p.rx0_buf_len,
                mac:           p.mac,
                mac_valid:     p.mac_valid,
                tx0_buf_pa:    p.tx0_buf_pa,
            },
        );
    }
}
