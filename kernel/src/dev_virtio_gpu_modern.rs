// virtio-gpu modern post-init: submit CMD_GET_DISPLAY_INFO over
// CTRLQ to populate real DisplayInfo. Called from
// `pci_boot::virtio_probe_arch` when the device id matches.

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;

/// Submit `CMD_GET_DISPLAY_INFO` on q0; spin-poll used.idx for
/// completion; parse the response and re-install the device with
/// real DisplayInfo (which propagates to `47` DRM/KMS via the
/// `VirtioGpuDrm` impl).
/// # SAFETY: caller is the boot path; PMM up; q0/notify VAs valid;
///   single-CPU; IRQs masked.
/// # C: O(spin-poll bound = 1e6)
pub unsafe fn get_display_info(
    bdf_bus: u8, bdf_dev: u8, bdf_fn: u8,
    drv_features: u64,
    q0_desc_pa: u64,
    q0_driver_pa: u64,
    q0_device_pa: u64,
    q0_notify_va: u64,
) -> bool {
    let hhdm = {
        #[cfg(target_arch = "x86_64")]
        { hal_x86_64::mmu_ops::hhdm_offset() }
        #[cfg(target_arch = "aarch64")]
        { hal_aarch64::mmu_ops::hhdm_offset() }
    };
    if hhdm == 0 { return false; }
    let buf_pa = match crate::pmm_setup::alloc_one_frame() {
        Some(pa) => pa, None => return false,
    };
    let buf_va = hhdm.wrapping_add(buf_pa) as *mut u8;
    // SAFETY: HHDM-mapped frame; aligned writes within 4 KiB; sole writer at boot.
    unsafe {
        for i in 0..0x1000usize { core::ptr::write_volatile(buf_va.add(i), 0); }
        let req = core::slice::from_raw_parts_mut(buf_va, 24);
        drv_virtio_gpu::encode_get_display_info(req);
    }
    let desc0 = (hhdm.wrapping_add(q0_desc_pa)) as *mut u64;
    // SAFETY: HHDM-mapped virtio q0 descriptor table; aligned u64 stores into driver-owned frame.
    unsafe {
        core::ptr::write_volatile(desc0.add(0), buf_pa);
        let d0 = 24u64
               | ((virtio::VRING_DESC_F_NEXT as u64) << 32)
               | (1u64 << 48);
        core::ptr::write_volatile(desc0.add(1), d0);
        core::ptr::write_volatile(desc0.add(2), buf_pa + 0x200);
        let d1 = 408u64 | ((virtio::VRING_DESC_F_WRITE as u64) << 32);
        core::ptr::write_volatile(desc0.add(3), d1);
    }
    let avail = (hhdm.wrapping_add(q0_driver_pa)) as *mut u16;
    // SAFETY: HHDM-mapped avail ring; aligned u16 stores within driver-owned frame.
    unsafe { core::ptr::write_volatile(avail.add(2), 0u16); }
    core::sync::atomic::fence(Ordering::Release);
    // SAFETY: same avail ring; idx at u16 offset 1.
    unsafe { core::ptr::write_volatile(avail.add(1), 1u16); }
    core::sync::atomic::fence(Ordering::Release);
    // SAFETY: q0_notify_va mapped Device-attr; queue idx written per virtio 1.2 §4.1.5.2.
    unsafe { core::ptr::write_volatile(q0_notify_va as *mut u16, 0u16); }
    let used = (hhdm.wrapping_add(q0_device_pa)) as *mut u16;
    let mut polls = 0u32;
    loop {
        // SAFETY: HHDM-mapped used ring; aligned u16 read.
        let idx = unsafe { core::ptr::read_volatile(used.add(1)) };
        if idx >= 1 || polls > 1_000_000 { break; }
        polls += 1;
        core::hint::spin_loop();
    }
    // SAFETY: same HHDM-mapped frame; bounded 408-byte slice for parser.
    let resp_slice = unsafe {
        core::slice::from_raw_parts(buf_va.add(0x200) as *const u8, 408)
    };
    let info = match drv_virtio_gpu::parse_display_info(resp_slice) {
        Ok(i)  => i,
        Err(_) => return false,
    };
    use core::sync::atomic::{AtomicU32, AtomicU64};
    let bdf_word = (bdf_bus as u32) << 16
                 | (bdf_dev as u32) << 8
                 | (bdf_fn as u32);
    drv_virtio_gpu::install_with_drm(drv_virtio_gpu::VirtioGpuDev {
        bdf: bdf_word, features_negotiated: drv_features,
        display: info,
        resource_id_alloc: AtomicU32::new(1),
        blob_uuid_alloc: AtomicU64::new(1), capset_count: 0,
    });
    debug_boot! {
        klog::write_raw(b"[INFO]  virtio-gpu display: enabled=");
        klog::write_dec_u64(info.count_enabled as u64);
        if info.count_enabled > 0 {
            klog::write_raw(b" mode0=");
            klog::write_dec_u64(info.modes[0].r.width as u64);
            klog::write_raw(b"x");
            klog::write_dec_u64(info.modes[0].r.height as u64);
        }
        klog::write_raw(b"\n");
    }
    true
}
