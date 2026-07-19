use super::*;

/// Submit `CMD_GET_DISPLAY_INFO` on q0; spin-poll used.idx for
/// completion; parse the response and re-install the device with
/// real DisplayInfo.
/// # C: O(spin-poll bound = 1e6)
pub fn get_display_info(
    device_key: virtio::VirtioChildDeviceKey,
    bdf_bus: u8, bdf_dev: u8, bdf_fn: u8,
    parent_bus: &'static str,
    parent_addr: String,
    drv_features: u64,
    resources: virtio::VirtioResources,
) -> bool {
    let Some(ctrlq) = resources.require_queue(0) else { return false };
    let Some(cursorq) = resources.require_queue(1) else { return false };
    if !resources.common_cfg_valid() {
        return false;
    }
    let cfg_va = resources.cfg_va;
    let hhdm = resources.hhdm;
    let mut cmd_buf = match ProbeCommandBuffer::alloc(hhdm) {
        Some(buf) => buf,
        None => return false,
    };
    unsafe {
        for i in 0..0x1000usize { core::ptr::write_volatile(cmd_buf.va.add(i), 0); }
        let req = core::slice::from_raw_parts_mut(cmd_buf.va, 24);
        crate::encode_get_display_info(req);
    }
    let desc0 = (hhdm.wrapping_add(ctrlq.desc_pa)) as *mut u64;
    unsafe {
        core::ptr::write_volatile(desc0.add(0), cmd_buf.pa);
        let d0 = 24u64
               | ((virtio::VRING_DESC_F_NEXT as u64) << 32)
               | (1u64 << 48);
        core::ptr::write_volatile(desc0.add(1), d0);
        core::ptr::write_volatile(desc0.add(2), cmd_buf.pa + 0x200);
        let d1 = 408u64 | ((virtio::VRING_DESC_F_WRITE as u64) << 32);
        core::ptr::write_volatile(desc0.add(3), d1);
    }
    let avail = (hhdm.wrapping_add(ctrlq.driver_pa)) as *mut u16;
    unsafe { core::ptr::write_volatile(avail.add(2), 0u16); }
    core::sync::atomic::fence(Ordering::Release);
    unsafe { core::ptr::write_volatile(avail.add(1), 1u16); }
    core::sync::atomic::fence(Ordering::Release);
    unsafe { core::ptr::write_volatile(ctrlq.notify_va as *mut u16, ctrlq.index); }
    let used = (hhdm.wrapping_add(ctrlq.device_pa)) as *mut u16;
    let mut polls = 0u32;
    loop {
        let idx = unsafe { core::ptr::read_volatile(used.add(1)) };
        if idx >= 1 || polls > 1_000_000 { break; }
        polls += 1;
        core::hint::spin_loop();
    }
    core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
    let resp_slice = unsafe {
        core::slice::from_raw_parts(cmd_buf.va.add(0x200) as *const u8, 408)
    };
    let info = match crate::parse_display_info(resp_slice) {
        Ok(i)  => i,
        Err(_) => return false,
    };
    use core::sync::atomic::{AtomicU32, AtomicU64};
    let bdf_word = (bdf_bus as u32) << 16
                 | (bdf_dev as u32) << 8
                 | (bdf_fn as u32);
    #[cfg(feature = "debug-boot")]
    {
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
    if info.count_enabled > 0 {
        let scanout_ok = unsafe {
            setup_scanout(
                device_key,
                bdf_word,
                info.modes[0].r.width, info.modes[0].r.height,
                cfg_va, ctrlq, cursorq, cmd_buf.va, cmd_buf.pa, hhdm,
            )
        };
        if !scanout_ok {
            return false;
        }
        cmd_buf.disarm();
    }
    match crate::install_with_drm_parent(crate::VirtioGpuDev {
        device_key, bdf: bdf_word, card_id: 0, cfg_va,
        ctrlq, cursorq,
        features_negotiated: drv_features,
        display: info,
        resource_id_alloc: AtomicU32::new(1),
        blob_uuid_alloc: AtomicU64::new(1), capset_count: 0,
    }, Some((parent_bus, parent_addr))) {
        Ok(_) => {}
        Err(_) => {
            if info.count_enabled > 0 {
                let _ = uninstall_scanout_after_failed_probe(device_key);
            }
            return false;
        }
    }
    publish_console_scanout(device_key);
    true
}

/// Allocate a backing fb and bind it to scanout 0, then flush to the host.
/// # SAFETY: caller is the boot path; queue + notify VAs valid; PMM up.
unsafe fn setup_scanout(
    device_key: virtio::VirtioChildDeviceKey,
    bdf: u32,
    w: u32, h: u32,
    cfg_va: u64,
    ctrlq: virtio::VirtQueueResource,
    cursorq: virtio::VirtQueueResource,
    cmd_buf_va: *mut u8, cmd_buf_pa: u64,
    hhdm: u64,
) -> bool {
    let pitch = w as u64 * 4;
    let fb_bytes = pitch * h as u64;
    let pages_req = ((fb_bytes + 0xFFF) / 0x1000) as usize;
    if pages_req == 0 { return false; }
    let mut order: u32 = 0;
    while (1usize << order) < pages_req { order += 1; }
    let mut fb_run = match ProbeFramebufferRun::alloc(order as u8) {
        Some(run) => run,
        None => return false,
    };
    let base_pa = fb_run.base_pa;
    let pages_alloc = fb_run.pages_alloc;
    {
        let mut console = fbcon::Console::new(w, h);
        console.fg = [0xff, 0xff, 0xff];
        console.bg = [0x10, 0x30, 0x80];
        let pitch = (w * 4) as usize;
        for y in 0..(h as usize) {
            let off = y * pitch;
            for x in 0..(w as usize) {
                console.fb[off + x*4]     = console.bg[2];
                console.fb[off + x*4 + 1] = console.bg[1];
                console.fb[off + x*4 + 2] = console.bg[0];
                console.fb[off + x*4 + 3] = 0xff;
            }
        }
        console.put(b"oxide kernel ready\n");
        console.put(b"virtio-gpu scanout active\n");
        let va = hhdm.wrapping_add(base_pa) as *mut u8;
        let n = fb_bytes as usize;
        unsafe {
            let src = console.fb.as_ptr();
            for j in 0..n.min(console.fb.len()) {
                core::ptr::write_volatile(va.add(j), *src.add(j));
            }
        }
    }
    let res_id: u32 = 1;
    let log_resp = |tag: &[u8]| {
        #[cfg(feature = "debug-boot")]
        {
            let resp = unsafe { core::ptr::read_volatile(cmd_buf_va.add(0x200) as *const u32) };
            klog::write_raw(b"[INFO]  virtio-gpu resp ");
            klog::write_raw(tag);
            klog::write_raw(b"=");
            klog::write_hex_u64(resp as u64);
            klog::write_raw(b"\n");
        }
        #[cfg(not(feature = "debug-boot"))]
        let _ = tag;
    };
    if unsafe { !submit_one(cmd_buf_va, cmd_buf_pa,
        |buf| crate::encode_resource_create_2d(buf, res_id,
            crate::VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM, w, h),
        ctrlq, hhdm,
    ) } {
        return false;
    }
    log_resp(b"create");
    if unsafe { !submit_one(cmd_buf_va, cmd_buf_pa,
        |buf| crate::encode_resource_attach_backing_one(
            buf, res_id, base_pa, fb_bytes as u32),
        ctrlq, hhdm,
    ) } {
        return false;
    }
    log_resp(b"attach");
    if unsafe { !submit_one(cmd_buf_va, cmd_buf_pa,
        |buf| crate::encode_set_scanout(buf, 0, res_id, 0, 0, w, h),
        ctrlq, hhdm,
    ) } {
        return false;
    }
    log_resp(b"setscanout");
    if unsafe { !submit_one(cmd_buf_va, cmd_buf_pa,
        |buf| crate::encode_transfer_to_host_2d(buf, res_id, 0, 0, w, h, 0),
        ctrlq, hhdm,
    ) } {
        return false;
    }
    log_resp(b"transfer");
    if unsafe { !submit_one(cmd_buf_va, cmd_buf_pa,
        |buf| crate::encode_resource_flush(buf, res_id, 0, 0, w, h),
        ctrlq, hhdm,
    ) } {
        return false;
    }
    log_resp(b"flush");
    if !install_scanout_ctx(
        device_key,
        bdf,
        w, h,
        cfg_va, hhdm.wrapping_add(base_pa), fb_bytes, pages_alloc, res_id,
        ctrlq, cursorq, cmd_buf_va as u64, cmd_buf_pa, hhdm,
    ) {
        return false;
    }
    fb_run.disarm();
    #[cfg(feature = "debug-boot")]
    {
        klog::write_raw(b"[INFO]  virtio-gpu scanout: ");
        klog::write_dec_u64(w as u64);
        klog::write_raw(b"x");
        klog::write_dec_u64(h as u64);
        klog::write_raw(b" pages=");
        klog::write_dec_u64(pages_req as u64);
        klog::write_raw(b" painted\n");
    }
    true
}

/// Submit a single CTRLQ command via the encoder closure.
pub(super) unsafe fn submit_one<F: FnOnce(&mut [u8]) -> usize>(
    buf_va: *mut u8, buf_pa: u64, encode: F,
    ctrlq: virtio::VirtQueueResource, hhdm: u64,
) -> bool {
    unsafe {
        for k in 0..0x100usize { core::ptr::write_volatile(buf_va.add(k), 0); }
        for k in 0x200..0x230usize { core::ptr::write_volatile(buf_va.add(k), 0); }
        let req = core::slice::from_raw_parts_mut(buf_va, 0x100);
        let _ = encode(req);
    }
    unsafe { submit_raw(buf_pa, 64, ctrlq, hhdm) }
}

unsafe fn submit_raw(
    buf_pa: u64, req_len: usize,
    ctrlq: virtio::VirtQueueResource, hhdm: u64,
) -> bool {
    let desc0 = (hhdm.wrapping_add(ctrlq.desc_pa)) as *mut u64;
    unsafe {
        core::ptr::write_volatile(desc0.add(0), buf_pa);
        let d0 = req_len as u64
               | ((virtio::VRING_DESC_F_NEXT as u64) << 32)
               | (1u64 << 48);
        core::ptr::write_volatile(desc0.add(1), d0);
        core::ptr::write_volatile(desc0.add(2), buf_pa + 0x200);
        let d1 = 24u64 | ((virtio::VRING_DESC_F_WRITE as u64) << 32);
        core::ptr::write_volatile(desc0.add(3), d1);
    }
    let avail = (hhdm.wrapping_add(ctrlq.driver_pa)) as *mut u16;
    let cur_idx = unsafe { core::ptr::read_volatile(avail.add(1)) };
    unsafe { core::ptr::write_volatile(avail.add(2 + (cur_idx as usize % ctrlq.size as usize)), 0u16); }
    core::sync::atomic::fence(Ordering::Release);
    unsafe { core::ptr::write_volatile(avail.add(1), cur_idx + 1); }
    core::sync::atomic::fence(Ordering::Release);
    unsafe { core::ptr::write_volatile(ctrlq.notify_va as *mut u16, ctrlq.index); }
    let used = (hhdm.wrapping_add(ctrlq.device_pa)) as *mut u16;
    let want = cur_idx + 1;
    let mut polls = 0u32;
    loop {
        let idx = unsafe { core::ptr::read_volatile(used.add(1)) };
        if idx >= want || polls > 1_000_000 { break; }
        polls += 1;
        core::hint::spin_loop();
    }
    polls <= 1_000_000
}
