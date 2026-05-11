// virtio-gpu modern post-init: submit CMD_GET_DISPLAY_INFO over
// CTRLQ to populate real DisplayInfo. Called from
// `pci_boot::virtio_probe_arch` when the device id matches.



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
    let buf_pa = match pmm::setup::alloc_one_frame() {
        Some(pa) => pa, None => return false,
    };
    let buf_va = hhdm.wrapping_add(buf_pa) as *mut u8;
    // SAFETY: HHDM-mapped frame; aligned writes within 4 KiB; sole writer at boot.
    unsafe {
        for i in 0..0x1000usize { core::ptr::write_volatile(buf_va.add(i), 0); }
        let req = core::slice::from_raw_parts_mut(buf_va, 24);
        crate::encode_get_display_info(req);
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
    let info = match crate::parse_display_info(resp_slice) {
        Ok(i)  => i,
        Err(_) => return false,
    };
    use core::sync::atomic::{AtomicU32, AtomicU64};
    let bdf_word = (bdf_bus as u32) << 16
                 | (bdf_dev as u32) << 8
                 | (bdf_fn as u32);
    crate::install_with_drm(crate::VirtioGpuDev {
        bdf: bdf_word, features_negotiated: drv_features,
        display: info,
        resource_id_alloc: AtomicU32::new(1),
        blob_uuid_alloc: AtomicU64::new(1), capset_count: 0,
    });
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
        // SAFETY: boot path; queue + notify VAs valid; PMM up.
        let _ = unsafe {
            setup_scanout(
                info.modes[0].r.width, info.modes[0].r.height,
                q0_desc_pa, q0_driver_pa, q0_device_pa, q0_notify_va,
                buf_va, buf_pa,
            )
        };
    }
    true
}

/// Allocate a backing fb (RESOURCE_CREATE_2D) + attach a contiguous
/// PMM region as the backing storage + bind it to scanout 0
/// (SET_SCANOUT) + transfer + flush so the host displays the buffer.
/// Paints a solid fill to validate the pipeline end-to-end.
/// # SAFETY: caller is the boot path; queue + notify VAs valid; PMM up.
/// # C: O(width * height) for the fill + O(1) per command.
unsafe fn setup_scanout(
    w: u32, h: u32,
    q0_desc_pa: u64, q0_driver_pa: u64, q0_device_pa: u64, q0_notify_va: u64,
    cmd_buf_va: *mut u8, cmd_buf_pa: u64,
) -> bool {
    let hhdm = {
        #[cfg(target_arch = "x86_64")]
        { hal_x86_64::mmu_ops::hhdm_offset() }
        #[cfg(target_arch = "aarch64")]
        { hal_aarch64::mmu_ops::hhdm_offset() }
    };
    let pitch = w as u64 * 4;
    let fb_bytes = pitch * h as u64;
    let pages_req = ((fb_bytes + 0xFFF) / 0x1000) as usize;
    if pages_req == 0 { return false; }
    // Allocate the FB as ONE contig run via the PMM buddy allocator.
    // Order = ceil_log2(pages_req); 1.92 MiB at 800×600 = 480 pages
    // → order 9 (512 pages = 2 MiB).
    let mut order: u32 = 0;
    while (1usize << order) < pages_req { order += 1; }
    let base_pa = match pmm::setup::alloc_contig(pmm::Order(order as u8)) {
        Some(pa) => pa, None => return false,
    };
    let _ = 1usize << order; // pages_alloc — informational only
    // Render a boot banner through fbcon and copy the result into
    // the virtio-gpu backing FB. Userspace sees rendered text on
    // the QEMU display immediately at boot.
    {
        let mut console = fbcon::Console::new(w, h);
        console.fg = [0xff, 0xff, 0xff];
        console.bg = [0x00, 0x10, 0x40];
        // EraseDisplay first to fill background.
        console.put(b"\x1b[2J\x1b[H");
        console.put(b"oxide kernel ready\n");
        console.put(b"virtio-gpu scanout active\n");
        let va = hhdm.wrapping_add(base_pa) as *mut u8;
        let n = fb_bytes as usize;
        // SAFETY: HHDM-mapped contig run of pages_req * 4 KiB; bounded copy of n bytes ≤ that span.
        unsafe {
            let src = console.fb.as_ptr();
            for j in 0..n.min(console.fb.len()) {
                core::ptr::write_volatile(va.add(j), *src.add(j));
            }
        }
    }
    let res_id: u32 = 1;
    // Helper: emit the 24-byte response type so failed commands are
    // visible. virtio-gpu acks with VIRTIO_GPU_RESP_OK_NODATA (0x1100);
    // anything else means the host rejected the request.
    let log_resp = |tag: &[u8]| {
        // SAFETY: cmd_buf_va is HHDM-mapped 4 KiB; response sits at
        // cmd_buf_va + 0x200 per submit_raw's descriptor layout.
        let resp = unsafe { core::ptr::read_volatile(cmd_buf_va.add(0x200) as *const u32) };
    #[cfg(feature = "debug-boot")]
        {
            klog::write_raw(b"[INFO]  virtio-gpu resp ");
            klog::write_raw(tag);
            klog::write_raw(b"=");
            klog::write_hex_u64(resp as u64);
            klog::write_raw(b"\n");
        }
    };
    // ---- 1. CMD_RESOURCE_CREATE_2D (40 B request, 24 B response) ----
    // SAFETY: caller's preconditions inherited; we hold the boot-path single-CPU invariants.
    if unsafe { !submit_one(cmd_buf_va, cmd_buf_pa,
        |buf| crate::encode_resource_create_2d(buf, res_id,
            crate::VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM, w, h),
        q0_desc_pa, q0_driver_pa, q0_device_pa, q0_notify_va, hhdm,
    ) } { return false; }
    log_resp(b"create");
    // ---- 2. CMD_RESOURCE_ATTACH_BACKING with ONE mem-entry ----
    // The FB lives in a SINGLE contiguous PMM run (alloc_contig
    // above), so we attach it as one mem-entry covering the full
    // fb_bytes span. The previous N-entries-per-page path wrote
    // 32 + N*16 bytes into a 4 KiB cmd_buf (~16 KiB at 1280×800,
    // ~7.5 KiB at 800×600) — overflowed the buffer and the device
    // read garbage mem-entry tables from whatever frame followed
    // cmd_buf in physmem, so the attach silently bound the wrong
    // backing pages and the host saw an all-zero scanout.
    // SAFETY: caller's preconditions inherited; encode writes 48 B
    // into the per-call slice we hand it; submit_raw advertises the
    // request as 48 bytes.
    if unsafe { !submit_one(cmd_buf_va, cmd_buf_pa,
        |buf| crate::encode_resource_attach_backing_one(
            buf, res_id, base_pa, fb_bytes as u32),
        q0_desc_pa, q0_driver_pa, q0_device_pa, q0_notify_va, hhdm,
    ) } { return false; }
    log_resp(b"attach");
    // ---- 3. CMD_SET_SCANOUT ----
    // SAFETY: caller's preconditions inherited; we hold the boot-path single-CPU invariants.
    if unsafe { !submit_one(cmd_buf_va, cmd_buf_pa,
        |buf| crate::encode_set_scanout(buf, 0, res_id, 0, 0, w, h),
        q0_desc_pa, q0_driver_pa, q0_device_pa, q0_notify_va, hhdm,
    ) } { return false; }
    log_resp(b"setscanout");
    // ---- 4. CMD_TRANSFER_TO_HOST_2D ----
    // SAFETY: caller's preconditions inherited; we hold the boot-path single-CPU invariants.
    if unsafe { !submit_one(cmd_buf_va, cmd_buf_pa,
        |buf| crate::encode_transfer_to_host_2d(buf, res_id, 0, 0, w, h, 0),
        q0_desc_pa, q0_driver_pa, q0_device_pa, q0_notify_va, hhdm,
    ) } { return false; }
    log_resp(b"transfer");
    // ---- 5. CMD_RESOURCE_FLUSH ----
    // SAFETY: caller's preconditions inherited; we hold the boot-path single-CPU invariants.
    if unsafe { !submit_one(cmd_buf_va, cmd_buf_pa,
        |buf| crate::encode_resource_flush(buf, res_id, 0, 0, w, h),
        q0_desc_pa, q0_driver_pa, q0_device_pa, q0_notify_va, hhdm,
    ) } { return false; }
    log_resp(b"flush");
    // Stash scanout context so the kernel-side fbcon klog sink can
    // repaint after boot. base_pa is the contig PMM run; HHDM-map
    // it to a kernel VA for byte-copy access.
    install_scanout_ctx(
        w, h,
        hhdm.wrapping_add(base_pa), fb_bytes, res_id,
        q0_desc_pa, q0_driver_pa, q0_device_pa, q0_notify_va,
        cmd_buf_va as u64, cmd_buf_pa, hhdm,
    );
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
/// 2-descriptor chain (req-out / resp-in 24 B). Returns true on
/// successful round-trip.
unsafe fn submit_one<F: FnOnce(&mut [u8]) -> usize>(
    buf_va: *mut u8, buf_pa: u64, encode: F,
    q0_desc_pa: u64, q0_driver_pa: u64, q0_device_pa: u64, q0_notify_va: u64,
    hhdm: u64,
) -> bool {
    // SAFETY: HHDM-mapped 4 KiB buffer; bounded zero of 0x100 + write of <0x100 B encoded request.
    unsafe {
        for k in 0..0x100usize { core::ptr::write_volatile(buf_va.add(k), 0); }
        for k in 0x200..0x230usize { core::ptr::write_volatile(buf_va.add(k), 0); }
        let req = core::slice::from_raw_parts_mut(buf_va, 0x100);
        let _ = encode(req);
    }
    // First descriptor sees the request length encoded as 0x100 max
    // (every encoder we call writes < 64 B). For exact length we
    // could parse it; using 64 B is enough for all encoders in the
    // arc so far per `45§5`.
    // SAFETY: cmd buffer + queue VAs valid by caller's contract.
    unsafe { submit_raw(buf_pa, 64, q0_desc_pa, q0_driver_pa, q0_device_pa, q0_notify_va, hhdm) }
}

/// Submit a request of length `req_len` followed by a 24-byte
/// response slot. Polls used.idx for completion.
unsafe fn submit_raw(
    buf_pa: u64, req_len: usize,
    q0_desc_pa: u64, q0_driver_pa: u64, q0_device_pa: u64, q0_notify_va: u64,
    hhdm: u64,
) -> bool {
    let desc0 = (hhdm.wrapping_add(q0_desc_pa)) as *mut u64;
    // SAFETY: HHDM-mapped virtio q0 descriptor table; aligned u64 stores into the driver-owned frame.
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
    let avail = (hhdm.wrapping_add(q0_driver_pa)) as *mut u16;
    // Read current avail.idx to know where to write the next ring slot.
    // SAFETY: HHDM-mapped avail ring; aligned u16 read of avail.idx then write of next slot.
    let cur_idx = unsafe { core::ptr::read_volatile(avail.add(1)) };
    // SAFETY: avail.ring is u16 ring of size N (>=256); cur_idx is a wrapping index used per virtio spec.
    unsafe { core::ptr::write_volatile(avail.add(2 + (cur_idx as usize % 256)), 0u16); }
    core::sync::atomic::fence(Ordering::Release);
    // SAFETY: same avail ring; idx at u16 offset 1.
    unsafe { core::ptr::write_volatile(avail.add(1), cur_idx + 1); }
    core::sync::atomic::fence(Ordering::Release);
    // SAFETY: notify VA mapped Device-attr; queue idx written per virtio 1.2 §4.1.5.2.
    unsafe { core::ptr::write_volatile(q0_notify_va as *mut u16, 0u16); }
    let used = (hhdm.wrapping_add(q0_device_pa)) as *mut u16;
    let want = cur_idx + 1;
    let mut polls = 0u32;
    loop {
        // SAFETY: HHDM-mapped used ring; aligned u16 read.
        let idx = unsafe { core::ptr::read_volatile(used.add(1)) };
        if idx >= want || polls > 1_000_000 { break; }
        polls += 1;
        core::hint::spin_loop();
    }
    polls <= 1_000_000
}


// ---- Persistent scanout state for ongoing fbcon flush (B07) ------
// After setup_scanout succeeds, save the context so the kernel-side
// fbcon driver can push klog text to the FB via transfer + flush
// after boot. Single scanout; single resource (res_id=1); single CPU
// caller at boot installs it, repeated callers from klog stream
// share via the Spinlock.

use sync::{TaskList as DriverLockClass, Spinlock};

struct ScanoutCtx {
    w: u32,
    h: u32,
    fb_va: u64,          // HHDM-mapped backing FB
    fb_bytes: u64,
    res_id: u32,
    q0_desc_pa: u64,
    q0_driver_pa: u64,
    q0_device_pa: u64,
    q0_notify_va: u64,
    cmd_buf_va: u64,
    cmd_buf_pa: u64,
    hhdm: u64,
}

static CTX: Spinlock<Option<ScanoutCtx>, DriverLockClass> = Spinlock::new(None);

/// Copy `pixels` into the live framebuffer, then issue
/// transfer_to_host_2d + resource_flush so the host repaints the
/// display. Called from the fbcon kernel klog sink for every
/// emitted record. Drops silently if scanout state isn't installed.
/// # C: O(fb_bytes) copy + O(1) per submit.
pub fn fbcon_flush_pixels(pixels: &[u8]) {
    let g = CTX.lock();
    let ctx = match g.as_ref() { Some(c) => c, None => return };
    let n = (ctx.fb_bytes as usize).min(pixels.len());
    // SAFETY: ctx.fb_va is HHDM-mapped for fb_bytes; bounded copy of n ≤ fb_bytes; CPL=0 writes through HHDM mapping.
    unsafe {
        let dst = ctx.fb_va as *mut u8;
        for i in 0..n {
            core::ptr::write_volatile(dst.add(i), pixels[i]);
        }
    }
    let cmd_buf_va_p = ctx.cmd_buf_va as *mut u8;
    let res_id = ctx.res_id;
    let w = ctx.w; let h = ctx.h;
    // SAFETY: cmd_buf_va_p is HHDM-mapped 4 KiB scratch; q0 descriptors and notify_va are the same VAs setup_scanout used; we are the sole writer for the duration of the lock.
    unsafe {
        let _ = submit_one(cmd_buf_va_p, ctx.cmd_buf_pa,
            |buf| crate::encode_transfer_to_host_2d(buf, res_id, 0, 0, w, h, 0),
            ctx.q0_desc_pa, ctx.q0_driver_pa, ctx.q0_device_pa,
            ctx.q0_notify_va, ctx.hhdm);
        let _ = submit_one(cmd_buf_va_p, ctx.cmd_buf_pa,
            |buf| crate::encode_resource_flush(buf, res_id, 0, 0, w, h),
            ctx.q0_desc_pa, ctx.q0_driver_pa, ctx.q0_device_pa,
            ctx.q0_notify_va, ctx.hhdm);
    }
}

/// Install the scanout context for later flushes. Called once from
/// `setup_scanout` after the resource is created and attached.
fn install_scanout_ctx(
    w: u32, h: u32, fb_va: u64, fb_bytes: u64, res_id: u32,
    q0_desc_pa: u64, q0_driver_pa: u64, q0_device_pa: u64, q0_notify_va: u64,
    cmd_buf_va: u64, cmd_buf_pa: u64, hhdm: u64,
) {
    *CTX.lock() = Some(ScanoutCtx {
        w, h, fb_va, fb_bytes, res_id,
        q0_desc_pa, q0_driver_pa, q0_device_pa, q0_notify_va,
        cmd_buf_va, cmd_buf_pa, hhdm,
    });
}

/// True iff the scanout context is installed (post-`setup_scanout`).
/// # C: O(1)
pub fn scanout_ready() -> bool { CTX.lock().is_some() }

/// Read back the scanout dimensions. Used by the kernel's fbcon
/// klog wiring to size its Console.
/// # C: O(1)
pub fn dimensions() -> Option<(u32, u32)> {
    CTX.lock().as_ref().map(|c| (c.w, c.h))
}
