use super::*;

/// Spin iterations a probe-time submission waits for the device to retire its
/// descriptor. Exceeding it means the descriptor is still device-owned, so the
/// command frame must be leaked rather than freed or reused.
const SUBMIT_POLL_BUDGET: u32 = 1_000_000;

/// Submit `CMD_GET_DISPLAY_INFO` on q0; spin-poll used.idx for
/// completion; parse the response and re-install the device with
/// real DisplayInfo.
/// # C: O(spin-poll bound = 1e6)
pub fn get_display_info(
    device_key: virtio::VirtioChildDeviceKey,
    bdf_bus: u8, bdf_dev: u8, bdf_fn: u8,
    parent: &alloc::sync::Arc<drv::Device>,
    drv_features: u64,
    resources: virtio::VirtioResources,
) -> bool {
    let Some(ctrlq) = resources.require_queue_at_least(0, 4) else { return false };
    let Some(cursorq) = resources.require_queue_at_least(1, 2) else { return false };
    if !resources.common_cfg_valid() {
        return false;
    }
    let cfg_va = resources.cfg_va;
    let hhdm = resources.hhdm;
    let mut cmd_buf = match ProbeCommandBuffer::alloc(hhdm) {
        Some(buf) => buf,
        None => return false,
    };
    // SAFETY: `cmd_buf.va` is the HHDM view of the single 4 KiB frame just
    // allocated by `ProbeCommandBuffer::alloc` and owned exclusively by this
    // probe; 0x1000 is exactly its length and the 24-byte request slice starts
    // at offset 0, so both stay inside. No descriptor references it yet.
    unsafe {
        for i in 0..0x1000usize { core::ptr::write_volatile(cmd_buf.va.add(i), 0); }
        let req = core::slice::from_raw_parts_mut(cmd_buf.va, 24);
        crate::encode_get_display_info(req);
    }
    let desc0 = (hhdm.wrapping_add(ctrlq.desc_pa)) as *mut u64;
    // SAFETY: `desc_pa` is the ctrlq descriptor frame via HHDM, holding at
    // least the two 16-byte entries written here (`program_queue` negotiates
    // `size` down to one frame's worth); descriptor 0 is the 24-byte request and
    // 1 the 408-byte reply at RESP_OFF, both inside the probe's command frame.
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
    // SAFETY: ctrlq avail frame via HHDM; slot 0 (`ring[0]` at u16 index 2) is
    // in bounds for any non-zero queue size, and this is the queue's first ever
    // use so no other producer contends for it.
    unsafe { core::ptr::write_volatile(avail.add(2), 0u16); }
    core::sync::atomic::fence(Ordering::Release);
    // SAFETY: same avail frame; `idx` is the aligned u16 at index 1, and the
    // Release fence above ordered the ring[0] store before this publish, which
    // is what hands descriptor head 0 to the device.
    unsafe { core::ptr::write_volatile(avail.add(1), 1u16); }
    core::sync::atomic::fence(Ordering::Release);
    // SAFETY: `notify_va` is ctrlq's doorbell in the Device-attr notify BAR
    // window, non-zero because `require_queue(0)` validated the resource; a u16
    // store of the queue index is its defined access (Virtio 1.2 §4.1.4.4).
    unsafe { core::ptr::write_volatile(ctrlq.notify_va as *mut u16, ctrlq.index); }
    let used = (hhdm.wrapping_add(ctrlq.device_pa)) as *mut u16;
    let mut polls = 0u32;
    let retired = loop {
        // SAFETY: ctrlq used frame via HHDM; `used.idx` is the aligned u16 at
        // index 1 (Virtio 1.2 §2.7.8), inside the frame for any queue size. The
        // volatile load re-reads the device's publish each iteration.
        let idx = unsafe { core::ptr::read_volatile(used.add(1)) };
        if idx >= 1 { break true; }
        if polls > SUBMIT_POLL_BUDGET { break false; }
        polls += 1;
        core::hint::spin_loop();
    };
    if !retired {
        // The device never retired the descriptor, so it may still write the
        // reply into this frame. Freeing it would hand a physical address the
        // device still DMAs into back to the buddy allocator (the B1339/B1340
        // class); leak it instead, exactly as the backing-store path does.
        cmd_buf.disarm();
        #[cfg(feature = "debug-boot")]
        { klog::write_raw(b"[VGPU] display-info timed out, leaking command frame\n"); }
        return false;
    }
    core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
    // Read-only view of DEVICE-written bytes; `parse_display_info` validates
    // every field it reads, so the contents stay untrusted.
    // SAFETY: RESP_OFF (0x200) + 408 is inside the probe's own 4 KiB command
    // frame, which outlives `resp_slice`; u8 needs no alignment. The poll saw
    // `used.idx` and the Acquire fence orders the device's writes before this.
    let resp_slice = unsafe {
        core::slice::from_raw_parts(cmd_buf.va.add(0x200) as *const u8, 408)
    };
    let info = match crate::parse_display_info(resp_slice) {
        Ok(i)  => i,
        Err(_) => return false,
    };
    // Fetch the display's EDID before the framebuffer takes over the command
    // frame. Optional by specification: a device that declines leaves the
    // connector without one and the probe carries on.
    let mut edid_timed_out = false;
    // SAFETY: this probe owns the command frame and CTRLQ exclusively, both VAs
    // are live, the frame is 4 KiB (≥ RESP_OFF + RESP_EDID_LEN = 0x200 + 1056),
    // and the display-info descriptor above was retired, so nothing else is in
    // flight on this queue — `fetch`'s documented contract.
    let edid = unsafe {
        super::edid::fetch(drv_features, cmd_buf.va, cmd_buf.pa, ctrlq, hhdm,
            &mut edid_timed_out)
    };
    if edid_timed_out {
        // Same reasoning as the display-info timeout: an unretired descriptor
        // leaves the device free to write into this frame later, so it may
        // neither be reused for the scanout commands nor returned to the PMM.
        cmd_buf.disarm();
        #[cfg(feature = "debug-boot")]
        { klog::write_raw(b"[VGPU] edid fetch timed out, leaking command frame\n"); }
        return false;
    }
    #[cfg(feature = "debug-boot")]
    {
        klog::write_raw(b"[INFO]  virtio-gpu edid: ");
        match edid.as_ref() {
            Some(bytes) => { klog::write_dec_u64(bytes.len() as u64); klog::write_raw(b" bytes\n"); }
            None => klog::write_raw(b"none\n"),
        }
    }
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
        // SAFETY: boot probe context — `require_queue` validated both queues and
        // `common_cfg_valid` the config window, the PMM is up (the command frame
        // came from it), and this probe holds the only reference to the command
        // frame and both queues for the duration of the call.
        let scanout_ok = unsafe {
            setup_scanout(
                device_key,
                info.modes[0].r.width, info.modes[0].r.height,
                cfg_va, ctrlq, cursorq, cmd_buf.va, cmd_buf.pa, hhdm,
            )
        };
        if !scanout_ok {
            // `setup_scanout` fails on a submit that the device never retired,
            // which leaves it free to write into the command frame afterwards.
            // Leak the frame rather than return a live DMA target to the PMM.
            cmd_buf.disarm();
            return false;
        }
        cmd_buf.disarm();
    }
    match crate::install_with_drm_parent(crate::VirtioGpuDev {
        device_key, bdf: bdf_word, card_id: 0, cfg_va,
        ctrlq, cursorq,
        features_negotiated: drv_features,
        display: info,
        edid,
        resource_id_alloc: AtomicU32::new(1),
        blob_uuid_alloc: AtomicU64::new(1), capset_count: 0,
    }, Some(parent)) {
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
    let fb_order = pmm::Order(order as u8);
    let mut fb_run = match ProbeFramebufferRun::alloc(fb_order) {
        Some(run) => run,
        None => return false,
    };
    let base_pa = fb_run.base_pa;
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
        // SAFETY: `va` is the HHDM view of the `alloc_contig(fb_order)` run just
        // allocated here, whose order was derived from `fb_bytes`, so the run
        // covers `n` bytes; the loop is additionally clamped to `console.fb`'s
        // length. No descriptor names this run yet, so the device cannot read it.
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
            // SAFETY: RESP_OFF (0x200) in the caller's 4 KiB command frame is a
            // 4-byte-aligned offset with 0xE00 bytes behind it, so this reads the
            // reply header's `type` word in bounds; the preceding `submit_one`
            // saw the descriptor retired, so the device is done writing it.
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
    // SAFETY: `submit_one`'s contract — this fn's own caller guarantees the
    // command frame is live and ≥ RESP_OFF + NODATA_RESP_LEN, CTRLQ's VAs are
    // valid, and the probe is single-threaded, so the previous submission was
    // already retired and no other producer touches the queue.
    if unsafe { !submit_one(cmd_buf_va, cmd_buf_pa,
        |buf| crate::encode_resource_create_2d(buf, res_id,
            crate::VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM, w, h),
        ctrlq, hhdm,
    ) } {
        return false;
    }
    log_resp(b"create");
    // SAFETY: `submit_one`'s contract — this fn's own caller guarantees the
    // command frame is live and ≥ RESP_OFF + NODATA_RESP_LEN, CTRLQ's VAs are
    // valid, and the probe is single-threaded, so the previous submission was
    // already retired and no other producer touches the queue.
    if unsafe { !submit_one(cmd_buf_va, cmd_buf_pa,
        |buf| crate::encode_resource_attach_backing_one(
            buf, res_id, base_pa, fb_bytes as u32),
        ctrlq, hhdm,
    ) } {
        return false;
    }
    log_resp(b"attach");
    // Corruption-hunt fix (state.md): once ATTACH succeeds, the device's
    // resource table holds base_pa as this resource's backing store —
    // `fb_run`'s ownership must transfer here, before any LATER submit
    // (setscanout/transfer/flush) can fail and return early. Without this,
    // an early return would drop `fb_run` and free_contig the frame while
    // the device still references it as live backing (no detach message
    // is ever sent on these failure paths), handing a physical address
    // the device may still write into back to the buddy free list for
    // reuse — the same class of bug as B1339/B1340. Leaking is safe here
    // (matches the DMA-buffer "leak rather than free-while-referenced"
    // pattern already established); a failed probe just wastes one run
    // of framebuffer memory rather than risking corrupting whatever gets
    // handed that page next.
    fb_run.disarm();
    // SAFETY: `submit_one`'s contract — this fn's own caller guarantees the
    // command frame is live and ≥ RESP_OFF + NODATA_RESP_LEN, CTRLQ's VAs are
    // valid, and the probe is single-threaded, so the previous submission was
    // already retired and no other producer touches the queue.
    if unsafe { !submit_one(cmd_buf_va, cmd_buf_pa,
        |buf| crate::encode_set_scanout(buf, 0, res_id, 0, 0, w, h),
        ctrlq, hhdm,
    ) } {
        return false;
    }
    log_resp(b"setscanout");
    // SAFETY: `submit_one`'s contract — this fn's own caller guarantees the
    // command frame is live and ≥ RESP_OFF + NODATA_RESP_LEN, CTRLQ's VAs are
    // valid, and the probe is single-threaded, so the previous submission was
    // already retired and no other producer touches the queue.
    if unsafe { !submit_one(cmd_buf_va, cmd_buf_pa,
        |buf| crate::encode_transfer_to_host_2d(buf, res_id, 0, 0, w, h, 0),
        ctrlq, hhdm,
    ) } {
        return false;
    }
    log_resp(b"transfer");
    // SAFETY: `submit_one`'s contract — this fn's own caller guarantees the
    // command frame is live and ≥ RESP_OFF + NODATA_RESP_LEN, CTRLQ's VAs are
    // valid, and the probe is single-threaded, so the previous submission was
    // already retired and no other producer touches the queue.
    if unsafe { !submit_one(cmd_buf_va, cmd_buf_pa,
        |buf| crate::encode_resource_flush(buf, res_id, 0, 0, w, h),
        ctrlq, hhdm,
    ) } {
        return false;
    }
    log_resp(b"flush");
    if !install_scanout_ctx(
        device_key,
        w, h,
        cfg_va, hhdm.wrapping_add(base_pa), fb_bytes, fb_order, res_id,
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
    // Scrubbing the reply area first stops a stale header from an earlier
    // command being read back as this one's status.
    // SAFETY: caller's contract gives a live 4 KiB command frame; request area
    // 0..0x100 and reply area RESP_OFF..+0x30 are inside it and disjoint from
    // the cursor area at 0x100; no descriptor names it until `submit_raw` below.
    unsafe {
        for k in 0..0x100usize { core::ptr::write_volatile(buf_va.add(k), 0); }
        for k in 0x200..0x230usize { core::ptr::write_volatile(buf_va.add(k), 0); }
        let req = core::slice::from_raw_parts_mut(buf_va, 0x100);
        let _ = encode(req);
    }
    // SAFETY: `buf_pa` is the physical address of the frame just encoded into,
    // whose request area is 0x100 bytes (≥ the 64 described) and whose reply
    // area at RESP_OFF has room for NODATA_RESP_LEN; CTRLQ's VAs come from the
    // caller's validated queue resource.
    unsafe { submit_raw(buf_pa, 64, NODATA_RESP_LEN, ctrlq, hhdm) }
}

/// Response descriptor length for a command whose reply is a bare ctrl header.
const NODATA_RESP_LEN: usize = 24;
/// Offset of the device-writable response area inside the probe command frame.
pub(super) const RESP_OFF: u64 = 0x200;

/// Submit one data-only CURSORQ command and wait until the device has consumed
/// it before reusing the serialized command buffer. Cursor queue commands have
/// no response descriptor by specification.
pub(super) unsafe fn submit_cursor_one<F: FnOnce(&mut [u8]) -> usize>(
    buf_va: *mut u8, buf_pa: u64, encode: F,
    cursorq: virtio::VirtQueueResource, hhdm: u64,
) -> bool {
    let cursor_off = 0x100usize;
    // The cursor area 0x100..0x200 is disjoint from the CTRLQ request (0..0x100)
    // and reply (RESP_OFF) areas, so an in-flight cursor command cannot alias one
    // SAFETY: caller's contract gives a live 4 KiB command frame; the scrub and
    // encode slice stay within 0x100..0x200 and `req_len` above 0x100 is rejected
    // before any descriptor names the region.
    unsafe {
        for k in cursor_off..cursor_off + 0x100usize {
            core::ptr::write_volatile(buf_va.add(k), 0);
        }
        let req = core::slice::from_raw_parts_mut(buf_va.add(cursor_off), 0x100);
        let req_len = encode(req);
        if req_len == 0 || req_len > 0x100 { return false; }
        submit_cursor_raw(buf_pa + cursor_off as u64, req_len, cursorq, hhdm)
    }
}

/// Post one request/response descriptor pair on CTRLQ and spin until the device
/// consumes it. `resp_len` sizes the device-writable descriptor; a command whose
/// reply is larger than a bare header must say so or the device truncates it.
pub(super) unsafe fn submit_raw(
    buf_pa: u64, req_len: usize, resp_len: usize,
    ctrlq: virtio::VirtQueueResource, hhdm: u64,
) -> bool {
    let desc0 = (hhdm.wrapping_add(ctrlq.desc_pa)) as *mut u64;
    // Descriptor 0 is the caller's request, 1 the device-writable reply at
    // RESP_OFF; the caller guarantees both lie in its command frame.
    // SAFETY: `desc_pa` is CTRLQ's descriptor frame via HHDM and entries 0/1 are
    // its first 32 bytes; this probe is the queue's sole producer and the
    // previous submission was retired before this one.
    unsafe {
        core::ptr::write_volatile(desc0.add(0), buf_pa);
        let d0 = req_len as u64
               | ((virtio::VRING_DESC_F_NEXT as u64) << 32)
               | (1u64 << 48);
        core::ptr::write_volatile(desc0.add(1), d0);
        core::ptr::write_volatile(desc0.add(2), buf_pa + RESP_OFF);
        let d1 = resp_len as u64 | ((virtio::VRING_DESC_F_WRITE as u64) << 32);
        core::ptr::write_volatile(desc0.add(3), d1);
    }
    let avail = (hhdm.wrapping_add(ctrlq.driver_pa)) as *mut u16;
    // SAFETY: CTRLQ avail frame via HHDM; `idx` is the aligned u16 at index 1
    // (Virtio 1.2 §2.7.6). Reading back the driver's own last publish is what
    // makes this fn re-entrant across the probe's successive commands.
    let cur_idx = unsafe { core::ptr::read_volatile(avail.add(1)) };
    // SAFETY: same avail frame; the index is reduced mod `ctrlq.size`, which
    // `program_queue` capped at one frame's worth of descriptors, so
    // `2 + slot` is an in-bounds aligned u16 slot in `ring[]`.
    unsafe { core::ptr::write_volatile(avail.add(2 + (cur_idx as usize % ctrlq.size as usize)), 0u16); }
    core::sync::atomic::fence(Ordering::Release);
    // SAFETY: same avail frame, aligned u16 `idx` at index 1; the Release fence
    // above ordered the ring-slot store before this publish, which is what hands
    // descriptor head 0 to the device.
    unsafe { core::ptr::write_volatile(avail.add(1), cur_idx + 1); }
    core::sync::atomic::fence(Ordering::Release);
    // SAFETY: CTRLQ's doorbell in the Device-attr notify BAR window, validated
    // non-zero when the queue resource was required; a u16 store of the queue
    // index is its defined access, and the fence published the ring first.
    unsafe { core::ptr::write_volatile(ctrlq.notify_va as *mut u16, ctrlq.index); }
    let used = (hhdm.wrapping_add(ctrlq.device_pa)) as *mut u16;
    let want = cur_idx + 1;
    let mut polls = 0u32;
    loop {
        // SAFETY: CTRLQ used frame via HHDM; `used.idx` is the aligned u16 at
        // index 1, inside the frame for any negotiated size. Volatile so each
        // iteration re-reads what the device published.
        let idx = unsafe { core::ptr::read_volatile(used.add(1)) };
        if idx >= want || polls > SUBMIT_POLL_BUDGET { break; }
        polls += 1;
        core::hint::spin_loop();
    }
    polls <= SUBMIT_POLL_BUDGET
}

unsafe fn submit_cursor_raw(
    buf_pa: u64, req_len: usize,
    cursorq: virtio::VirtQueueResource, hhdm: u64,
) -> bool {
    let desc = (hhdm.wrapping_add(cursorq.desc_pa)) as *mut u64;
    // Data-only: one read-only descriptor, no reply (Virtio 1.2 §5.7.6).
    // SAFETY: CURSORQ's descriptor frame via HHDM; entry 0 is its first 16
    // bytes. The caller guarantees `buf_pa..buf_pa+req_len` lies in the command
    // frame it owns and that no other producer uses this queue.
    unsafe {
        core::ptr::write_volatile(desc.add(0), buf_pa);
        core::ptr::write_volatile(desc.add(1), req_len as u64);
    }
    let avail = (hhdm.wrapping_add(cursorq.driver_pa)) as *mut u16;
    // SAFETY: CURSORQ avail frame via HHDM; aligned u16 `idx` at index 1, read
    // back so successive cursor commands advance the driver's own counter.
    let cur_idx = unsafe { core::ptr::read_volatile(avail.add(1)) };
    // SAFETY: same avail frame; the slot is reduced mod `cursorq.size`, capped
    // by `program_queue` at one frame's worth, so `2 + slot` is in bounds.
    unsafe { core::ptr::write_volatile(avail.add(2 + (cur_idx as usize % cursorq.size as usize)), 0u16); }
    core::sync::atomic::fence(Ordering::Release);
    // SAFETY: same avail frame, aligned u16 `idx`; the Release fence ordered the
    // ring-slot store before this publish, which hands head 0 to the device.
    unsafe { core::ptr::write_volatile(avail.add(1), cur_idx + 1); }
    core::sync::atomic::fence(Ordering::Release);
    // SAFETY: CURSORQ's doorbell in the Device-attr notify BAR window, validated
    // non-zero when the queue resource was required; a u16 store of the queue
    // index is its defined access, and the fence published the ring first.
    unsafe { core::ptr::write_volatile(cursorq.notify_va as *mut u16, cursorq.index); }
    let used = (hhdm.wrapping_add(cursorq.device_pa)) as *mut u16;
    let want = cur_idx + 1;
    let mut polls = 0u32;
    loop {
        // SAFETY: CURSORQ used frame via HHDM; `used.idx` is the aligned u16 at
        // index 1, in bounds for any negotiated size. Volatile so each iteration
        // re-reads the device's publish.
        let idx = unsafe { core::ptr::read_volatile(used.add(1)) };
        if idx >= want || polls > SUBMIT_POLL_BUDGET { break; }
        polls += 1;
        core::hint::spin_loop();
    }
    polls <= SUBMIT_POLL_BUDGET
}
