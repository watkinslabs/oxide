use super::*;

/// Process-context completion queues for one deferred GPU initialization.
pub(super) struct CompletionWaits<'a> {
    pub(super) wake: &'a sched::live::WaitList,
    pub(super) cancelled: &'a core::sync::atomic::AtomicBool,
}

/// Submit `CMD_GET_DISPLAY_INFO` on q0; wait for its used-ring completion,
/// then parse the response and install the device with real DisplayInfo.
/// # C: O(command completion)
pub fn get_display_info(
    device_key: virtio::VirtioChildDeviceKey,
    bdf: pci::Bdf,
    parent: &alloc::sync::Arc<drv::Device>,
    drv_features: u64,
    resources: virtio::VirtioResources,
    waits: &CompletionWaits<'_>,
) -> bool {
    let Some(ctrlq_resource) = resources.require_queue_at_least(0, 4) else { return false };
    let Some(cursorq_resource) = resources.require_queue_at_least(1, 2) else { return false };
    if !resources.common_cfg_valid() {
        return false;
    }
    let cfg_va = resources.cfg_va;
    let hhdm = resources.hhdm;
    let mut ctrlq = match virtio::VirtioSplitQueue::new_with_features(
        ctrlq_resource, hhdm, drv_features,
    ) {
        Ok(queue) => Some(queue), Err(_) => return false,
    };
    let mut cursorq = match virtio::VirtioSplitQueue::new_with_features(
        cursorq_resource, hhdm, drv_features,
    ) {
        Ok(queue) => Some(queue), Err(_) => return false,
    };
    let mut cmd_buf = match ProbeCommandBuffer::alloc(hhdm, bdf) {
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
    // SAFETY: the frame is exclusively owned by this synchronous probe.  The
    // shared queue owns descriptor allocation, publication, and retirement.
    let retired = unsafe { submit_raw_wait(cmd_buf.dma, 24, 408, ctrlq.as_mut().unwrap(), waits) };
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
        super::edid::fetch(drv_features, cmd_buf.va, cmd_buf.dma, ctrlq.as_mut().unwrap(),
            waits, &mut edid_timed_out)
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
                cfg_va, &mut ctrlq, &mut cursorq, cmd_buf.va, cmd_buf.pa, cmd_buf.dma, bdf, hhdm,
                waits,
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
        device_key, bdf, card_id: 0, cfg_va,
        ctrlq: ctrlq_resource, cursorq: cursorq_resource,
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
    ctrlq: &mut Option<virtio::VirtioSplitQueue>,
    cursorq: &mut Option<virtio::VirtioSplitQueue>,
    cmd_buf_va: *mut u8, cmd_buf_pa: u64, cmd_buf_dma: u64, bdf: pci::Bdf,
    hhdm: u64,
    waits: &CompletionWaits<'_>,
) -> bool {
    let pitch = w as u64 * 4;
    let fb_bytes = pitch * h as u64;
    let pages_req = ((fb_bytes + 0xFFF) / 0x1000) as usize;
    if pages_req == 0 { return false; }
    let mut order: u32 = 0;
    while (1usize << order) < pages_req { order += 1; }
    let fb_order = pmm::Order(order as u8);
    let mut fb_run = match ProbeFramebufferRun::alloc(bdf, fb_order) {
        Some(run) => run,
        None => return false,
    };
    let base_pa = fb_run.base_pa;
    let base_dma = fb_run.base_dma;
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
            // reply header's `type` word in bounds; the preceding `submit_one_wait`
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
    // SAFETY: `submit_one_wait`'s contract — this fn's own caller guarantees the
    // command frame is live and ≥ RESP_OFF + NODATA_RESP_LEN, CTRLQ's VAs are
    // valid, and the probe is single-threaded, so the previous submission was
    // already retired and no other producer touches the queue.
    if unsafe { !submit_one_wait(cmd_buf_va, cmd_buf_dma,
        |buf| crate::encode_resource_create_2d(buf, res_id,
            crate::VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM, w, h),
        ctrlq.as_mut().unwrap(),
        waits,
    ) } {
        return false;
    }
    log_resp(b"create");
    // SAFETY: `submit_one_wait`'s contract — this fn's own caller guarantees the
    // command frame is live and ≥ RESP_OFF + NODATA_RESP_LEN, CTRLQ's VAs are
    // valid, and the probe is single-threaded, so the previous submission was
    // already retired and no other producer touches the queue.
    if unsafe { !submit_one_wait(cmd_buf_va, cmd_buf_dma,
        |buf| crate::encode_resource_attach_backing_one(
            buf, res_id, base_dma, fb_bytes as u32),
        ctrlq.as_mut().unwrap(),
        waits,
    ) } {
        return false;
    }
    log_resp(b"attach");
    // Corruption-hunt fix (state.md): once ATTACH succeeds, the device's
    // resource table holds the mapped backing DMA range —
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
    // SAFETY: `submit_one_wait`'s contract — this fn's own caller guarantees the
    // command frame is live and ≥ RESP_OFF + NODATA_RESP_LEN, CTRLQ's VAs are
    // valid, and the probe is single-threaded, so the previous submission was
    // already retired and no other producer touches the queue.
    if unsafe { !submit_one_wait(cmd_buf_va, cmd_buf_dma,
        |buf| crate::encode_set_scanout(buf, 0, res_id, 0, 0, w, h),
        ctrlq.as_mut().unwrap(),
        waits,
    ) } {
        return false;
    }
    log_resp(b"setscanout");
    // SAFETY: `submit_one_wait`'s contract — this fn's own caller guarantees the
    // command frame is live and ≥ RESP_OFF + NODATA_RESP_LEN, CTRLQ's VAs are
    // valid, and the probe is single-threaded, so the previous submission was
    // already retired and no other producer touches the queue.
    if unsafe { !submit_one_wait(cmd_buf_va, cmd_buf_dma,
        |buf| crate::encode_transfer_to_host_2d(buf, res_id, 0, 0, w, h, 0),
        ctrlq.as_mut().unwrap(),
        waits,
    ) } {
        return false;
    }
    log_resp(b"transfer");
    // SAFETY: `submit_one_wait`'s contract — this fn's own caller guarantees the
    // command frame is live and ≥ RESP_OFF + NODATA_RESP_LEN, CTRLQ's VAs are
    // valid, and the probe is single-threaded, so the previous submission was
    // already retired and no other producer touches the queue.
    if unsafe { !submit_one_wait(cmd_buf_va, cmd_buf_dma,
        |buf| crate::encode_resource_flush(buf, res_id, 0, 0, w, h),
        ctrlq.as_mut().unwrap(),
        waits,
    ) } {
        return false;
    }
    log_resp(b"flush");
    if !install_scanout_ctx(
        device_key,
        w, h,
        cfg_va, hhdm.wrapping_add(base_pa), base_dma, fb_run.map_bytes, fb_bytes, fb_order, res_id,
        ctrlq.take(), cursorq.take(), cmd_buf_va as u64, cmd_buf_pa, cmd_buf_dma, bdf, hhdm,
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

/// Submit one CTRLQ command from the deferred boot probe and sleep until the
/// per-device IRQ says a used entry may be reaped.
/// # SAFETY: same frame and queue ownership contract as the prior direct
/// submit path, plus
/// process context with no driver lock held while this function can sleep.
pub(super) unsafe fn submit_one_wait<F: FnOnce(&mut [u8]) -> usize>(
    buf_va: *mut u8, buf_dma: u64, encode: F,
    ctrlq: &mut virtio::VirtioSplitQueue, waits: &CompletionWaits<'_>,
) -> bool {
    // SAFETY: caller gives the same exclusive 4 KiB frame contract as the
    // direct submission path; this substitutes the completion wait primitive.
    unsafe {
        for k in 0..0x100usize { core::ptr::write_volatile(buf_va.add(k), 0); }
        for k in 0x200..0x230usize { core::ptr::write_volatile(buf_va.add(k), 0); }
        let req = core::slice::from_raw_parts_mut(buf_va, 0x100);
        let _ = encode(req);
        submit_raw_wait(buf_dma, 64, NODATA_RESP_LEN, ctrlq, waits)
    }
}

/// Response descriptor length for a command whose reply is a bare ctrl header.
const NODATA_RESP_LEN: usize = 24;
/// Offset of the device-writable response area inside the probe command frame.
pub(super) const RESP_OFF: u64 = 0x200;

/// Submit one data-only CURSORQ command and sleep until it retires. Cursor
/// commands have no response descriptor by specification.
pub(super) unsafe fn submit_cursor_one_wait<F: FnOnce(&mut [u8]) -> usize>(
    buf_va: *mut u8, buf_dma: u64, encode: F,
    cursorq: &mut virtio::VirtioSplitQueue,
    wake: &sched::live::WaitList,
    cancelled: &core::sync::atomic::AtomicBool,
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
        submit_cursor_raw_wait(buf_dma + cursor_off as u64, req_len, cursorq, wake, cancelled)
    }
}

/// Post one CTRLQ descriptor pair, then use the generic publish/recheck wait.
/// # SAFETY: caller owns `ctrlq` and the complete mapped request/reply frame;
/// this call is process context and holds no driver lock while it parks.
pub(super) unsafe fn submit_raw_wait(
    buf_dma: u64, req_len: usize, resp_len: usize,
    ctrlq: &mut virtio::VirtioSplitQueue, waits: &CompletionWaits<'_>,
) -> bool {
    if ctrlq.submit(&[
        virtio::SplitQueueSeg { dma: buf_dma, len: req_len as u32, device_writes: false },
        virtio::SplitQueueSeg { dma: buf_dma + RESP_OFF, len: resp_len as u32, device_writes: true },
    ]).is_err() { return false; }
    let deadline = sched::deadline::clock::now_ns().saturating_add(super::limits::BOOT_COMPLETION_TIMEOUT_NS);
    let mut retired = false;
    // SAFETY: deferred init runs from kworker process context after transport
    // publication and no spinlock survives from descriptor submission to wait.
    let _ = unsafe {
        sched::live::wait_event_uninterruptible_until(
            waits.wake, deadline, sched::deadline::clock::now_ns, || {
                if waits.cancelled.load(core::sync::atomic::Ordering::Acquire) { return true; }
                match ctrlq.pop_used() {
                    Ok(Some(_)) => { retired = true; true }
                    Ok(None) => false,
                    Err(_) => true,
                }
            },
        )
    };
    retired
}

unsafe fn submit_cursor_raw_wait(
    buf_dma: u64, req_len: usize,
    cursorq: &mut virtio::VirtioSplitQueue,
    wake: &sched::live::WaitList,
    cancelled: &core::sync::atomic::AtomicBool,
) -> bool {
    if cursorq.submit(&[virtio::SplitQueueSeg { dma: buf_dma, len: req_len as u32, device_writes: false }]).is_err() { return false; }
    let deadline = sched::deadline::clock::now_ns().saturating_add(super::limits::BOOT_COMPLETION_TIMEOUT_NS);
    let mut retired = false;
    // SAFETY: the worker owns this cursor queue and command frame while the
    // generic wait publishes, sleeps, and rechecks the used-ring predicate.
    let _ = unsafe {
        sched::live::wait_event_uninterruptible_until(
            wake, deadline, sched::deadline::clock::now_ns, || {
                if cancelled.load(core::sync::atomic::Ordering::Acquire) { return true; }
                match cursorq.pop_used() {
                    Ok(Some(_)) => { retired = true; true }
                    Ok(None) => false,
                    Err(_) => true,
                }
            },
        )
    };
    retired
}
