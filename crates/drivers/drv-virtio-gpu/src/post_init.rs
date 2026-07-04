// virtio-gpu modern display setup. Called by the virtio-gpu model driver's
// probe after virtio-pci transport init has produced queue0/config state.



use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

struct ProbeCommandBuffer {
    pa: u64,
    va: *mut u8,
    owned: bool,
}

impl ProbeCommandBuffer {
    fn alloc(hhdm: u64) -> Option<Self> {
        let pa = pmm::setup::alloc_one_frame()?;
        Some(Self {
            pa,
            va: hhdm.wrapping_add(pa) as *mut u8,
            owned: true,
        })
    }

    fn disarm(&mut self) {
        self.owned = false;
    }
}

impl Drop for ProbeCommandBuffer {
    fn drop(&mut self) {
        if self.owned {
            // SAFETY: the buffer is still owned by this probe guard and has not
            // been transferred to the installed scanout context.
            unsafe { pmm::setup::free_one_frame(self.pa); }
        }
    }
}

struct ProbeFramebufferRun {
    base_pa: u64,
    pages_alloc: usize,
    owned: bool,
}

impl ProbeFramebufferRun {
    fn alloc(order: u8) -> Option<Self> {
        let base_pa = pmm::setup::alloc_contig(pmm::Order(order))?;
        Some(Self {
            base_pa,
            pages_alloc: 1usize << order,
            owned: true,
        })
    }

    fn disarm(&mut self) {
        self.owned = false;
    }
}

impl Drop for ProbeFramebufferRun {
    fn drop(&mut self) {
        if self.owned {
            // SAFETY: this contiguous run is still probe-owned and has not been
            // published into the persistent scanout context.
            unsafe {
                for i in 0..self.pages_alloc {
                    pmm::setup::free_one_frame(self.base_pa + (i as u64) * 4096);
                }
            }
        }
    }
}

/// Submit `CMD_GET_DISPLAY_INFO` on q0; spin-poll used.idx for
/// completion; parse the response and re-install the device with
/// real DisplayInfo (which propagates to `47` DRM/KMS via the
/// `VirtioGpuDrm` impl).
/// # C: O(spin-poll bound = 1e6)
pub fn get_display_info(
    bdf_bus: u8, bdf_dev: u8, bdf_fn: u8,
    drv_features: u64,
    resources: virtio::VirtioResources,
) -> bool {
    let Some(ctrlq) = resources.require_queue(0) else { return false };
    if !resources.common_cfg_valid() {
        return false;
    }
    let cfg_va = resources.cfg_va;
    let hhdm = resources.hhdm;
    let mut cmd_buf = match ProbeCommandBuffer::alloc(hhdm) {
        Some(buf) => buf,
        None => return false,
    };
    // SAFETY: HHDM-mapped frame; aligned writes within 4 KiB; sole writer at boot.
    unsafe {
        for i in 0..0x1000usize { core::ptr::write_volatile(cmd_buf.va.add(i), 0); }
        let req = core::slice::from_raw_parts_mut(cmd_buf.va, 24);
        crate::encode_get_display_info(req);
    }
    let desc0 = (hhdm.wrapping_add(ctrlq.desc_pa)) as *mut u64;
    // SAFETY: HHDM-mapped virtio q0 descriptor table; aligned u64 stores into driver-owned frame.
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
    // SAFETY: HHDM-mapped avail ring; aligned u16 stores within driver-owned frame.
    unsafe { core::ptr::write_volatile(avail.add(2), 0u16); }
    core::sync::atomic::fence(Ordering::Release);
    // SAFETY: same avail ring; idx at u16 offset 1.
    unsafe { core::ptr::write_volatile(avail.add(1), 1u16); }
    core::sync::atomic::fence(Ordering::Release);
    // SAFETY: notify_va mapped Device-attr; queue idx written per virtio 1.2 §4.1.5.2.
    unsafe { core::ptr::write_volatile(ctrlq.notify_va as *mut u16, ctrlq.index); }
    let used = (hhdm.wrapping_add(ctrlq.device_pa)) as *mut u16;
    let mut polls = 0u32;
    loop {
        // SAFETY: HHDM-mapped used ring; aligned u16 read.
        let idx = unsafe { core::ptr::read_volatile(used.add(1)) };
        if idx >= 1 || polls > 1_000_000 { break; }
        polls += 1;
        core::hint::spin_loop();
    }
    // virtio 1.2 §2.7.13.2: after observing used.idx advance, an acquire
    // barrier must precede reading any device-written buffer so the response
    // bytes are not speculated ahead of the idx load (no-op on x86 TSO,
    // load-load barrier on aarch64).
    core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
    // SAFETY: same HHDM-mapped frame; bounded 408-byte slice for parser.
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
        // SAFETY: boot path; queue + notify VAs valid; PMM up.
        let scanout_ok = unsafe {
            setup_scanout(
                bdf_word,
                info.modes[0].r.width, info.modes[0].r.height,
                cfg_va, ctrlq, cmd_buf.va, cmd_buf.pa, hhdm,
            )
        };
        if !scanout_ok {
            return false;
        }
        cmd_buf.disarm();
    }
    match crate::install_with_drm(crate::VirtioGpuDev {
        bdf: bdf_word, card_id: 0, cfg_va,
        ctrlq,
        features_negotiated: drv_features,
        display: info,
        resource_id_alloc: AtomicU32::new(1),
        blob_uuid_alloc: AtomicU64::new(1), capset_count: 0,
    }) {
        Ok(_) => {}
        Err(_) => {
            if info.count_enabled > 0 {
                let _ = uninstall_scanout_after_failed_probe(bdf_word);
            }
            return false;
        }
    }
    publish_console_scanout(bdf_word);
    true
}

/// Allocate a backing fb (RESOURCE_CREATE_2D) + attach a contiguous
/// PMM region as the backing storage + bind it to scanout 0
/// (SET_SCANOUT) + transfer + flush so the host displays the buffer.
/// Paints a solid fill to validate the pipeline end-to-end.
/// # SAFETY: caller is the boot path; queue + notify VAs valid; PMM up.
/// # C: O(width * height) for the fill + O(1) per command.
unsafe fn setup_scanout(
    bdf: u32,
    w: u32, h: u32,
    cfg_va: u64,
    ctrlq: virtio::VirtQueueResource,
    cmd_buf_va: *mut u8, cmd_buf_pa: u64,
    hhdm: u64,
) -> bool {
    let pitch = w as u64 * 4;
    let fb_bytes = pitch * h as u64;
    let pages_req = ((fb_bytes + 0xFFF) / 0x1000) as usize;
    if pages_req == 0 { return false; }
    // Allocate the FB as ONE contig run via the PMM buddy allocator.
    // Order = ceil_log2(pages_req); 1.92 MiB at 800×600 = 480 pages
    // → order 9 (512 pages = 2 MiB).
    let mut order: u32 = 0;
    while (1usize << order) < pages_req { order += 1; }
    let mut fb_run = match ProbeFramebufferRun::alloc(order as u8) {
        Some(run) => run,
        None => return false,
    };
    let base_pa = fb_run.base_pa;
    let pages_alloc = fb_run.pages_alloc;
    // Render boot text. Paint the entire FB with the bg color
    // first (not all-zero) so glyphs aren't drowning on solid
    // black; Console's EraseDisplay would zero the buffer.
    {
        let mut console = fbcon::Console::new(w, h);
        console.fg = [0xff, 0xff, 0xff];
        console.bg = [0x10, 0x30, 0x80]; // brighter navy so display is visibly populated
        let pitch = (w * 4) as usize;
        for y in 0..(h as usize) {
            let off = y * pitch;
            for x in 0..(w as usize) {
                console.fb[off + x*4]     = console.bg[2]; // B
                console.fb[off + x*4 + 1] = console.bg[1]; // G
                console.fb[off + x*4 + 2] = console.bg[0]; // R
                console.fb[off + x*4 + 3] = 0xff;          // A
            }
        }
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
        #[cfg(feature = "debug-boot")]
        {
            // SAFETY: cmd_buf_va is HHDM-mapped 4 KiB; response sits at
            // cmd_buf_va + 0x200 per submit_raw's descriptor layout.
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
    // ---- 1. CMD_RESOURCE_CREATE_2D (40 B request, 24 B response) ----
    // SAFETY: caller's preconditions inherited; we hold the boot-path single-CPU invariants.
    if unsafe { !submit_one(cmd_buf_va, cmd_buf_pa,
        |buf| crate::encode_resource_create_2d(buf, res_id,
            crate::VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM, w, h),
        ctrlq, hhdm,
    ) } {
        return false;
    }
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
        ctrlq, hhdm,
    ) } {
        return false;
    }
    log_resp(b"attach");
    // ---- 3. CMD_SET_SCANOUT ----
    // SAFETY: caller's preconditions inherited; we hold the boot-path single-CPU invariants.
    if unsafe { !submit_one(cmd_buf_va, cmd_buf_pa,
        |buf| crate::encode_set_scanout(buf, 0, res_id, 0, 0, w, h),
        ctrlq, hhdm,
    ) } {
        return false;
    }
    log_resp(b"setscanout");
    // ---- 4. CMD_TRANSFER_TO_HOST_2D ----
    // SAFETY: caller's preconditions inherited; we hold the boot-path single-CPU invariants.
    if unsafe { !submit_one(cmd_buf_va, cmd_buf_pa,
        |buf| crate::encode_transfer_to_host_2d(buf, res_id, 0, 0, w, h, 0),
        ctrlq, hhdm,
    ) } {
        return false;
    }
    log_resp(b"transfer");
    // ---- 5. CMD_RESOURCE_FLUSH ----
    // SAFETY: caller's preconditions inherited; we hold the boot-path single-CPU invariants.
    if unsafe { !submit_one(cmd_buf_va, cmd_buf_pa,
        |buf| crate::encode_resource_flush(buf, res_id, 0, 0, w, h),
        ctrlq, hhdm,
    ) } {
        return false;
    }
    log_resp(b"flush");
    // Stash scanout context so the kernel-side fbcon klog sink can
    // repaint after boot. base_pa is the contig PMM run; HHDM-map
    // it to a kernel VA for byte-copy access.
    if !install_scanout_ctx(
        bdf,
        w, h,
        cfg_va, hhdm.wrapping_add(base_pa), fb_bytes, pages_alloc, res_id,
        ctrlq, cmd_buf_va as u64, cmd_buf_pa, hhdm,
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
/// 2-descriptor chain (req-out / resp-in 24 B). Returns true on
/// successful round-trip.
unsafe fn submit_one<F: FnOnce(&mut [u8]) -> usize>(
    buf_va: *mut u8, buf_pa: u64, encode: F,
    ctrlq: virtio::VirtQueueResource, hhdm: u64,
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
    unsafe { submit_raw(buf_pa, 64, ctrlq, hhdm) }
}

/// Submit a request of length `req_len` followed by a 24-byte
/// response slot. Polls used.idx for completion.
unsafe fn submit_raw(
    buf_pa: u64, req_len: usize,
    ctrlq: virtio::VirtQueueResource, hhdm: u64,
) -> bool {
    let desc0 = (hhdm.wrapping_add(ctrlq.desc_pa)) as *mut u64;
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
    let avail = (hhdm.wrapping_add(ctrlq.driver_pa)) as *mut u16;
    // Read current avail.idx to know where to write the next ring slot.
    // SAFETY: HHDM-mapped avail ring; aligned u16 read of avail.idx then write of next slot.
    let cur_idx = unsafe { core::ptr::read_volatile(avail.add(1)) };
    // SAFETY: avail.ring is a u16 ring of the negotiated queue size; cur_idx is a wrapping index used per virtio spec.
    unsafe { core::ptr::write_volatile(avail.add(2 + (cur_idx as usize % ctrlq.size as usize)), 0u16); }
    core::sync::atomic::fence(Ordering::Release);
    // SAFETY: same avail ring; idx at u16 offset 1.
    unsafe { core::ptr::write_volatile(avail.add(1), cur_idx + 1); }
    core::sync::atomic::fence(Ordering::Release);
    // SAFETY: notify VA mapped Device-attr; queue idx written per virtio 1.2 §4.1.5.2.
    unsafe { core::ptr::write_volatile(ctrlq.notify_va as *mut u16, ctrlq.index); }
    let used = (hhdm.wrapping_add(ctrlq.device_pa)) as *mut u16;
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
// After setup_scanout succeeds, save the context so the kernel-side fbcon
// driver can push klog text to the FB via transfer + flush after boot.
// Contexts are keyed by owning parent BDF. DRM KMS hooks are registered per
// card/BDF, while the current fbcon/fbdev/VT helper layer still exposes one
// console scanout and therefore operates on the explicitly elected console
// owner. Remove and shutdown target the exact BDF-owned context.

use sync::{TaskList as DriverLockClass, Spinlock};

struct ScanoutCtx {
    bdf: u32,
    cfg_va: u64,
    w: u32,
    h: u32,
    fb_va: u64,          // HHDM-mapped backing FB
    fb_bytes: u64,
    fb_pages_alloc: usize,
    res_id: u32,
    ctrlq: virtio::VirtQueueResource,
    cmd_buf_va: u64,
    cmd_buf_pa: u64,
    hhdm: u64,
}

static CTX: Spinlock<Vec<ScanoutCtx>, DriverLockClass> = Spinlock::new(Vec::new());
const NO_CONSOLE_OWNER: u32 = u32::MAX;
static CONSOLE_OWNER_BDF: AtomicU32 = AtomicU32::new(NO_CONSOLE_OWNER);

fn console_owner_bdf() -> Option<u32> {
    match CONSOLE_OWNER_BDF.load(Ordering::Acquire) {
        NO_CONSOLE_OWNER => None,
        bdf => Some(bdf),
    }
}

/// Copy `pixels` into the live framebuffer, then issue
/// transfer_to_host_2d + resource_flush so the host repaints the
/// display. Called from the fbcon kernel klog sink for every
/// emitted record. Drops silently if scanout state isn't installed.
/// # C: O(fb_bytes) copy + O(1) per submit.
pub fn fbcon_flush_pixels(pixels: &[u8]) {
    let g = CTX.lock();
    let owner = match console_owner_bdf() { Some(bdf) => bdf, None => return };
    let ctx = match g.iter().find(|ctx| ctx.bdf == owner) { Some(c) => c, None => return };
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
            ctx.ctrlq, ctx.hhdm);
        let _ = submit_one(cmd_buf_va_p, ctx.cmd_buf_pa,
            |buf| crate::encode_resource_flush(buf, res_id, 0, 0, w, h),
            ctx.ctrlq, ctx.hhdm);
    }
}

/// Blank the displayed scanout: write black into the live framebuffer
/// backing, then transfer+flush so the screen goes black. Used by the fbdev
/// FBIOBLANK path (FB_BLANK_NORMAL..POWERDOWN). We have no DPMS hardware
/// power path on a virtual GPU, so this is image-level blanking — the real,
/// observable effect — NOT a panel power-down. No-op pre-setup.
/// # C: O(fb_bytes) clear + O(1) submits.
pub fn blank_scanout_for_bdf(bdf: u32) {
    let g = CTX.lock();
    let ctx = match g.iter().find(|ctx| ctx.bdf == bdf) { Some(c) => c, None => return };
    // SAFETY: ctx.fb_va is HHDM-mapped for fb_bytes; bounded zero of the whole backing; CPL=0 writes through the HHDM mapping.
    hal::zerotrap::trap((ctx.fb_va as *mut u8) as *const u8, (ctx.fb_bytes as usize) as usize);
    unsafe { core::ptr::write_bytes(ctx.fb_va as *mut u8, 0, ctx.fb_bytes as usize); }
    let cmd_buf_va_p = ctx.cmd_buf_va as *mut u8;
    let (res_id, w, h) = (ctx.res_id, ctx.w, ctx.h);
    // SAFETY: same VAs/PAs setup_scanout installed; sole writer under the CTX lock; cmd_buf is HHDM-mapped 4 KiB scratch.
    unsafe {
        let _ = submit_one(cmd_buf_va_p, ctx.cmd_buf_pa,
            |buf| crate::encode_transfer_to_host_2d(buf, res_id, 0, 0, w, h, 0),
            ctx.ctrlq, ctx.hhdm);
        let _ = submit_one(cmd_buf_va_p, ctx.cmd_buf_pa,
            |buf| crate::encode_resource_flush(buf, res_id, 0, 0, w, h),
            ctx.ctrlq, ctx.hhdm);
    }
}

/// Unblank: repaint the live console into the scanout and flush. Delegates to
/// `fbcon::force_repaint` (re-blits every cell of the fg VT, raises the flush
/// softirq). The FBIOBLANK(UNBLANK) restore path. # C: O(cols*rows) repaint.
pub fn unblank_scanout_for_bdf(bdf: u32) {
    if console_owner_bdf() == Some(bdf) {
        fbcon::kernel::force_repaint();
    }
}

/// Install the scanout context for later flushes. Called once from
/// `setup_scanout` after the resource is created and attached.
fn install_scanout_ctx(
    bdf: u32,
    w: u32, h: u32, cfg_va: u64, fb_va: u64, fb_bytes: u64, fb_pages_alloc: usize, res_id: u32,
    ctrlq: virtio::VirtQueueResource, cmd_buf_va: u64, cmd_buf_pa: u64, hhdm: u64,
) -> bool {
    let mut ctxs = CTX.lock();
    if ctxs.iter().any(|ctx| ctx.bdf == bdf) {
        return false;
    }
    ctxs.push(ScanoutCtx {
        bdf, cfg_va, w, h, fb_va, fb_bytes, fb_pages_alloc, res_id,
        ctrlq, cmd_buf_va, cmd_buf_pa, hhdm,
    });
    true
}

/// Tear down the installed scanout context, reset the virtio device, and free
/// the command buffer plus framebuffer run.
/// # C: O(fb_pages_alloc)
pub fn uninstall_scanout(bdf: u32) -> bool {
    let ctx = {
        let mut guard = CTX.lock();
        match guard.iter().position(|ctx| ctx.bdf == bdf) {
            Some(idx) => Some(guard.remove(idx)),
            None => None,
        }
    };
    let ctx = match ctx {
        Some(ctx) => ctx,
        None => return false,
    };
    // SAFETY: cfg_va is the mapped common-cfg window captured at probe;
    // device_status is a u8 at +0x14. Reset before releasing queue storage.
    unsafe { core::ptr::write_volatile((ctx.cfg_va + 0x14) as *mut u8, 0u8); }
    let fb_base_pa = ctx.fb_va - ctx.hhdm;
    // SAFETY: these frames were allocated by this driver and are no longer
    // reachable after CTX removal and device reset. The ctrlq vring frames are
    // transport-owned after successful probe and are released on unpublish.
    unsafe {
        pmm::setup::free_one_frame(ctx.cmd_buf_pa);
        for i in 0..ctx.fb_pages_alloc {
            pmm::setup::free_one_frame(fb_base_pa + (i as u64) * 4096);
        }
    }
    true
}

/// Stop scanout queue activity for terminal system shutdown.
///
/// Unlike `uninstall_scanout`, this intentionally does not unregister fbdev,
/// clear DRM publication, or free the framebuffer backing. Those objects can
/// still be visible to late shutdown callers, and the system is powering off.
/// # C: O(1)
pub fn shutdown_scanout(bdf: u32) -> bool {
    let ctx = {
        let mut guard = CTX.lock();
        match guard.iter().position(|ctx| ctx.bdf == bdf) {
            Some(idx) => Some(guard.remove(idx)),
            None => None,
        }
    };
    let ctx = match ctx {
        Some(ctx) => ctx,
        None => return false,
    };
    if ctx.cfg_va != 0 {
        // SAFETY: cfg_va is the mapped common-cfg window captured at probe;
        // device_status is a u8 at +0x14.
        unsafe { core::ptr::write_volatile((ctx.cfg_va + 0x14) as *mut u8, 0u8); }
    }
    true
}

/// Tear down scanout-only state after a probe failure. The caller still owns
/// the transport unwind and will reset the virtio device and release q0.
/// # C: O(fb_pages_alloc)
pub fn uninstall_scanout_after_failed_probe(bdf: u32) -> bool {
    let ctx = {
        let mut guard = CTX.lock();
        match guard.iter().position(|ctx| ctx.bdf == bdf) {
            Some(idx) => Some(guard.remove(idx)),
            None => None,
        }
    };
    let ctx = match ctx {
        Some(ctx) => ctx,
        None => return false,
    };
    let fb_base_pa = ctx.fb_va - ctx.hhdm;
    // SAFETY: scanout was not published to the runtime driver. The transport
    // q0 frames remain owned by the caller's failed-probe cleanup path.
    unsafe {
        pmm::setup::free_one_frame(ctx.cmd_buf_pa);
        for i in 0..ctx.fb_pages_alloc {
            pmm::setup::free_one_frame(fb_base_pa + (i as u64) * 4096);
        }
    }
    true
}

/// True iff the scanout context is installed (post-`setup_scanout`).
/// # C: O(1)
pub fn scanout_ready() -> bool { !CTX.lock().is_empty() }

/// True iff the BDF-owned scanout context is installed.
/// # C: O(N)
pub fn scanout_ready_for_bdf(bdf: u32) -> bool {
    CTX.lock().iter().any(|ctx| ctx.bdf == bdf)
}

/// Read back the scanout dimensions. Used by the kernel's fbcon
/// klog wiring to size its Console.
/// # C: O(1)
pub fn dimensions() -> Option<(u32, u32)> {
    let owner = console_owner_bdf()?;
    dimensions_for_bdf(owner)
}

/// Read back the scanout dimensions for a BDF-owned context.
/// # C: O(N)
pub fn dimensions_for_bdf(bdf: u32) -> Option<(u32, u32)> {
    CTX.lock().iter().find(|c| c.bdf == bdf).map(|c| (c.w, c.h))
}

/// The scanout framebuffer as `(base_pa, fb_va, bytes, pitch, w, h)` for the
/// fbdev presenter (`/dev/fb0`): `base_pa` is the contiguous physical backing
/// userspace mmaps; `fb_va` is its HHDM kernel VA (for read/write); `pitch` =
/// `w*4` (BGRA32). `None` before scanout setup. # C: O(1)
pub fn framebuffer() -> Option<(u64, u64, u64, u32, u32, u32)> {
    let owner = console_owner_bdf()?;
    framebuffer_for_bdf(owner)
}

/// The scanout framebuffer for a BDF-owned context.
/// # C: O(N)
pub fn framebuffer_for_bdf(bdf: u32) -> Option<(u64, u64, u64, u32, u32, u32)> {
    let g = CTX.lock();
    let c = g.iter().find(|ctx| ctx.bdf == bdf)?;
    Some((c.fb_va - c.hhdm, c.fb_va, c.fb_bytes, c.w * 4, c.w, c.h))
}

/// Publish the installed virtio-gpu scanout through fbcon, fbdev, printk, and
/// the live VT query hooks. Called from the virtio-gpu probe after scanout and
/// DRM registration succeed, matching the Linux pattern where the driver owns
/// its console/fb helper registration.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn publish_console_scanout(bdf: u32) {
    let Some((w, h)) = dimensions_for_bdf(bdf) else { return };
    if CONSOLE_OWNER_BDF
        .compare_exchange(NO_CONSOLE_OWNER, bdf, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    fbcon::kernel::kernel_init(w, h, fbcon_flush_pixels);
    if let Some((base_pa, fb_va, bytes, pitch, fw, fh)) = framebuffer_for_bdf(bdf) {
        let idx = fbdev::init_scanout(base_pa, fb_va, bytes, pitch, fw, fh);
        let _ = fbdev::set_ops(idx, fbdev::FbOps {
            driver_key: bdf,
            flush: flush_scanout_for_bdf,
            blank: blank_scanout_for_bdf,
            unblank: unblank_scanout_for_bdf,
        });
        fbdev::set_yield_hook(fbdev_vsync_yield);
        fbdev::set_now_hook(monotonic_now_ns);
    }
    klog::set_aux_sink(fbcon::kernel::vt_console_sink);
    fbcon::kernel::set_reply_sink(console::vt_reply_sink);
    tty::live::set_app_cursor_query(fbcon::kernel::fg_app_cursor);
    tty::live::set_bracketed_paste_query(fbcon::kernel::fg_bracketed_paste);
}

/// Unpublish the console/fb helper state owned by the installed scanout before
/// the scanout backing and queue scratch pages are released.
/// # C: O(N + depth)
#[cfg(target_os = "oxide-kernel")]
pub fn unpublish_console_scanout(bdf: u32) {
    let fb_base = {
        let ctxs = CTX.lock();
        match ctxs.iter().find(|ctx| ctx.bdf == bdf) {
            Some(ctx) if ctx.bdf == bdf => ctx.fb_va - ctx.hhdm,
            _ => return,
        }
    };
    if console_owner_bdf() != Some(bdf) {
        return;
    }
    klog::clear_aux_sink();
    tty::live::clear_vt_mode_queries();
    fbcon::kernel::kernel_unregister();
    fbdev::clear_wait_hooks();
    let _ = fbdev::unregister_by_base(fb_base);
    CONSOLE_OWNER_BDF.store(NO_CONSOLE_OWNER, Ordering::Release);
}

#[cfg(target_os = "oxide-kernel")]
fn fbdev_vsync_yield() {
    // SAFETY: invoked from the FBIOWAITFORVSYNC ioctl path in process context;
    // wait_vblank drops hook guards before calling it, so no fbdev lock is held.
    unsafe { sched::live::tick_yield(); }
}

#[cfg(target_os = "oxide-kernel")]
fn monotonic_now_ns() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        use hal::TimerOps;
        hal_x86_64::X86TimerOps::monotonic_ns().0
    }
    #[cfg(target_arch = "aarch64")]
    {
        use hal::TimerOps;
        hal_aarch64::ArmTimerOps::monotonic_ns().0
    }
}

// ============================================================
// D5b-2 runtime KMS scanout API (the drm crate calls these via the
// hook registered in `register_drm_hooks`). The DRM-facing hooks are keyed by
// card/BDF and honest-fail (return false/None) if that card's scanout context
// does not exist, so SETCRTC must -EINVAL upstream.
//
// CONSOLE SAFETY: the boot fbcon framebuffer is res_id 1 and stays
// allocated+attached for the whole boot. SETCRTC creates a NEW res_id
// (>=2) for the client's dumb buffer and switches scanout 0 to it.
// res_id 1 is never unref'd, so `restore_console_scanout` can
// SET_SCANOUT back to it + force_repaint to bring the console (and
// getty) back when the client closes its card fd.
// ============================================================

/// Boot fbcon scanout resource id (set up by `setup_scanout`).
pub const BOOT_SCANOUT_RES_ID: u32 = 1;

/// Runtime resource-id allocator. Boot fb is res_id 1; runtime KMS
/// resources start at 2 so they never collide with the console fb.
static NEXT_RUNTIME_RES_ID: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(2);

/// The BDF argument is accepted for the per-card DRM hook shape; the boot
/// console resource id is fixed within each virtio-gpu instance.
pub fn boot_scanout_res_id_for_bdf(_bdf: u32) -> u32 { BOOT_SCANOUT_RES_ID }

/// Run an encode closure as one CTRLQ command + poll used. Mirrors the
/// boot `submit_one` but takes the queue context from the BDF-owned scanout.
/// `false` if no scanout or the round-trip times out / NAKs.
/// # C: O(1) submit + host-side O(work).
fn submit_ctrl_for_bdf<F: Fn(&mut [u8]) -> usize>(bdf: u32, encode: F) -> bool {
    let g = CTX.lock();
    let ctx = match g.iter().find(|ctx| ctx.bdf == bdf) { Some(c) => c, None => return false };
    let cmd_buf_va_p = ctx.cmd_buf_va as *mut u8;
    // SAFETY: cmd_buf is the HHDM-mapped 4 KiB scratch frame setup_scanout installed; q0 descriptor/avail/used/notify VAs are the exact ones the boot path validated; we hold the CTX lock so we are the sole writer for this submit; the encode closure writes < 0x100 bytes into the per-call request slice.
    let ok = unsafe {
        submit_one(cmd_buf_va_p, ctx.cmd_buf_pa, |b| encode(b),
            ctx.ctrlq, ctx.hhdm)
    };
    if !ok { return false; }
    // SAFETY: cmd_buf_va is HHDM-mapped 4 KiB; submit_raw places the 24-byte response at +0x200; aligned u32 read of the response type word.
    let resp = unsafe { core::ptr::read_volatile((ctx.cmd_buf_va + 0x200) as *const u32) };
    // Accept any RESP_OK_* (0x1100..0x1200).
    resp >= 0x1100 && resp < 0x1200
}

/// Create a new virtio-gpu 2D resource backed by a userspace-painted
/// contiguous physical buffer (`pa`, `w*h*4` bytes). Issues
/// RESOURCE_CREATE_2D + RESOURCE_ATTACH_BACKING (one mem-entry over the
/// whole contiguous run). Returns the new res_id, or `None` if no
/// requested BDF's scanout context or a command failed. The buffer's PA must
/// be a single contiguous run (DRM dumb buffers are alloc_contig).
/// # C: O(1) submits.
pub fn create_scanout_from_pa_for_bdf(bdf: u32, pa: u64, w: u32, h: u32, fmt_drm: u32) -> Option<u32> {
    if !scanout_ready_for_bdf(bdf) { return None; }
    let fmt = crate::drm_fourcc_to_virtio(fmt_drm)?;
    if w == 0 || h == 0 { return None; }
    let bytes = (w as u64) * (h as u64) * 4;
    if bytes == 0 || bytes > u32::MAX as u64 { return None; }
    let res_id = NEXT_RUNTIME_RES_ID.fetch_add(1, Ordering::AcqRel);
    if !submit_ctrl_for_bdf(bdf, |b| crate::encode_resource_create_2d(b, res_id, fmt, w, h)) {
        return None;
    }
    if !submit_ctrl_for_bdf(bdf, |b| crate::encode_resource_attach_backing_one(b, res_id, pa, bytes as u32)) {
        return None;
    }
    Some(res_id)
}

/// Switch scanout 0 to `res_id` and make its pixels visible:
/// SET_SCANOUT(0, res_id, 0,0,w,h) + TRANSFER_TO_HOST_2D + RESOURCE_FLUSH.
/// `false` if the requested BDF has no scanout or a command failed.
/// # C: O(1) submits.
pub fn set_scanout_for_bdf(bdf: u32, res_id: u32, w: u32, h: u32) -> bool {
    if !scanout_ready_for_bdf(bdf) || w == 0 || h == 0 { return false; }
    if !submit_ctrl_for_bdf(bdf, |b| crate::encode_set_scanout(b, 0, res_id, 0, 0, w, h)) { return false; }
    if !submit_ctrl_for_bdf(bdf, |b| crate::encode_transfer_to_host_2d(b, res_id, 0, 0, w, h, 0)) { return false; }
    if !submit_ctrl_for_bdf(bdf, |b| crate::encode_resource_flush(b, res_id, 0, 0, w, h)) { return false; }
    true
}

/// Restore the boot fbcon scanout (res_id 1) and re-paint the console.
/// Called from `DrmCardInode::on_release` when a KMS client that took
/// the scanout closes its card fd, so the fb console + getty come back.
/// SET_SCANOUT back to res_id 1 over the boot dimensions + flush, then
/// `fbcon::force_repaint()` re-blits the live VT into res_id 1's backing
/// (via fbcon_flush_pixels) so the next flush shows real content.
/// `false` if the requested BDF has no scanout.
/// # C: O(1) submits + O(cols*rows) repaint.
pub fn restore_console_scanout_for_bdf(bdf: u32) -> bool {
    let (w, h) = match dimensions_for_bdf(bdf) { Some(d) => d, None => return false };
    let ok = set_scanout_for_bdf(bdf, BOOT_SCANOUT_RES_ID, w, h);
    // Bring the console content back: force_repaint marks the fg VT
    // dirty + raises the flush softirq, which calls fbcon_flush_pixels
    // → writes res_id 1's backing + transfer/flush.
    fbcon::kernel::force_repaint();
    ok
}

/// Register the DRM↔virtio-gpu runtime scanout hooks with the `47` DRM
/// core. Called once from `install_with_drm` so SETCRTC/PAGE_FLIP can
/// drive the scanout without a crate dependency cycle (drm cannot
/// depend on this crate; this crate depends on drm). # C: O(1)
pub fn register_drm_hooks(card_id: u32, bdf: u32) {
    drm::node::set_scanout_ops(card_id, drm::node::ScanoutOps {
        driver_key: bdf,
        create_from_pa: create_scanout_from_pa_for_bdf,
        set_scanout: set_scanout_for_bdf,
        restore_console: restore_console_scanout_for_bdf,
        boot_res_id: boot_scanout_res_id_for_bdf,
    });
}

pub fn unregister_drm_hooks(card_id: u32) {
    drm::node::clear_scanout_ops(card_id);
}

/// Push the CURRENT framebuffer contents to the host display
/// (transfer_to_host_2d + resource_flush, no pixel copy). For the fbdev
/// path: userspace wrote the mmap'd scanout directly (or via write()), this
/// makes those pixels visible (Linux fb pan/defio flush). No-op pre-setup.
/// # C: O(1) submits (+ host-side O(w*h) transfer).
pub fn flush_scanout_for_bdf(bdf: u32) {
    let g = CTX.lock();
    let ctx = match g.iter().find(|ctx| ctx.bdf == bdf) { Some(c) => c, None => return };
    let cmd_buf_va_p = ctx.cmd_buf_va as *mut u8;
    let (res_id, w, h) = (ctx.res_id, ctx.w, ctx.h);
    // SAFETY: same VAs/PAs setup_scanout installed; sole writer under the CTX lock; cmd_buf is HHDM-mapped 4 KiB scratch.
    unsafe {
        let _ = submit_one(cmd_buf_va_p, ctx.cmd_buf_pa,
            |buf| crate::encode_transfer_to_host_2d(buf, res_id, 0, 0, w, h, 0),
            ctx.ctrlq, ctx.hhdm);
        let _ = submit_one(cmd_buf_va_p, ctx.cmd_buf_pa,
            |buf| crate::encode_resource_flush(buf, res_id, 0, 0, w, h),
            ctx.ctrlq, ctx.hhdm);
    }
}
