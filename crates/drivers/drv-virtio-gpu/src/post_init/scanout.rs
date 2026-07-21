use super::*;

fn key_from_raw(raw: u32) -> virtio::VirtioChildDeviceKey {
    virtio::VirtioChildDeviceKey::from_raw(raw)
}

fn key_from_fb_driver(driver_key: fbdev::FbDriverKey) -> virtio::VirtioChildDeviceKey {
    key_from_raw(driver_key.raw())
}

pub(super) fn console_owner_key() -> Option<virtio::VirtioChildDeviceKey> {
    match CONSOLE_OWNER_KEY.load(Ordering::Acquire) {
        NO_CONSOLE_OWNER_KEY => None,
        raw => Some(key_from_raw(raw)),
    }
}

/// Copy `pixels` into the live framebuffer, then issue transfer+flush.
pub fn fbcon_flush_pixels(pixels: &[u8]) {
    let g = CTX.lock();
    let owner = match console_owner_key() { Some(key) => key, None => return };
    let ctx = match g.iter().find(|ctx| ctx.device_key == owner) { Some(c) => c, None => return };
    if ctx.quiesced {
        return;
    }
    let n = (ctx.fb_bytes as usize).min(pixels.len());
    unsafe {
        // Bulk copy the frame into the GPU resource backing (guest RAM, WB — not
        // MMIO, so no per-byte volatile needed). The old byte-by-byte
        // `write_volatile` loop ran millions of volatile stores per flush with the
        // CTX lock held (IRQ-masked), so a burst of console output (every systemd
        // log line renders here) stalled the LAPIC timer for seconds — surfacing
        // as multi-second scheduler wake gaps that serialized sysinit. A single
        // `copy_nonoverlapping` (memcpy) is ~1-2 orders of magnitude faster and
        // keeps the IRQ-masked window short.
        core::ptr::copy_nonoverlapping(pixels.as_ptr(), ctx.fb_va as *mut u8, n);
    }
    let cmd_buf_va_p = ctx.cmd_buf_va as *mut u8;
    let res_id = ctx.res_id;
    let w = ctx.w;
    let h = ctx.h;
    unsafe {
        let _ = submit_one(cmd_buf_va_p, ctx.cmd_buf_pa,
            |buf| crate::encode_transfer_to_host_2d(buf, res_id, 0, 0, w, h, 0),
            ctx.ctrlq, ctx.hhdm);
        let _ = submit_one(cmd_buf_va_p, ctx.cmd_buf_pa,
            |buf| crate::encode_resource_flush(buf, res_id, 0, 0, w, h),
            ctx.ctrlq, ctx.hhdm);
    }
}

pub fn blank_scanout_for_key(driver_key: fbdev::FbDriverKey) {
    let owner = key_from_fb_driver(driver_key);
    let g = CTX.lock();
    let ctx = match g.iter().find(|ctx| ctx.device_key == owner) { Some(c) => c, None => return };
    if ctx.quiesced {
        return;
    }
    hal::zerotrap::trap((ctx.fb_va as *mut u8) as *const u8, ctx.fb_bytes as usize);
    unsafe { core::ptr::write_bytes(ctx.fb_va as *mut u8, 0, ctx.fb_bytes as usize); }
    let cmd_buf_va_p = ctx.cmd_buf_va as *mut u8;
    let (res_id, w, h) = (ctx.res_id, ctx.w, ctx.h);
    unsafe {
        let _ = submit_one(cmd_buf_va_p, ctx.cmd_buf_pa,
            |buf| crate::encode_transfer_to_host_2d(buf, res_id, 0, 0, w, h, 0),
            ctx.ctrlq, ctx.hhdm);
        let _ = submit_one(cmd_buf_va_p, ctx.cmd_buf_pa,
            |buf| crate::encode_resource_flush(buf, res_id, 0, 0, w, h),
            ctx.ctrlq, ctx.hhdm);
    }
}

pub fn unblank_scanout_for_key(driver_key: fbdev::FbDriverKey) {
    if console_owner_key().map(|key| key.raw()) == Some(driver_key.raw()) {
        fbcon::kernel::force_repaint();
    }
}

pub(super) fn install_scanout_ctx(
    device_key: virtio::VirtioChildDeviceKey,
    bdf: u32,
    w: u32, h: u32, cfg_va: u64, fb_va: u64, fb_bytes: u64, fb_order: pmm::Order, res_id: u32,
    ctrlq: virtio::VirtQueueResource, cursorq: virtio::VirtQueueResource,
    cmd_buf_va: u64, cmd_buf_pa: u64, hhdm: u64,
) -> bool {
    let mut ctxs = CTX.lock();
    if ctxs.iter().any(|ctx| ctx.device_key == device_key) {
        return false;
    }
    ctxs.push(ScanoutCtx {
        device_key, bdf, cfg_va, w, h, fb_va, fb_bytes, fb_order, res_id,
        ctrlq, cursorq, cmd_buf_va, cmd_buf_pa, hhdm, fbdev_idx: None, quiesced: false,
    });
    true
}

#[cfg(any(target_os = "oxide-kernel", test))]
fn set_scanout_fbdev_idx(device_key: virtio::VirtioChildDeviceKey, fbdev_idx: Option<u32>) -> bool {
    let mut ctxs = CTX.lock();
    let Some(ctx) = ctxs.iter_mut().find(|ctx| ctx.device_key == device_key) else {
        return false;
    };
    ctx.fbdev_idx = fbdev_idx;
    true
}

#[cfg(any(target_os = "oxide-kernel", test))]
fn take_scanout_fbdev_idx(device_key: virtio::VirtioChildDeviceKey) -> Option<u32> {
    let mut ctxs = CTX.lock();
    let ctx = ctxs.iter_mut().find(|ctx| ctx.device_key == device_key)?;
    ctx.fbdev_idx.take()
}

#[cfg(any(target_os = "oxide-kernel", test))]
fn install_console_fbdev(device_key: virtio::VirtioChildDeviceKey) -> Option<u32> {
    let (base_pa, fb_va, bytes, pitch, fw, fh) = framebuffer_for_key(device_key)?;
    let driver_key = fbdev::FbDriverKey::from_raw(device_key.raw())?;
    let idx = fbdev::init_scanout(base_pa, fb_va, bytes, pitch, fw, fh);
    if idx == fbdev::INVALID_FB_INDEX
        || !fbdev::set_ops(idx, fbdev::FbOps {
            driver_key,
            flush: super::flush_scanout_for_key,
            blank: blank_scanout_for_key,
            unblank: unblank_scanout_for_key,
        })
        || !set_scanout_fbdev_idx(device_key, Some(idx))
    {
        if idx != fbdev::INVALID_FB_INDEX {
            let _ = fbdev::unregister(idx);
        }
        return None;
    }
    Some(idx)
}

#[cfg(any(target_os = "oxide-kernel", test))]
fn commit_console_owner_key(device_key: virtio::VirtioChildDeviceKey, idx: u32) -> bool {
    let owner_raw = device_key.raw();
    if CONSOLE_OWNER_KEY
        .compare_exchange(NO_CONSOLE_OWNER_KEY, owner_raw, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        return true;
    }
    let _ = set_scanout_fbdev_idx(device_key, None);
    let _ = fbdev::unregister(idx);
    false
}

pub fn uninstall_scanout(device_key: virtio::VirtioChildDeviceKey) -> bool {
    let ctx = {
        let mut guard = CTX.lock();
        match guard.iter().position(|ctx| ctx.device_key == device_key) {
            Some(idx) => Some(guard.remove(idx)),
            None => None,
        }
    };
    let ctx = match ctx {
        Some(ctx) => ctx,
        None => return false,
    };
    virtio::reset_device(ctx.cfg_va);
    let fb_base_pa = ctx.fb_va - ctx.hhdm;
    unsafe {
        if ctx.cmd_buf_pa != 0 {
            pmm::setup::free_one_frame(ctx.cmd_buf_pa);
        }
        if fb_base_pa != 0 {
            pmm::setup::free_contig(fb_base_pa, ctx.fb_order);
        }
    }
    true
}

pub fn shutdown_scanout(device_key: virtio::VirtioChildDeviceKey) -> bool {
    let cfg_va = {
        let mut guard = CTX.lock();
        let Some(ctx) = guard.iter_mut().find(|ctx| ctx.device_key == device_key) else {
            return false;
        };
        ctx.quiesced = true;
        ctx.cfg_va
    };
    virtio::reset_device(cfg_va);
    true
}

pub fn uninstall_scanout_after_failed_probe(device_key: virtio::VirtioChildDeviceKey) -> bool {
    let ctx = {
        let mut guard = CTX.lock();
        match guard.iter().position(|ctx| ctx.device_key == device_key) {
            Some(idx) => Some(guard.remove(idx)),
            None => None,
        }
    };
    let ctx = match ctx {
        Some(ctx) => ctx,
        None => return false,
    };
    let fb_base_pa = ctx.fb_va - ctx.hhdm;
    unsafe {
        if ctx.cmd_buf_pa != 0 {
            pmm::setup::free_one_frame(ctx.cmd_buf_pa);
        }
        if fb_base_pa != 0 {
            pmm::setup::free_contig(fb_base_pa, ctx.fb_order);
        }
    }
    true
}

pub fn scanout_ready() -> bool { !CTX.lock().is_empty() }

pub fn scanout_ready_for_key(device_key: virtio::VirtioChildDeviceKey) -> bool {
    CTX.lock().iter().any(|ctx| ctx.device_key == device_key)
}

pub fn dimensions() -> Option<(u32, u32)> {
    let owner = console_owner_key()?;
    dimensions_for_key(owner)
}

pub fn dimensions_for_key(device_key: virtio::VirtioChildDeviceKey) -> Option<(u32, u32)> {
    CTX.lock().iter().find(|c| c.device_key == device_key).map(|c| (c.w, c.h))
}

pub fn framebuffer() -> Option<(u64, u64, u64, u32, u32, u32)> {
    let owner = console_owner_key()?;
    framebuffer_for_key(owner)
}

pub fn framebuffer_for_key(device_key: virtio::VirtioChildDeviceKey) -> Option<(u64, u64, u64, u32, u32, u32)> {
    let g = CTX.lock();
    let c = g.iter().find(|ctx| ctx.device_key == device_key)?;
    Some((c.fb_va - c.hhdm, c.fb_va, c.fb_bytes, c.w * 4, c.w, c.h))
}

#[cfg(target_os = "oxide-kernel")]
pub fn publish_console_scanout(device_key: virtio::VirtioChildDeviceKey) {
    let Some((w, h)) = dimensions_for_key(device_key) else { return };
    let Some(idx) = install_console_fbdev(device_key) else { return };
    if !commit_console_owner_key(device_key, idx) { return; }

    fbcon::kernel::kernel_init(w, h, fbcon_flush_pixels);
    fbdev::set_yield_hook(fbdev_vsync_yield);
    fbdev::set_now_hook(monotonic_now_ns);
    // Register the fbcon printk console only if a `console=tty<n>` token asked
    // for it (Linux `register_console` per `console=`). The VT ttys + scanout
    // are set up regardless; this gates only klog fan-out to the framebuffer.
    // No `console=` at all → default true (keep the sink).
    if cmdline::console_classes().1 {
        klog::set_aux_sink(fbcon::kernel::vt_console_sink);
    }
    fbcon::kernel::set_reply_sink(console::vt_reply_sink);
    tty::live::set_app_cursor_query(fbcon::kernel::fg_app_cursor);
    tty::live::set_bracketed_paste_query(fbcon::kernel::fg_bracketed_paste);
}

#[cfg(not(target_os = "oxide-kernel"))]
pub fn publish_console_scanout(_device_key: virtio::VirtioChildDeviceKey) {}

#[cfg(target_os = "oxide-kernel")]
pub fn unpublish_console_scanout(device_key: virtio::VirtioChildDeviceKey) {
    let owner_raw = device_key.raw();
    if CONSOLE_OWNER_KEY
        .compare_exchange(owner_raw, NO_CONSOLE_OWNER_KEY, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    let fbdev_idx = take_scanout_fbdev_idx(device_key);
    klog::clear_aux_sink();
    tty::live::clear_vt_mode_queries();
    fbcon::kernel::kernel_unregister();
    fbdev::clear_wait_hooks();
    if let Some(idx) = fbdev_idx {
        let _ = fbdev::unregister(idx);
    }
}

#[cfg(not(target_os = "oxide-kernel"))]
pub fn unpublish_console_scanout(_device_key: virtio::VirtioChildDeviceKey) {}

#[cfg(target_os = "oxide-kernel")]
fn fbdev_vsync_yield() {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn key(raw: u32) -> virtio::VirtioChildDeviceKey {
        virtio::VirtioChildDeviceKey::from_raw(raw)
    }

    fn ctrlq() -> virtio::VirtQueueResource {
        virtio::VirtQueueResource {
            index: 0,
            size: 1,
            desc_pa: 0,
            driver_pa: 0,
            device_pa: 0,
            notify_va: 0,
            notify_off: 0,
        }
    }

    fn ctx(device_key: virtio::VirtioChildDeviceKey) -> ScanoutCtx {
        ScanoutCtx {
            device_key,
            bdf: device_key.raw(),
            cfg_va: 0,
            w: 640,
            h: 480,
            fb_va: 0,
            fb_bytes: 0,
            fb_order: pmm::Order(0),
            res_id: BOOT_SCANOUT_RES_ID,
            ctrlq: ctrlq(), cursorq: ctrlq(),
            cmd_buf_va: 0,
            cmd_buf_pa: 0,
            hhdm: 0,
            fbdev_idx: None,
            quiesced: false,
        }
    }

    fn reset_publication_state() {
        CONSOLE_OWNER_KEY.store(NO_CONSOLE_OWNER_KEY, Ordering::Release);
        CTX.lock().clear();
        fbdev::FBS.lock().clear();
    }

    #[test]
    fn fbdev_idx_is_stored_and_taken_by_owner_key() {
        let _guard = super::super::TEST_LOCK.lock();
        reset_publication_state();
        CTX.lock().push(ctx(key(0x10)));
        CTX.lock().push(ctx(key(0x20)));

        assert!(set_scanout_fbdev_idx(key(0x10), Some(3)));
        assert!(set_scanout_fbdev_idx(key(0x20), Some(7)));
        assert!(!set_scanout_fbdev_idx(key(0x30), Some(9)));
        assert_eq!(take_scanout_fbdev_idx(key(0x20)), Some(7));
        assert_eq!(take_scanout_fbdev_idx(key(0x20)), None);
        assert_eq!(take_scanout_fbdev_idx(key(0x10)), Some(3));
        assert_eq!(take_scanout_fbdev_idx(key(0x30)), None);

        reset_publication_state();
    }

    #[test]
    fn console_owner_commits_after_fbdev_idx_is_stored() {
        let _guard = super::super::TEST_LOCK.lock();
        reset_publication_state();
        CTX.lock().push(ctx(key(0x10)));

        let idx = install_console_fbdev(key(0x10)).unwrap();

        assert_eq!(console_owner_key(), None);
        assert_eq!(CTX.lock()[0].fbdev_idx, Some(idx));
        assert_eq!(fbdev::count(), 1);
        assert!(commit_console_owner_key(key(0x10), idx));
        assert_eq!(console_owner_key(), Some(key(0x10)));

        reset_publication_state();
    }

    #[test]
    fn console_owner_commit_failure_unwinds_stored_fbdev_idx() {
        let _guard = super::super::TEST_LOCK.lock();
        reset_publication_state();
        CTX.lock().push(ctx(key(0x10)));
        CONSOLE_OWNER_KEY.store(key(0x20).raw(), Ordering::Release);

        let idx = install_console_fbdev(key(0x10)).unwrap();

        assert!(!commit_console_owner_key(key(0x10), idx));
        assert_eq!(console_owner_key(), Some(key(0x20)));
        assert_eq!(CTX.lock()[0].fbdev_idx, None);
        assert_eq!(fbdev::count(), 0);

        reset_publication_state();
    }

    #[test]
    fn shutdown_scanout_quiesces_without_dropping_publication_metadata() {
        let _guard = super::super::TEST_LOCK.lock();
        reset_publication_state();
        let mut ctx = ctx(key(0x10));
        ctx.fb_va = 0xffff_8000_0000_4000;
        ctx.fb_bytes = 0x2000;
        ctx.fb_order = pmm::Order(1);
        ctx.cmd_buf_pa = 0x9000;
        let idx = fbdev::init_scanout(0x4000, ctx.fb_va, ctx.fb_bytes, 128, 32, 16);
        ctx.fbdev_idx = Some(idx);
        CTX.lock().push(ctx);

        assert!(shutdown_scanout(key(0x10)));

        let guard = CTX.lock();
        assert_eq!(guard.len(), 1);
        assert!(guard[0].quiesced);
        assert_eq!(guard[0].fbdev_idx, Some(idx));
        assert_eq!(guard[0].fb_va, 0xffff_8000_0000_4000);
        assert_eq!(guard[0].fb_bytes, 0x2000);
        assert_eq!(guard[0].fb_order, pmm::Order(1));
        assert_eq!(guard[0].cmd_buf_pa, 0x9000);
        drop(guard);
        assert_eq!(fbdev::count(), 1);

        reset_publication_state();
    }
}
