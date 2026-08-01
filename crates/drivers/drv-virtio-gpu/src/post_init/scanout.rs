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

/// Copy the damaged part of `pixels` into the live framebuffer, then issue
/// transfer+flush for exactly that rectangle.
///
/// Scope is the whole cost here. Every console write reaches this path, and
/// uploading the whole frame for one changed line meant a multi-megabyte copy
/// under the `CTX` spinlock (interrupts masked) plus two whole-screen device
/// commands, each of which spin-waits for the used ring. The console tells us
/// which scanlines actually changed, so all three shrink together.
///
/// An earlier fix cut the copy's constant factor — it had been a byte-by-byte
/// `write_volatile` loop whose IRQ-masked window stalled the timer tick for
/// seconds — but left it whole-frame; this cuts the extent.
pub fn fbcon_flush_pixels(pixels: &[u8], rect: fbcon::kernel::FlushRect) {
    let g = CTX.lock();
    let owner = match console_owner_key() { Some(key) => key, None => return };
    let ctx = match g.iter().find(|ctx| ctx.device_key == owner) { Some(c) => c, None => return };
    if ctx.quiesced {
        return;
    }
    let plan = match damage::plan_copy(rect, ctx.w, ctx.h, pixels.len(), ctx.fb_bytes as usize) {
        Some(p) => p,
        // Nothing of the damage lands on this resource: no copy, no command.
        None => return,
    };
    // SAFETY: copy_damage into the GPU resource backing at ctx.fb_va, whose
    // length ctx.fb_bytes bounded the plan above, from `pixels` whose length
    // bounded it likewise; the plan's last touched byte is inside both.
    unsafe { copy_damage(pixels, ctx.fb_va as *mut u8, &plan); }
    let cmd_buf_va_p = ctx.cmd_buf_va as *mut u8;
    let res_id = ctx.res_id;
    let (x, y, w, h, off) = (plan.x, plan.y, plan.w, plan.h, plan.dst_off);
    // The rectangle is `plan_copy`'s, already clipped to `ctx.w`/`ctx.h`, so the
    // device is asked to transfer only bytes the copy above actually wrote.
    // SAFETY: `submit_one`'s contract — `CTX` is held, so this ctx's command
    // frame and CTRLQ are live and single-producer for the whole call, and the
    // frame was allocated 4 KiB by the probe that installed the ctx.
    unsafe {
        let _ = submit_one(cmd_buf_va_p, ctx.cmd_buf_pa,
            |buf| crate::encode_transfer_to_host_2d(buf, res_id, x, y, w, h, off),
            ctx.ctrlq, ctx.hhdm);
        let _ = submit_one(cmd_buf_va_p, ctx.cmd_buf_pa,
            |buf| crate::encode_resource_flush(buf, res_id, x, y, w, h),
            ctx.ctrlq, ctx.hhdm);
    }
}

/// Copy the planned scanlines from `src` into the resource backing at `dst`.
/// Guest RAM on both sides (write-back, not MMIO), so plain `memcpy` moves —
/// no per-byte volatile.
///
/// # Safety
/// `dst` must be the base of a backing at least as long as the `dst_len`
/// `plan` was built against, and `src` at least its `src_len`.
/// # C: O(plan.bytes())
unsafe fn copy_damage(src: &[u8], dst: *mut u8, plan: &damage::CopyPlan) {
    if plan.is_contiguous() {
        // SAFETY: plan_copy proved src_off..+bytes() is inside src and
        // dst_off..+bytes() inside the backing; contiguity means the rows are
        // adjacent in both, so this is the same extent as the loop below.
        unsafe {
            core::ptr::copy_nonoverlapping(
                src.as_ptr().add(plan.src_off),
                dst.add(plan.dst_off as usize),
                plan.bytes(),
            );
        }
        return;
    }
    for row in 0..plan.h as usize {
        // SAFETY: plan_copy bounded the last row's end against both buffer
        // lengths, so every row offset derived here is in range of each.
        unsafe {
            core::ptr::copy_nonoverlapping(
                src.as_ptr().add(plan.src_off + row * plan.src_stride_b),
                dst.add(plan.dst_off as usize + row * plan.dst_stride_b),
                plan.row_bytes,
            );
        }
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
    // SAFETY: `fb_va`/`fb_bytes` are the HHDM view and byte length of the
    // `alloc_contig` run this ctx owns as its resource backing, so the whole
    // range is inside it; `CTX` is held and `quiesced` was checked, so the ctx
    // (and its run) cannot be torn down underneath this write.
    unsafe { core::ptr::write_bytes(ctx.fb_va as *mut u8, 0, ctx.fb_bytes as usize); }
    let cmd_buf_va_p = ctx.cmd_buf_va as *mut u8;
    let (res_id, w, h) = (ctx.res_id, ctx.w, ctx.h);
    // SAFETY: `submit_one`'s contract — `CTX` is held, so this ctx's command
    // frame and CTRLQ are live and single-producer for the whole call, and the
    // frame was allocated 4 KiB by the probe that installed the ctx.
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
    w: u32, h: u32, cfg_va: u64, fb_va: u64, fb_bytes: u64, fb_order: pmm::Order, res_id: u32,
    ctrlq: virtio::VirtQueueResource, cursorq: virtio::VirtQueueResource,
    cmd_buf_va: u64, cmd_buf_pa: u64, hhdm: u64,
) -> bool {
    let mut ctxs = CTX.lock();
    if ctxs.iter().any(|ctx| ctx.device_key == device_key) {
        return false;
    }
    ctxs.push(ScanoutCtx {
        device_key, cfg_va, w, h, fb_va, fb_bytes, fb_order, res_id,
        ctrlq, cursorq, cmd_buf_va, cmd_buf_pa, hhdm, fbdev_idx: None, quiesced: false, bound: None,
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
    release_scanout_dma(&ctx, virtio::reset_device(ctx.cfg_va));
    true
}

/// Return a removed scanout's DMA frames to the PMM, but only those
/// `release::releasable_dma` says the device can no longer reach.
/// # C: O(1)
fn release_scanout_dma(ctx: &ScanoutCtx, reset_confirmed: bool) {
    let fb_base_pa = ctx.fb_va.wrapping_sub(ctx.hhdm);
    let (cmd_frame, fb_run) =
        release::releasable_dma(reset_confirmed, ctx.cmd_buf_pa, fb_base_pa);
    if !reset_confirmed {
        klog::write_raw(b"[VGPU] reset unconfirmed, leaking scanout DMA frames\n");
    }
    if let Some(pa) = cmd_frame {
        // SAFETY: the command frame this driver allocated in `get_display_info`
        // and stored in the ctx just removed from CTX, so no other path can
        // reach it; the confirmed reset proves the device no longer holds a
        // descriptor naming it, and it is freed exactly once here.
        unsafe { pmm::setup::free_one_frame(pa); }
    }
    if let Some(pa) = fb_run {
        // SAFETY: the `alloc_contig(ctx.fb_order)` run this driver attached as
        // the scanout resource's backing store, freed at the same order it was
        // allocated; the confirmed reset dropped the device's resource table, so
        // nothing can still DMA into it, and the ctx that owned it is gone.
        unsafe { pmm::setup::free_contig(pa, ctx.fb_order); }
    }
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
    let _ = virtio::reset_device(cfg_va);
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
    // The probe reached ATTACH_BACKING before this unwind, so the device's
    // resource table names `fb_base_pa` as live backing and no DETACH is ever
    // sent. Reset first and honour its confirmation, exactly as the orderly
    // removal path does — freeing here unconditionally handed a physical
    // address the device may still write into back to the buddy allocator.
    release_scanout_dma(&ctx, virtio::reset_device(ctx.cfg_va));
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
    // SAFETY: fbdev calls its yield hook from process context while waiting on
    // vsync, holding no spinlock — the precondition `tick_yield` needs to run
    // the scheduler and return to this task.
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
            bound: None,
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
