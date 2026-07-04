use super::*;

pub(super) fn console_owner_bdf() -> Option<u32> {
    match CONSOLE_OWNER_BDF.load(Ordering::Acquire) {
        NO_CONSOLE_OWNER => None,
        bdf => Some(bdf),
    }
}

/// Copy `pixels` into the live framebuffer, then issue transfer+flush.
pub fn fbcon_flush_pixels(pixels: &[u8]) {
    let g = CTX.lock();
    let owner = match console_owner_bdf() { Some(bdf) => bdf, None => return };
    let ctx = match g.iter().find(|ctx| ctx.bdf == owner) { Some(c) => c, None => return };
    if ctx.quiesced {
        return;
    }
    let n = (ctx.fb_bytes as usize).min(pixels.len());
    unsafe {
        let dst = ctx.fb_va as *mut u8;
        for i in 0..n {
            core::ptr::write_volatile(dst.add(i), pixels[i]);
        }
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

pub fn blank_scanout_for_bdf(bdf: u32) {
    let g = CTX.lock();
    let ctx = match g.iter().find(|ctx| ctx.bdf == bdf) { Some(c) => c, None => return };
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

pub fn unblank_scanout_for_bdf(bdf: u32) {
    if console_owner_bdf() == Some(bdf) {
        fbcon::kernel::force_repaint();
    }
}

pub(super) fn install_scanout_ctx(
    device_key: virtio::VirtioChildDeviceKey,
    bdf: u32,
    w: u32, h: u32, cfg_va: u64, fb_va: u64, fb_bytes: u64, fb_pages_alloc: usize, res_id: u32,
    ctrlq: virtio::VirtQueueResource, cmd_buf_va: u64, cmd_buf_pa: u64, hhdm: u64,
) -> bool {
    let mut ctxs = CTX.lock();
    if ctxs.iter().any(|ctx| ctx.device_key == device_key) {
        return false;
    }
    ctxs.push(ScanoutCtx {
        device_key, bdf, cfg_va, w, h, fb_va, fb_bytes, fb_pages_alloc, res_id,
        ctrlq, cmd_buf_va, cmd_buf_pa, hhdm, fbdev_idx: None, quiesced: false,
    });
    true
}

#[cfg(target_os = "oxide-kernel")]
fn set_scanout_fbdev_idx(bdf: u32, fbdev_idx: Option<u32>) -> bool {
    let mut ctxs = CTX.lock();
    let Some(ctx) = ctxs.iter_mut().find(|ctx| ctx.bdf == bdf) else {
        return false;
    };
    ctx.fbdev_idx = fbdev_idx;
    true
}

#[cfg(target_os = "oxide-kernel")]
fn take_scanout_fbdev_idx(bdf: u32) -> Option<u32> {
    let mut ctxs = CTX.lock();
    let ctx = ctxs.iter_mut().find(|ctx| ctx.bdf == bdf)?;
    ctx.fbdev_idx.take()
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
    if ctx.cfg_va != 0 {
        unsafe { core::ptr::write_volatile((ctx.cfg_va + 0x14) as *mut u8, 0u8); }
    }
    let fb_base_pa = ctx.fb_va - ctx.hhdm;
    unsafe {
        if ctx.cmd_buf_pa != 0 {
            pmm::setup::free_one_frame(ctx.cmd_buf_pa);
        }
        for i in 0..ctx.fb_pages_alloc {
            let frame = fb_base_pa + (i as u64) * 4096;
            if frame != 0 {
                pmm::setup::free_one_frame(frame);
            }
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
    if cfg_va != 0 {
        unsafe { core::ptr::write_volatile((cfg_va + 0x14) as *mut u8, 0u8); }
    }
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
        for i in 0..ctx.fb_pages_alloc {
            let frame = fb_base_pa + (i as u64) * 4096;
            if frame != 0 {
                pmm::setup::free_one_frame(frame);
            }
        }
    }
    true
}

pub fn scanout_ready() -> bool { !CTX.lock().is_empty() }

pub fn scanout_ready_for_bdf(bdf: u32) -> bool {
    CTX.lock().iter().any(|ctx| ctx.bdf == bdf)
}

pub fn dimensions() -> Option<(u32, u32)> {
    let owner = console_owner_bdf()?;
    dimensions_for_bdf(owner)
}

pub fn dimensions_for_bdf(bdf: u32) -> Option<(u32, u32)> {
    CTX.lock().iter().find(|c| c.bdf == bdf).map(|c| (c.w, c.h))
}

pub fn framebuffer() -> Option<(u64, u64, u64, u32, u32, u32)> {
    let owner = console_owner_bdf()?;
    framebuffer_for_bdf(owner)
}

pub fn framebuffer_for_bdf(bdf: u32) -> Option<(u64, u64, u64, u32, u32, u32)> {
    let g = CTX.lock();
    let c = g.iter().find(|ctx| ctx.bdf == bdf)?;
    Some((c.fb_va - c.hhdm, c.fb_va, c.fb_bytes, c.w * 4, c.w, c.h))
}

#[cfg(target_os = "oxide-kernel")]
pub fn publish_console_scanout(bdf: u32) {
    let Some((w, h)) = dimensions_for_bdf(bdf) else { return };
    if CONSOLE_OWNER_BDF
        .compare_exchange(NO_CONSOLE_OWNER, bdf, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }

    let Some((base_pa, fb_va, bytes, pitch, fw, fh)) = framebuffer_for_bdf(bdf) else {
        CONSOLE_OWNER_BDF.store(NO_CONSOLE_OWNER, Ordering::Release);
        return;
    };
    let idx = fbdev::init_scanout(base_pa, fb_va, bytes, pitch, fw, fh);
    if idx == fbdev::INVALID_FB_INDEX
        || !fbdev::set_ops(idx, fbdev::FbOps {
            driver_key: bdf,
            flush: super::flush_scanout_for_bdf,
            blank: blank_scanout_for_bdf,
            unblank: unblank_scanout_for_bdf,
        })
        || !set_scanout_fbdev_idx(bdf, Some(idx))
    {
        if idx != fbdev::INVALID_FB_INDEX {
            let _ = fbdev::unregister(idx);
        }
        CONSOLE_OWNER_BDF.store(NO_CONSOLE_OWNER, Ordering::Release);
        return;
    }

    fbcon::kernel::kernel_init(w, h, fbcon_flush_pixels);
    fbdev::set_yield_hook(fbdev_vsync_yield);
    fbdev::set_now_hook(monotonic_now_ns);
    klog::set_aux_sink(fbcon::kernel::vt_console_sink);
    fbcon::kernel::set_reply_sink(console::vt_reply_sink);
    tty::live::set_app_cursor_query(fbcon::kernel::fg_app_cursor);
    tty::live::set_bracketed_paste_query(fbcon::kernel::fg_bracketed_paste);
}

#[cfg(not(target_os = "oxide-kernel"))]
pub fn publish_console_scanout(_bdf: u32) {}

#[cfg(target_os = "oxide-kernel")]
pub fn unpublish_console_scanout(bdf: u32) {
    if CONSOLE_OWNER_BDF
        .compare_exchange(bdf, NO_CONSOLE_OWNER, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    let fbdev_idx = take_scanout_fbdev_idx(bdf);
    klog::clear_aux_sink();
    tty::live::clear_vt_mode_queries();
    fbcon::kernel::kernel_unregister();
    fbdev::clear_wait_hooks();
    if let Some(idx) = fbdev_idx {
        let _ = fbdev::unregister(idx);
    }
}

#[cfg(not(target_os = "oxide-kernel"))]
pub fn unpublish_console_scanout(_bdf: u32) {}

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
