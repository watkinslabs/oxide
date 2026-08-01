use super::*;
use super::probe::submit_cursor_one;

fn key_from_raw(raw: u32) -> virtio::VirtioChildDeviceKey {
    virtio::VirtioChildDeviceKey::from_raw(raw)
}

fn key_from_scanout_driver(driver_key: drm::node::ScanoutDriverKey) -> virtio::VirtioChildDeviceKey {
    key_from_raw(driver_key.raw())
}

pub fn boot_scanout_res_id_for_key(_driver_key: drm::node::ScanoutDriverKey) -> u32 { BOOT_SCANOUT_RES_ID }

fn submit_ctrl_for_key<F: Fn(&mut [u8]) -> usize>(driver_key: drm::node::ScanoutDriverKey, encode: F) -> bool {
    let owner = key_from_scanout_driver(driver_key);
    let g = CTX.lock();
    let ctx = match g.iter().find(|ctx| ctx.device_key == owner) { Some(c) => c, None => return false };
    if ctx.quiesced {
        return false;
    }
    let cmd_buf_va_p = ctx.cmd_buf_va as *mut u8;
    // SAFETY: `submit_one`'s contract — `CTX` is held for the whole call, so
    // this ctx's 4 KiB command frame and its CTRLQ stay live and single-producer
    // and the previous submission on the queue was already retired.
    let ok = unsafe {
        submit_one(cmd_buf_va_p, ctx.cmd_buf_pa, |b| encode(b), ctx.ctrlq, ctx.hhdm)
    };
    if !ok { return false; }
    // SAFETY: RESP_OFF (0x200) is a 4-byte-aligned offset with 0xE00 bytes left
    // in the ctx's command frame, so this reads the reply header's `type` word
    // in bounds; `ok` means the device retired the descriptor, so it is done
    // writing, and `CTX` is still held so the frame cannot be freed.
    let resp = unsafe { core::ptr::read_volatile((ctx.cmd_buf_va + 0x200) as *const u32) };
    resp >= 0x1100 && resp < 0x1200
}

pub fn create_scanout_from_pa_for_key(driver_key: drm::node::ScanoutDriverKey, pa: u64, w: u32, h: u32, fmt_drm: u32) -> Option<u32> {
    let owner = key_from_scanout_driver(driver_key);
    if !scanout_ready_for_key(owner) { return None; }
    let fmt = crate::drm_fourcc_to_virtio(fmt_drm)?;
    if w == 0 || h == 0 { return None; }
    // virtio-gpu RESOURCE_CREATE_2D derives the host stride as width*bpp, so the
    // backing must be tightly packed at that stride (BYTES_PER_PIXEL for the
    // XRGB/ARGB scanout formats). Mode widths are alignment-friendly (e.g. 1280),
    // so the dumb pitch equals width*bpp and no padding is dropped here.
    const BYTES_PER_PIXEL: u64 = 4;
    let bytes = (w as u64) * (h as u64) * BYTES_PER_PIXEL;
    if bytes == 0 || bytes > u32::MAX as u64 { return None; }
    let res_id = NEXT_RUNTIME_RES_ID.fetch_add(1, Ordering::AcqRel);
    if !submit_ctrl_for_key(driver_key, |b| crate::encode_resource_create_2d(b, res_id, fmt, w, h)) {
        return None;
    }
    if !submit_ctrl_for_key(driver_key, |b| crate::encode_resource_attach_backing_one(b, res_id, pa, bytes as u32)) {
        let _ = unref_scanout_resource_for_key(driver_key, res_id);
        return None;
    }
    Some(res_id)
}

pub fn unref_scanout_resource_for_key(driver_key: drm::node::ScanoutDriverKey, res_id: u32) -> bool {
    if res_id == 0 || res_id == BOOT_SCANOUT_RES_ID {
        return false;
    }
    // A destroyed resource can no longer be what the scanout is bound to, so
    // drop the record; leaving it would let a later present skip the rebind.
    {
        let owner = key_from_scanout_driver(driver_key);
        let mut g = CTX.lock();
        if let Some(ctx) = g.iter_mut().find(|ctx| ctx.device_key == owner) {
            if ctx.bound.is_some_and(|b| b.res_id == res_id) { ctx.bound = None; }
        }
    }
    let _ = submit_ctrl_for_key(driver_key, |b| crate::encode_resource_detach_backing(b, res_id));
    submit_ctrl_for_key(driver_key, |b| crate::encode_resource_unref(b, res_id))
}

/// Present the whole of `res_id` on scanout 0 at `w` x `h`.
/// # C: O(1) + O(scanout)
pub fn set_scanout_for_key(driver_key: drm::node::ScanoutDriverKey, res_id: u32, w: u32, h: u32) -> bool {
    present_rect_for_key(driver_key, res_id, w, h, present::Rect::full(w, h))
}

/// `ScanoutOps::present` — present the damaged region userspace reported.
/// # C: O(1) + O(scanout)
pub fn present_for_key(driver_key: drm::node::ScanoutDriverKey, res_id: u32, w: u32, h: u32,
    damage: drm::node::DamageRect) -> bool
{
    present_rect_for_key(driver_key, res_id, w, h,
        present::Rect { x: damage.x, y: damage.y, w: damage.w, h: damage.h })
}

/// Present `rect` of `res_id` on scanout 0, following `present::plan`: upload
/// the damaged region, bind the scanout only when the binding actually
/// changed, then flush. The whole sequence runs under one `CTX` acquisition so
/// a concurrent presentation cannot interleave between the commands and leave
/// the scanout bound to a resource whose contents were never uploaded.
/// # C: O(1) + O(scanout)
pub fn present_rect_for_key(driver_key: drm::node::ScanoutDriverKey, res_id: u32,
    w: u32, h: u32, rect: present::Rect) -> bool
{
    let owner = key_from_scanout_driver(driver_key);
    if !scanout_ready_for_key(owner) || w == 0 || h == 0 { return false; }
    let Some(rect) = present::clamp_rect(rect, w, h) else { return false };
    let next = present::Binding { res_id, w, h };
    let mut g = CTX.lock();
    let Some(ctx) = g.iter_mut().find(|ctx| ctx.device_key == owner) else { return false };
    if ctx.quiesced { return false; }
    let (steps, n) = present::plan(ctx.bound, next, rect, damage::BYTES_PER_PIXEL as u32);
    let cmd_buf_va_p = ctx.cmd_buf_va as *mut u8;
    let (cmd_buf_pa, ctrlq, hhdm) = (ctx.cmd_buf_pa, ctx.ctrlq, ctx.hhdm);
    for step in steps.iter().take(n) {
        let ok = match *step {
            // SAFETY: `submit_one`'s contract — `CTX` is held across the whole
            // plan, so the ctx's 4 KiB command frame and CTRLQ stay live and
            // single-producer, and each step waits for the previous descriptor
            // to retire before the frame is reused.
            present::Step::Transfer { rect: r, offset } => unsafe {
                submit_one(cmd_buf_va_p, cmd_buf_pa,
                    |b| crate::encode_transfer_to_host_2d(b, res_id, r.x, r.y, r.w, r.h, offset), ctrlq, hhdm)
            },
            // SAFETY: `submit_one`'s contract — `CTX` is held across the whole
            // plan, so the ctx's 4 KiB command frame and CTRLQ stay live and
            // single-producer, and each step waits for the previous descriptor
            // to retire before the frame is reused.
            present::Step::SetScanout => unsafe {
                submit_one(cmd_buf_va_p, cmd_buf_pa,
                    |b| crate::encode_set_scanout(b, 0, res_id, 0, 0, w, h), ctrlq, hhdm)
            },
            // SAFETY: `submit_one`'s contract — `CTX` is held across the whole
            // plan, so the ctx's 4 KiB command frame and CTRLQ stay live and
            // single-producer, and each step waits for the previous descriptor
            // to retire before the frame is reused.
            present::Step::Flush { rect: r } => unsafe {
                submit_one(cmd_buf_va_p, cmd_buf_pa,
                    |b| crate::encode_resource_flush(b, res_id, r.x, r.y, r.w, r.h), ctrlq, hhdm)
            },
        };
        if !ok { return false; }
        if matches!(step, present::Step::SetScanout) { ctx.bound = Some(next); }
    }
    true
}

/// Publish a cursor resource after transferring its pixels on CTRLQ, then
/// update it on CURSORQ. The shared context lock serializes both queues and
/// the reusable command buffer, so the data-only cursor descriptor cannot be
/// overwritten before its used-ring completion.
pub fn set_cursor_for_key(driver_key: drm::node::ScanoutDriverKey, res_id: u32,
    w: u32, h: u32, x: i32, y: i32, hot_x: i32, hot_y: i32) -> bool {
    if res_id == 0 {
        let owner = key_from_scanout_driver(driver_key);
        let g = CTX.lock();
        let ctx = match g.iter().find(|ctx| ctx.device_key == owner) { Some(c) => c, None => return false };
        if ctx.quiesced { return false; }
        // SAFETY: `submit_cursor_one`'s contract — `CTX` is held, so the ctx's
        // 4 KiB command frame and CURSORQ are live and single-producer; the
        // cursor area 0x100..0x200 is disjoint from the CTRLQ areas.
        return unsafe {
            submit_cursor_one(ctx.cmd_buf_va as *mut u8, ctx.cmd_buf_pa,
                |b| crate::encode_update_cursor(b, 0, 0, 0, 0, 0, 0, 0), ctx.cursorq, ctx.hhdm)
        };
    }
    if w == 0 || h == 0 || w > 64 || h > 64 || hot_x < 0 || hot_y < 0
        || hot_x as u32 >= w || hot_y as u32 >= h {
        return false;
    }
    let owner = key_from_scanout_driver(driver_key);
    let g = CTX.lock();
    let ctx = match g.iter().find(|ctx| ctx.device_key == owner) { Some(c) => c, None => return false };
    if ctx.quiesced { return false; }
    let cmd_buf_va = ctx.cmd_buf_va as *mut u8;
    // SAFETY: `submit_one` / `submit_cursor_one` contract — `CTX` is held for
    // all three commands, so the ctx's 4 KiB command frame and both queues stay
    // live and single-producer, and each command waits for the previous
    // descriptor to retire before the frame is reused.
    unsafe {
        if !submit_one(cmd_buf_va, ctx.cmd_buf_pa,
            |b| crate::encode_transfer_to_host_2d(b, res_id, 0, 0, w, h, 0), ctx.ctrlq, ctx.hhdm) {
            return false;
        }
        if !submit_one(cmd_buf_va, ctx.cmd_buf_pa,
            |b| crate::encode_resource_flush(b, res_id, 0, 0, w, h), ctx.ctrlq, ctx.hhdm) {
            return false;
        }
        submit_cursor_one(cmd_buf_va, ctx.cmd_buf_pa,
            |b| crate::encode_update_cursor(b, res_id, w, h, x, y, hot_x, hot_y), ctx.cursorq, ctx.hhdm)
    }
}

/// Reposition the current cursor without re-uploading its resource.
pub fn move_cursor_for_key(driver_key: drm::node::ScanoutDriverKey, x: i32, y: i32) -> bool {
    let owner = key_from_scanout_driver(driver_key);
    let g = CTX.lock();
    let ctx = match g.iter().find(|ctx| ctx.device_key == owner) { Some(c) => c, None => return false };
    if ctx.quiesced { return false; }
    // SAFETY: `submit_cursor_one`'s contract — `CTX` is held, so the ctx's 4 KiB
    // command frame and CURSORQ are live and single-producer, and the cursor
    // area 0x100..0x200 is disjoint from the CTRLQ request and reply areas.
    unsafe {
        submit_cursor_one(ctx.cmd_buf_va as *mut u8, ctx.cmd_buf_pa,
            |b| crate::encode_move_cursor(b, x, y), ctx.cursorq, ctx.hhdm)
    }
}

pub fn restore_console_scanout_for_key(driver_key: drm::node::ScanoutDriverKey) -> bool {
    let owner = key_from_scanout_driver(driver_key);
    let (w, h) = match dimensions_for_key(owner) { Some(d) => d, None => return false };
    let ok = set_scanout_for_key(driver_key, BOOT_SCANOUT_RES_ID, w, h);
    fbcon::kernel::force_repaint();
    ok
}

pub fn register_drm_hooks(card_id: u32, device_key: virtio::VirtioChildDeviceKey) {
    let Some(driver_key) = drm::node::ScanoutDriverKey::from_raw(device_key.raw()) else { return };
    drm::node::set_scanout_ops(card_id, drm::node::ScanoutOps {
        driver_key,
        create_from_pa: create_scanout_from_pa_for_key,
        destroy_resource: unref_scanout_resource_for_key,
        present: present_for_key,
        set_cursor: set_cursor_for_key,
        move_cursor: move_cursor_for_key,
        restore_console: restore_console_scanout_for_key,
        boot_res_id: boot_scanout_res_id_for_key,
    });
}

pub fn unregister_drm_hooks(card_id: u32) {
    drm::node::clear_scanout_ops(card_id);
}

pub fn flush_scanout_for_key(driver_key: fbdev::FbDriverKey) {
    let owner = key_from_raw(driver_key.raw());
    let g = CTX.lock();
    let ctx = match g.iter().find(|ctx| ctx.device_key == owner) { Some(c) => c, None => return };
    if ctx.quiesced {
        return;
    }
    let cmd_buf_va_p = ctx.cmd_buf_va as *mut u8;
    let (res_id, w, h) = (ctx.res_id, ctx.w, ctx.h);
    // SAFETY: `submit_one`'s contract — `CTX` is held for the whole call, so
    // this ctx's 4 KiB command frame and its CTRLQ stay live and single-producer
    // and the previous submission on the queue was already retired.
    unsafe {
        let _ = submit_one(cmd_buf_va_p, ctx.cmd_buf_pa,
            |buf| crate::encode_transfer_to_host_2d(buf, res_id, 0, 0, w, h, 0),
            ctx.ctrlq, ctx.hhdm);
        let _ = submit_one(cmd_buf_va_p, ctx.cmd_buf_pa,
            |buf| crate::encode_resource_flush(buf, res_id, 0, 0, w, h),
            ctx.ctrlq, ctx.hhdm);
    }
}
