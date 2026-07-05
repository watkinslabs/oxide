use super::*;

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
    let ok = unsafe {
        submit_one(cmd_buf_va_p, ctx.cmd_buf_pa, |b| encode(b), ctx.ctrlq, ctx.hhdm)
    };
    if !ok { return false; }
    let resp = unsafe { core::ptr::read_volatile((ctx.cmd_buf_va + 0x200) as *const u32) };
    resp >= 0x1100 && resp < 0x1200
}

pub fn create_scanout_from_pa_for_key(driver_key: drm::node::ScanoutDriverKey, pa: u64, w: u32, h: u32, fmt_drm: u32) -> Option<u32> {
    let owner = key_from_scanout_driver(driver_key);
    if !scanout_ready_for_key(owner) { return None; }
    let fmt = crate::drm_fourcc_to_virtio(fmt_drm)?;
    if w == 0 || h == 0 { return None; }
    let bytes = (w as u64) * (h as u64) * 4;
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
    let _ = submit_ctrl_for_key(driver_key, |b| crate::encode_resource_detach_backing(b, res_id));
    submit_ctrl_for_key(driver_key, |b| crate::encode_resource_unref(b, res_id))
}

pub fn set_scanout_for_key(driver_key: drm::node::ScanoutDriverKey, res_id: u32, w: u32, h: u32) -> bool {
    let owner = key_from_scanout_driver(driver_key);
    if !scanout_ready_for_key(owner) || w == 0 || h == 0 { return false; }
    if !submit_ctrl_for_key(driver_key, |b| crate::encode_set_scanout(b, 0, res_id, 0, 0, w, h)) { return false; }
    if !submit_ctrl_for_key(driver_key, |b| crate::encode_transfer_to_host_2d(b, res_id, 0, 0, w, h, 0)) { return false; }
    if !submit_ctrl_for_key(driver_key, |b| crate::encode_resource_flush(b, res_id, 0, 0, w, h)) { return false; }
    true
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
        set_scanout: set_scanout_for_key,
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
    unsafe {
        let _ = submit_one(cmd_buf_va_p, ctx.cmd_buf_pa,
            |buf| crate::encode_transfer_to_host_2d(buf, res_id, 0, 0, w, h, 0),
            ctx.ctrlq, ctx.hhdm);
        let _ = submit_one(cmd_buf_va_p, ctx.cmd_buf_pa,
            |buf| crate::encode_resource_flush(buf, res_id, 0, 0, w, h),
            ctx.ctrlq, ctx.hhdm);
    }
}
