use super::*;

pub fn boot_scanout_res_id_for_bdf(_bdf: u32) -> u32 { BOOT_SCANOUT_RES_ID }

fn submit_ctrl_for_bdf<F: Fn(&mut [u8]) -> usize>(bdf: u32, encode: F) -> bool {
    let g = CTX.lock();
    let ctx = match g.iter().find(|ctx| ctx.bdf == bdf) { Some(c) => c, None => return false };
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
        let _ = unref_scanout_resource_for_bdf(bdf, res_id);
        return None;
    }
    Some(res_id)
}

pub fn unref_scanout_resource_for_bdf(bdf: u32, res_id: u32) -> bool {
    if res_id == 0 || res_id == BOOT_SCANOUT_RES_ID {
        return false;
    }
    let _ = submit_ctrl_for_bdf(bdf, |b| crate::encode_resource_detach_backing(b, res_id));
    submit_ctrl_for_bdf(bdf, |b| crate::encode_resource_unref(b, res_id))
}

pub fn set_scanout_for_bdf(bdf: u32, res_id: u32, w: u32, h: u32) -> bool {
    if !scanout_ready_for_bdf(bdf) || w == 0 || h == 0 { return false; }
    if !submit_ctrl_for_bdf(bdf, |b| crate::encode_set_scanout(b, 0, res_id, 0, 0, w, h)) { return false; }
    if !submit_ctrl_for_bdf(bdf, |b| crate::encode_transfer_to_host_2d(b, res_id, 0, 0, w, h, 0)) { return false; }
    if !submit_ctrl_for_bdf(bdf, |b| crate::encode_resource_flush(b, res_id, 0, 0, w, h)) { return false; }
    true
}

pub fn restore_console_scanout_for_bdf(bdf: u32) -> bool {
    let (w, h) = match dimensions_for_bdf(bdf) { Some(d) => d, None => return false };
    let ok = set_scanout_for_bdf(bdf, BOOT_SCANOUT_RES_ID, w, h);
    fbcon::kernel::force_repaint();
    ok
}

pub fn register_drm_hooks(card_id: u32, bdf: u32) {
    drm::node::set_scanout_ops(card_id, drm::node::ScanoutOps {
        driver_key: bdf,
        create_from_pa: create_scanout_from_pa_for_bdf,
        destroy_resource: unref_scanout_resource_for_bdf,
        set_scanout: set_scanout_for_bdf,
        restore_console: restore_console_scanout_for_bdf,
        boot_res_id: boot_scanout_res_id_for_bdf,
    });
}

pub fn unregister_drm_hooks(card_id: u32) {
    drm::node::clear_scanout_ops(card_id);
}

pub fn flush_scanout_for_bdf(bdf: u32) {
    let g = CTX.lock();
    let ctx = match g.iter().find(|ctx| ctx.bdf == bdf) { Some(c) => c, None => return };
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
