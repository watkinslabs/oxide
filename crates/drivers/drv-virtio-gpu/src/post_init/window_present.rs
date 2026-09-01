use super::{console_owner_key, ctx_lock, runtime_queue};

/// Copy a native GDI surface into the primary scanout and flush its damage. # C: O(width*height)
pub fn present_window_pixels(pixels: &[u32], width: u32, height: u32, x: i32, y: i32) -> bool {
    if width == 0 || height == 0 || pixels.len() < (width as usize).saturating_mul(height as usize) { return false; }
    let Some(owner) = console_owner_key() else { return false; };
    let mut contexts = ctx_lock();
    let Some(ctx) = contexts.iter_mut().find(|ctx| ctx.device_key == owner) else { return false; };
    if ctx.quiesced { return false; }
    let left = x.max(0).min(ctx.w as i32);
    let top = y.max(0).min(ctx.h as i32);
    let right = x.saturating_add(width as i32).max(left).min(ctx.w as i32);
    let bottom = y.saturating_add(height as i32).max(top).min(ctx.h as i32);
    if right <= left || bottom <= top { return true; }
    let source_x = (left - x) as usize;
    let source_y = (top - y) as usize;
    let row_words = (right - left) as usize;
    for row in 0..(bottom - top) as usize {
        let source = &pixels[(source_y + row) * width as usize + source_x..(source_y + row) * width as usize + source_x + row_words];
        let destination = (ctx.fb_va as *mut u32).wrapping_add((top as usize + row) * ctx.w as usize + left as usize);
        // SAFETY: ctx owns a mapped guest scanout of ctx.fb_bytes bytes; the clipped row lies within that allocation and source is bounded by pixels above.
        unsafe { core::ptr::copy_nonoverlapping(source.as_ptr(), destination, row_words); }
    }
    let res_id = ctx.res_id;
    let scanout_w = ctx.w;
    let (damage_x, damage_y, damage_w, damage_h) = (left as u32, top as u32, (right - left) as u32, (bottom - top) as u32);
    drop(contexts);
    runtime_queue::enqueue_ctrl(owner, &[
        runtime_queue::RuntimeCmd::Transfer { res_id, x: damage_x, y: damage_y, w: damage_w, h: damage_h, off: (damage_y as u64 * scanout_w as u64 + damage_x as u64) * 4 },
        runtime_queue::RuntimeCmd::Flush { res_id, x: damage_x, y: damage_y, w: damage_w, h: damage_h },
    ])
}
