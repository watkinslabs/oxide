use super::{console_owner_key, ctx_lock, runtime_queue};

/// Copy a native GDI surface into the primary scanout and flush its damage. # C: O(width*height)
pub fn present_window_pixels(pixels: &[u32], width: u32, height: u32, x: i32, y: i32) -> bool {
    if width == 0 || height == 0 || pixels.len() < (width as usize).saturating_mul(height as usize) { return false; }
    let Some(owner) = console_owner_key() else { return false; };
    let mut contexts = ctx_lock();
    let Some(ctx) = contexts.iter_mut().find(|ctx| ctx.device_key == owner) else { return false; };
    if ctx.quiesced { return false; }
    let Some(clip) = clip_present_rect(width, height, x, y, ctx.w, ctx.h) else { return true; };
    let (left, top, right, bottom) = (clip.left, clip.top, clip.right, clip.bottom);
    let source_x = clip.source_x as usize;
    let source_y = clip.source_y as usize;
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

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct PresentClip { left: u32, top: u32, right: u32, bottom: u32, source_x: u32, source_y: u32 }

fn clip_present_rect(width: u32, height: u32, x: i32, y: i32, scan_width: u32, scan_height: u32) -> Option<PresentClip> {
    if width == 0 || height == 0 || scan_width == 0 || scan_height == 0 { return None; }
    let x = i64::from(x); let y = i64::from(y);
    let right = x.checked_add(i64::from(width))?; let bottom = y.checked_add(i64::from(height))?;
    let left_clip = x.max(0).min(i64::from(scan_width)); let top_clip = y.max(0).min(i64::from(scan_height));
    let right_clip = right.max(left_clip).min(i64::from(scan_width)); let bottom_clip = bottom.max(top_clip).min(i64::from(scan_height));
    if right_clip <= left_clip || bottom_clip <= top_clip { return None; }
    Some(PresentClip { left: left_clip as u32, top: top_clip as u32, right: right_clip as u32, bottom: bottom_clip as u32,
        source_x: (left_clip - x) as u32, source_y: (top_clip - y) as u32 })
}

#[cfg(test)]
mod tests {
    use super::{clip_present_rect, PresentClip};

    #[test]
    fn present_clip_uses_wide_arithmetic_for_large_surfaces() {
        assert_eq!(clip_present_rect(u32::MAX, 2, 0, 0, 640, 480), Some(PresentClip { left: 0, top: 0, right: 640, bottom: 2, source_x: 0, source_y: 0 }));
        assert_eq!(clip_present_rect(10, 10, -4, -3, 640, 480), Some(PresentClip { left: 0, top: 0, right: 6, bottom: 7, source_x: 4, source_y: 3 }));
    }

    #[test]
    fn fully_offscreen_present_has_no_copy_region() {
        assert_eq!(clip_present_rect(10, 10, 700, 0, 640, 480), None);
        assert_eq!(clip_present_rect(10, 10, 0, 500, 640, 480), None);
    }
}
