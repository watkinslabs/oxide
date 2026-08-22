//! DRM framebuffer clip-copy helper for shadow-backed scanout.

use super::*;

const DRM_FORMAT_PLANES_OFF: usize = 5;
const DRM_FORMAT_CPP_OFF: usize = 6;
const DRM_FB_FORMAT_OFF: usize = 72;
const DRM_FB_PITCHES_OFF: usize = 88;
const IOSYS_MAP_SIZE: usize = 16;
const IOSYS_MAP_VADDR_OFF: usize = 0;
const IOSYS_MAP_IOMEM_OFF: usize = 8;
const DRM_RECT_X1_OFF: usize = 0;
const DRM_RECT_Y1_OFF: usize = 4;
const DRM_RECT_X2_OFF: usize = 8;
const DRM_RECT_Y2_OFF: usize = 12;

pub(super) fn export_symbols() { crate::symtab::export("drm_fb_memcpy", drm_fb_memcpy as *const () as usize, false); crate::symtab::export("drm_fb_clip_offset", drm_fb_clip_offset as *const () as usize, false); }

/// Return a clip rectangle's top-left byte offset in the first framebuffer plane. # C: O(1)
pub(super) extern "C" fn drm_fb_clip_offset(pitch: u32, format: *const u8, clip: *const c_void) -> u32 {
    if format.is_null() || clip.is_null() { return 0; }
    // SAFETY: format and clip are complete immutable ABI records supplied by the DRM format-helper call chain.
    let (cpp, x1, y1) = unsafe { (*format.add(DRM_FORMAT_CPP_OFF) as u64, read(clip.cast::<u8>().add(DRM_RECT_X1_OFF).cast::<i32>()), read(clip.cast::<u8>().add(DRM_RECT_Y1_OFF).cast::<i32>())) };
    if x1 < 0 || y1 < 0 { return 0; }
    (y1 as u64).saturating_mul(pitch as u64).saturating_add((x1 as u64).saturating_mul(cpp)).min(u32::MAX as u64) as u32
}

/// Copy a rectangle from shadow GEM mappings into display mappings. # C: O(planes * height * width)
pub(super) extern "C" fn drm_fb_memcpy(dst: *mut c_void, dst_pitch: *const u32, src: *const c_void, fb: *const c_void, clip: *const c_void) {
    if dst.is_null() || src.is_null() || fb.is_null() || clip.is_null() { return; }
    // SAFETY: framebuffer and rectangle are complete ABI records supplied by the DRM helper call chain.
    let (format, x1, y1, x2, y2) = unsafe { (read(fb.cast::<u8>().add(DRM_FB_FORMAT_OFF).cast::<*const u8>()), read(clip.cast::<u8>().add(DRM_RECT_X1_OFF).cast::<i32>()), read(clip.cast::<u8>().add(DRM_RECT_Y1_OFF).cast::<i32>()), read(clip.cast::<u8>().add(DRM_RECT_X2_OFF).cast::<i32>()), read(clip.cast::<u8>().add(DRM_RECT_Y2_OFF).cast::<i32>())) };
    if format.is_null() || x1 < 0 || y1 < 0 || x2 < x1 || y2 < y1 { return; }
    // SAFETY: format is immutable DRM metadata; only its fixed plane count is read.
    let planes = unsafe { *format.add(DRM_FORMAT_PLANES_OFF) as usize };
    if planes == 0 || planes > 4 { return; }
    for plane in 0..planes {
        // SAFETY: every indexed array is bounded by DRM_FORMAT_MAX_PLANES.
        let (cpp, src_pitch, dp, dst_map, src_map) = unsafe { (*format.add(DRM_FORMAT_CPP_OFF + plane) as usize, read(fb.cast::<u8>().add(DRM_FB_PITCHES_OFF + plane * 4).cast::<u32>()) as usize, if dst_pitch.is_null() { 0 } else { read(dst_pitch.add(plane)) as usize }, dst.cast::<u8>().add(plane * IOSYS_MAP_SIZE), src.cast::<u8>().add(plane * IOSYS_MAP_SIZE)) };
        if cpp == 0 { return; }
        let width = (x2 - x1) as usize; let height = (y2 - y1) as usize;
        let Some(bytes) = width.checked_mul(cpp) else { return; };
        let effective_dst_pitch = if dp == 0 { bytes } else { dp };
        // SAFETY: iosys_map records contain a pointer at offset zero and a boolean I/O-memory tag at offset eight.
        let (dst_base, src_base, dst_iomem) = unsafe { (read(dst_map.add(IOSYS_MAP_VADDR_OFF).cast::<*mut u8>()), read(src_map.add(IOSYS_MAP_VADDR_OFF).cast::<*const u8>()), read(dst_map.add(IOSYS_MAP_IOMEM_OFF).cast::<bool>())) };
        if dst_base.is_null() || src_base.is_null() { return; }
        let Some(src_start) = (y1 as usize).checked_mul(src_pitch).and_then(|v| v.checked_add((x1 as usize).saturating_mul(cpp))) else { return; };
        for row in 0..height {
            let Some(src_off) = src_start.checked_add(row.saturating_mul(src_pitch)) else { return; };
            let Some(dst_off) = row.checked_mul(effective_dst_pitch) else { return; };
            // SAFETY: DRM validates the clip and framebuffer pitches before this helper; the caller owns both live mappings for this copy.
            unsafe { if dst_iomem { for byte in 0..bytes { core::ptr::write_volatile(dst_base.add(dst_off + byte), core::ptr::read_volatile(src_base.add(src_off + byte))); } } else { core::ptr::copy_nonoverlapping(src_base.add(src_off), dst_base.add(dst_off), bytes); } }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_the_clipped_xrgb_rows_with_framebuffer_pitch() {
        let mut dst = [0u8; 64]; let mut src = [0u8; 64]; let mut fb = [0u8; 192]; let mut format = [0u8; 24]; let clip = [1i32, 1, 3, 3];
        for (i, byte) in src.iter_mut().enumerate() { *byte = i as u8; }
        format[DRM_FORMAT_PLANES_OFF] = 1; format[DRM_FORMAT_CPP_OFF] = 4;
        // SAFETY: test arrays reserve each ABI record and its first iosys_map slot.
        unsafe { write(dst.as_mut_ptr().cast::<*mut u8>(), dst.as_mut_ptr()); write(src.as_mut_ptr().cast::<*mut u8>(), src.as_mut_ptr()); write(fb.as_mut_ptr().add(DRM_FB_FORMAT_OFF).cast::<*const u8>(), format.as_ptr()); write(fb.as_mut_ptr().add(DRM_FB_PITCHES_OFF).cast::<u32>(), 16); }
        drm_fb_memcpy(dst.as_mut_ptr().cast(), core::ptr::null(), src.as_ptr().cast(), fb.as_ptr().cast(), clip.as_ptr().cast());
        assert_eq!(&dst[..8], &src[20..28]); assert_eq!(&dst[8..16], &src[36..44]);
    }

    #[test]
    fn format_helpers_are_module_exports() { let _modules = crate::test_serial::claim(); export_symbols(); assert!(crate::symtab::is_exported("drm_fb_memcpy")); assert!(crate::symtab::is_exported("drm_fb_clip_offset")); }

    #[test]
    fn clip_offset_uses_first_plane_pitch_and_pixel_size() {
        let mut format = [0u8; 24]; let clip = [3i32, 2, 0, 0]; format[DRM_FORMAT_CPP_OFF] = 4;
        assert_eq!(drm_fb_clip_offset(64, format.as_ptr(), clip.as_ptr().cast()), 140);
    }
}
