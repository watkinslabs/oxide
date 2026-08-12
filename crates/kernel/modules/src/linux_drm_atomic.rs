//! DRM atomic plane-state ownership helpers.

use super::*;
use alloc::alloc::{alloc_zeroed, dealloc};

const DRM_PLANE_STATE_SIZE: usize = 184;
const DRM_CRTC_STATE_SIZE: usize = 336;
const DRM_SHADOW_PLANE_STATE_SIZE: usize = 336;
const DRM_PLANE_STATE_PLANE_OFF: usize = 0;
const DRM_PLANE_STATE_FB_OFF: usize = 16;
const DRM_PLANE_STATE_FENCE_OFF: usize = 24;
const DRM_PLANE_STATE_DAMAGE_OFF: usize = 96;
const DRM_PLANE_STATE_COMMIT_OFF: usize = 160;
const DRM_PLANE_STATE_COLOR_CHANGED_OFF: usize = 176;
const DRM_PLANE_STATE_OFF: usize = 1232;
const DRM_PLANE_STATE_CRTC_OFF: usize = 8;
const DRM_PLANE_STATE_CRTC_X_OFF: usize = 32;
const DRM_PLANE_STATE_CRTC_Y_OFF: usize = 36;
const DRM_PLANE_STATE_CRTC_W_OFF: usize = 40;
const DRM_PLANE_STATE_CRTC_H_OFF: usize = 44;
const DRM_PLANE_STATE_SRC_X_OFF: usize = 48;
const DRM_PLANE_STATE_SRC_Y_OFF: usize = 52;
const DRM_PLANE_STATE_SRC_H_OFF: usize = 56;
const DRM_PLANE_STATE_SRC_W_OFF: usize = 60;
const DRM_PLANE_STATE_ROTATION_OFF: usize = 76;
const DRM_PLANE_STATE_SRC_OFF: usize = 108;
const DRM_PLANE_STATE_DST_OFF: usize = 124;
const DRM_PLANE_STATE_VISIBLE_OFF: usize = 140;
const DRM_CRTC_STATE_CRTC_OFF: usize = 0;
const DRM_CRTC_STATE_ENABLE_OFF: usize = 8;
const DRM_CRTC_STATE_PLANE_MASK_OFF: usize = 12;
const DRM_CRTC_STATE_MODE_HDISPLAY_OFF: usize = 96;
const DRM_CRTC_STATE_MODE_VDISPLAY_OFF: usize = 106;
const DRM_PLANE_TYPE_OFF: usize = 1216;
const DRM_PLANE_INDEX_OFF: usize = 1220;
const DRM_FB_WIDTH_OFF: usize = 128;
const DRM_FB_HEIGHT_OFF: usize = 132;
const DRM_PLANE_TYPE_PRIMARY: i32 = 1;
const DRM_ROTATE_0: u32 = 1;
const DRM_ROTATE_90: u32 = 2;
const DRM_ROTATE_180: u32 = 4;
const DRM_ROTATE_270: u32 = 8;
const DRM_ROTATE_MASK: u32 = DRM_ROTATE_0 | DRM_ROTATE_90 | DRM_ROTATE_180 | DRM_ROTATE_270;
const DRM_REFLECT_X: u32 = 16;
const DRM_REFLECT_Y: u32 = 32;
const LINUX_EINVAL: i32 = 22;
const LINUX_ERANGE: i32 = 34;

#[repr(C)]
#[derive(Copy, Clone)]
struct Rect { x1: i32, y1: i32, x2: i32, y2: i32 }

fn rect_width(rect: Rect) -> i32 { rect.x2.wrapping_sub(rect.x1) }
fn rect_height(rect: Rect) -> i32 { rect.y2.wrapping_sub(rect.y1) }

fn calc_scale(src: i32, dst: i32, min: i32, max: i32) -> Result<(), i32> {
    if src < 0 || dst < 0 { return Err(-LINUX_ERANGE); }
    if dst == 0 { return Ok(()); }
    let src = src as i64; let dst = dst as i64;
    let scale = if src > (dst << 16) { ((src + dst - 1) / dst) as i32 } else { (src / dst) as i32 };
    if scale < min || scale > max { Err(-LINUX_ERANGE) } else { Ok(()) }
}

fn clip_scaled(src: i32, dst: i32, clip: &mut i32) -> i32 {
    if dst == 0 { return 0; }
    *clip = (*clip).min(dst);
    let remaining = dst.wrapping_sub(*clip) as i64;
    let scaled = (src as i64).wrapping_mul(remaining);
    if src < (dst << 16) { ((scaled + dst as i64 - 1) / dst as i64) as i32 } else { (scaled / dst as i64) as i32 }
}

fn rotate(rect: &mut Rect, width: i32, height: i32, rotation: u32) {
    if rotation & (DRM_REFLECT_X | DRM_REFLECT_Y) != 0 {
        let old = *rect;
        if rotation & DRM_REFLECT_X != 0 { rect.x1 = width.wrapping_sub(old.x2); rect.x2 = width.wrapping_sub(old.x1); }
        if rotation & DRM_REFLECT_Y != 0 { rect.y1 = height.wrapping_sub(old.y2); rect.y2 = height.wrapping_sub(old.y1); }
    }
    let old = *rect;
    match rotation & DRM_ROTATE_MASK {
        DRM_ROTATE_0 => (), DRM_ROTATE_90 => { rect.x1 = old.y1; rect.x2 = old.y2; rect.y1 = width.wrapping_sub(old.x2); rect.y2 = width.wrapping_sub(old.x1); },
        DRM_ROTATE_180 => { rect.x1 = width.wrapping_sub(old.x2); rect.x2 = width.wrapping_sub(old.x1); rect.y1 = height.wrapping_sub(old.y2); rect.y2 = height.wrapping_sub(old.y1); },
        DRM_ROTATE_270 => { rect.x1 = height.wrapping_sub(old.y2); rect.x2 = height.wrapping_sub(old.y1); rect.y1 = old.x1; rect.y2 = old.x2; }, _ => (),
    }
}

fn rotate_inv(rect: &mut Rect, width: i32, height: i32, rotation: u32) {
    let old = *rect;
    match rotation & DRM_ROTATE_MASK {
        DRM_ROTATE_0 => (), DRM_ROTATE_90 => { rect.x1 = width.wrapping_sub(old.y2); rect.x2 = width.wrapping_sub(old.y1); rect.y1 = old.x1; rect.y2 = old.x2; },
        DRM_ROTATE_180 => { rect.x1 = width.wrapping_sub(old.x2); rect.x2 = width.wrapping_sub(old.x1); rect.y1 = height.wrapping_sub(old.y2); rect.y2 = height.wrapping_sub(old.y1); },
        DRM_ROTATE_270 => { rect.x1 = old.y1; rect.x2 = old.y2; rect.y1 = height.wrapping_sub(old.x2); rect.y2 = height.wrapping_sub(old.x1); }, _ => (),
    }
    if rotation & (DRM_REFLECT_X | DRM_REFLECT_Y) != 0 {
        let old = *rect;
        if rotation & DRM_REFLECT_X != 0 { rect.x1 = width.wrapping_sub(old.x2); rect.x2 = width.wrapping_sub(old.x1); }
        if rotation & DRM_REFLECT_Y != 0 { rect.y1 = height.wrapping_sub(old.y2); rect.y2 = height.wrapping_sub(old.y1); }
    }
}

fn clip_rect_scaled(src: &mut Rect, dst: &mut Rect, clip: Rect) -> bool {
    let mut diff = clip.x1.wrapping_sub(dst.x1);
    if diff > 0 { let width = clip_scaled(rect_width(*src), rect_width(*dst), &mut diff); src.x1 = src.x2.wrapping_sub(width); dst.x1 = dst.x1.wrapping_add(diff); }
    diff = clip.y1.wrapping_sub(dst.y1);
    if diff > 0 { let height = clip_scaled(rect_height(*src), rect_height(*dst), &mut diff); src.y1 = src.y2.wrapping_sub(height); dst.y1 = dst.y1.wrapping_add(diff); }
    diff = dst.x2.wrapping_sub(clip.x2);
    if diff > 0 { let width = clip_scaled(rect_width(*src), rect_width(*dst), &mut diff); src.x2 = src.x1.wrapping_add(width); dst.x2 = dst.x2.wrapping_sub(diff); }
    diff = dst.y2.wrapping_sub(clip.y2);
    if diff > 0 { let height = clip_scaled(rect_height(*src), rect_height(*dst), &mut diff); src.y2 = src.y1.wrapping_add(height); dst.y2 = dst.y2.wrapping_sub(diff); }
    dst.x1 < dst.x2 && dst.y1 < dst.y2
}

pub(super) fn export_symbols() {
    crate::symtab::export("drm_gem_reset_shadow_plane", drm_gem_reset_shadow_plane as *const () as usize, false);
    crate::symtab::export("drm_gem_duplicate_shadow_plane_state", drm_gem_duplicate_shadow_plane_state as *const () as usize, false);
    crate::symtab::export("drm_gem_destroy_shadow_plane_state", drm_gem_destroy_shadow_plane_state as *const () as usize, false);
    crate::symtab::export("drm_atomic_helper_check_plane_state", drm_atomic_helper_check_plane_state as *const () as usize, false);
    crate::symtab::export("drm_atomic_helper_check_crtc_primary_plane", drm_atomic_helper_check_crtc_primary_plane as *const () as usize, false);
}

/// Validate a plane's scale, visibility, clipping, and primary-plane coverage. # C: O(1)
pub(super) extern "C" fn drm_atomic_helper_check_plane_state(state: *mut c_void, crtc_state: *const c_void, min_scale: i32, max_scale: i32, can_position: bool, can_update_disabled: bool) -> i32 {
    if state.is_null() || crtc_state.is_null() || min_scale <= 0 || max_scale < min_scale { return -LINUX_EINVAL; }
    let state = state.cast::<u8>(); let crtc_state = crtc_state.cast::<u8>();
    // SAFETY: the caller supplies complete, live DRM plane/CRTC state objects using their verified ABI fields.
    let (fb, crtc, enabled, rotation) = unsafe { (read(state.add(DRM_PLANE_STATE_FB_OFF).cast::<*mut c_void>()), read(state.add(DRM_PLANE_STATE_CRTC_OFF).cast::<*mut c_void>()), read(crtc_state.add(DRM_CRTC_STATE_ENABLE_OFF).cast::<bool>()), read(state.add(DRM_PLANE_STATE_ROTATION_OFF).cast::<u32>())) };
    if fb.is_null() { unsafe { write(state.add(DRM_PLANE_STATE_VISIBLE_OFF).cast::<bool>(), false); } return 0; }
    if crtc.is_null() { unsafe { write(state.add(DRM_PLANE_STATE_VISIBLE_OFF).cast::<bool>(), false); } return 0; }
    if !enabled && !can_update_disabled { return -LINUX_EINVAL; }
    // SAFETY: coordinate fields and derived source/destination rectangles lie inside the complete plane-state ABI record.
    let (sx, sy, sw, sh, dx, dy, dw, dh, mode_w, mode_h) = unsafe {
        (read(state.add(DRM_PLANE_STATE_SRC_X_OFF).cast::<u32>()), read(state.add(DRM_PLANE_STATE_SRC_Y_OFF).cast::<u32>()), read(state.add(DRM_PLANE_STATE_SRC_W_OFF).cast::<u32>()), read(state.add(DRM_PLANE_STATE_SRC_H_OFF).cast::<u32>()), read(state.add(DRM_PLANE_STATE_CRTC_X_OFF).cast::<i32>()), read(state.add(DRM_PLANE_STATE_CRTC_Y_OFF).cast::<i32>()), read(state.add(DRM_PLANE_STATE_CRTC_W_OFF).cast::<u32>()), read(state.add(DRM_PLANE_STATE_CRTC_H_OFF).cast::<u32>()), read(crtc_state.add(DRM_CRTC_STATE_MODE_HDISPLAY_OFF).cast::<u16>()), read(crtc_state.add(DRM_CRTC_STATE_MODE_VDISPLAY_OFF).cast::<u16>()))
    };
    let mut src = Rect { x1: sx as i32, y1: sy as i32, x2: sx.wrapping_add(sw) as i32, y2: sy.wrapping_add(sh) as i32 };
    let mut dst = Rect { x1: dx, y1: dy, x2: dx.wrapping_add(dw as i32), y2: dy.wrapping_add(dh as i32) };
    // SAFETY: framebuffer dimensions are fixed ABI fields in the non-null framebuffer record.
    let (fb_w, fb_h) = unsafe { (read(fb.cast::<u8>().add(DRM_FB_WIDTH_OFF).cast::<u32>()) as i32, read(fb.cast::<u8>().add(DRM_FB_HEIGHT_OFF).cast::<u32>()) as i32) };
    rotate(&mut src, fb_w.wrapping_shl(16), fb_h.wrapping_shl(16), rotation);
    if calc_scale(rect_width(src), rect_width(dst), min_scale, max_scale).is_err() || calc_scale(rect_height(src), rect_height(dst), min_scale, max_scale).is_err() { return -LINUX_ERANGE; }
    let clip = if enabled { Rect { x1: 0, y1: 0, x2: mode_w as i32, y2: mode_h as i32 } } else { Rect { x1: 0, y1: 0, x2: 0, y2: 0 } };
    let visible = clip_rect_scaled(&mut src, &mut dst, clip);
    rotate_inv(&mut src, fb_w.wrapping_shl(16), fb_h.wrapping_shl(16), rotation);
    // SAFETY: derived rectangles and visibility are owned by the validated plane state.
    unsafe { write(state.add(DRM_PLANE_STATE_SRC_OFF).cast::<Rect>(), src); write(state.add(DRM_PLANE_STATE_DST_OFF).cast::<Rect>(), dst); write(state.add(DRM_PLANE_STATE_VISIBLE_OFF).cast::<bool>(), visible); }
    if visible && !can_position && dst.x1 == clip.x1 && dst.y1 == clip.y1 && dst.x2 == clip.x2 && dst.y2 == clip.y2 { 0 } else if visible && !can_position { -LINUX_EINVAL } else { 0 }
}

/// Require a primary plane in the enabled CRTC's device-relative plane mask. # C: O(N_planes)
pub(super) extern "C" fn drm_atomic_helper_check_crtc_primary_plane(state: *mut c_void) -> i32 {
    if state.is_null() { return -LINUX_EINVAL; }
    // SAFETY: CRTC state and embedded CRTC pointer are live for this atomic check.
    let (crtc, mask) = unsafe { (read(state.cast::<u8>().add(DRM_CRTC_STATE_CRTC_OFF).cast::<*mut c_void>()), read(state.cast::<u8>().add(DRM_CRTC_STATE_PLANE_MASK_OFF).cast::<u32>())) };
    if crtc.is_null() { return -LINUX_EINVAL; }
    // SAFETY: CRTC's first field is its owning DRM device pointer, initialized by drm_crtc_init_with_planes.
    let dev = unsafe { read(crtc.cast::<*mut c_void>()) };
    let devices = DEVICES.lock(); let Some(record) = devices.iter().find(|record| record.dev == dev as usize) else { return -LINUX_EINVAL; };
    for plane in &record.planes {
        // SAFETY: plane publication initialized its device-relative immutable index.
        let index = unsafe { read((plane.ptr as *const u8).add(DRM_PLANE_INDEX_OFF).cast::<u32>()) };
        if index >= 32 || mask & (1u32 << index) == 0 { continue; }
        // SAFETY: plane publication initialized the verified immutable type field.
        if unsafe { read((plane.ptr as *const u8).add(DRM_PLANE_TYPE_OFF).cast::<i32>()) } == DRM_PLANE_TYPE_PRIMARY { return 0; }
    }
    -LINUX_EINVAL
}

/// Reset a plane with a fresh zeroed shadow-plane state. # C: O(1)
pub(super) extern "C" fn drm_gem_reset_shadow_plane(plane: *mut c_void) {
    if plane.is_null() { return; }
    // SAFETY: plane is a complete external drm_plane whose state field is at this verified offset.
    let old = unsafe { read(plane.cast::<u8>().add(DRM_PLANE_STATE_OFF).cast::<*mut c_void>()) };
    if !old.is_null() { drm_gem_destroy_shadow_plane_state(plane, old); }
    // SAFETY: reset must withdraw the old state before an allocation failure can leave a stale plane pointer.
    unsafe { write(plane.cast::<u8>().add(DRM_PLANE_STATE_OFF).cast::<*mut c_void>(), core::ptr::null_mut()); }
    let layout = Layout::from_size_align(DRM_SHADOW_PLANE_STATE_SIZE, core::mem::align_of::<u64>()).unwrap();
    // SAFETY: the allocation is the complete shadow-plane state record and is initialized before publication.
    let state = unsafe { alloc_zeroed(layout) };
    if state.is_null() { return; }
    // SAFETY: base.plane and plane.state are the two ownership links established together by reset.
    unsafe { write(state.add(DRM_PLANE_STATE_PLANE_OFF).cast::<*mut c_void>(), plane); write(plane.cast::<u8>().add(DRM_PLANE_STATE_OFF).cast::<*mut u8>(), state); }
}

/// Duplicate the current shadow-plane state without carrying transient mappings. # C: O(1)
pub(super) extern "C" fn drm_gem_duplicate_shadow_plane_state(plane: *mut c_void) -> *mut c_void {
    if plane.is_null() { return core::ptr::null_mut(); }
    // SAFETY: plane is complete and its state pointer is the current atomic state.
    let old = unsafe { read(plane.cast::<u8>().add(DRM_PLANE_STATE_OFF).cast::<*mut u8>()) };
    if old.is_null() { return core::ptr::null_mut(); }
    let layout = Layout::from_size_align(DRM_SHADOW_PLANE_STATE_SIZE, core::mem::align_of::<u64>()).unwrap();
    // SAFETY: new storage holds the complete subclass record; only the base state is copied, leaving maps transient and empty.
    let new = unsafe { alloc_zeroed(layout) }; if new.is_null() { return core::ptr::null_mut(); }
    // SAFETY: both states own complete base records; framebuffer ownership is retained for the duplicate.
    unsafe { core::ptr::copy_nonoverlapping(old, new, DRM_PLANE_STATE_SIZE); write(new.add(DRM_PLANE_STATE_FENCE_OFF).cast::<*mut c_void>(), core::ptr::null_mut()); write(new.add(DRM_PLANE_STATE_COMMIT_OFF).cast::<*mut c_void>(), core::ptr::null_mut()); write(new.add(DRM_PLANE_STATE_DAMAGE_OFF).cast::<*mut c_void>(), core::ptr::null_mut()); *new.add(DRM_PLANE_STATE_COLOR_CHANGED_OFF) = 0; }
    let fb = unsafe { read(new.add(DRM_PLANE_STATE_FB_OFF).cast::<*mut c_void>()) }; gem::framebuffer_get(fb); new.cast()
}

/// Destroy a shadow-plane state after its transient mappings have ended. # C: O(1)
pub(super) extern "C" fn drm_gem_destroy_shadow_plane_state(_plane: *mut c_void, state: *mut c_void) {
    if state.is_null() { return; }
    // SAFETY: state is a complete shadow-plane allocation and holds one framebuffer reference if fb is non-null.
    let fb = unsafe { read(state.cast::<u8>().add(DRM_PLANE_STATE_FB_OFF).cast::<*mut c_void>()) }; gem::framebuffer_put(fb);
    let layout = Layout::from_size_align(DRM_SHADOW_PLANE_STATE_SIZE, core::mem::align_of::<u64>()).unwrap();
    // SAFETY: this callback owns the allocation made by reset or duplicate exactly once.
    unsafe { dealloc(state.cast(), layout); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shadow_state_reset_duplicate_and_destroy_preserve_framebuffer_ownership() {
        let mut plane = [0u8; 1352]; let mut fb = [0u8; 192];
        drm_gem_reset_shadow_plane(plane.as_mut_ptr().cast());
        // SAFETY: reset publishes a complete shadow state through the verified plane field.
        let state = unsafe { read(plane.as_ptr().add(DRM_PLANE_STATE_OFF).cast::<*mut u8>()) }; assert!(!state.is_null());
        // SAFETY: fabricated framebuffer uses the same embedded reference field as the ABI object.
        unsafe { write(fb.as_mut_ptr().add(40).cast::<i32>(), 3); write(state.add(DRM_PLANE_STATE_FB_OFF).cast::<*mut u8>(), fb.as_mut_ptr()); }
        let duplicate = drm_gem_duplicate_shadow_plane_state(plane.as_mut_ptr().cast()); assert!(!duplicate.is_null());
        assert_eq!(unsafe { read(fb.as_ptr().add(40).cast::<i32>()) }, 4);
        drm_gem_destroy_shadow_plane_state(plane.as_mut_ptr().cast(), duplicate);
        assert_eq!(unsafe { read(fb.as_ptr().add(40).cast::<i32>()) }, 3);
        drm_gem_destroy_shadow_plane_state(plane.as_mut_ptr().cast(), state.cast());
        assert_eq!(unsafe { read(fb.as_ptr().add(40).cast::<i32>()) }, 2);
    }

    #[test]
    fn shadow_state_entry_points_are_module_exports() {
        export_symbols();
        for name in ["drm_gem_reset_shadow_plane", "drm_gem_duplicate_shadow_plane_state", "drm_gem_destroy_shadow_plane_state"] { assert!(crate::symtab::is_exported(name)); }
    }

    #[test]
    fn plane_check_derives_visibility_and_refuses_invalid_primary_coverage() {
        let mut plane = [0u8; DRM_PLANE_STATE_SIZE]; let mut crtc = [0u8; DRM_CRTC_STATE_SIZE]; let mut fb = [0u8; 192];
        // SAFETY: fabricated ABI records reserve every field read/written by the helper.
        unsafe {
            write(plane.as_mut_ptr().add(DRM_PLANE_STATE_FB_OFF).cast::<*mut u8>(), fb.as_mut_ptr()); write(plane.as_mut_ptr().add(DRM_PLANE_STATE_CRTC_OFF).cast::<*mut u8>(), 1usize as *mut u8); write(plane.as_mut_ptr().add(DRM_PLANE_STATE_ROTATION_OFF).cast::<u32>(), DRM_ROTATE_0); write(plane.as_mut_ptr().add(DRM_PLANE_STATE_CRTC_W_OFF).cast::<u32>(), 64); write(plane.as_mut_ptr().add(DRM_PLANE_STATE_CRTC_H_OFF).cast::<u32>(), 48); write(plane.as_mut_ptr().add(DRM_PLANE_STATE_SRC_W_OFF).cast::<u32>(), 64 << 16); write(plane.as_mut_ptr().add(DRM_PLANE_STATE_SRC_H_OFF).cast::<u32>(), 48 << 16); write(crtc.as_mut_ptr().add(DRM_CRTC_STATE_ENABLE_OFF).cast::<bool>(), true); write(crtc.as_mut_ptr().add(DRM_CRTC_STATE_MODE_HDISPLAY_OFF).cast::<u16>(), 64); write(crtc.as_mut_ptr().add(DRM_CRTC_STATE_MODE_VDISPLAY_OFF).cast::<u16>(), 48);
        }
        assert_eq!(drm_atomic_helper_check_plane_state(plane.as_mut_ptr().cast(), crtc.as_ptr().cast(), 1 << 16, 1 << 16, false, false), 0);
        assert!(unsafe { read(plane.as_ptr().add(DRM_PLANE_STATE_VISIBLE_OFF).cast::<bool>()) });
        // SAFETY: move the requested plane right so the clipped destination no longer covers the CRTC.
        unsafe { write(plane.as_mut_ptr().add(DRM_PLANE_STATE_CRTC_X_OFF).cast::<i32>(), 1); }
        assert_eq!(drm_atomic_helper_check_plane_state(plane.as_mut_ptr().cast(), crtc.as_ptr().cast(), 1 << 16, 1 << 16, false, false), -LINUX_EINVAL);
        // SAFETY: disabled CRTC must refuse updates unless explicitly allowed.
        unsafe { write(crtc.as_mut_ptr().add(DRM_CRTC_STATE_ENABLE_OFF).cast::<bool>(), false); }
        assert_eq!(drm_atomic_helper_check_plane_state(plane.as_mut_ptr().cast(), crtc.as_ptr().cast(), 1 << 16, 1 << 16, true, false), -LINUX_EINVAL);
    }

    #[test]
    fn scaled_clip_preserves_fixed_point_source_and_rotation_is_reversible() {
        let mut src = Rect { x1: 0, y1: 0, x2: 100 << 16, y2: 50 << 16 };
        let mut dst = Rect { x1: -20, y1: 0, x2: 80, y2: 50 };
        assert!(clip_rect_scaled(&mut src, &mut dst, Rect { x1: 0, y1: 0, x2: 80, y2: 50 }));
        assert_eq!((src.x1, src.x2, dst.x1, dst.x2), (20 << 16, 100 << 16, 0, 80));
        let original = src; rotate(&mut src, 100 << 16, 50 << 16, DRM_ROTATE_90 | DRM_REFLECT_X); rotate_inv(&mut src, 100 << 16, 50 << 16, DRM_ROTATE_90 | DRM_REFLECT_X);
        assert_eq!((src.x1, src.y1, src.x2, src.y2), (original.x1, original.y1, original.x2, original.y2));
    }

    #[test]
    fn atomic_validation_exports_are_present() {
        export_symbols();
        for name in ["drm_atomic_helper_check_plane_state", "drm_atomic_helper_check_crtc_primary_plane"] { assert!(crate::symtab::is_exported(name)); }
    }
}
