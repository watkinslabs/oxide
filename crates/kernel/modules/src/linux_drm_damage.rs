//! DRM atomic plane-damage iterator ABI.

use super::*;

const DRM_PLANE_STATE_CRTC_OFF: usize = 8;
const DRM_PLANE_STATE_FB_OFF: usize = 16;
const DRM_PLANE_STATE_DAMAGE_OFF: usize = 96;
const DRM_PLANE_STATE_IGNORE_DAMAGE_OFF: usize = 104;
const DRM_PLANE_STATE_SRC_OFF: usize = 108;
const DRM_PLANE_STATE_VISIBLE_OFF: usize = 140;
const DRM_PROPERTY_BLOB_LENGTH_OFF: usize = 72;
const DRM_PROPERTY_BLOB_DATA_OFF: usize = 80;
const DRM_RECT_SIZE: usize = 16;
const ITER_PLANE_SRC_OFF: usize = 0;
const ITER_CLIPS_OFF: usize = 16;
const ITER_NUM_CLIPS_OFF: usize = 24;
const ITER_CURR_CLIP_OFF: usize = 28;
const ITER_FULL_UPDATE_OFF: usize = 32;
const ITER_SIZE: usize = 40;
const FIXED_FRAC_MASK: i32 = 0xffff;

#[derive(Copy, Clone, Eq, PartialEq)]
#[repr(C)]
struct Rect { x1: i32, y1: i32, x2: i32, y2: i32 }

pub(super) fn export_symbols() {
    crate::symtab::export("drm_atomic_helper_damage_iter_init", drm_atomic_helper_damage_iter_init as *const () as usize, false);
    crate::symtab::export("drm_atomic_helper_damage_iter_next", drm_atomic_helper_damage_iter_next as *const () as usize, false);
}

fn empty(iter: *mut u8) {
    // SAFETY: iter points to the complete fixed ABI iterator record supplied by the caller.
    unsafe { core::ptr::write_bytes(iter, 0, ITER_SIZE); }
}

fn intersect(one: &mut Rect, two: Rect) -> bool {
    one.x1 = one.x1.max(two.x1); one.y1 = one.y1.max(two.y1); one.x2 = one.x2.min(two.x2); one.y2 = one.y2.min(two.y2); one.x1 < one.x2 && one.y1 < one.y2
}

fn state_src(state: *const u8) -> Rect {
    // SAFETY: source rectangle is a complete four-i32 ABI field in plane state.
    unsafe { read(state.add(DRM_PLANE_STATE_SRC_OFF).cast::<Rect>()) }
}

/// Initialize damage traversal with the exact whole-pixel source rounding. # C: O(1)
pub(super) extern "C" fn drm_atomic_helper_damage_iter_init(iter: *mut c_void, old: *const c_void, state: *const c_void) {
    if iter.is_null() { return; } let iter = iter.cast::<u8>(); empty(iter);
    if old.is_null() || state.is_null() { return; } let state = state.cast::<u8>(); let old = old.cast::<u8>();
    // SAFETY: these plane-state scalar fields are read from complete caller-owned atomic states.
    let usable = unsafe { !read(state.add(DRM_PLANE_STATE_CRTC_OFF).cast::<*mut c_void>()).is_null() && !read(state.add(DRM_PLANE_STATE_FB_OFF).cast::<*mut c_void>()).is_null() && read(state.add(DRM_PLANE_STATE_VISIBLE_OFF).cast::<bool>()) };
    if !usable { return; }
    let source = state_src(state);
    let plane_src = Rect { x1: source.x1 >> 16, y1: source.y1 >> 16, x2: (source.x2 >> 16) + i32::from(source.x2 & FIXED_FRAC_MASK != 0), y2: (source.y2 >> 16) + i32::from(source.y2 & FIXED_FRAC_MASK != 0) };
    // SAFETY: iterator's plane source is its first fixed rectangle field.
    unsafe { write(iter.add(ITER_PLANE_SRC_OFF).cast::<Rect>(), plane_src); }
    // SAFETY: damage blob field and ignore flag are stable plane-state ABI fields.
    let (damage, ignore) = unsafe { (read(state.add(DRM_PLANE_STATE_DAMAGE_OFF).cast::<*mut u8>()), read(state.add(DRM_PLANE_STATE_IGNORE_DAMAGE_OFF).cast::<bool>())) };
    if damage.is_null() || ignore || state_src(old) != source {
        // SAFETY: full-update is the iterator's stable terminal boolean field.
        unsafe { write(iter.add(ITER_FULL_UPDATE_OFF).cast::<bool>(), true); }
        return;
    }
    // SAFETY: property-blob length/data fields describe the contiguous mode-rect payload retained by the state.
    unsafe { let length = read(damage.add(DRM_PROPERTY_BLOB_LENGTH_OFF).cast::<usize>()); write(iter.add(ITER_CLIPS_OFF).cast::<*const Rect>(), damage.add(DRM_PROPERTY_BLOB_DATA_OFF).cast()); write(iter.add(ITER_NUM_CLIPS_OFF).cast::<u32>(), (length / DRM_RECT_SIZE) as u32); }
}

/// Return the next source-clipped damage rectangle. # C: O(N_clips)
pub(super) extern "C" fn drm_atomic_helper_damage_iter_next(iter: *mut c_void, rect: *mut c_void) -> bool {
    if iter.is_null() || rect.is_null() { return false; } let iter = iter.cast::<u8>();
    // SAFETY: iterator and result use the fixed ABI layouts initialized by the paired init entry point.
    unsafe {
        let plane_src = read(iter.add(ITER_PLANE_SRC_OFF).cast::<Rect>());
        if read(iter.add(ITER_FULL_UPDATE_OFF).cast::<bool>()) { write(rect.cast::<Rect>(), plane_src); write(iter.add(ITER_FULL_UPDATE_OFF).cast::<bool>(), false); return true; }
        let clips = read(iter.add(ITER_CLIPS_OFF).cast::<*const Rect>()); let count = read(iter.add(ITER_NUM_CLIPS_OFF).cast::<u32>()); let mut current = read(iter.add(ITER_CURR_CLIP_OFF).cast::<u32>());
        while current < count { let mut clip = read(clips.add(current as usize)); current += 1; write(iter.add(ITER_CURR_CLIP_OFF).cast::<u32>(), current); if intersect(&mut clip, plane_src) { write(rect.cast::<Rect>(), clip); return true; } }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn damage_iterator_clips_each_rect_and_falls_back_to_full_source() {
        let mut old = [0u8; 184]; let mut state = [0u8; 184]; let mut blob = [0u8; 120]; let mut iter = [0u8; ITER_SIZE]; let mut out = Rect { x1: 0, y1: 0, x2: 0, y2: 0 };
        unsafe { write(state.as_mut_ptr().add(DRM_PLANE_STATE_CRTC_OFF).cast::<*mut c_void>(), 1usize as *mut c_void); write(state.as_mut_ptr().add(DRM_PLANE_STATE_FB_OFF).cast::<*mut c_void>(), 1usize as *mut c_void); write(state.as_mut_ptr().add(DRM_PLANE_STATE_VISIBLE_OFF).cast::<bool>(), true); let src = Rect { x1: 1 << 16, y1: 2 << 16, x2: 9 << 16, y2: 8 << 16 }; write(old.as_mut_ptr().add(DRM_PLANE_STATE_SRC_OFF).cast::<Rect>(), src); write(state.as_mut_ptr().add(DRM_PLANE_STATE_SRC_OFF).cast::<Rect>(), src); write(blob.as_mut_ptr().add(DRM_PROPERTY_BLOB_LENGTH_OFF).cast::<usize>(), DRM_RECT_SIZE * 2); write(blob.as_mut_ptr().add(DRM_PROPERTY_BLOB_DATA_OFF).cast::<Rect>(), Rect { x1: 0, y1: 3, x2: 4, y2: 9 }); write(blob.as_mut_ptr().add(DRM_PROPERTY_BLOB_DATA_OFF + DRM_RECT_SIZE).cast::<Rect>(), Rect { x1: 11, y1: 0, x2: 12, y2: 1 }); write(state.as_mut_ptr().add(DRM_PLANE_STATE_DAMAGE_OFF).cast::<*mut u8>(), blob.as_mut_ptr()); }
        drm_atomic_helper_damage_iter_init(iter.as_mut_ptr().cast(), old.as_ptr().cast(), state.as_ptr().cast()); assert!(drm_atomic_helper_damage_iter_next(iter.as_mut_ptr().cast(), (&mut out as *mut Rect).cast())); assert_eq!((out.x1, out.y1, out.x2, out.y2), (1, 3, 4, 8)); assert!(!drm_atomic_helper_damage_iter_next(iter.as_mut_ptr().cast(), (&mut out as *mut Rect).cast()));
        unsafe { write(state.as_mut_ptr().add(DRM_PLANE_STATE_DAMAGE_OFF).cast::<*mut u8>(), core::ptr::null_mut()); } drm_atomic_helper_damage_iter_init(iter.as_mut_ptr().cast(), old.as_ptr().cast(), state.as_ptr().cast()); assert!(drm_atomic_helper_damage_iter_next(iter.as_mut_ptr().cast(), (&mut out as *mut Rect).cast())); assert_eq!((out.x1, out.y1, out.x2, out.y2), (1, 2, 9, 8));
    }
}
