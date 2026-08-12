//! DRM atomic plane-state ownership helpers.

use super::*;
use alloc::alloc::{alloc_zeroed, dealloc};

const DRM_PLANE_STATE_SIZE: usize = 184;
const DRM_SHADOW_PLANE_STATE_SIZE: usize = 336;
const DRM_PLANE_STATE_PLANE_OFF: usize = 0;
const DRM_PLANE_STATE_FB_OFF: usize = 16;
const DRM_PLANE_STATE_FENCE_OFF: usize = 24;
const DRM_PLANE_STATE_DAMAGE_OFF: usize = 96;
const DRM_PLANE_STATE_COMMIT_OFF: usize = 160;
const DRM_PLANE_STATE_COLOR_CHANGED_OFF: usize = 176;
const DRM_PLANE_STATE_OFF: usize = 1232;

pub(super) fn export_symbols() {
    crate::symtab::export("drm_gem_reset_shadow_plane", drm_gem_reset_shadow_plane as *const () as usize, false);
    crate::symtab::export("drm_gem_duplicate_shadow_plane_state", drm_gem_duplicate_shadow_plane_state as *const () as usize, false);
    crate::symtab::export("drm_gem_destroy_shadow_plane_state", drm_gem_destroy_shadow_plane_state as *const () as usize, false);
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
}
