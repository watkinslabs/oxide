//! Default DRM atomic CRTC-state ownership.

use super::*;
use alloc::alloc::{alloc_zeroed, dealloc};

const DRM_CRTC_STATE_SIZE: usize = 336;
const DRM_CRTC_STATE_CHANGE_FLAGS_OFF: usize = 10;
const DRM_CRTC_STATE_MODE_BLOB_OFF: usize = 264;
const DRM_CRTC_STATE_DEGAMMA_OFF: usize = 272;
const DRM_CRTC_STATE_CTM_OFF: usize = 280;
const DRM_CRTC_STATE_GAMMA_OFF: usize = 288;
const DRM_CRTC_STATE_ASYNC_FLIP_OFF: usize = 300;
const DRM_CRTC_STATE_SELF_REFRESH_OFF: usize = 302;
const DRM_CRTC_STATE_EVENT_OFF: usize = 312;
const DRM_CRTC_STATE_COMMIT_OFF: usize = 320;
const DRM_CRTC_STATE_OFF: usize = 1488;

pub(super) fn export_symbols() {
    crate::symtab::export("drm_atomic_helper_crtc_reset", drm_atomic_helper_crtc_reset as *const () as usize, false);
    crate::symtab::export("drm_atomic_helper_crtc_duplicate_state", drm_atomic_helper_crtc_duplicate_state as *const () as usize, false);
    crate::symtab::export("drm_atomic_helper_crtc_destroy_state", drm_atomic_helper_crtc_destroy_state as *const () as usize, false);
}

fn layout() -> Layout { Layout::from_size_align(DRM_CRTC_STATE_SIZE, 8).unwrap() }
fn resources(state: *const u8) -> bool {
    // SAFETY: each listed field is a pointer in the verified complete CRTC-state layout.
    unsafe { [DRM_CRTC_STATE_MODE_BLOB_OFF, DRM_CRTC_STATE_DEGAMMA_OFF, DRM_CRTC_STATE_CTM_OFF, DRM_CRTC_STATE_GAMMA_OFF, DRM_CRTC_STATE_COMMIT_OFF].into_iter().any(|offset| !read(state.add(offset).cast::<*mut c_void>()).is_null()) }
}

/// Reset a CRTC to a fresh standard atomic state. # C: O(1)
pub(super) extern "C" fn drm_atomic_helper_crtc_reset(crtc: *mut c_void) {
    if crtc.is_null() { return; }
    // SAFETY: CRTC state is stored at its verified external ABI offset.
    let old = unsafe { read(crtc.cast::<u8>().add(DRM_CRTC_STATE_OFF).cast::<*mut c_void>()) };
    if !old.is_null() { drm_atomic_helper_crtc_destroy_state(crtc, old); }
    // SAFETY: a stale pointer must be withdrawn before allocation can fail.
    unsafe { write(crtc.cast::<u8>().add(DRM_CRTC_STATE_OFF).cast::<*mut c_void>(), core::ptr::null_mut()); }
    let state = unsafe { alloc_zeroed(layout()) }; if state.is_null() { return; }
    // SAFETY: fresh state backpointer and CRTC state publication are paired.
    unsafe { write(state.cast::<*mut c_void>(), crtc); write(crtc.cast::<u8>().add(DRM_CRTC_STATE_OFF).cast::<*mut u8>(), state); }
}

/// Duplicate a standard CRTC state and reset Linux's inferred/transient fields. # C: O(1)
pub(super) extern "C" fn drm_atomic_helper_crtc_duplicate_state(crtc: *mut c_void) -> *mut c_void {
    if crtc.is_null() { return core::ptr::null_mut(); }
    // SAFETY: caller holds the modeset serialization required by Linux for the current state pointer.
    let old = unsafe { read(crtc.cast::<u8>().add(DRM_CRTC_STATE_OFF).cast::<*mut u8>()) };
    if old.is_null() || resources(old) { return core::ptr::null_mut(); }
    let state = unsafe { alloc_zeroed(layout()) }; if state.is_null() { return core::ptr::null_mut(); }
    // SAFETY: both buffers are complete standard CRTC-state records.
    unsafe { core::ptr::copy_nonoverlapping(old, state, DRM_CRTC_STATE_SIZE); *state.add(DRM_CRTC_STATE_CHANGE_FLAGS_OFF) &= !0x3f; *state.add(DRM_CRTC_STATE_ASYNC_FLIP_OFF) = 0; *state.add(DRM_CRTC_STATE_SELF_REFRESH_OFF) = 0; write(state.add(DRM_CRTC_STATE_EVENT_OFF).cast::<*mut c_void>(), core::ptr::null_mut()); write(state.add(DRM_CRTC_STATE_COMMIT_OFF).cast::<*mut c_void>(), core::ptr::null_mut()); }
    state.cast()
}

/// Release a standard resource-free CRTC state. # C: O(1)
pub(super) extern "C" fn drm_atomic_helper_crtc_destroy_state(_crtc: *mut c_void, state: *mut c_void) {
    if state.is_null() || resources(state.cast()) { return; }
    // SAFETY: state was allocated by reset or duplicate under this exact layout.
    unsafe { dealloc(state.cast(), layout()); }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn standard_crtc_states_reset_duplicate_and_clear_transient_fields() {
        let mut crtc = [0u8; 1656]; drm_atomic_helper_crtc_reset(crtc.as_mut_ptr().cast()); let state = unsafe { read(crtc.as_ptr().add(DRM_CRTC_STATE_OFF).cast::<*mut u8>()) }; assert_eq!(unsafe { read(state.cast::<*mut c_void>()) }, crtc.as_mut_ptr().cast());
        unsafe { *state.add(DRM_CRTC_STATE_CHANGE_FLAGS_OFF) = 0x3f; *state.add(DRM_CRTC_STATE_ASYNC_FLIP_OFF) = 1; *state.add(DRM_CRTC_STATE_SELF_REFRESH_OFF) = 1; write(state.add(DRM_CRTC_STATE_EVENT_OFF).cast::<*mut c_void>(), 1usize as *mut c_void); }
        let duplicate = drm_atomic_helper_crtc_duplicate_state(crtc.as_mut_ptr().cast()).cast::<u8>(); assert!(!duplicate.is_null()); assert_eq!(unsafe { *duplicate.add(DRM_CRTC_STATE_CHANGE_FLAGS_OFF) & 0x3f }, 0); assert_eq!(unsafe { *duplicate.add(DRM_CRTC_STATE_ASYNC_FLIP_OFF) }, 0); assert!(unsafe { read(duplicate.add(DRM_CRTC_STATE_EVENT_OFF).cast::<*mut c_void>()) }.is_null());
        drm_atomic_helper_crtc_destroy_state(crtc.as_mut_ptr().cast(), duplicate.cast()); unsafe { write(state.add(DRM_CRTC_STATE_EVENT_OFF).cast::<*mut c_void>(), core::ptr::null_mut()); } drm_atomic_helper_crtc_destroy_state(crtc.as_mut_ptr().cast(), state.cast());
    }
    #[test]
    fn standard_crtc_state_entry_points_are_module_exports() { export_symbols(); for name in ["drm_atomic_helper_crtc_reset", "drm_atomic_helper_crtc_duplicate_state", "drm_atomic_helper_crtc_destroy_state"] { assert!(crate::symtab::is_exported(name)); } }
}
