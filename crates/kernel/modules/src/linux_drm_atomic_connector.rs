//! Default DRM atomic connector-state ownership.

use super::*;
use alloc::alloc::dealloc;

const DRM_CONNECTOR_STATE_SIZE: usize = 440;
const DRM_CONNECTOR_STATE_CONNECTOR_OFF: usize = 0;
const DRM_CONNECTOR_STATE_CRTC_OFF: usize = 8;
const DRM_CONNECTOR_STATE_COMMIT_OFF: usize = 40;
const DRM_CONNECTOR_STATE_WRITEBACK_JOB_OFF: usize = 136;
const DRM_CONNECTOR_STATE_HDR_METADATA_OFF: usize = 152;
const DRM_CONNECTOR_STATE_ALIGN: usize = 8;
const DRM_CONNECTOR_STATE_OFF: usize = 1968;
const DRM_CONNECTOR_BASE_OFF: usize = 64;

pub(super) fn export_symbols() {
    crate::symtab::export("drm_atomic_helper_connector_reset", drm_atomic_helper_connector_reset as *const () as usize, false);
    crate::symtab::export("drm_atomic_helper_connector_duplicate_state", drm_atomic_helper_connector_duplicate_state as *const () as usize, false);
    crate::symtab::export("drm_atomic_helper_connector_destroy_state", drm_atomic_helper_connector_destroy_state as *const () as usize, false);
}

fn state_layout() -> Layout { Layout::from_size_align(DRM_CONNECTOR_STATE_SIZE, DRM_CONNECTOR_STATE_ALIGN).unwrap() }

fn has_unowned_resources(state: *const u8) -> bool {
    // SAFETY: all resource fields are in the complete verified connector-state object.
    unsafe { !read(state.add(DRM_CONNECTOR_STATE_WRITEBACK_JOB_OFF).cast::<*mut c_void>()).is_null() || !read(state.add(DRM_CONNECTOR_STATE_HDR_METADATA_OFF).cast::<*mut c_void>()).is_null() }
}

/// Reset a connector's standard atomic state, withdrawing the old state first. # C: O(1)
pub(super) extern "C" fn drm_atomic_helper_connector_reset(connector: *mut c_void) {
    if connector.is_null() { return; }
    // SAFETY: connector contains its current state pointer at the verified ABI offset.
    let old = unsafe { read(connector.cast::<u8>().add(DRM_CONNECTOR_STATE_OFF).cast::<*mut c_void>()) };
    if !old.is_null() { drm_atomic_helper_connector_destroy_state(connector, old); }
    // SAFETY: reset publishes a zeroed state only after the old state is withdrawn.
    unsafe { write(connector.cast::<u8>().add(DRM_CONNECTOR_STATE_OFF).cast::<*mut c_void>(), core::ptr::null_mut()); }
    // SAFETY: allocates a fresh block of exactly state_layout()'s size/align; the following writes populate it before publication.
    let state = unsafe { alloc_zeroed_state() }; if state.is_null() { return; }
    // SAFETY: state is a fresh standard connector state and connector is its immutable backpointer.
    unsafe { write(state.add(DRM_CONNECTOR_STATE_CONNECTOR_OFF).cast::<*mut c_void>(), connector); write(connector.cast::<u8>().add(DRM_CONNECTOR_STATE_OFF).cast::<*mut u8>(), state); }
}

unsafe fn alloc_zeroed_state() -> *mut u8 { unsafe { alloc::alloc::alloc_zeroed(state_layout()) } }

/// Duplicate a standard connector state, retaining its connector only when a CRTC relation exists. # C: O(1)
pub(super) extern "C" fn drm_atomic_helper_connector_duplicate_state(connector: *mut c_void) -> *mut c_void {
    if connector.is_null() { return core::ptr::null_mut(); }
    // SAFETY: connector is an ABI-complete external object whose state field is current under the caller's modeset lock.
    let old = unsafe { read(connector.cast::<u8>().add(DRM_CONNECTOR_STATE_OFF).cast::<*mut u8>()) };
    if old.is_null() || has_unowned_resources(old) { return core::ptr::null_mut(); }
    // SAFETY: allocates a fresh block of exactly state_layout()'s size/align; the copy below populates it from old before publication.
    let state = unsafe { alloc_zeroed_state() }; if state.is_null() { return core::ptr::null_mut(); }
    // SAFETY: two distinct complete standard connector states are copied before transient resource fields are cleared.
    unsafe { core::ptr::copy_nonoverlapping(old, state, DRM_CONNECTOR_STATE_SIZE); write(state.add(DRM_CONNECTOR_STATE_COMMIT_OFF).cast::<*mut c_void>(), core::ptr::null_mut()); write(state.add(DRM_CONNECTOR_STATE_WRITEBACK_JOB_OFF).cast::<*mut c_void>(), core::ptr::null_mut()); }
    // SAFETY: Linux retains the connector only for a state that carries a CRTC relation.
    let crtc = unsafe { read(state.add(DRM_CONNECTOR_STATE_CRTC_OFF).cast::<*mut c_void>()) };
    // SAFETY: connector was validated non-null above; its embedded mode-object base is the fixed offset every mode_object_refs call uses.
    if !crtc.is_null() { mode_object_refs::get(unsafe { connector.cast::<u8>().add(DRM_CONNECTOR_BASE_OFF).cast() }); }
    state.cast()
}

/// Release a standard connector state and its conditional connector reference. # C: O(1)
pub(super) extern "C" fn drm_atomic_helper_connector_destroy_state(_connector: *mut c_void, state: *mut c_void) {
    if state.is_null() { return; }
    let state = state.cast::<u8>();
    // SAFETY: a connector state owns one commit reference when its ABI commit field is non-null.
    let commit = unsafe { read(state.add(DRM_CONNECTOR_STATE_COMMIT_OFF).cast::<*mut u8>()) };
    crtc_commit::put(commit);
    // SAFETY: release makes a repeated state-destroy call unable to consume the same commit reference twice.
    unsafe { write(state.add(DRM_CONNECTOR_STATE_COMMIT_OFF).cast::<*mut u8>(), core::ptr::null_mut()); }
    if has_unowned_resources(state) { return; }
    // SAFETY: a duplicated state with a CRTC relation owns precisely one connector mode-object reference.
    let crtc = unsafe { read(state.add(DRM_CONNECTOR_STATE_CRTC_OFF).cast::<*mut c_void>()) };
    // SAFETY: owner is the state's own CONNECTOR_OFF backpointer, set at reset/duplicate time; balances the get taken in duplicate_state for a CRTC-attached state.
    if !crtc.is_null() { let owner = unsafe { read(state.add(DRM_CONNECTOR_STATE_CONNECTOR_OFF).cast::<*mut c_void>()) }; if !owner.is_null() { mode_object_refs::put(unsafe { owner.cast::<u8>().add(DRM_CONNECTOR_BASE_OFF).cast() }); } }
    // SAFETY: state is a standard allocation made by reset or duplicate and is released exactly once.
    unsafe { dealloc(state, state_layout()); }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn standard_connector_states_reset_duplicate_and_release_the_crtc_reference() {
        let mut connector = [0u8; 2280]; drm_atomic_helper_connector_reset(connector.as_mut_ptr().cast());
        // SAFETY: reset just published state through this same field; reads it back and its embedded backpointer, both within the fabricated 2280-byte connector.
        let state = unsafe { read(connector.as_ptr().add(DRM_CONNECTOR_STATE_OFF).cast::<*mut u8>()) }; assert!(!state.is_null()); assert_eq!(unsafe { read(state.cast::<*mut c_void>()) }, connector.as_mut_ptr().cast());
        // SAFETY: fabricates a CRTC relation and a mode-object refcount/lock-owner pair at the offsets duplicate/destroy read through mode_object_refs.
        unsafe { write(state.add(DRM_CONNECTOR_STATE_CRTC_OFF).cast::<*mut c_void>(), 1usize as *mut c_void); write(connector.as_mut_ptr().add(DRM_CONNECTOR_BASE_OFF + 16).cast::<i32>(), 2); write(connector.as_mut_ptr().add(DRM_CONNECTOR_BASE_OFF + 24).cast::<usize>(), 1); }
        // SAFETY: duplicating a state with a CRTC relation must take one mode-object ref; reads back the refcount field bumped by mode_object_refs::get.
        let duplicate = drm_atomic_helper_connector_duplicate_state(connector.as_mut_ptr().cast()); assert!(!duplicate.is_null()); assert_eq!(unsafe { read(connector.as_ptr().add(DRM_CONNECTOR_BASE_OFF + 16).cast::<i32>()) }, 3);
        // SAFETY: destroying the duplicate drops exactly the one mode-object ref taken at line 55; reads back the same fabricated refcount field.
        drm_atomic_helper_connector_destroy_state(connector.as_mut_ptr().cast(), duplicate); assert_eq!(unsafe { read(connector.as_ptr().add(DRM_CONNECTOR_BASE_OFF + 16).cast::<i32>()) }, 2);
        // SAFETY: clears the CRTC relation on the still-live state so the final destroy takes the no-crtc path, freeing without a second mode-object put.
        unsafe { write(state.add(DRM_CONNECTOR_STATE_CRTC_OFF).cast::<*mut c_void>(), core::ptr::null_mut()); } drm_atomic_helper_connector_destroy_state(connector.as_mut_ptr().cast(), state.cast());
    }
    #[test]
    fn standard_connector_state_entry_points_are_module_exports() { let _modules = crate::test_serial::claim(); export_symbols(); for name in ["drm_atomic_helper_connector_reset", "drm_atomic_helper_connector_duplicate_state", "drm_atomic_helper_connector_destroy_state"] { assert!(crate::symtab::is_exported(name)); } }
}
