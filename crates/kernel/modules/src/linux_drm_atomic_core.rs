//! DRM atomic-state allocation and release ownership.

use super::*;

const DRM_ATOMIC_STATE_SIZE: usize = 128;
const DRM_ATOMIC_REF_OFF: usize = 0;
const DRM_ATOMIC_DEV_OFF: usize = 8;
const DRM_ATOMIC_ALLOW_MODESET_OFF: usize = 16;
const DRM_ATOMIC_CHECKED_BIT: u8 = 1 << 4;
const DRM_ATOMIC_PLANES_OFF: usize = 32;
const DRM_ATOMIC_CRTCS_OFF: usize = 40;
const DRM_ATOMIC_NUM_CONNECTOR_OFF: usize = 48;
const DRM_ATOMIC_CONNECTORS_OFF: usize = 56;
const DRM_ATOMIC_PLANE_ENTRY_SIZE: usize = 32;
const DRM_ATOMIC_CRTC_ENTRY_SIZE: usize = 56;
const DRM_ATOMIC_CONNECTOR_ENTRY_SIZE: usize = 40;
const DRM_DEVICE_MODE_CONFIG_OFF: usize = 360;
const DRM_MODE_CONFIG_FUNCS_OFF: usize = 456;
const DRM_MODE_CONFIG_ATOMIC_STATE_ALLOC_OFF: usize = 40;
const DRM_MODE_CONFIG_ATOMIC_STATE_CLEAR_OFF: usize = 48;
const DRM_MODE_CONFIG_ATOMIC_STATE_FREE_OFF: usize = 56;
const DRM_PLANE_FUNCS_OFF: usize = 176;
const DRM_CRTC_FUNCS_OFF: usize = 408;
const DRM_PLANE_DESTROY_STATE_OFF: usize = 48;
const DRM_CRTC_DESTROY_STATE_OFF: usize = 88;
const DRM_CONNECTOR_DESTROY_STATE_OFF: usize = 56;
const DRM_STATE_ENTRY_OBJECT_OFF: usize = 0;
const DRM_STATE_ENTRY_DESTROY_OFF: usize = 8;
const DRM_CRTC_ENTRY_COMMIT_OFF: usize = 32;
const DRM_ATOMIC_FAKE_COMMIT_OFF: usize = 88;

fn layout(size: usize) -> Option<Layout> { Layout::from_size_align(size.max(1), core::mem::align_of::<u64>()).ok() }
fn alloc_array(entries: usize, bytes: usize) -> Option<*mut u8> {
    let layout = layout(entries.checked_mul(bytes)?)?;
    // SAFETY: layout describes one zeroed state-array allocation owned by its caller.
    let ptr = unsafe { alloc_zeroed(layout) };
    (!ptr.is_null()).then_some(ptr)
}
fn release_array(ptr: *mut u8, entries: usize, bytes: usize) {
    if ptr.is_null() { return; }
    let Some(layout) = entries.checked_mul(bytes).and_then(layout) else { return; };
    // SAFETY: this state owns the exact array allocation matching its device object count.
    unsafe { dealloc(ptr, layout); }
}
fn allocation_counts(dev: *mut c_void) -> Option<(usize, usize, usize)> {
    let devices = DEVICES.lock();
    let record = devices.iter().find(|record| record.dev == dev as usize && record.mode_config && !record.put_pending && !record.unplugged)?;
    Some((record.planes.len(), record.crtcs.len(), record.connectors.len()))
}
fn release_counts(dev: *mut c_void) -> Option<(usize, usize, usize)> {
    let devices = DEVICES.lock();
    let record = devices.iter().find(|record| record.dev == dev as usize && record.mode_config && !record.put_pending)?;
    Some((record.planes.len(), record.crtcs.len(), record.connectors.len()))
}
fn mode_config_funcs(dev: *mut c_void) -> *const u8 {
    if dev.is_null() { return core::ptr::null(); }
    // SAFETY: a live DRM device contains its ABI-pinned mode-config function-table pointer.
    unsafe { read(dev.cast::<u8>().add(DRM_DEVICE_MODE_CONFIG_OFF + DRM_MODE_CONFIG_FUNCS_OFF).cast::<*const u8>()) }
}
unsafe fn state_callback(funcs: *const u8, offset: usize) -> usize {
    // SAFETY: funcs is a non-null ABI function table and offset names one callback slot.
    unsafe { read(funcs.add(offset).cast::<usize>()) }
}
unsafe fn call_destroy(object: *mut c_void, funcs_off: usize, destroy_off: usize, state: *mut c_void) {
    if object.is_null() || state.is_null() { return; }
    // SAFETY: object owns a complete ABI callback table whose destroy slot has this signature.
    let funcs = unsafe { read(object.cast::<u8>().add(funcs_off).cast::<*const u8>()) };
    if funcs.is_null() { return; }
    // SAFETY: a nonzero atomic destroy callback receives its object and state exactly once.
    let callback = unsafe { state_callback(funcs, destroy_off) };
    // SAFETY: destroy_off's ABI signature is atomic_destroy_state(object, state); object/state are the caller's own non-null pointers.
    if callback != 0 { unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut c_void, *mut c_void)>(callback)(object, state); } }
}

pub(super) fn export_symbols() {
    crate::symtab::export("drm_atomic_commit_alloc", drm_atomic_commit_alloc as *const () as usize, false);
    crate::symtab::export("drm_atomic_commit_clear", drm_atomic_commit_clear as *const () as usize, false);
    crate::symtab::export("drm_atomic_commit_put", drm_atomic_commit_put as *const () as usize, false);
    crate::symtab::export("drm_atomic_commit_default_clear", drm_atomic_commit_default_clear as *const () as usize, false);
    crate::symtab::export("drm_atomic_commit_default_release", drm_atomic_commit_default_release as *const () as usize, false);
}

/// Allocate one empty atomic state with arrays sized to its live mode graph. # C: O(N_objects)
pub(super) extern "C" fn drm_atomic_commit_alloc(dev: *mut c_void) -> *mut c_void {
    let funcs = mode_config_funcs(dev);
    if !funcs.is_null() {
        // SAFETY: a mode-config custom allocator owns the complete returned atomic-state layout.
        let callback = unsafe { state_callback(funcs, DRM_MODE_CONFIG_ATOMIC_STATE_ALLOC_OFF) };
        // SAFETY: ALLOC_OFF's ABI signature is atomic_state_alloc(dev) -> *mut state; dev is the caller's own device pointer.
        if callback != 0 { return unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut c_void) -> *mut c_void>(callback)(dev) }; }
    }
    let Some((planes, crtcs, _)) = allocation_counts(dev) else { return core::ptr::null_mut(); };
    let Some(state_layout) = layout(DRM_ATOMIC_STATE_SIZE) else { return core::ptr::null_mut(); };
    // SAFETY: state_layout is the complete, aligned atomic-state ABI allocation.
    let state = unsafe { alloc_zeroed(state_layout) };
    if state.is_null() { return core::ptr::null_mut(); }
    // SAFETY: on plane-array allocation failure, state is the just-allocated block above and state_layout is its exact matching layout, freed exactly once.
    let Some(plane_states) = alloc_array(planes, DRM_ATOMIC_PLANE_ENTRY_SIZE) else { unsafe { dealloc(state, state_layout); } return core::ptr::null_mut(); };
    // SAFETY: on crtc-array allocation failure, plane_states is released by release_array before state is freed by its own matching layout, both exactly once.
    let Some(crtc_states) = alloc_array(crtcs, DRM_ATOMIC_CRTC_ENTRY_SIZE) else { release_array(plane_states, planes, DRM_ATOMIC_PLANE_ENTRY_SIZE); unsafe { dealloc(state, state_layout); } return core::ptr::null_mut(); };
    // SAFETY: every write names a verified field inside the newly allocated atomic state.
    unsafe { write(state.add(DRM_ATOMIC_REF_OFF).cast::<i32>(), 1); write(state.add(DRM_ATOMIC_DEV_OFF).cast::<*mut c_void>(), dev); write(state.add(DRM_ATOMIC_ALLOW_MODESET_OFF).cast::<u8>(), 1); write(state.add(DRM_ATOMIC_PLANES_OFF).cast::<*mut u8>(), plane_states); write(state.add(DRM_ATOMIC_CRTCS_OFF).cast::<*mut u8>(), crtc_states); }
    drm_dev_get(dev);
    state.cast()
}

/// Release one atomic state after its final caller reference. # C: O(N_objects)
pub(super) extern "C" fn drm_atomic_commit_put(state: *mut c_void) {
    if state.is_null() { return; }
    let state = state.cast::<u8>();
    // SAFETY: caller owns one atomic-state reference; the count is private to this state.
    let refs = unsafe { read(state.add(DRM_ATOMIC_REF_OFF).cast::<i32>()) };
    // SAFETY: refs was just read from this same non-null state's own REF_OFF field, still exclusively owned by this call.
    if refs > 1 { unsafe { write(state.add(DRM_ATOMIC_REF_OFF).cast::<i32>(), refs - 1); } return; }
    // SAFETY: a live atomic state always retains its live DRM device until final release.
    let dev = unsafe { read(state.add(DRM_ATOMIC_DEV_OFF).cast::<*mut c_void>()) };
    drm_atomic_commit_clear(state.cast());
    let funcs = mode_config_funcs(dev);
    if !funcs.is_null() {
        // SAFETY: custom state lifecycle callback owns final-state storage for this device.
        let release = unsafe { state_callback(funcs, DRM_MODE_CONFIG_ATOMIC_STATE_FREE_OFF) };
        // SAFETY: FREE_OFF's ABI signature is atomic_state_free(state), taking ownership of the caller's non-null state pointer.
        if release != 0 { unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut c_void)>(release)(state.cast()); } }
        // SAFETY: no custom free callback, so this call frees the fixed-size state block itself, matching the layout alloc used in commit_alloc.
        else { drm_atomic_commit_default_release(state.cast()); unsafe { dealloc(state, layout(DRM_ATOMIC_STATE_SIZE).unwrap()); } }
    } else {
        drm_atomic_commit_default_release(state.cast());
        // SAFETY: final default release owns the original complete atomic-state allocation exactly once.
        unsafe { dealloc(state, layout(DRM_ATOMIC_STATE_SIZE).unwrap()); }
    }
    drm_dev_put(dev);
}

/// Discard cached object states after modeset-lock backoff. # C: O(N_objects)
pub(super) extern "C" fn drm_atomic_commit_clear(state: *mut c_void) {
    if state.is_null() { return; }
    let state = state.cast::<u8>();
    // SAFETY: a live atomic state retains its device until final release and carries its lifecycle table.
    let funcs = mode_config_funcs(unsafe { read(state.add(DRM_ATOMIC_DEV_OFF).cast::<*mut c_void>()) });
    if !funcs.is_null() {
        // SAFETY: the optional driver callback clears its own extension before the transaction is reused.
        let clear = unsafe { state_callback(funcs, DRM_MODE_CONFIG_ATOMIC_STATE_CLEAR_OFF) };
        // SAFETY: CLEAR_OFF's ABI signature is atomic_state_clear(state); state is the caller's own non-null pointer.
        if clear != 0 { unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut c_void)>(clear)(state.cast()); } return; }
    }
    drm_atomic_commit_default_clear(state.cast());
}

/// Destroy every duplicated default state and drop connector references. # C: O(N_objects)
pub(super) extern "C" fn drm_atomic_commit_default_clear(state: *mut c_void) {
    if state.is_null() { return; }
    let state = state.cast::<u8>();
    // SAFETY: checked is private transaction metadata and must be cleared before a retry may acquire state.
    unsafe { *state.add(DRM_ATOMIC_ALLOW_MODESET_OFF) &= !DRM_ATOMIC_CHECKED_BIT; }
    // SAFETY: the state retains a live device while its arrays and duplicated states are cleared.
    let dev = unsafe { read(state.add(DRM_ATOMIC_DEV_OFF).cast::<*mut c_void>()) };
    let Some((planes, crtcs, _)) = release_counts(dev) else { return; };
    // SAFETY: each array entry is initialized only by atomic acquisition and is cleared after destruction.
    unsafe {
        let connectors = read(state.add(DRM_ATOMIC_NUM_CONNECTOR_OFF).cast::<i32>()).max(0) as usize;
        let connector_entries = read(state.add(DRM_ATOMIC_CONNECTORS_OFF).cast::<*mut u8>());
        for index in 0..connectors { let entry = connector_entries.add(index * DRM_ATOMIC_CONNECTOR_ENTRY_SIZE); let object = read(entry.add(DRM_STATE_ENTRY_OBJECT_OFF).cast::<*mut c_void>()); call_destroy(object, connector::DRM_CONNECTOR_FUNCS_OFF, DRM_CONNECTOR_DESTROY_STATE_OFF, read(entry.add(DRM_STATE_ENTRY_DESTROY_OFF).cast::<*mut c_void>())); if !object.is_null() { mode_object_refs::put(object.cast::<u8>().add(connector::DRM_CONNECTOR_BASE_OFF).cast()); } core::ptr::write_bytes(entry, 0, DRM_ATOMIC_CONNECTOR_ENTRY_SIZE); }
        let crtc_entries = read(state.add(DRM_ATOMIC_CRTCS_OFF).cast::<*mut u8>());
        for index in 0..crtcs { let entry = crtc_entries.add(index * DRM_ATOMIC_CRTC_ENTRY_SIZE); let object = read(entry.add(DRM_STATE_ENTRY_OBJECT_OFF).cast::<*mut c_void>()); call_destroy(object, DRM_CRTC_FUNCS_OFF, DRM_CRTC_DESTROY_STATE_OFF, read(entry.add(DRM_STATE_ENTRY_DESTROY_OFF).cast::<*mut c_void>())); crtc_commit::put(read(entry.add(DRM_CRTC_ENTRY_COMMIT_OFF).cast::<*mut u8>())); core::ptr::write_bytes(entry, 0, DRM_ATOMIC_CRTC_ENTRY_SIZE); }
        let plane_entries = read(state.add(DRM_ATOMIC_PLANES_OFF).cast::<*mut u8>());
        for index in 0..planes { let entry = plane_entries.add(index * DRM_ATOMIC_PLANE_ENTRY_SIZE); let object = read(entry.add(DRM_STATE_ENTRY_OBJECT_OFF).cast::<*mut c_void>()); call_destroy(object, DRM_PLANE_FUNCS_OFF, DRM_PLANE_DESTROY_STATE_OFF, read(entry.add(DRM_STATE_ENTRY_DESTROY_OFF).cast::<*mut c_void>())); core::ptr::write_bytes(entry, 0, DRM_ATOMIC_PLANE_ENTRY_SIZE); }
        crtc_commit::put(read(state.add(DRM_ATOMIC_FAKE_COMMIT_OFF).cast::<*mut u8>())); write(state.add(DRM_ATOMIC_FAKE_COMMIT_OFF).cast::<*mut u8>(), core::ptr::null_mut());
    }
}

/// Release state-owned default arrays without dropping the state allocation. # C: O(N_objects)
pub(super) extern "C" fn drm_atomic_commit_default_release(state: *mut c_void) {
    if state.is_null() { return; }
    let state = state.cast::<u8>();
    // SAFETY: state is a complete atomic object whose retained device names its object counts.
    let dev = unsafe { read(state.add(DRM_ATOMIC_DEV_OFF).cast::<*mut c_void>()) };
    let Some((planes, crtcs, _)) = release_counts(dev) else { return; };
    // SAFETY: each pointer is an owned default allocation, then cleared to make repeat release benign.
    unsafe { let plane_states = read(state.add(DRM_ATOMIC_PLANES_OFF).cast::<*mut u8>()); let crtc_states = read(state.add(DRM_ATOMIC_CRTCS_OFF).cast::<*mut u8>()); let connector_states = read(state.add(DRM_ATOMIC_CONNECTORS_OFF).cast::<*mut u8>()); let connectors = read(state.add(DRM_ATOMIC_NUM_CONNECTOR_OFF).cast::<i32>()).max(0) as usize; release_array(plane_states, planes, DRM_ATOMIC_PLANE_ENTRY_SIZE); release_array(crtc_states, crtcs, DRM_ATOMIC_CRTC_ENTRY_SIZE); release_array(connector_states, connectors, DRM_ATOMIC_CONNECTOR_ENTRY_SIZE); write(state.add(DRM_ATOMIC_PLANES_OFF).cast::<*mut u8>(), core::ptr::null_mut()); write(state.add(DRM_ATOMIC_CRTCS_OFF).cast::<*mut u8>(), core::ptr::null_mut()); write(state.add(DRM_ATOMIC_CONNECTORS_OFF).cast::<*mut u8>(), core::ptr::null_mut()); write(state.add(DRM_ATOMIC_NUM_CONNECTOR_OFF).cast::<i32>(), 0); }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static CLEAR_CALLS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn clear_callback(_state: *mut c_void) { CLEAR_CALLS.fetch_add(1, Ordering::SeqCst); }
    #[test]
    fn atomic_state_exports_are_present() {
        export_symbols();
        for name in ["drm_atomic_commit_alloc", "drm_atomic_commit_clear", "drm_atomic_commit_put", "drm_atomic_commit_default_release"] { assert!(crate::symtab::is_exported(name)); }
        assert_eq!(DRM_ATOMIC_STATE_SIZE, 128); assert_eq!(DRM_ATOMIC_PLANE_ENTRY_SIZE, 32); assert_eq!(DRM_ATOMIC_CRTC_ENTRY_SIZE, 56); assert_eq!(DRM_ATOMIC_CONNECTOR_ENTRY_SIZE, 40);
    }

    #[test]
    fn clear_resets_checked_and_prefers_driver_lifecycle_callback() {
        let mut state = [0u8; DRM_ATOMIC_STATE_SIZE];
        state[DRM_ATOMIC_ALLOW_MODESET_OFF] = DRM_ATOMIC_CHECKED_BIT;
        drm_atomic_commit_clear(state.as_mut_ptr().cast());
        assert_eq!(state[DRM_ATOMIC_ALLOW_MODESET_OFF] & DRM_ATOMIC_CHECKED_BIT, 0);

        let mut dev = [0u8; DRM_DEVICE_MODE_CONFIG_OFF + DRM_MODE_CONFIG_FUNCS_OFF + 8];
        let mut funcs = [0u8; DRM_MODE_CONFIG_ATOMIC_STATE_FREE_OFF + 8];
        CLEAR_CALLS.store(0, Ordering::SeqCst);
        // SAFETY: fabricated ABI records reserve the mode-config callback and atomic-device pointer fields.
        unsafe {
            write(dev.as_mut_ptr().add(DRM_DEVICE_MODE_CONFIG_OFF + DRM_MODE_CONFIG_FUNCS_OFF).cast::<*mut u8>(), funcs.as_mut_ptr());
            write(funcs.as_mut_ptr().add(DRM_MODE_CONFIG_ATOMIC_STATE_CLEAR_OFF).cast::<usize>(), clear_callback as *const () as usize);
            write(state.as_mut_ptr().add(DRM_ATOMIC_DEV_OFF).cast::<*mut u8>(), dev.as_mut_ptr());
        }
        drm_atomic_commit_clear(state.as_mut_ptr().cast());
        assert_eq!(CLEAR_CALLS.load(Ordering::SeqCst), 1);
    }
}
