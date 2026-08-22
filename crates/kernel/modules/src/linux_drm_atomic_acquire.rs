//! DRM atomic object-state acquisition through modeset locks.

use super::*;
use alloc::alloc::{alloc_zeroed, dealloc};

const DRM_ATOMIC_DEV_OFF: usize = 8;
const DRM_ATOMIC_PLANES_OFF: usize = 32;
const DRM_ATOMIC_CRTCS_OFF: usize = 40;
const DRM_ATOMIC_NUM_CONNECTOR_OFF: usize = 48;
const DRM_ATOMIC_CONNECTORS_OFF: usize = 56;
const DRM_ATOMIC_ACQUIRE_CTX_OFF: usize = 80;
const DRM_PLANE_LOCK_OFF: usize = 32;
const DRM_PLANE_FUNCS_OFF: usize = 176;
const DRM_PLANE_INDEX_OFF: usize = 1220;
const DRM_PLANE_STATE_OFF: usize = 1232;
const DRM_CRTC_LOCK_OFF: usize = 40;
const DRM_CRTC_FUNCS_OFF: usize = 408;
const DRM_CRTC_INDEX_OFF: usize = 144;
const DRM_CRTC_STATE_OFF: usize = 1488;
const DRM_CONNECTOR_FUNCS_OFF: usize = 416;
const DRM_CONNECTOR_INDEX_OFF: usize = 136;
const DRM_CONNECTOR_STATE_OFF: usize = 1968;
const DRM_DEVICE_MODE_CONFIG_OFF: usize = 360;
const DRM_MODE_CONFIG_CONNECTION_MUTEX_OFF: usize = 32;
const DRM_PLANE_ENTRY_SIZE: usize = 32;
const DRM_CRTC_ENTRY_SIZE: usize = 56;
const DRM_CONNECTOR_ENTRY_SIZE: usize = 40;
const DRM_ENTRY_OBJECT_OFF: usize = 0;
const DRM_ENTRY_DESTROY_OFF: usize = 8;
const DRM_ENTRY_OLD_OFF: usize = 16;
const DRM_ENTRY_NEW_OFF: usize = 24;
const DRM_PLANE_DUPLICATE_OFF: usize = 40;
const DRM_CRTC_DUPLICATE_OFF: usize = 80;
const DRM_CONNECTOR_DUPLICATE_OFF: usize = 72;
const DRM_PLANE_STATE_ATOMIC_OFF: usize = 168;
const DRM_CRTC_STATE_ATOMIC_OFF: usize = 328;
const DRM_CONNECTOR_STATE_ATOMIC_OFF: usize = 32;
const DRM_OBJECT_DEV_OFF: usize = 0;
const DRM_PLANE_STATE_CRTC_OFF: usize = 8;
const DRM_CONNECTOR_STATE_CRTC_OFF: usize = 8;
const LINUX_ENOMEM: i32 = 12;
const LINUX_EINVAL: i32 = 22;

fn err_ptr(errno: i32) -> *mut c_void { (-(errno as isize)) as usize as *mut c_void }
fn is_err_ptr(ptr: *mut c_void) -> bool { (ptr as usize) >= usize::MAX - 4095 }
fn entry(state: *mut u8, array_off: usize, size: usize, index: usize) -> *mut u8 {
    // SAFETY: validated atomic-state array pointer and a verified entry size compute this entry address.
    unsafe { read(state.add(array_off).cast::<*mut u8>()).wrapping_add(index.saturating_mul(size)) }
}
unsafe fn duplicate(object: *mut u8, funcs_off: usize, duplicate_off: usize) -> *mut c_void {
    // SAFETY: object exposes the ABI function-table slot for atomic state duplication.
    let funcs = unsafe { read(object.add(funcs_off).cast::<*const u8>()) };
    if funcs.is_null() { return core::ptr::null_mut(); }
    // SAFETY: a nonzero callback has the documented single-object duplication signature.
    let callback = unsafe { read(funcs.add(duplicate_off).cast::<usize>()) };
    if callback == 0 { return core::ptr::null_mut(); }
    // SAFETY: the funcs-table slot at duplicate_off is the ABI's atomic_duplicate_state entry, taking one object pointer and returning one owned state pointer.
    unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut c_void) -> *mut c_void>(callback)(object.cast()) }
}
fn acquire_ctx(state: *mut u8) -> *mut c_void {
    // SAFETY: atomic-state acquire context is an ABI-pinned pointer field.
    unsafe { read(state.add(DRM_ATOMIC_ACQUIRE_CTX_OFF).cast::<*mut c_void>()) }
}
fn registered_object(dev: *mut c_void, object: *mut u8, index: usize, kind: u8) -> bool {
    if dev.is_null() || object.is_null() { return false; }
    // SAFETY: every published KMS object begins with its owning DRM device pointer.
    if unsafe { read(object.add(DRM_OBJECT_DEV_OFF).cast::<*mut c_void>()) } != dev { return false; }
    let devices = DEVICES.lock();
    let Some(record) = devices.iter().find(|record| record.dev == dev as usize && record.mode_config && !record.put_pending && !record.unplugged) else { return false; };
    match kind {
        0 => record.planes.get(index).is_some_and(|entry| entry.ptr == object as usize),
        1 => record.crtcs.get(index).is_some_and(|entry| entry.ptr == object as usize),
        _ => record.connectors.get(index).is_some_and(|entry| entry.ptr == object as usize),
    }
}
fn fixed_array_entry(state: *mut u8, array_off: usize, entry_size: usize, index: usize, kind: u8) -> bool {
    // SAFETY: every caller passes the atomic-state pointer already validated non-null by the entry point.
    let dev = unsafe { read(state.add(DRM_ATOMIC_DEV_OFF).cast::<*mut c_void>()) };
    let devices = DEVICES.lock();
    let Some(record) = devices.iter().find(|record| record.dev == dev as usize && record.mode_config && !record.put_pending && !record.unplugged) else { return false; };
    let count = if kind == 0 { record.planes.len() } else { record.crtcs.len() };
    if index >= count { return false; }
    // SAFETY: state came from the matching device allocator and the checked index is in its fixed array.
    unsafe { !read(state.add(array_off).cast::<*mut u8>()).is_null() && entry_size != 0 }
}
fn array_layout(entries: usize) -> Option<Layout> { Layout::array::<u8>(entries.checked_mul(DRM_CONNECTOR_ENTRY_SIZE)?).ok() }
fn ensure_connector_entries(state: *mut u8, index: usize) -> bool {
    // SAFETY: the state retains its device and the connection modeset lock serializes connector topology.
    let dev = unsafe { read(state.add(DRM_ATOMIC_DEV_OFF).cast::<*mut c_void>()) };
    let required = { let devices = DEVICES.lock(); let Some(record) = devices.iter().find(|record| record.dev == dev as usize && record.mode_config && !record.put_pending) else { return false; }; record.connectors.len().max(index.saturating_add(1)) };
    // SAFETY: num_connector is the currently allocated connector-entry capacity.
    let current = unsafe { read(state.add(DRM_ATOMIC_NUM_CONNECTOR_OFF).cast::<i32>()) }.max(0) as usize;
    if index < current { return true; }
    let Some(layout) = array_layout(required) else { return false; };
    // SAFETY: allocation covers exactly the new zeroed connector-state entry capacity.
    let next = unsafe { alloc_zeroed(layout) }; if next.is_null() { return false; }
    // SAFETY: old entries are copied exactly once, then the prior allocation is released by its recorded capacity.
    unsafe { let old = read(state.add(DRM_ATOMIC_CONNECTORS_OFF).cast::<*mut u8>()); if !old.is_null() { core::ptr::copy_nonoverlapping(old, next, current * DRM_CONNECTOR_ENTRY_SIZE); if let Some(old_layout) = array_layout(current) { dealloc(old, old_layout); } } write(state.add(DRM_ATOMIC_CONNECTORS_OFF).cast::<*mut u8>(), next); write(state.add(DRM_ATOMIC_NUM_CONNECTOR_OFF).cast::<i32>(), required as i32); }
    true
}
fn duplicate_state(state: *mut u8, object: *mut u8, lock: *mut u8, funcs_off: usize, duplicate_off: usize, object_state_off: usize, array_off: usize, entry_size: usize, index: usize, state_off: usize) -> *mut c_void {
    let slot = entry(state, array_off, entry_size, index);
    // SAFETY: state entry has one object pointer field and one new-state field.
    if unsafe { read(slot.add(DRM_ENTRY_NEW_OFF).cast::<*mut c_void>()) }.is_null() == false { return unsafe { read(slot.add(DRM_ENTRY_NEW_OFF).cast::<*mut c_void>()) }; }
    let ctx = acquire_ctx(state); if ctx.is_null() { return err_ptr(LINUX_EINVAL); }
    let ret = modeset::drm_modeset_lock(lock.cast(), ctx); if ret != 0 { return err_ptr(-ret); }
    // SAFETY: the object remains locked until the enclosing acquire context is dropped.
    let copy = unsafe { duplicate(object, funcs_off, duplicate_off) };
    if copy.is_null() { return err_ptr(LINUX_ENOMEM); }
    // SAFETY: duplicated state, current state, and array ownership fields are all ABI-pinned pointers.
    unsafe { write(slot.add(DRM_ENTRY_OBJECT_OFF).cast::<*mut c_void>(), object.cast()); write(slot.add(DRM_ENTRY_DESTROY_OFF).cast::<*mut c_void>(), copy); write(slot.add(DRM_ENTRY_OLD_OFF).cast::<*mut c_void>(), read(object.add(object_state_off).cast::<*mut c_void>())); write(slot.add(DRM_ENTRY_NEW_OFF).cast::<*mut c_void>(), copy); write(copy.cast::<u8>().add(state_off).cast::<*mut c_void>(), state.cast()); }
    copy
}

pub(super) fn export_symbols() {
    crate::symtab::export("drm_atomic_get_plane_state", drm_atomic_get_plane_state as *const () as usize, false);
    crate::symtab::export("drm_atomic_get_crtc_state", drm_atomic_get_crtc_state as *const () as usize, false);
    crate::symtab::export("drm_atomic_get_connector_state", drm_atomic_get_connector_state as *const () as usize, false);
}
/// Acquire or return one plane's duplicated state in this transaction. # C: O(1)
pub(super) extern "C" fn drm_atomic_get_plane_state(state: *mut c_void, plane: *mut c_void) -> *mut c_void {
    if state.is_null() || plane.is_null() { return err_ptr(LINUX_EINVAL); }
    let state = state.cast::<u8>(); let plane = plane.cast::<u8>();
    // SAFETY: plane index is initialized with the plane's device graph membership.
    let index = unsafe { read(plane.add(DRM_PLANE_INDEX_OFF).cast::<u32>()) as usize };
    // SAFETY: state is the non-null atomic-state pointer checked above and dev is its ABI-pinned device field.
    let dev = unsafe { read(state.add(DRM_ATOMIC_DEV_OFF).cast::<*mut c_void>()) };
    if !registered_object(dev, plane, index, 0) || !fixed_array_entry(state, DRM_ATOMIC_PLANES_OFF, DRM_PLANE_ENTRY_SIZE, index, 0) { return err_ptr(LINUX_EINVAL); }
    let result = duplicate_state(state, plane, plane.wrapping_add(DRM_PLANE_LOCK_OFF), DRM_PLANE_FUNCS_OFF, DRM_PLANE_DUPLICATE_OFF, DRM_PLANE_STATE_OFF, DRM_ATOMIC_PLANES_OFF, DRM_PLANE_ENTRY_SIZE, index, DRM_PLANE_STATE_ATOMIC_OFF);
    if is_err_ptr(result) { return result; }
    // SAFETY: every plane state begins with plane then its optionally attached CRTC.
    let crtc = unsafe { read(result.cast::<u8>().add(DRM_PLANE_STATE_CRTC_OFF).cast::<*mut c_void>()) };
    if crtc.is_null() { result } else { let related = drm_atomic_get_crtc_state(state.cast(), crtc); if is_err_ptr(related) { related } else { result } }
}
/// Acquire or return one CRTC's duplicated state in this transaction. # C: O(1)
pub(super) extern "C" fn drm_atomic_get_crtc_state(state: *mut c_void, crtc: *mut c_void) -> *mut c_void {
    if state.is_null() || crtc.is_null() { return err_ptr(LINUX_EINVAL); }
    let state = state.cast::<u8>(); let crtc = crtc.cast::<u8>();
    // SAFETY: CRTC index is initialized with the CRTC's device graph membership.
    let index = unsafe { read(crtc.add(DRM_CRTC_INDEX_OFF).cast::<u32>()) as usize };
    // SAFETY: state is the non-null atomic-state pointer checked above and dev is its ABI-pinned device field.
    let dev = unsafe { read(state.add(DRM_ATOMIC_DEV_OFF).cast::<*mut c_void>()) };
    if !registered_object(dev, crtc, index, 1) || !fixed_array_entry(state, DRM_ATOMIC_CRTCS_OFF, DRM_CRTC_ENTRY_SIZE, index, 1) { return err_ptr(LINUX_EINVAL); }
    duplicate_state(state, crtc, crtc.wrapping_add(DRM_CRTC_LOCK_OFF), DRM_CRTC_FUNCS_OFF, DRM_CRTC_DUPLICATE_OFF, DRM_CRTC_STATE_OFF, DRM_ATOMIC_CRTCS_OFF, DRM_CRTC_ENTRY_SIZE, index, DRM_CRTC_STATE_ATOMIC_OFF)
}
/// Acquire or return one connector's duplicated state in this transaction. # C: O(N_connectors)
pub(super) extern "C" fn drm_atomic_get_connector_state(state: *mut c_void, connector: *mut c_void) -> *mut c_void {
    if state.is_null() || connector.is_null() { return err_ptr(LINUX_EINVAL); }
    let state = state.cast::<u8>(); let connector = connector.cast::<u8>();
    // SAFETY: connector index and device pointer are initialized with connector graph membership.
    let index = unsafe { read(connector.add(DRM_CONNECTOR_INDEX_OFF).cast::<u32>()) as usize }; let dev = unsafe { read(state.add(DRM_ATOMIC_DEV_OFF).cast::<*mut u8>()) };
    if !registered_object(dev.cast(), connector, index, 2) { return err_ptr(LINUX_EINVAL); }
    let lock = dev.wrapping_add(DRM_DEVICE_MODE_CONFIG_OFF + DRM_MODE_CONFIG_CONNECTION_MUTEX_OFF);
    let ctx = acquire_ctx(state); if ctx.is_null() { return err_ptr(LINUX_EINVAL); }
    let ret = modeset::drm_modeset_lock(lock.cast(), ctx); if ret != 0 { return err_ptr(-ret); }
    if !ensure_connector_entries(state, index) { return err_ptr(LINUX_ENOMEM); }
    let slot = entry(state, DRM_ATOMIC_CONNECTORS_OFF, DRM_CONNECTOR_ENTRY_SIZE, index);
    // SAFETY: connector capacity was ensured and the new-state field identifies first acquisition.
    let new = unsafe { read(slot.add(DRM_ENTRY_NEW_OFF).cast::<*mut c_void>()).is_null() };
    let result = duplicate_state(state, connector, lock, DRM_CONNECTOR_FUNCS_OFF, DRM_CONNECTOR_DUPLICATE_OFF, DRM_CONNECTOR_STATE_OFF, DRM_ATOMIC_CONNECTORS_OFF, DRM_CONNECTOR_ENTRY_SIZE, index, DRM_CONNECTOR_STATE_ATOMIC_OFF);
    if is_err_ptr(result) { return result; }
    if new {
        // SAFETY: registered connector storage contains its embedded mode object at this fixed offset.
        let base = unsafe { connector.add(connector::DRM_CONNECTOR_BASE_OFF) };
        mode_object_refs::get(base.cast());
    }
    // SAFETY: every connector state begins with connector then its optionally attached CRTC.
    let crtc = unsafe { read(result.cast::<u8>().add(DRM_CONNECTOR_STATE_CRTC_OFF).cast::<*mut c_void>()) };
    if crtc.is_null() { result } else { let related = drm_atomic_get_crtc_state(state.cast(), crtc); if is_err_ptr(related) { related } else { result } }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_acquisition_rejects_missing_transaction_or_object() {
        assert_eq!(drm_atomic_get_plane_state(core::ptr::null_mut(), core::ptr::null_mut()), err_ptr(LINUX_EINVAL));
        assert_eq!(drm_atomic_get_crtc_state(core::ptr::null_mut(), core::ptr::null_mut()), err_ptr(LINUX_EINVAL));
        assert_eq!(drm_atomic_get_connector_state(core::ptr::null_mut(), core::ptr::null_mut()), err_ptr(LINUX_EINVAL));
    }

    #[test]
    fn atomic_acquisition_exports_all_object_state_entry_points() {
        let _modules = crate::test_serial::claim();
        export_symbols();
        for name in ["drm_atomic_get_plane_state", "drm_atomic_get_crtc_state", "drm_atomic_get_connector_state"] { assert!(crate::symtab::is_exported(name)); }
    }
}
