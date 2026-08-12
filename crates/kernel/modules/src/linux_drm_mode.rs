use super::*;

pub(super) const DRM_DISPLAY_MODE_SIZE: usize = 120;
pub(super) const DRM_DISPLAY_MODE_HEAD_OFF: usize = 64;
pub(super) const DRM_CONNECTOR_MODES_OFF: usize = 168;
pub(super) const DRM_CONNECTOR_PROBED_MODES_OFF: usize = 184;

pub(super) fn export_symbols() {
    crate::symtab::export("drm_mode_create", drm_mode_create as *const () as usize, false);
    crate::symtab::export("drm_mode_destroy", drm_mode_destroy as *const () as usize, false);
    crate::symtab::export("drm_mode_probed_add", drm_mode_probed_add as *const () as usize, false);
}

pub(super) fn mode_layout() -> Layout { Layout::from_size_align(DRM_DISPLAY_MODE_SIZE, core::mem::align_of::<u64>()).unwrap() }

/// Allocate one zeroed display-mode object. # C: O(1)
pub(super) extern "C" fn drm_mode_create(_dev: *mut c_void) -> *mut c_void {
    // SAFETY: mode_layout names the complete ABI-verified display-mode allocation.
    unsafe { alloc_zeroed(mode_layout()).cast() }
}

/// Destroy one display-mode object and unlink it from a connector when published. # C: O(N_connectors + N_modes)
pub(super) extern "C" fn drm_mode_destroy(_dev: *mut c_void, mode: *mut c_void) {
    if mode.is_null() { return; }
    let mut devices = DEVICES.lock();
    for rec in devices.iter_mut() {
        for connector in rec.connectors.iter_mut() {
            let Some(pos) = connector.modes.iter().position(|entry| *entry == mode as usize) else { continue; };
            connector.modes.remove(pos);
            // SAFETY: the recorded mode was linked by drm_mode_probed_add and has a valid list node.
            unsafe { unlink_mode(mode); dealloc(mode.cast(), mode_layout()); }
            return;
        }
    }
    drop(devices);
    // SAFETY: callers destroy exactly objects returned by drm_mode_create or compatible core allocations.
    unsafe { dealloc(mode.cast(), mode_layout()); }
}

/// Append a newly probed mode to one connector's pending mode list. # C: O(N_connectors)
pub(super) extern "C" fn drm_mode_probed_add(connector: *mut c_void, mode: *mut c_void) {
    if connector.is_null() || mode.is_null() { return; }
    let dev = unsafe { *(connector.cast::<*mut c_void>()) };
    let mut devices = DEVICES.lock();
    if devices.iter().any(|record| record.connectors.iter().any(|entry| entry.modes.iter().any(|ptr| *ptr == mode as usize))) { return; }
    let Some(record) = devices.iter_mut().find(|rec| rec.dev == dev as usize && !rec.put_pending && !rec.unplugged) else { return; };
    let Some(entry) = record.connectors.iter_mut().find(|entry| entry.ptr == connector as usize) else { return; };
    // SAFETY: mode is a caller-owned display mode and connector's initialized probed list is serialized here.
    unsafe { link_tail(connector.cast::<u8>().add(DRM_CONNECTOR_PROBED_MODES_OFF), mode.cast::<u8>().add(DRM_DISPLAY_MODE_HEAD_OFF)); }
    entry.modes.push(mode as usize);
}

pub(super) unsafe fn initialize_mode_lists(connector: *mut u8) {
    // SAFETY: connector points at the ABI-sized connector object and these are its two list heads.
    unsafe { initialize_list(connector.add(DRM_CONNECTOR_MODES_OFF)); initialize_list(connector.add(DRM_CONNECTOR_PROBED_MODES_OFF)); }
}

unsafe fn initialize_list(head: *mut u8) {
    // SAFETY: head is an aligned list_head field in a live connector object.
    unsafe { write(head.cast::<*mut c_void>(), head.cast()); write(head.cast::<*mut c_void>().add(1), head.cast()); }
}

unsafe fn link_tail(head: *mut u8, node: *mut u8) {
    // SAFETY: head is initialized and node is an unlinked display-mode list node.
    unsafe { let previous = *(head.cast::<*mut c_void>().add(1)); write(node.cast::<*mut c_void>(), head.cast()); write(node.cast::<*mut c_void>().add(1), previous); write(previous.cast::<*mut c_void>(), node.cast()); write(head.cast::<*mut c_void>().add(1), node.cast()); }
}

pub(super) unsafe fn unlink_mode(mode: *mut c_void) {
    // SAFETY: mode is tracked as linked by drm_mode_probed_add, so its list node has live neighbours.
    unsafe { let node = mode.cast::<u8>().add(DRM_DISPLAY_MODE_HEAD_OFF).cast::<*mut c_void>(); let next = *node; let previous = *node.add(1); write(previous.cast::<*mut c_void>(), next); write(next.cast::<*mut c_void>().add(1), previous); }
}
