//! DRM atomic affected-connector and affected-plane expansion.

use super::*;

const DRM_ATOMIC_DEV_OFF: usize = 8;
const DRM_ATOMIC_ACQUIRE_CTX_OFF: usize = 80;
const DRM_ATOMIC_CRTCS_OFF: usize = 40;
const DRM_ATOMIC_CRTC_ENTRY_SIZE: usize = 56;
const DRM_ATOMIC_ENTRY_OLD_OFF: usize = 16;
const DRM_CRTC_STATE_PLANE_MASK_OFF: usize = 12;
const DRM_CRTC_STATE_CONNECTOR_MASK_OFF: usize = 16;
const DRM_CRTC_INDEX_OFF: usize = 144;
const DRM_CONNECTOR_INDEX_OFF: usize = 136;
const DRM_PLANE_INDEX_OFF: usize = 1220;
const DRM_DEVICE_MODE_CONFIG_OFF: usize = 360;
const DRM_MODE_CONFIG_CONNECTION_MUTEX_OFF: usize = 32;
const LINUX_EINVAL: i32 = 22;

fn error_ptr(ptr: *mut c_void) -> Option<i32> { ((ptr as usize) >= usize::MAX - 4095).then_some(ptr as isize as i32) }

fn live_objects(dev: *mut c_void) -> Option<(Vec<usize>, Vec<usize>)> {
    let devices = DEVICES.lock();
    let record = devices.iter().find(|record| record.dev == dev as usize && record.mode_config && !record.put_pending && !record.unplugged)?;
    Some((record.connectors.iter().map(|connector| connector.ptr).collect(), record.planes.iter().map(|plane| plane.ptr).collect()))
}

fn transaction_device(state: *mut c_void) -> *mut c_void {
    if state.is_null() { core::ptr::null_mut() } else {
        // SAFETY: every atomic state stores its retained device at this ABI-pinned field.
        unsafe { read(state.cast::<u8>().add(DRM_ATOMIC_DEV_OFF).cast::<*mut c_void>()) }
    }
}

pub(super) fn export_symbols() {
    crate::symtab::export("drm_atomic_add_affected_connectors", drm_atomic_add_affected_connectors as *const () as usize, false);
    crate::symtab::export("drm_atomic_add_affected_planes", drm_atomic_add_affected_planes as *const () as usize, false);
}

/// Add every current connector selected by a CRTC's atomic connector mask. # C: O(N_connectors)
pub(super) extern "C" fn drm_atomic_add_affected_connectors(state: *mut c_void, crtc: *mut c_void) -> i32 {
    if state.is_null() || crtc.is_null() { return -LINUX_EINVAL; }
    let dev = transaction_device(state); if dev.is_null() { return -LINUX_EINVAL; }
    // SAFETY: the transaction retains its acquire context and the mode-config mutex is the canonical connector-topology lock.
    let ctx = unsafe { read(state.cast::<u8>().add(DRM_ATOMIC_ACQUIRE_CTX_OFF).cast::<*mut c_void>()) };
    if ctx.is_null() { return -LINUX_EINVAL; }
    let lock = dev.cast::<u8>().wrapping_add(DRM_DEVICE_MODE_CONFIG_OFF + DRM_MODE_CONFIG_CONNECTION_MUTEX_OFF);
    let ret = modeset::drm_modeset_lock(lock.cast(), ctx); if ret != 0 { return ret; }
    let Some((connectors, _)) = live_objects(dev) else { return -LINUX_EINVAL; };
    let crtc_state = atomic_acquire::drm_atomic_get_crtc_state(state, crtc);
    if let Some(errno) = error_ptr(crtc_state) { return errno; }
    if crtc_state.is_null() { return -LINUX_EINVAL; }
    // SAFETY: a newly acquired CRTC state owns its current connector mask for this transaction.
    let mask = unsafe { read(crtc_state.cast::<u8>().add(DRM_CRTC_STATE_CONNECTOR_MASK_OFF).cast::<u32>()) };
    for connector in connectors {
        // SAFETY: connector index is stable for the published mode graph lifetime.
        let index = unsafe { read((connector as *const u8).add(DRM_CONNECTOR_INDEX_OFF).cast::<u32>()) as usize };
        if index >= 32 || mask & (1u32 << index) == 0 { continue; }
        let result = atomic_acquire::drm_atomic_get_connector_state(state, connector as *mut c_void);
        if let Some(errno) = error_ptr(result) { return errno; }
        if result.is_null() { return -LINUX_EINVAL; }
    }
    0
}

/// Add every current plane selected by a CRTC's old plane mask. # C: O(N_planes)
pub(super) extern "C" fn drm_atomic_add_affected_planes(state: *mut c_void, crtc: *mut c_void) -> i32 {
    if state.is_null() || crtc.is_null() { return -LINUX_EINVAL; }
    let dev = transaction_device(state); let Some((_, planes)) = live_objects(dev) else { return -LINUX_EINVAL; };
    // SAFETY: CRTC index selects the fixed CRTC entry allocated with this atomic state.
    let index = unsafe { read(crtc.cast::<u8>().add(DRM_CRTC_INDEX_OFF).cast::<u32>()) as usize };
    let Some((_, crtcs)) = ({ let devices = DEVICES.lock(); devices.iter().find(|record| record.dev == dev as usize && record.mode_config && !record.put_pending && !record.unplugged).map(|record| (record.planes.len(), record.crtcs.len())) }) else { return -LINUX_EINVAL; };
    if index >= crtcs { return -LINUX_EINVAL; }
    // SAFETY: the matching fixed CRTC entry contains the old state at byte 16.
    let old = unsafe { let entries = read(state.cast::<u8>().add(DRM_ATOMIC_CRTCS_OFF).cast::<*mut u8>()); if entries.is_null() { return -LINUX_EINVAL; } read(entries.add(index * DRM_ATOMIC_CRTC_ENTRY_SIZE + DRM_ATOMIC_ENTRY_OLD_OFF).cast::<*mut u8>()) };
    if old.is_null() { return -LINUX_EINVAL; }
    // SAFETY: old state is immutable for this transaction and stores the committed plane-membership mask.
    let mask = unsafe { read(old.add(DRM_CRTC_STATE_PLANE_MASK_OFF).cast::<u32>()) };
    for plane in planes {
        // SAFETY: plane index is stable for the published mode graph lifetime.
        let plane_index = unsafe { read((plane as *const u8).add(DRM_PLANE_INDEX_OFF).cast::<u32>()) as usize };
        if plane_index >= 32 || mask & (1u32 << plane_index) == 0 { continue; }
        let result = atomic_acquire::drm_atomic_get_plane_state(state, plane as *mut c_void);
        if let Some(errno) = error_ptr(result) { return errno; }
        if result.is_null() { return -LINUX_EINVAL; }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn affected_object_exports_and_null_rejection_are_present() {
        export_symbols();
        assert!(crate::symtab::is_exported("drm_atomic_add_affected_connectors"));
        assert!(crate::symtab::is_exported("drm_atomic_add_affected_planes"));
        assert_eq!(drm_atomic_add_affected_connectors(core::ptr::null_mut(), core::ptr::null_mut()), -LINUX_EINVAL);
        assert_eq!(drm_atomic_add_affected_planes(core::ptr::null_mut(), core::ptr::null_mut()), -LINUX_EINVAL);
    }
}
