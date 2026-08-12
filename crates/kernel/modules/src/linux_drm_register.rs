use super::*;

const DRM_DEVICE_REGISTERED_OFF: usize = 96;

pub(super) fn export_symbols() {
    crate::symtab::export("drm_dev_register", drm_dev_register as *const () as usize, false);
    crate::symtab::export("drm_dev_unregister", drm_dev_unregister as *const () as usize, false);
}

/// Publish a fully initialized DRM device to driver clients. # C: O(N_devices)
extern "C" fn drm_dev_register(dev: *mut c_void, _flags: usize) -> i32 {
    if !is_live_device(dev) { return -LINUX_ENODEV; }
    // SAFETY: dev is a live managed drm_device and registered is its verified ABI bool field.
    unsafe { *(dev.cast::<u8>().add(DRM_DEVICE_REGISTERED_OFF).cast::<bool>()) = true; }
    0
}

/// Withdraw a DRM device from driver clients without releasing its allocation. # C: O(N_devices)
extern "C" fn drm_dev_unregister(dev: *mut c_void) {
    if !is_live_device(dev) { return; }
    // SAFETY: dev is a live managed drm_device and registered is its verified ABI bool field.
    unsafe { *(dev.cast::<u8>().add(DRM_DEVICE_REGISTERED_OFF).cast::<bool>()) = false; }
}
