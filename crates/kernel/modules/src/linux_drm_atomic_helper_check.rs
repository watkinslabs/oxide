//! DRM default atomic-check orchestration.

use super::*;

const DRM_ATOMIC_DEV_OFF: usize = 8;
const DRM_ATOMIC_FLAGS_OFF: usize = 16;
const DRM_ATOMIC_LEGACY_CURSOR_UPDATE_BIT: u8 = 1 << 1;
const DRM_ATOMIC_ASYNC_UPDATE_BIT: u8 = 1 << 2;
const DRM_DEVICE_MODE_CONFIG_OFF: usize = 360;
const DRM_MODE_CONFIG_NORMALIZE_ZPOS_OFF: usize = 1076;
const LINUX_EINVAL: i32 = 22;

pub(super) fn export_symbols() {
    crate::symtab::export("drm_atomic_helper_check", drm_atomic_helper_check as *const () as usize, false);
}

/// Validate an atomic state in dependency order before driver commit dispatch. # C: O(N_objects log N_planes)
pub(super) extern "C" fn drm_atomic_helper_check(dev: *mut c_void, state: *mut c_void) -> i32 {
    if dev.is_null() || state.is_null() { return -LINUX_EINVAL; }
    let state_bytes = state.cast::<u8>();
    // SAFETY: the atomic state owns this ABI-pinned device pointer until its final release.
    if unsafe { read(state_bytes.add(DRM_ATOMIC_DEV_OFF).cast::<*mut c_void>()) } != dev { return -LINUX_EINVAL; }
    let ret = atomic_modeset_check::drm_atomic_helper_check_modeset(dev, state); if ret != 0 { return ret; }
    // SAFETY: normalize_zpos is the verified mode-config boolean in this live DRM device.
    if unsafe { read(dev.cast::<u8>().add(DRM_DEVICE_MODE_CONFIG_OFF + DRM_MODE_CONFIG_NORMALIZE_ZPOS_OFF).cast::<bool>()) } {
        let ret = atomic_zpos::drm_atomic_normalize_zpos(dev, state); if ret != 0 { return ret; }
    }
    let ret = atomic_check::drm_atomic_helper_check_planes(dev, state); if ret != 0 { return ret; }
    // SAFETY: these bitfields are transaction-private hints owned by atomic check.
    let flags = unsafe { state_bytes.add(DRM_ATOMIC_FLAGS_OFF) };
    if unsafe { *flags & DRM_ATOMIC_LEGACY_CURSOR_UPDATE_BIT } != 0 {
        let accepted = atomic_async::drm_atomic_helper_async_check(dev, state) == 0;
        // SAFETY: the hint is set only after every synchronous validation stage passed.
        unsafe { if accepted { *flags |= DRM_ATOMIC_ASYNC_UPDATE_BIT; } else { *flags &= !DRM_ATOMIC_ASYNC_UPDATE_BIT; } }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_check_exports_and_refuses_a_mismatched_transaction_device() {
        let _modules = crate::test_serial::claim(); export_symbols();
        assert!(crate::symtab::is_exported("drm_atomic_helper_check"));
        let mut dev = [0u8; DRM_DEVICE_MODE_CONFIG_OFF + DRM_MODE_CONFIG_NORMALIZE_ZPOS_OFF + 1]; let mut other = [0u8; 1]; let mut state = [0u8; 128];
        // SAFETY: state exposes the sole device-pointer field read before any state-array access.
        unsafe { write(state.as_mut_ptr().add(DRM_ATOMIC_DEV_OFF).cast::<*mut u8>(), other.as_mut_ptr()); }
        assert_eq!(drm_atomic_helper_check(dev.as_mut_ptr().cast(), state.as_mut_ptr().cast()), -LINUX_EINVAL);
    }
}
