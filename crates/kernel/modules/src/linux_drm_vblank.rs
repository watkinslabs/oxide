//! DRM CRTC vblank modeset transitions.

use super::*;

const DRM_CRTC_DEV_OFF: usize = 0;
const DRM_CRTC_INDEX_OFF: usize = 144;
const DRM_DEVICE_VBLANK_OFF: usize = 312;
const DRM_DEVICE_NUM_CRTCS_OFF: usize = 356;
const DRM_VBLANK_CRTC_SIZE: usize = 400;
const DRM_VBLANK_REFCOUNT_OFF: usize = 96;
const DRM_VBLANK_INMODESET_OFF: usize = 108;
const DRM_VBLANK_ENABLED_OFF: usize = 256;

pub(super) fn export_symbols() {
    crate::symtab::export("drm_crtc_vblank_off", drm_crtc_vblank_off as *const () as usize, false);
    crate::symtab::export("drm_crtc_vblank_on", drm_crtc_vblank_on as *const () as usize, false);
}

fn record(crtc: *mut c_void) -> Option<*mut u8> {
    if crtc.is_null() { return None; }
    // SAFETY: CRTC construction publishes the device pointer and immutable index at these verified ABI offsets.
    let (dev, pipe) = unsafe { (read(crtc.cast::<u8>().add(DRM_CRTC_DEV_OFF).cast::<*mut c_void>()), read(crtc.cast::<u8>().add(DRM_CRTC_INDEX_OFF).cast::<u32>())) };
    if dev.is_null() { return None; }
    let devices = DEVICES.lock();
    if !devices.iter().any(|entry| entry.dev == dev as usize && !entry.put_pending && !entry.unplugged) { return None; }
    // SAFETY: a live device owns its vblank array; the pipe bound is checked before deriving its record address.
    unsafe { let count = read(dev.cast::<u8>().add(DRM_DEVICE_NUM_CRTCS_OFF).cast::<u32>()); let base = read(dev.cast::<u8>().add(DRM_DEVICE_VBLANK_OFF).cast::<*mut u8>()); if base.is_null() || pipe >= count { None } else { Some(base.add(pipe as usize * DRM_VBLANK_CRTC_SIZE)) } }
}

/// Quiesce a CRTC whose hardware vblank counter can reset during a modeset. # C: O(1)
pub(super) extern "C" fn drm_crtc_vblank_off(crtc: *mut c_void) {
    let Some(vblank) = record(crtc) else { return; };
    // SAFETY: the vblank record belongs to this live CRTC and the modeset reference prevents immediate re-enable.
    unsafe { if read(vblank.add(DRM_VBLANK_INMODESET_OFF).cast::<u32>()) == 0 { let refs = read(vblank.add(DRM_VBLANK_REFCOUNT_OFF).cast::<i32>()); write(vblank.add(DRM_VBLANK_REFCOUNT_OFF).cast::<i32>(), refs.saturating_add(1)); write(vblank.add(DRM_VBLANK_INMODESET_OFF).cast::<u32>(), 1); } write(vblank.add(DRM_VBLANK_ENABLED_OFF).cast::<bool>(), false); }
}

/// Restore vblank delivery after a CRTC modeset transition. # C: O(1)
pub(super) extern "C" fn drm_crtc_vblank_on(crtc: *mut c_void) {
    let Some(vblank) = record(crtc) else { return; };
    // SAFETY: this reverses only the private modeset reference created by drm_crtc_vblank_off for this live record.
    unsafe { if read(vblank.add(DRM_VBLANK_INMODESET_OFF).cast::<u32>()) != 0 { let refs = read(vblank.add(DRM_VBLANK_REFCOUNT_OFF).cast::<i32>()); write(vblank.add(DRM_VBLANK_REFCOUNT_OFF).cast::<i32>(), refs.saturating_sub(1)); write(vblank.add(DRM_VBLANK_INMODESET_OFF).cast::<u32>(), 0); } write(vblank.add(DRM_VBLANK_ENABLED_OFF).cast::<bool>(), true); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vblank_modeset_transition_is_balanced_and_idempotent() {
        let _modules = crate::test_serial::claim();
        let mut crtc = [0u8; 1228]; let mut dev = [0u8; 512]; let mut records = [0u8; DRM_VBLANK_CRTC_SIZE];
        // SAFETY: test arrays reserve the relevant CRTC, device, and one vblank record ABI fields.
        unsafe { write(crtc.as_mut_ptr().cast::<*mut c_void>(), dev.as_mut_ptr().cast()); write(crtc.as_mut_ptr().add(DRM_CRTC_INDEX_OFF).cast::<u32>(), 0); write(dev.as_mut_ptr().add(DRM_DEVICE_NUM_CRTCS_OFF).cast::<u32>(), 1); write(dev.as_mut_ptr().add(DRM_DEVICE_VBLANK_OFF).cast::<*mut u8>(), records.as_mut_ptr()); }
        DEVICES.lock().push(DeviceAllocation { dev: dev.as_mut_ptr() as usize, base: 0, layout: Layout::new::<u8>(), refs: 1, mode_config: false, objects: Vec::new(), planes: Vec::new(), crtcs: Vec::new(), encoders: Vec::new(), connectors: Vec::new(), clients: Vec::new(), vblank: None, primary_master: None, put_pending: false, unplugged: false });
        drm_crtc_vblank_off(crtc.as_mut_ptr().cast()); drm_crtc_vblank_off(crtc.as_mut_ptr().cast());
        assert_eq!(unsafe { read(records.as_ptr().add(DRM_VBLANK_REFCOUNT_OFF).cast::<i32>()) }, 1);
        drm_crtc_vblank_on(crtc.as_mut_ptr().cast()); assert_eq!(unsafe { read(records.as_ptr().add(DRM_VBLANK_REFCOUNT_OFF).cast::<i32>()) }, 0); assert!(unsafe { read(records.as_ptr().add(DRM_VBLANK_ENABLED_OFF).cast::<bool>()) });
        DEVICES.lock().clear();
    }

    #[test]
    fn vblank_transition_entry_points_are_module_exports() {
        export_symbols();
        assert!(crate::symtab::is_exported("drm_crtc_vblank_off"));
        assert!(crate::symtab::is_exported("drm_crtc_vblank_on"));
    }
}
