//! DRM atomic helper plane-check callback ordering.

use super::*;

const DRM_ATOMIC_DEV_OFF: usize = 8;
const DRM_ATOMIC_PLANES_OFF: usize = 32;
const DRM_ATOMIC_CRTCS_OFF: usize = 40;
const DRM_STATE_ENTRY_OBJECT_OFF: usize = 0;
const DRM_STATE_ENTRY_OLD_OFF: usize = 16;
const DRM_STATE_ENTRY_NEW_OFF: usize = 24;
const DRM_ATOMIC_PLANE_ENTRY_SIZE: usize = 32;
const DRM_ATOMIC_CRTC_ENTRY_SIZE: usize = 56;
const DRM_PLANE_HELPER_PRIVATE_OFF: usize = 1224;
const DRM_CRTC_HELPER_PRIVATE_OFF: usize = 432;
const DRM_PLANE_HELPER_ATOMIC_CHECK_OFF: usize = 32;
const DRM_CRTC_HELPER_ATOMIC_CHECK_OFF: usize = 80;
const DRM_PLANE_STATE_CRTC_OFF: usize = 8;
const DRM_CRTC_STATE_PLANES_CHANGED_OFF: usize = 10;
const DRM_CRTC_STATE_PLANES_CHANGED_BIT: u8 = 1;
const LINUX_EINVAL: i32 = 22;

fn error_ptr(ptr: *mut c_void) -> Option<i32> {
    ((ptr as usize) >= usize::MAX - 4095).then_some(ptr as isize as i32)
}

fn object_counts(dev: *mut c_void) -> Option<(usize, usize, usize)> {
    let devices = DEVICES.lock();
    let record = devices.iter().find(|record| record.dev == dev as usize
        && record.mode_config && !record.put_pending && !record.unplugged)?;
    Some((record.planes.len(), record.crtcs.len(), record.connectors.len()))
}

unsafe fn entry(state: *mut u8, array_off: usize, entry_size: usize, index: usize) -> *mut u8 {
    // SAFETY: caller bounds index against the live device count and state owns the matching fixed array.
    unsafe { read(state.add(array_off).cast::<*mut u8>()).add(index * entry_size) }
}

fn mark_planes_changed(state: *mut u8, crtc: *mut c_void) -> Result<(), i32> {
    if crtc.is_null() { return Ok(()); }
    let result = atomic_acquire::drm_atomic_get_crtc_state(state.cast(), crtc);
    if let Some(errno) = error_ptr(result) { return Err(errno); }
    if result.is_null() { return Err(-LINUX_EINVAL); }
    // SAFETY: a new CRTC state was acquired for this transaction; bit zero is its planes_changed field.
    unsafe { *result.cast::<u8>().add(DRM_CRTC_STATE_PLANES_CHANGED_OFF) |= DRM_CRTC_STATE_PLANES_CHANGED_BIT; }
    Ok(())
}

fn plane_changed(state: *mut u8, old: *mut u8, new: *mut u8) -> Result<(), i32> {
    // SAFETY: old and new are complete plane-state records held by this atomic transaction.
    let old_crtc = unsafe { read(old.add(DRM_PLANE_STATE_CRTC_OFF).cast::<*mut c_void>()) };
    // SAFETY: old and new are complete plane-state records held by this atomic transaction.
    let new_crtc = unsafe { read(new.add(DRM_PLANE_STATE_CRTC_OFF).cast::<*mut c_void>()) };
    mark_planes_changed(state, old_crtc)?;
    mark_planes_changed(state, new_crtc)
}

unsafe fn plane_check(plane: *mut u8, state: *mut u8) -> i32 {
    // SAFETY: plane is a live ABI object and helper_private, when non-null, names its complete helper vtable.
    let helpers = unsafe { read(plane.add(DRM_PLANE_HELPER_PRIVATE_OFF).cast::<*const u8>()) };
    if helpers.is_null() { return 0; }
    // SAFETY: atomic_check is the ABI-pinned callback slot in the plane helper table.
    let callback = unsafe { read(helpers.add(DRM_PLANE_HELPER_ATOMIC_CHECK_OFF).cast::<usize>()) };
    if callback == 0 { return 0; }
    // SAFETY: nonzero atomic_check accepts exactly (drm_plane *, drm_atomic_commit *).
    unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut c_void, *mut c_void) -> i32>(callback)(plane.cast(), state.cast()) }
}

unsafe fn crtc_check(crtc: *mut u8, state: *mut u8) -> i32 {
    // SAFETY: crtc is a live ABI object and helper_private, when non-null, names its complete helper vtable.
    let helpers = unsafe { read(crtc.add(DRM_CRTC_HELPER_PRIVATE_OFF).cast::<*const u8>()) };
    if helpers.is_null() { return 0; }
    // SAFETY: atomic_check is the ABI-pinned callback slot in the CRTC helper table.
    let callback = unsafe { read(helpers.add(DRM_CRTC_HELPER_ATOMIC_CHECK_OFF).cast::<usize>()) };
    if callback == 0 { return 0; }
    // SAFETY: nonzero atomic_check accepts exactly (drm_crtc *, drm_atomic_commit *).
    unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut c_void, *mut c_void) -> i32>(callback)(crtc.cast(), state.cast()) }
}

pub(super) fn export_symbols() {
    crate::symtab::export("drm_atomic_helper_check_planes", drm_atomic_helper_check_planes as *const () as usize, false);
}

/// Mark affected CRTCs and call plane callbacks before CRTC callbacks. # C: O(N_planes + N_crtcs)
pub(super) extern "C" fn drm_atomic_helper_check_planes(dev: *mut c_void, state: *mut c_void) -> i32 {
    if dev.is_null() || state.is_null() { return -LINUX_EINVAL; }
    let state = state.cast::<u8>();
    // SAFETY: atomic state retains the device it was allocated for throughout the check phase.
    if unsafe { read(state.add(DRM_ATOMIC_DEV_OFF).cast::<*mut c_void>()) } != dev { return -LINUX_EINVAL; }
    let Some((planes, crtcs, _)) = object_counts(dev) else { return -LINUX_EINVAL; };
    for index in 0..planes {
        // SAFETY: index is bounded by the recorded plane count for this transaction's device.
        let slot = unsafe { entry(state, DRM_ATOMIC_PLANES_OFF, DRM_ATOMIC_PLANE_ENTRY_SIZE, index) };
        // SAFETY: every atomic plane entry uses these ABI-pinned object and state slots.
        let (plane, old, new) = unsafe { (read(slot.add(DRM_STATE_ENTRY_OBJECT_OFF).cast::<*mut u8>()), read(slot.add(DRM_STATE_ENTRY_OLD_OFF).cast::<*mut u8>()), read(slot.add(DRM_STATE_ENTRY_NEW_OFF).cast::<*mut u8>())) };
        if plane.is_null() || old.is_null() || new.is_null() { continue; }
        if let Err(errno) = plane_changed(state, old, new) { return errno; }
        // SAFETY: plane and state are live for the entire atomic callback stage.
        let ret = unsafe { plane_check(plane, state) };
        if ret != 0 { return ret; }
    }
    for index in 0..crtcs {
        // SAFETY: index is bounded by the recorded CRTC count for this transaction's device.
        let slot = unsafe { entry(state, DRM_ATOMIC_CRTCS_OFF, DRM_ATOMIC_CRTC_ENTRY_SIZE, index) };
        // SAFETY: every atomic CRTC entry uses these ABI-pinned object and new-state slots.
        let (crtc, new) = unsafe { (read(slot.add(DRM_STATE_ENTRY_OBJECT_OFF).cast::<*mut u8>()), read(slot.add(DRM_STATE_ENTRY_NEW_OFF).cast::<*mut u8>())) };
        if crtc.is_null() || new.is_null() { continue; }
        // SAFETY: CRTC and state are live for the entire atomic callback stage.
        let ret = unsafe { crtc_check(crtc, state) };
        if ret != 0 { return ret; }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::sync::atomic::{AtomicU8, Ordering};

    static CALLBACK_ORDER: AtomicU8 = AtomicU8::new(0);

    unsafe extern "C" fn plane_callback(_plane: *mut c_void, _state: *mut c_void) -> i32 {
        CALLBACK_ORDER.store(1, Ordering::SeqCst); 0
    }

    unsafe extern "C" fn crtc_callback(_crtc: *mut c_void, _state: *mut c_void) -> i32 {
        if CALLBACK_ORDER.load(Ordering::SeqCst) == 1 { CALLBACK_ORDER.store(2, Ordering::SeqCst); 0 } else { -LINUX_EINVAL }
    }

    #[test]
    fn check_planes_export_is_present() {
        export_symbols();
        assert!(crate::symtab::is_exported("drm_atomic_helper_check_planes"));
    }

    #[test]
    fn error_pointer_decoding_preserves_linux_errno() {
        assert_eq!(error_ptr((-(35isize)) as usize as *mut c_void), Some(-35));
        assert_eq!(error_ptr(core::ptr::null_mut()), None);
    }

    #[test]
    fn check_planes_marks_crtc_then_calls_plane_before_crtc() {
        let _modules = crate::test_serial::claim();
        CALLBACK_ORDER.store(0, Ordering::SeqCst);
        let mut dev = [0u8; 1]; let mut state = [0u8; 128];
        let mut plane = [0u8; 1360]; let mut crtc = [0u8; 1656];
        let mut plane_helpers = [0u8; 96]; let mut crtc_helpers = [0u8; 136];
        let mut old_plane_state = [0u8; 184]; let mut new_plane_state = [0u8; 184];
        let mut new_crtc_state = [0u8; 336]; let mut plane_entries = [0u8; 32]; let mut crtc_entries = [0u8; 56];
        // SAFETY: each array reserves the ABI fields read by the helper and makes one plane/CRTC transaction.
        unsafe {
            write(plane.as_mut_ptr().add(DRM_PLANE_HELPER_PRIVATE_OFF).cast::<*mut u8>(), plane_helpers.as_mut_ptr());
            write(crtc.as_mut_ptr().add(DRM_CRTC_HELPER_PRIVATE_OFF).cast::<*mut u8>(), crtc_helpers.as_mut_ptr());
            write(plane_helpers.as_mut_ptr().add(DRM_PLANE_HELPER_ATOMIC_CHECK_OFF).cast::<usize>(), plane_callback as *const () as usize);
            write(crtc_helpers.as_mut_ptr().add(DRM_CRTC_HELPER_ATOMIC_CHECK_OFF).cast::<usize>(), crtc_callback as *const () as usize);
            write(crtc.as_mut_ptr().cast::<*mut u8>(), dev.as_mut_ptr());
            write(crtc.as_mut_ptr().add(144).cast::<u32>(), 0);
            write(old_plane_state.as_mut_ptr().add(DRM_PLANE_STATE_CRTC_OFF).cast::<*mut u8>(), crtc.as_mut_ptr());
            write(new_plane_state.as_mut_ptr().add(DRM_PLANE_STATE_CRTC_OFF).cast::<*mut u8>(), crtc.as_mut_ptr());
            write(plane_entries.as_mut_ptr().add(DRM_STATE_ENTRY_OBJECT_OFF).cast::<*mut u8>(), plane.as_mut_ptr());
            write(plane_entries.as_mut_ptr().add(DRM_STATE_ENTRY_OLD_OFF).cast::<*mut u8>(), old_plane_state.as_mut_ptr());
            write(plane_entries.as_mut_ptr().add(DRM_STATE_ENTRY_NEW_OFF).cast::<*mut u8>(), new_plane_state.as_mut_ptr());
            write(crtc_entries.as_mut_ptr().add(DRM_STATE_ENTRY_OBJECT_OFF).cast::<*mut u8>(), crtc.as_mut_ptr());
            write(crtc_entries.as_mut_ptr().add(DRM_STATE_ENTRY_NEW_OFF).cast::<*mut u8>(), new_crtc_state.as_mut_ptr());
            write(state.as_mut_ptr().add(DRM_ATOMIC_DEV_OFF).cast::<*mut u8>(), dev.as_mut_ptr());
            write(state.as_mut_ptr().add(DRM_ATOMIC_PLANES_OFF).cast::<*mut u8>(), plane_entries.as_mut_ptr());
            write(state.as_mut_ptr().add(DRM_ATOMIC_CRTCS_OFF).cast::<*mut u8>(), crtc_entries.as_mut_ptr());
        }
        DEVICES.lock().push(DeviceAllocation {
            dev: dev.as_mut_ptr() as usize, base: 0, layout: Layout::new::<u8>(), refs: 1, mode_config: true,
            objects: Vec::new(), planes: vec![PlaneRecord { ptr: plane.as_mut_ptr() as usize, formats: 0, layout: Layout::new::<u8>() }],
            crtcs: vec![CrtcRecord { ptr: crtc.as_mut_ptr() as usize, name: 0, layout: Layout::new::<u8>() }], encoders: Vec::new(), connectors: Vec::new(), clients: Vec::new(), vblank: None, primary_master: None, put_pending: false, unplugged: false,
        });
        assert_eq!(drm_atomic_helper_check_planes(dev.as_mut_ptr().cast(), state.as_mut_ptr().cast()), 0);
        assert_eq!(CALLBACK_ORDER.load(Ordering::SeqCst), 2);
        assert_eq!(new_crtc_state[DRM_CRTC_STATE_PLANES_CHANGED_OFF] & DRM_CRTC_STATE_PLANES_CHANGED_BIT, DRM_CRTC_STATE_PLANES_CHANGED_BIT);
        DEVICES.lock().clear();
    }
}
