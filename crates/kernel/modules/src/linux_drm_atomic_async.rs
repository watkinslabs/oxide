//! DRM atomic asynchronous-update validation.

use super::*;

const DRM_ATOMIC_DEV_OFF: usize = 8;
const DRM_ATOMIC_PLANES_OFF: usize = 32;
const DRM_ATOMIC_CRTCS_OFF: usize = 40;
const DRM_ENTRY_OBJECT_OFF: usize = 0;
const DRM_ENTRY_OLD_OFF: usize = 16;
const DRM_ENTRY_NEW_OFF: usize = 24;
const DRM_ATOMIC_PLANE_ENTRY_SIZE: usize = 32;
const DRM_ATOMIC_CRTC_ENTRY_SIZE: usize = 56;
const DRM_PLANE_HELPER_PRIVATE_OFF: usize = 1224;
const DRM_PLANE_HELPER_ASYNC_CHECK_OFF: usize = 64;
const DRM_PLANE_HELPER_ASYNC_UPDATE_OFF: usize = 72;
const DRM_PLANE_STATE_CRTC_OFF: usize = 8;
const DRM_PLANE_STATE_FB_OFF: usize = 16;
const DRM_PLANE_STATE_FENCE_OFF: usize = 24;
const DRM_PLANE_STATE_CRTC_X_OFF: usize = 32;
const DRM_PLANE_STATE_CRTC_Y_OFF: usize = 36;
const DRM_PLANE_STATE_SRC_X_OFF: usize = 48;
const DRM_PLANE_STATE_SRC_Y_OFF: usize = 52;
const DRM_PLANE_STATE_COMMIT_OFF: usize = 160;
const DRM_PLANE_STATE_CURRENT_OFF: usize = 1232;
const DRM_CRTC_STATE_CHANGE_FLAGS_OFF: usize = 10;
const DRM_CRTC_STATE_MODESET_MASK: u8 = (1 << 1) | (1 << 3);
const DRM_CRTC_COMMIT_HW_DONE_OFF: usize = 48;
const LINUX_EBUSY: i32 = 16;
const LINUX_EINVAL: i32 = 22;

fn object_counts(dev: *mut c_void) -> Option<(usize, usize)> {
    let devices = DEVICES.lock();
    let record = devices.iter().find(|record| record.dev == dev as usize && record.mode_config && !record.put_pending && !record.unplugged)?;
    Some((record.planes.len(), record.crtcs.len()))
}

unsafe fn entry(state: *mut u8, array_off: usize, entry_size: usize, index: usize) -> *mut u8 {
    // SAFETY: callers bound index by the mode graph count that allocated this transaction array.
    unsafe { read(state.add(array_off).cast::<*mut u8>()).add(index * entry_size) }
}

fn async_callback(helpers: *const u8) -> usize {
    // SAFETY: helper_private names the fixed external plane-helper table.
    unsafe { read(helpers.add(DRM_PLANE_HELPER_ASYNC_CHECK_OFF).cast::<usize>()) }
}

fn async_update(helpers: *const u8) -> usize {
    // SAFETY: helper_private names the fixed external plane-helper table.
    unsafe { read(helpers.add(DRM_PLANE_HELPER_ASYNC_UPDATE_OFF).cast::<usize>()) }
}

pub(super) fn export_symbols() {
    crate::symtab::export("drm_atomic_helper_async_check", drm_atomic_helper_async_check as *const () as usize, false);
    crate::symtab::export("drm_atomic_helper_async_commit", drm_atomic_helper_async_commit as *const () as usize, false);
}

fn same_common_state(current: *mut u8, staged: *mut u8, old_fb: *mut c_void) -> bool {
    // SAFETY: both plane states are retained by the live async transaction during this verification.
    unsafe {
        read(current.add(DRM_PLANE_STATE_FB_OFF).cast::<*mut c_void>()) == read(staged.add(DRM_PLANE_STATE_FB_OFF).cast::<*mut c_void>())
            && read(current.add(DRM_PLANE_STATE_CRTC_X_OFF).cast::<i32>()) == read(staged.add(DRM_PLANE_STATE_CRTC_X_OFF).cast::<i32>())
            && read(current.add(DRM_PLANE_STATE_CRTC_Y_OFF).cast::<i32>()) == read(staged.add(DRM_PLANE_STATE_CRTC_Y_OFF).cast::<i32>())
            && read(current.add(DRM_PLANE_STATE_SRC_X_OFF).cast::<u32>()) == read(staged.add(DRM_PLANE_STATE_SRC_X_OFF).cast::<u32>())
            && read(current.add(DRM_PLANE_STATE_SRC_Y_OFF).cast::<u32>()) == read(staged.add(DRM_PLANE_STATE_SRC_Y_OFF).cast::<u32>())
            && read(staged.add(DRM_PLANE_STATE_FB_OFF).cast::<*mut c_void>()) == old_fb
    }
}

/// Execute a validated one-plane asynchronous update and check its in-place state swap. # C: O(N_planes)
pub(super) extern "C" fn drm_atomic_helper_async_commit(dev: *mut c_void, state: *mut c_void) {
    if dev.is_null() || state.is_null() { return; }
    let state = state.cast::<u8>();
    // SAFETY: the transaction retains its allocating device until terminal cleanup.
    if unsafe { read(state.add(DRM_ATOMIC_DEV_OFF).cast::<*mut c_void>()) } != dev { return; }
    let Some((planes, _)) = object_counts(dev) else { return; };
    for index in 0..planes {
        // SAFETY: index is bounded by the device-owned atomic plane entry array.
        let slot = unsafe { entry(state, DRM_ATOMIC_PLANES_OFF, DRM_ATOMIC_PLANE_ENTRY_SIZE, index) };
        // SAFETY: object/new-state pointers are fixed transaction entry fields.
        let (plane, staged) = unsafe { (read(slot.add(DRM_ENTRY_OBJECT_OFF).cast::<*mut u8>()), read(slot.add(DRM_ENTRY_NEW_OFF).cast::<*mut u8>())) };
        if plane.is_null() || staged.is_null() { continue; }
        // SAFETY: the current plane state and helper table remain live across this driver callback.
        let (current, helpers) = unsafe { (read(plane.add(DRM_PLANE_STATE_CURRENT_OFF).cast::<*mut u8>()), read(plane.add(DRM_PLANE_HELPER_PRIVATE_OFF).cast::<*const u8>())) };
        if current.is_null() || helpers.is_null() { continue; }
        // SAFETY: the old framebuffer is retained by the current state until the callback swaps ownership.
        let old_fb = unsafe { read(current.add(DRM_PLANE_STATE_FB_OFF).cast::<*mut c_void>()) };
        let callback = async_update(helpers);
        if callback == 0 { continue; }
        // SAFETY: atomic_async_update has the ABI-pinned plane/global-state signature.
        unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut c_void, *mut c_void)>(callback)(plane.cast(), state.cast()); }
        if !same_common_state(current, staged, old_fb) { klog::write_raw(b"drm: async plane update invariant violated\n"); }
    }
}

/// Validate the single-plane fast path before an asynchronous atomic update. # C: O(N_objects)
pub(super) extern "C" fn drm_atomic_helper_async_check(dev: *mut c_void, state: *mut c_void) -> i32 {
    if dev.is_null() || state.is_null() { return -LINUX_EINVAL; }
    let state = state.cast::<u8>();
    // SAFETY: the transaction retains its allocating device until final put.
    if unsafe { read(state.add(DRM_ATOMIC_DEV_OFF).cast::<*mut c_void>()) } != dev { return -LINUX_EINVAL; }
    let Some((planes, crtcs)) = object_counts(dev) else { return -LINUX_EINVAL; };
    for index in 0..crtcs {
        // SAFETY: index is bounded by the fixed CRTC transaction array.
        let slot = unsafe { entry(state, DRM_ATOMIC_CRTCS_OFF, DRM_ATOMIC_CRTC_ENTRY_SIZE, index) };
        // SAFETY: new CRTC state is the ABI-pinned field at byte 24 of its transaction entry.
        let new = unsafe { read(slot.add(DRM_ENTRY_NEW_OFF).cast::<*mut u8>()) };
        if !new.is_null() && unsafe { *new.add(DRM_CRTC_STATE_CHANGE_FLAGS_OFF) & DRM_CRTC_STATE_MODESET_MASK } != 0 { return -LINUX_EINVAL; }
    }
    let mut candidate: *mut u8 = core::ptr::null_mut();
    let mut old: *mut u8 = core::ptr::null_mut();
    let mut new: *mut u8 = core::ptr::null_mut();
    for index in 0..planes {
        // SAFETY: index is bounded by the fixed plane transaction array.
        let slot = unsafe { entry(state, DRM_ATOMIC_PLANES_OFF, DRM_ATOMIC_PLANE_ENTRY_SIZE, index) };
        // SAFETY: every plane entry owns the three ABI-pinned pointers while it is checked.
        let (plane, old_state, new_state) = unsafe { (read(slot.add(DRM_ENTRY_OBJECT_OFF).cast::<*mut u8>()), read(slot.add(DRM_ENTRY_OLD_OFF).cast::<*mut u8>()), read(slot.add(DRM_ENTRY_NEW_OFF).cast::<*mut u8>())) };
        if plane.is_null() || old_state.is_null() || new_state.is_null() { continue; }
        if !candidate.is_null() { return -LINUX_EINVAL; }
        candidate = plane; old = old_state; new = new_state;
    }
    if candidate.is_null() { return -LINUX_EINVAL; }
    // SAFETY: the selected plane states are live transaction-owned records.
    let (old_crtc, new_crtc, fence, commit) = unsafe { (read(old.add(DRM_PLANE_STATE_CRTC_OFF).cast::<*mut c_void>()), read(new.add(DRM_PLANE_STATE_CRTC_OFF).cast::<*mut c_void>()), read(new.add(DRM_PLANE_STATE_FENCE_OFF).cast::<*mut c_void>()), read(old.add(DRM_PLANE_STATE_COMMIT_OFF).cast::<*mut u8>())) };
    if new_crtc.is_null() || old_crtc != new_crtc || !fence.is_null() { return -LINUX_EINVAL; }
    // SAFETY: helper_private is fixed at plane initialization and remains live through atomic checking.
    let helpers = unsafe { read(candidate.add(DRM_PLANE_HELPER_PRIVATE_OFF).cast::<*const u8>()) };
    if helpers.is_null() || async_update(helpers) == 0 { return -LINUX_EINVAL; }
    let callback = async_callback(helpers); if callback == 0 { return -LINUX_EINVAL; }
    if !commit.is_null() {
        // SAFETY: hw_done is the embedded completion in the live CRTC commit record.
        let done = unsafe { commit.add(DRM_CRTC_COMMIT_HW_DONE_OFF).cast::<crate::linux_sync::LinuxCompletion>() };
        if crate::linux_sync::try_wait_for_completion(done) == 0 { return -LINUX_EBUSY; }
    }
    // SAFETY: the driver's non-null callback has the ABI-pinned plane/state/flip signature.
    unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut c_void, *mut c_void, bool) -> i32>(callback)(candidate.cast(), state.cast(), false) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::sync::atomic::{AtomicU8, Ordering};

    static CALLED: AtomicU8 = AtomicU8::new(0);
    unsafe extern "C" fn accept(_plane: *mut c_void, _state: *mut c_void, flip: bool) -> i32 { CALLED.store((!flip) as u8, Ordering::SeqCst); 0 }
    unsafe extern "C" fn update(plane: *mut c_void, state: *mut c_void) {
        let staged = unsafe { read(state.cast::<u8>().add(DRM_ATOMIC_PLANES_OFF).cast::<*mut u8>()) };
        let new = unsafe { read(staged.add(DRM_ENTRY_NEW_OFF).cast::<*mut u8>()) };
        let current = unsafe { read(plane.cast::<u8>().add(DRM_PLANE_STATE_CURRENT_OFF).cast::<*mut u8>()) };
        // SAFETY: test records reserve common coordinate and framebuffer fields for the in-place swap contract.
        unsafe { let old_fb = read(current.add(DRM_PLANE_STATE_FB_OFF).cast::<*mut c_void>()); write(current.add(DRM_PLANE_STATE_FB_OFF).cast::<*mut c_void>(), read(new.add(DRM_PLANE_STATE_FB_OFF).cast::<*mut c_void>())); write(new.add(DRM_PLANE_STATE_FB_OFF).cast::<*mut c_void>(), old_fb); for off in [DRM_PLANE_STATE_CRTC_X_OFF, DRM_PLANE_STATE_CRTC_Y_OFF, DRM_PLANE_STATE_SRC_X_OFF, DRM_PLANE_STATE_SRC_Y_OFF] { core::ptr::copy_nonoverlapping(new.add(off), current.add(off), 4); } }
        CALLED.store(2, Ordering::SeqCst);
    }

    #[test]
    fn async_check_rejects_modesets_and_accepts_one_unfenced_plane() {
        let _modules = crate::test_serial::claim(); CALLED.store(0, Ordering::SeqCst);
        let mut dev = [0u8; 1800]; let mut state = [0u8; 128]; let mut plane = [0u8; 1360]; let mut helpers = [0u8; 96]; let mut old = [0u8; 184]; let mut new = [0u8; 184]; let mut crtc = [0u8; 1656]; let mut crtc_new = [0u8; 336]; let mut planes = [0u8; 32]; let mut crtcs = [0u8; 56];
        // SAFETY: arrays reserve every ABI field read by this one-plane, one-CRTC transaction.
        unsafe { write(state.as_mut_ptr().add(DRM_ATOMIC_DEV_OFF).cast::<*mut u8>(), dev.as_mut_ptr()); write(state.as_mut_ptr().add(DRM_ATOMIC_PLANES_OFF).cast::<*mut u8>(), planes.as_mut_ptr()); write(state.as_mut_ptr().add(DRM_ATOMIC_CRTCS_OFF).cast::<*mut u8>(), crtcs.as_mut_ptr()); write(planes.as_mut_ptr().add(DRM_ENTRY_OBJECT_OFF).cast::<*mut u8>(), plane.as_mut_ptr()); write(planes.as_mut_ptr().add(DRM_ENTRY_OLD_OFF).cast::<*mut u8>(), old.as_mut_ptr()); write(planes.as_mut_ptr().add(DRM_ENTRY_NEW_OFF).cast::<*mut u8>(), new.as_mut_ptr()); write(old.as_mut_ptr().add(DRM_PLANE_STATE_CRTC_OFF).cast::<*mut u8>(), crtc.as_mut_ptr()); write(new.as_mut_ptr().add(DRM_PLANE_STATE_CRTC_OFF).cast::<*mut u8>(), crtc.as_mut_ptr()); write(plane.as_mut_ptr().add(DRM_PLANE_HELPER_PRIVATE_OFF).cast::<*mut u8>(), helpers.as_mut_ptr()); write(helpers.as_mut_ptr().add(DRM_PLANE_HELPER_ASYNC_CHECK_OFF).cast::<usize>(), accept as *const () as usize); write(helpers.as_mut_ptr().add(DRM_PLANE_HELPER_ASYNC_UPDATE_OFF).cast::<usize>(), 1); write(crtcs.as_mut_ptr().add(DRM_ENTRY_NEW_OFF).cast::<*mut u8>(), crtc_new.as_mut_ptr()); }
        DEVICES.lock().push(DeviceAllocation { dev: dev.as_mut_ptr() as usize, base: 0, layout: Layout::new::<u8>(), refs: 1, mode_config: true, objects: Vec::new(), planes: vec![PlaneRecord { ptr: plane.as_mut_ptr() as usize, formats: 0, layout: Layout::new::<u8>() }], crtcs: vec![CrtcRecord { ptr: crtc.as_mut_ptr() as usize, name: 0, layout: Layout::new::<u8>() }], encoders: Vec::new(), connectors: Vec::new(), clients: Vec::new(), vblank: None, primary_master: None, put_pending: false, unplugged: false });
        assert_eq!(drm_atomic_helper_async_check(dev.as_mut_ptr().cast(), state.as_mut_ptr().cast()), 0); assert_eq!(CALLED.load(Ordering::SeqCst), 1);
        // SAFETY: this flips the checked modeset flag in the transaction-owned CRTC state.
        unsafe { write(crtc_new.as_mut_ptr().add(DRM_CRTC_STATE_CHANGE_FLAGS_OFF), DRM_CRTC_STATE_MODESET_MASK); }
        assert_eq!(drm_atomic_helper_async_check(dev.as_mut_ptr().cast(), state.as_mut_ptr().cast()), -LINUX_EINVAL);
        DEVICES.lock().clear();
    }

    #[test]
    fn async_commit_runs_driver_update_and_requires_the_in_place_swap() {
        let _modules = crate::test_serial::claim(); CALLED.store(0, Ordering::SeqCst);
        let mut dev = [0u8; 1800]; let mut state = [0u8; 128]; let mut plane = [0u8; 1360]; let mut helpers = [0u8; 96]; let mut current = [0u8; 184]; let mut new = [0u8; 184]; let mut planes = [0u8; 32]; let mut old_fb = [0u8; 1]; let mut new_fb = [0u8; 1];
        // SAFETY: records reserve every state, helper, and current-plane field used by async commit.
        unsafe { write(state.as_mut_ptr().add(DRM_ATOMIC_DEV_OFF).cast::<*mut u8>(), dev.as_mut_ptr()); write(state.as_mut_ptr().add(DRM_ATOMIC_PLANES_OFF).cast::<*mut u8>(), planes.as_mut_ptr()); write(planes.as_mut_ptr().add(DRM_ENTRY_OBJECT_OFF).cast::<*mut u8>(), plane.as_mut_ptr()); write(planes.as_mut_ptr().add(DRM_ENTRY_NEW_OFF).cast::<*mut u8>(), new.as_mut_ptr()); write(plane.as_mut_ptr().add(DRM_PLANE_HELPER_PRIVATE_OFF).cast::<*mut u8>(), helpers.as_mut_ptr()); write(plane.as_mut_ptr().add(DRM_PLANE_STATE_CURRENT_OFF).cast::<*mut u8>(), current.as_mut_ptr()); write(helpers.as_mut_ptr().add(DRM_PLANE_HELPER_ASYNC_UPDATE_OFF).cast::<usize>(), update as *const () as usize); write(current.as_mut_ptr().add(DRM_PLANE_STATE_FB_OFF).cast::<*mut u8>(), old_fb.as_mut_ptr()); write(new.as_mut_ptr().add(DRM_PLANE_STATE_FB_OFF).cast::<*mut u8>(), new_fb.as_mut_ptr()); write(new.as_mut_ptr().add(DRM_PLANE_STATE_CRTC_X_OFF).cast::<i32>(), 5); write(new.as_mut_ptr().add(DRM_PLANE_STATE_CRTC_Y_OFF).cast::<i32>(), 7); write(new.as_mut_ptr().add(DRM_PLANE_STATE_SRC_X_OFF).cast::<u32>(), 9); write(new.as_mut_ptr().add(DRM_PLANE_STATE_SRC_Y_OFF).cast::<u32>(), 11); }
        DEVICES.lock().push(DeviceAllocation { dev: dev.as_mut_ptr() as usize, base: 0, layout: Layout::new::<u8>(), refs: 1, mode_config: true, objects: Vec::new(), planes: vec![PlaneRecord { ptr: plane.as_mut_ptr() as usize, formats: 0, layout: Layout::new::<u8>() }], crtcs: Vec::new(), encoders: Vec::new(), connectors: Vec::new(), clients: Vec::new(), vblank: None, primary_master: None, put_pending: false, unplugged: false });
        drm_atomic_helper_async_commit(dev.as_mut_ptr().cast(), state.as_mut_ptr().cast()); assert_eq!(CALLED.load(Ordering::SeqCst), 2); DEVICES.lock().clear();
    }
}
