//! DRM atomic-core validation and mode-config dispatch.

use super::*;

const DRM_ATOMIC_DEV_OFF: usize = 8;
const DRM_ATOMIC_FLAGS_OFF: usize = 16;
const DRM_ATOMIC_CHECKED_BIT: u8 = 1 << 4;
const DRM_ATOMIC_PLANES_OFF: usize = 32;
const DRM_ATOMIC_CRTCS_OFF: usize = 40;
const DRM_ATOMIC_PLANE_ENTRY_SIZE: usize = 32;
const DRM_ATOMIC_CRTC_ENTRY_SIZE: usize = 56;
const DRM_ENTRY_OBJECT_OFF: usize = 0;
const DRM_ENTRY_OLD_OFF: usize = 16;
const DRM_ENTRY_NEW_OFF: usize = 24;
const DRM_PLANE_POSSIBLE_CRTCS_OFF: usize = 112;
const DRM_PLANE_FORMATS_OFF: usize = 120;
const DRM_PLANE_FORMAT_COUNT_OFF: usize = 128;
const DRM_CRTC_INDEX_OFF: usize = 144;
const DRM_PLANE_STATE_CRTC_OFF: usize = 8;
const DRM_PLANE_STATE_FB_OFF: usize = 16;
const DRM_PLANE_STATE_CRTC_X_OFF: usize = 32;
const DRM_PLANE_STATE_CRTC_Y_OFF: usize = 36;
const DRM_PLANE_STATE_CRTC_W_OFF: usize = 40;
const DRM_PLANE_STATE_CRTC_H_OFF: usize = 44;
const DRM_PLANE_STATE_SRC_X_OFF: usize = 48;
const DRM_PLANE_STATE_SRC_Y_OFF: usize = 52;
const DRM_PLANE_STATE_SRC_H_OFF: usize = 56;
const DRM_PLANE_STATE_SRC_W_OFF: usize = 60;
const DRM_CRTC_STATE_ENABLE_OFF: usize = 8;
const DRM_CRTC_STATE_ACTIVE_OFF: usize = 9;
const DRM_CRTC_STATE_EVENT_OFF: usize = 312;
const DRM_FB_FORMAT_OFF: usize = 72;
const DRM_FB_WIDTH_OFF: usize = 128;
const DRM_FB_HEIGHT_OFF: usize = 132;
const DRM_DEVICE_MODE_CONFIG_OFF: usize = 360;
const DRM_MODE_CONFIG_FUNCS_OFF: usize = 456;
const DRM_MODE_CONFIG_ATOMIC_CHECK_OFF: usize = 24;
const DRM_MODE_CONFIG_ATOMIC_COMMIT_OFF: usize = 32;
const LINUX_EINVAL: i32 = 22;
const LINUX_ENOSPC: i32 = 28;
const LINUX_ERANGE: i32 = 34;

fn object_counts(dev: *mut c_void) -> Option<(usize, usize)> {
    let devices = DEVICES.lock();
    let record = devices.iter().find(|record| record.dev == dev as usize && record.mode_config && !record.put_pending && !record.unplugged)?;
    Some((record.planes.len(), record.crtcs.len()))
}
unsafe fn entry(state: *mut u8, array_off: usize, entry_size: usize, index: usize) -> *mut u8 {
    // SAFETY: callers bound the index by the graph count that allocated this transaction array.
    unsafe { read(state.add(array_off).cast::<*mut u8>()).add(index * entry_size) }
}
fn format_supported(plane: *mut u8, fb: *mut u8) -> bool {
    // SAFETY: live plane and framebuffer expose their immutable format list and selected format pointer.
    let (formats, count, info) = unsafe { (read(plane.add(DRM_PLANE_FORMATS_OFF).cast::<*const u32>()), read(plane.add(DRM_PLANE_FORMAT_COUNT_OFF).cast::<u32>()) as usize, read(fb.add(DRM_FB_FORMAT_OFF).cast::<*const u8>())) };
    if formats.is_null() || info.is_null() { return false; }
    // SAFETY: format list has exactly count 32-bit entries published at plane initialization.
    let selected = unsafe { read(info.cast::<u32>()) };
    // SAFETY: formats is checked non-null with count entries published at plane init; index stays inside that same 0..count range.
    (0..count).any(|index| unsafe { read(formats.add(index)) == selected })
}
fn plane_check(plane: *mut u8, old: *mut u8, new: *mut u8) -> i32 {
    // SAFETY: atomic entry owns the paired old/new plane states during validation.
    let (old_crtc, crtc, fb) = unsafe { (read(old.add(DRM_PLANE_STATE_CRTC_OFF).cast::<*mut u8>()), read(new.add(DRM_PLANE_STATE_CRTC_OFF).cast::<*mut u8>()), read(new.add(DRM_PLANE_STATE_FB_OFF).cast::<*mut u8>())) };
    if crtc.is_null() != fb.is_null() { return -LINUX_EINVAL; }
    if crtc.is_null() { return 0; }
    // SAFETY: a registered CRTC has a stable index and plane has its immutable compatibility mask.
    let (index, possible) = unsafe { (read(crtc.add(DRM_CRTC_INDEX_OFF).cast::<u32>()), read(plane.add(DRM_PLANE_POSSIBLE_CRTCS_OFF).cast::<u32>())) };
    if index >= 32 || possible & (1u32 << index) == 0 || !format_supported(plane, fb) { return -LINUX_EINVAL; }
    // SAFETY: source/destination fields and framebuffer dimensions are complete ABI scalar fields.
    let (x, y, w, h, sx, sy, sw, sh, fb_w, fb_h) = unsafe { (read(new.add(DRM_PLANE_STATE_CRTC_X_OFF).cast::<i32>()), read(new.add(DRM_PLANE_STATE_CRTC_Y_OFF).cast::<i32>()), read(new.add(DRM_PLANE_STATE_CRTC_W_OFF).cast::<u32>()), read(new.add(DRM_PLANE_STATE_CRTC_H_OFF).cast::<u32>()), read(new.add(DRM_PLANE_STATE_SRC_X_OFF).cast::<u32>()), read(new.add(DRM_PLANE_STATE_SRC_Y_OFF).cast::<u32>()), read(new.add(DRM_PLANE_STATE_SRC_W_OFF).cast::<u32>()), read(new.add(DRM_PLANE_STATE_SRC_H_OFF).cast::<u32>()), read(fb.add(DRM_FB_WIDTH_OFF).cast::<u32>()), read(fb.add(DRM_FB_HEIGHT_OFF).cast::<u32>())) };
    if w > i32::MAX as u32 || h > i32::MAX as u32 || x > i32::MAX - w as i32 || y > i32::MAX - h as i32 { return -LINUX_ERANGE; }
    let (fb_w, fb_h) = (fb_w.checked_shl(16).unwrap_or(0), fb_h.checked_shl(16).unwrap_or(0));
    if sw > fb_w || sx > fb_w - sw || sh > fb_h || sy > fb_h - sh { return -LINUX_ENOSPC; }
    if !old_crtc.is_null() && old_crtc != crtc { return -LINUX_EINVAL; }
    0
}
fn crtc_check(old: *mut u8, new: *mut u8) -> i32 {
    // SAFETY: old/new CRTC state records remain owned by the transaction while checked.
    let (old_active, active, enable, event) = unsafe { (read(old.add(DRM_CRTC_STATE_ACTIVE_OFF).cast::<bool>()), read(new.add(DRM_CRTC_STATE_ACTIVE_OFF).cast::<bool>()), read(new.add(DRM_CRTC_STATE_ENABLE_OFF).cast::<bool>()), read(new.add(DRM_CRTC_STATE_EVENT_OFF).cast::<*mut c_void>())) };
    if active && !enable { return -LINUX_EINVAL; }
    if !event.is_null() && !active && !old_active { return -LINUX_EINVAL; }
    0
}
unsafe fn mode_callback(dev: *mut u8, offset: usize) -> usize {
    // SAFETY: device mode-config owns the ABI-pinned mode config function table.
    let funcs = unsafe { read(dev.add(DRM_DEVICE_MODE_CONFIG_OFF + DRM_MODE_CONFIG_FUNCS_OFF).cast::<*const u8>()) };
    // SAFETY: funcs is checked non-null above; offset names one callback slot inside the same fixed mode-config function table.
    if funcs.is_null() { 0 } else { unsafe { read(funcs.add(offset).cast::<usize>()) } }
}

pub(super) fn export_symbols() {
    crate::symtab::export("drm_atomic_check_only", drm_atomic_check_only as *const () as usize, false);
    crate::symtab::export("drm_atomic_commit", drm_atomic_commit as *const () as usize, false);
    crate::symtab::export("drm_atomic_nonblocking_commit", drm_atomic_nonblocking_commit as *const () as usize, false);
}

/// Validate core object invariants, then invoke the driver's atomic checker. # C: O(N_objects)
pub(super) extern "C" fn drm_atomic_check_only(state: *mut c_void) -> i32 {
    if state.is_null() { return -LINUX_EINVAL; }
    let state = state.cast::<u8>();
    // SAFETY: device pointer is retained by every allocated atomic transaction.
    let dev = unsafe { read(state.add(DRM_ATOMIC_DEV_OFF).cast::<*mut u8>()) };
    let Some((planes, crtcs)) = object_counts(dev.cast()) else { return -LINUX_EINVAL; };
    for index in 0..planes {
        // SAFETY: index is bounded by the fixed plane transaction array.
        let slot = unsafe { entry(state, DRM_ATOMIC_PLANES_OFF, DRM_ATOMIC_PLANE_ENTRY_SIZE, index) };
        // SAFETY: object and paired state pointers occupy the stable entry slots.
        let (plane, old, new) = unsafe { (read(slot.add(DRM_ENTRY_OBJECT_OFF).cast::<*mut u8>()), read(slot.add(DRM_ENTRY_OLD_OFF).cast::<*mut u8>()), read(slot.add(DRM_ENTRY_NEW_OFF).cast::<*mut u8>())) };
        if plane.is_null() || old.is_null() || new.is_null() { continue; }
        let ret = plane_check(plane, old, new); if ret != 0 { return ret; }
    }
    for index in 0..crtcs {
        // SAFETY: index is bounded by the fixed CRTC transaction array.
        let slot = unsafe { entry(state, DRM_ATOMIC_CRTCS_OFF, DRM_ATOMIC_CRTC_ENTRY_SIZE, index) };
        // SAFETY: paired CRTC state pointers occupy the stable entry slots.
        let (old, new) = unsafe { (read(slot.add(DRM_ENTRY_OLD_OFF).cast::<*mut u8>()), read(slot.add(DRM_ENTRY_NEW_OFF).cast::<*mut u8>())) };
        if old.is_null() || new.is_null() { continue; }
        let ret = crtc_check(old, new); if ret != 0 { return ret; }
    }
    // SAFETY: a nonzero driver validation slot has the registered atomic-check ABI signature.
    let callback = unsafe { mode_callback(dev, DRM_MODE_CONFIG_ATOMIC_CHECK_OFF) };
    // SAFETY: atomic_check's ABI signature is (dev, state) -> i32; both are the caller's own validated non-null pointers.
    if callback != 0 { let ret = unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut c_void, *mut c_void) -> i32>(callback)(dev.cast(), state.cast()) }; if ret != 0 { return ret; } }
    // SAFETY: the checked bit is transaction-private and can be published only after every callback succeeds.
    unsafe { *state.add(DRM_ATOMIC_FLAGS_OFF) |= DRM_ATOMIC_CHECKED_BIT; }
    0
}

fn atomic_commit(state: *mut c_void, nonblock: bool) -> i32 {
    let ret = drm_atomic_check_only(state); if ret != 0 { return ret; }
    let state_bytes = state.cast::<u8>();
    // SAFETY: check_only validated state and retained device before dispatching the driver's commit operation.
    let dev = unsafe { read(state_bytes.add(DRM_ATOMIC_DEV_OFF).cast::<*mut u8>()) };
    // SAFETY: a nonzero driver commit slot has the registered atomic-commit ABI signature.
    let callback = unsafe { mode_callback(dev, DRM_MODE_CONFIG_ATOMIC_COMMIT_OFF) };
    if callback == 0 { return -LINUX_EINVAL; }
    // SAFETY: atomic_commit's ABI signature is (dev, state, nonblock) -> i32; dev/state are the same validated non-null pointers passed to check_only.
    unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut c_void, *mut c_void, bool) -> i32>(callback)(dev.cast(), state, nonblock) }
}

/// Check and synchronously submit one atomic transaction. # C: O(N_objects)
pub(super) extern "C" fn drm_atomic_commit(state: *mut c_void) -> i32 { atomic_commit(state, false) }
/// Check and nonblockingly submit one atomic transaction. # C: O(N_objects)
pub(super) extern "C" fn drm_atomic_nonblocking_commit(state: *mut c_void) -> i32 { atomic_commit(state, true) }

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::sync::atomic::{AtomicUsize, Ordering};
    const DRM_ATOMIC_STATE_SIZE: usize = 128;
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    unsafe extern "C" fn check_callback(_dev: *mut c_void, _state: *mut c_void) -> i32 { CALLS.fetch_add(1, Ordering::SeqCst); 0 }
    #[test]
    fn atomic_core_exports_are_present() { export_symbols(); for symbol in ["drm_atomic_check_only", "drm_atomic_commit", "drm_atomic_nonblocking_commit"] { assert!(crate::symtab::is_exported(symbol)); } }
    #[test]
    fn check_rejects_unpaired_plane_and_runs_driver_after_core_validation() {
        let _modules = crate::test_serial::claim();
        let mut dev = [0u8; DRM_DEVICE_MODE_CONFIG_OFF + DRM_MODE_CONFIG_FUNCS_OFF + 8]; let mut funcs = [0u8; 40]; let mut state = [0u8; DRM_ATOMIC_STATE_SIZE]; let mut plane_entries = [0u8; DRM_ATOMIC_PLANE_ENTRY_SIZE]; let mut plane = [0u8; 1232]; let mut old = [0u8; 184]; let mut new = [0u8; 184];
        // SAFETY: fabricated records reserve every callback, transaction, and plane-state ABI field read by validation.
        unsafe { write(dev.as_mut_ptr().add(DRM_DEVICE_MODE_CONFIG_OFF + DRM_MODE_CONFIG_FUNCS_OFF).cast::<*mut u8>(), funcs.as_mut_ptr()); write(funcs.as_mut_ptr().add(DRM_MODE_CONFIG_ATOMIC_CHECK_OFF).cast::<usize>(), check_callback as *const () as usize); write(state.as_mut_ptr().add(DRM_ATOMIC_DEV_OFF).cast::<*mut u8>(), dev.as_mut_ptr()); write(state.as_mut_ptr().add(DRM_ATOMIC_PLANES_OFF).cast::<*mut u8>(), plane_entries.as_mut_ptr()); write(plane_entries.as_mut_ptr().add(DRM_ENTRY_OBJECT_OFF).cast::<*mut u8>(), plane.as_mut_ptr()); write(plane_entries.as_mut_ptr().add(DRM_ENTRY_OLD_OFF).cast::<*mut u8>(), old.as_mut_ptr()); write(plane_entries.as_mut_ptr().add(DRM_ENTRY_NEW_OFF).cast::<*mut u8>(), new.as_mut_ptr()); }
        DEVICES.lock().push(DeviceAllocation { dev: dev.as_mut_ptr() as usize, base: 0, layout: Layout::new::<u8>(), refs: 1, mode_config: true, objects: Vec::new(), planes: vec![PlaneRecord { ptr: plane.as_mut_ptr() as usize, formats: 0, layout: Layout::new::<u8>() }], crtcs: Vec::new(), encoders: Vec::new(), connectors: Vec::new(), clients: Vec::new(), vblank: None, primary_master: None, put_pending: false, unplugged: false });
        CALLS.store(0, Ordering::SeqCst); assert_eq!(drm_atomic_check_only(state.as_mut_ptr().cast()), 0); assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        // SAFETY: sets a non-null bogus CRTC with a still-null fb on the fabricated new state, to force plane_check's crtc.is_null() != fb.is_null() rejection before the driver callback runs.
        unsafe { write(new.as_mut_ptr().add(DRM_PLANE_STATE_CRTC_OFF).cast::<*mut u8>(), 1usize as *mut u8); } CALLS.store(0, Ordering::SeqCst); assert_eq!(drm_atomic_check_only(state.as_mut_ptr().cast()), -LINUX_EINVAL); assert_eq!(CALLS.load(Ordering::SeqCst), 0); DEVICES.lock().clear();
    }
}
