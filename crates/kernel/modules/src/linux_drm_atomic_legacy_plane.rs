//! DRM legacy plane operations routed through atomic state.

use super::*;

const DRM_ATOMIC_ACQUIRE_CTX_OFF: usize = 80;
const DRM_ATOMIC_LEGACY_CURSOR_UPDATE_OFF: usize = 16;
const DRM_ATOMIC_LEGACY_CURSOR_UPDATE: u8 = 1 << 1;
const DRM_PLANE_DEV_OFF: usize = 0;
const DRM_PLANE_INDEX_OFF: usize = 1220;
const DRM_CRTC_CURSOR_OFF: usize = 136;
const DRM_PLANE_STATE_PLANE_OFF: usize = 0;
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
const DRM_PLANE_STATE_ATOMIC_OFF: usize = 168;
const DRM_CRTC_STATE_PLANE_MASK_OFF: usize = 12;
const LINUX_ENOMEM: i32 = 12;
const LINUX_EINVAL: i32 = 22;

fn errno(ptr: *mut c_void) -> Option<i32> { ((ptr as usize) >= usize::MAX - 4095).then_some(-(ptr as isize) as i32) }

pub(super) fn export_symbols() {
    for (name, address) in [
        ("drm_atomic_set_crtc_for_plane", drm_atomic_set_crtc_for_plane as *const () as usize),
        ("drm_atomic_set_fb_for_plane", drm_atomic_set_fb_for_plane as *const () as usize),
        ("drm_atomic_helper_update_plane", drm_atomic_helper_update_plane as *const () as usize),
        ("drm_atomic_helper_disable_plane", drm_atomic_helper_disable_plane as *const () as usize),
    ] { crate::symtab::export(name, address, false); }
}

fn set_crtc(plane_state: *mut u8, crtc: *mut c_void) -> i32 {
    if plane_state.is_null() { return -LINUX_EINVAL; }
    // SAFETY: a live duplicated plane state owns the referenced plane, transaction, and optional CRTC fields.
    let (plane, state, old) = unsafe { (read(plane_state.add(DRM_PLANE_STATE_PLANE_OFF).cast::<*mut u8>()), read(plane_state.add(DRM_PLANE_STATE_ATOMIC_OFF).cast::<*mut c_void>()), read(plane_state.add(DRM_PLANE_STATE_CRTC_OFF).cast::<*mut c_void>())) };
    if plane.is_null() || state.is_null() { return -LINUX_EINVAL; }
    if old == crtc { return 0; }
    // SAFETY: plane index is immutable for the plane's registered lifetime.
    let index = unsafe { read(plane.add(DRM_PLANE_INDEX_OFF).cast::<u32>()) };
    if index >= u32::BITS { return -LINUX_EINVAL; }
    if !old.is_null() {
        let old_state = atomic_acquire::drm_atomic_get_crtc_state(state, old);
        if let Some(code) = errno(old_state) { return -code; }
        // SAFETY: acquired CRTC state remains transaction-owned until commit put.
        unsafe { *old_state.cast::<u8>().add(DRM_CRTC_STATE_PLANE_MASK_OFF).cast::<u32>() &= !(1u32 << index); }
    }
    // SAFETY: the incoming CRTC pointer is published only after the old CRTC mask is removed.
    unsafe { write(plane_state.add(DRM_PLANE_STATE_CRTC_OFF).cast::<*mut c_void>(), crtc); }
    if crtc.is_null() { return 0; }
    let new_state = atomic_acquire::drm_atomic_get_crtc_state(state, crtc);
    if let Some(code) = errno(new_state) { return -code; }
    // SAFETY: acquired CRTC state remains transaction-owned until commit put.
    unsafe { *new_state.cast::<u8>().add(DRM_CRTC_STATE_PLANE_MASK_OFF).cast::<u32>() |= 1u32 << index; }
    0
}

/// Assign a plane's CRTC and keep both affected CRTC plane masks transaction-consistent. # C: O(1)
pub(super) extern "C" fn drm_atomic_set_crtc_for_plane(plane_state: *mut c_void, crtc: *mut c_void) -> i32 { set_crtc(plane_state.cast(), crtc) }

/// Replace a plane-state framebuffer with the corresponding retained framebuffer reference. # C: O(1)
pub(super) extern "C" fn drm_atomic_set_fb_for_plane(plane_state: *mut c_void, fb: *mut c_void) {
    if plane_state.is_null() { return; }
    let plane_state = plane_state.cast::<u8>();
    // SAFETY: plane state owns its framebuffer reference until its destroy callback runs.
    let old = unsafe { read(plane_state.add(DRM_PLANE_STATE_FB_OFF).cast::<*mut c_void>()) };
    framebuffer_get(fb); framebuffer_put(old);
    // SAFETY: the framebuffer pointer is the ABI-pinned state field whose prior reference was just released.
    unsafe { write(plane_state.add(DRM_PLANE_STATE_FB_OFF).cast::<*mut c_void>(), fb); }
}

fn mark_cursor_update(state: *mut u8, plane: *mut u8, crtc: *mut c_void) {
    if state.is_null() || plane.is_null() || crtc.is_null() { return; }
    // SAFETY: live CRTC and atomic state expose their fixed cursor pointer and transaction flag bit.
    if unsafe { read(crtc.cast::<u8>().add(DRM_CRTC_CURSOR_OFF).cast::<*mut u8>()) } == plane {
        unsafe { *state.add(DRM_ATOMIC_LEGACY_CURSOR_UPDATE_OFF) |= DRM_ATOMIC_LEGACY_CURSOR_UPDATE; }
    }
}

/// Submit one legacy primary-plane update through the driver's atomic commit path. # C: O(N_objects)
pub(super) extern "C" fn drm_atomic_helper_update_plane(plane: *mut c_void, crtc: *mut c_void, fb: *mut c_void, crtc_x: i32, crtc_y: i32, crtc_w: u32, crtc_h: u32, src_x: u32, src_y: u32, src_w: u32, src_h: u32, ctx: *mut c_void) -> i32 {
    if plane.is_null() || crtc.is_null() || fb.is_null() { return -LINUX_EINVAL; }
    let plane = plane.cast::<u8>();
    // SAFETY: a registered plane begins with its owning DRM device pointer.
    let dev = unsafe { read(plane.add(DRM_PLANE_DEV_OFF).cast::<*mut c_void>()) };
    let state = atomic_core::drm_atomic_commit_alloc(dev);
    if state.is_null() { return -LINUX_ENOMEM; }
    let state_bytes = state.cast::<u8>();
    // SAFETY: newly allocated atomic state owns this caller's acquire context pointer until final put.
    unsafe { write(state_bytes.add(DRM_ATOMIC_ACQUIRE_CTX_OFF).cast::<*mut c_void>(), ctx); }
    let plane_state = atomic_acquire::drm_atomic_get_plane_state(state, plane.cast());
    let result = if let Some(code) = errno(plane_state) { -code } else {
        let state = plane_state.cast::<u8>();
        let ret = set_crtc(state, crtc);
        if ret != 0 { ret } else {
            drm_atomic_set_fb_for_plane(state.cast(), fb);
            // SAFETY: these scalar coordinates are owned by the transaction's duplicated plane state.
            unsafe { write(state.add(DRM_PLANE_STATE_CRTC_X_OFF).cast::<i32>(), crtc_x); write(state.add(DRM_PLANE_STATE_CRTC_Y_OFF).cast::<i32>(), crtc_y); write(state.add(DRM_PLANE_STATE_CRTC_W_OFF).cast::<u32>(), crtc_w); write(state.add(DRM_PLANE_STATE_CRTC_H_OFF).cast::<u32>(), crtc_h); write(state.add(DRM_PLANE_STATE_SRC_X_OFF).cast::<u32>(), src_x); write(state.add(DRM_PLANE_STATE_SRC_Y_OFF).cast::<u32>(), src_y); write(state.add(DRM_PLANE_STATE_SRC_W_OFF).cast::<u32>(), src_w); write(state.add(DRM_PLANE_STATE_SRC_H_OFF).cast::<u32>(), src_h); }
            mark_cursor_update(state_bytes, plane, crtc);
            atomic_validate::drm_atomic_commit(state.cast())
        }
    };
    atomic_core::drm_atomic_commit_put(state);
    result
}

/// Disable one legacy plane through the driver's atomic commit path. # C: O(N_objects)
pub(super) extern "C" fn drm_atomic_helper_disable_plane(plane: *mut c_void, ctx: *mut c_void) -> i32 {
    if plane.is_null() { return -LINUX_EINVAL; }
    let plane = plane.cast::<u8>();
    // SAFETY: a registered plane begins with its owning DRM device pointer.
    let dev = unsafe { read(plane.add(DRM_PLANE_DEV_OFF).cast::<*mut c_void>()) };
    let state = atomic_core::drm_atomic_commit_alloc(dev);
    if state.is_null() { return -LINUX_ENOMEM; }
    let state_bytes = state.cast::<u8>();
    // SAFETY: newly allocated atomic state owns this caller's acquire context pointer until final put.
    unsafe { write(state_bytes.add(DRM_ATOMIC_ACQUIRE_CTX_OFF).cast::<*mut c_void>(), ctx); }
    let plane_state = atomic_acquire::drm_atomic_get_plane_state(state, plane.cast());
    let result = if let Some(code) = errno(plane_state) { -code } else {
        let plane_state = plane_state.cast::<u8>();
        // SAFETY: duplicated plane state retains its old CRTC while the legacy cursor decision is made.
        let crtc = unsafe { read(plane_state.add(DRM_PLANE_STATE_CRTC_OFF).cast::<*mut c_void>()) };
        mark_cursor_update(state_bytes, plane, crtc);
        let ret = set_crtc(plane_state, core::ptr::null_mut());
        if ret == 0 { drm_atomic_set_fb_for_plane(plane_state.cast(), core::ptr::null_mut()); atomic_validate::drm_atomic_commit(state) } else { ret }
    };
    atomic_core::drm_atomic_commit_put(state);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const DRM_FB_REFCOUNT_OFF: usize = 40;

    #[test]
    fn legacy_plane_exports_and_framebuffer_assignment_transfer_one_reference() {
        let _modules = crate::test_serial::claim();
        export_symbols();
        for name in ["drm_atomic_set_crtc_for_plane", "drm_atomic_set_fb_for_plane", "drm_atomic_helper_update_plane", "drm_atomic_helper_disable_plane"] { assert!(crate::symtab::is_exported(name)); }
        let mut state = [0u8; 184]; let mut old = [0u8; 64]; let mut new = [0u8; 64];
        // SAFETY: fabricated records reserve the state framebuffer and embedded framebuffer kref fields.
        unsafe { write(state.as_mut_ptr().add(DRM_PLANE_STATE_FB_OFF).cast::<*mut u8>(), old.as_mut_ptr()); write(old.as_mut_ptr().add(DRM_FB_REFCOUNT_OFF).cast::<i32>(), 2); write(new.as_mut_ptr().add(DRM_FB_REFCOUNT_OFF).cast::<i32>(), 1); }
        drm_atomic_set_fb_for_plane(state.as_mut_ptr().cast(), new.as_mut_ptr().cast());
        // SAFETY: the assignment owns exactly the old put, new get, and state pointer writes above.
        unsafe { assert_eq!(read(state.as_ptr().add(DRM_PLANE_STATE_FB_OFF).cast::<*mut u8>()), new.as_mut_ptr()); assert_eq!(read(old.as_ptr().add(DRM_FB_REFCOUNT_OFF).cast::<i32>()), 1); assert_eq!(read(new.as_ptr().add(DRM_FB_REFCOUNT_OFF).cast::<i32>()), 2); }
        assert_eq!(drm_atomic_set_crtc_for_plane(core::ptr::null_mut(), core::ptr::null_mut()), -LINUX_EINVAL);
    }
}
