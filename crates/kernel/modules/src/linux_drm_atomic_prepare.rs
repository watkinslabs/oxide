//! DRM atomic plane-resource preparation and rollback.

use super::*;

const DRM_ATOMIC_DEV_OFF: usize = 8;
const DRM_ATOMIC_PLANES_OFF: usize = 32;
const DRM_ENTRY_OBJECT_OFF: usize = 0;
const DRM_ENTRY_OLD_OFF: usize = 16;
const DRM_ENTRY_NEW_OFF: usize = 24;
const DRM_ATOMIC_PLANE_ENTRY_SIZE: usize = 32;
const DRM_PLANE_HELPER_PRIVATE_OFF: usize = 1224;
const DRM_PLANE_HELPER_PREPARE_FB_OFF: usize = 0;
const DRM_PLANE_HELPER_CLEANUP_FB_OFF: usize = 8;
const DRM_PLANE_HELPER_BEGIN_FB_ACCESS_OFF: usize = 16;
const DRM_PLANE_HELPER_END_FB_ACCESS_OFF: usize = 24;
const LINUX_EINVAL: i32 = 22;

fn plane_count(dev: *mut c_void) -> Option<usize> {
    let devices = DEVICES.lock();
    Some(devices.iter().find(|record| record.dev == dev as usize && record.mode_config && !record.put_pending && !record.unplugged)?.planes.len())
}

unsafe fn entry(state: *mut u8, index: usize) -> *mut u8 {
    // SAFETY: callers bound index by the device's fixed plane transaction array.
    unsafe { read(state.add(DRM_ATOMIC_PLANES_OFF).cast::<*mut u8>()).add(index * DRM_ATOMIC_PLANE_ENTRY_SIZE) }
}

fn callback(helpers: *const u8, offset: usize) -> usize {
    // SAFETY: helper_private names the fixed external plane-helper callback table.
    unsafe { read(helpers.add(offset).cast::<usize>()) }
}

fn transaction(state: *mut c_void) -> Option<(*mut u8, usize)> {
    if state.is_null() { return None; }
    let state = state.cast::<u8>();
    // SAFETY: this state retains the device that allocated it.
    let dev = unsafe { read(state.add(DRM_ATOMIC_DEV_OFF).cast::<*mut c_void>()) };
    if dev.is_null() { None } else { plane_count(dev).map(|count| (state, count)) }
}

fn each_plane(state: *mut u8, count: usize, f: &mut impl FnMut(*mut c_void, *mut c_void, *const u8) -> i32) -> i32 {
    for index in 0..count {
        // SAFETY: index is bounded by the transaction's plane array capacity.
        let entry = unsafe { entry(state, index) };
        // SAFETY: object/new state fields are stable transaction entry members.
        let (plane, new) = unsafe { (read(entry.add(DRM_ENTRY_OBJECT_OFF).cast::<*mut c_void>()), read(entry.add(DRM_ENTRY_NEW_OFF).cast::<*mut c_void>())) };
        if plane.is_null() || new.is_null() { continue; }
        // SAFETY: a published plane holds its fixed helper table pointer during atomic work.
        let helpers = unsafe { read(plane.cast::<u8>().add(DRM_PLANE_HELPER_PRIVATE_OFF).cast::<*const u8>()) };
        if helpers.is_null() { continue; }
        let ret = f(plane, new, helpers); if ret != 0 { return ret; }
    }
    0
}

pub(super) fn export_symbols() {
    crate::symtab::export("drm_atomic_helper_prepare_planes", drm_atomic_helper_prepare_planes as *const () as usize, false);
    crate::symtab::export("drm_atomic_helper_unprepare_planes", drm_atomic_helper_unprepare_planes as *const () as usize, false);
    crate::symtab::export("drm_atomic_helper_cleanup_planes", drm_atomic_helper_cleanup_planes as *const () as usize, false);
}

/// Prepare framebuffer resources, unwinding exactly the acquired prefix on failure. # C: O(N_planes)
pub(super) extern "C" fn drm_atomic_helper_prepare_planes(dev: *mut c_void, state: *mut c_void) -> i32 {
    let Some((state, count)) = transaction(state) else { return -LINUX_EINVAL; };
    // SAFETY: every atomic state holds the same device pointer used to size its entries.
    if unsafe { read(state.add(DRM_ATOMIC_DEV_OFF).cast::<*mut c_void>()) } != dev { return -LINUX_EINVAL; }
    let mut prepared = 0usize;
    for index in 0..count {
        // SAFETY: index is bounded by the state-owned plane entry array.
        let entry = unsafe { entry(state, index) };
        // SAFETY: object/new state fields are stable transaction entry members.
        let (plane, new) = unsafe { (read(entry.add(DRM_ENTRY_OBJECT_OFF).cast::<*mut c_void>()), read(entry.add(DRM_ENTRY_NEW_OFF).cast::<*mut c_void>())) };
        if plane.is_null() || new.is_null() { continue; }
        // SAFETY: the plane helper table remains live for the atomic callback sequence.
        let helpers = unsafe { read(plane.cast::<u8>().add(DRM_PLANE_HELPER_PRIVATE_OFF).cast::<*const u8>()) };
        if helpers.is_null() { continue; }
        let prepare = callback(helpers, DRM_PLANE_HELPER_PREPARE_FB_OFF);
        if prepare == 0 { continue; }
        // SAFETY: prepare_fb has the ABI-pinned plane/new-state signature.
        let ret = unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut c_void, *mut c_void) -> i32>(prepare)(plane, new) };
        if ret != 0 {
            // SAFETY: cleanup_fb has the ABI-pinned plane/new-state signature; each_plane bounds prior/prior_new to the `prepared` prefix that actually ran prepare_fb.
            let _ = each_plane(state, prepared, &mut |prior, prior_new, prior_helpers| { let cleanup = callback(prior_helpers, DRM_PLANE_HELPER_CLEANUP_FB_OFF); if cleanup != 0 { unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut c_void, *mut c_void)>(cleanup)(prior, prior_new); } } 0 });
            return ret;
        }
        prepared = index.saturating_add(1);
    }
    let mut begun = 0usize;
    for index in 0..count {
        // SAFETY: index is bounded by the state-owned plane entry array.
        let entry = unsafe { entry(state, index) };
        // SAFETY: object/new state fields are stable transaction entry members.
        let (plane, new) = unsafe { (read(entry.add(DRM_ENTRY_OBJECT_OFF).cast::<*mut c_void>()), read(entry.add(DRM_ENTRY_NEW_OFF).cast::<*mut c_void>())) };
        if plane.is_null() || new.is_null() { continue; }
        // SAFETY: the plane helper table remains live for the atomic callback sequence.
        let helpers = unsafe { read(plane.cast::<u8>().add(DRM_PLANE_HELPER_PRIVATE_OFF).cast::<*const u8>()) };
        if helpers.is_null() { continue; }
        let begin = callback(helpers, DRM_PLANE_HELPER_BEGIN_FB_ACCESS_OFF);
        if begin == 0 { continue; }
        // SAFETY: begin_fb_access has the ABI-pinned plane/new-state signature.
        let ret = unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut c_void, *mut c_void) -> i32>(begin)(plane, new) };
        if ret != 0 {
            // SAFETY: end_fb_access has the ABI-pinned plane/new-state signature; each_plane bounds prior/prior_new to the `begun` prefix that actually ran begin_fb_access.
            let _ = each_plane(state, begun, &mut |prior, prior_new, prior_helpers| { let end = callback(prior_helpers, DRM_PLANE_HELPER_END_FB_ACCESS_OFF); if end != 0 { unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut c_void, *mut c_void)>(end)(prior, prior_new); } } 0 });
            // SAFETY: cleanup_fb has the ABI-pinned plane/new-state signature; every plane in this transaction ran prepare_fb by this point, so cleanup covers the full `count`.
            let _ = each_plane(state, count, &mut |prior, prior_new, prior_helpers| { let cleanup = callback(prior_helpers, DRM_PLANE_HELPER_CLEANUP_FB_OFF); if cleanup != 0 { unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut c_void, *mut c_void)>(cleanup)(prior, prior_new); } } 0 });
            return ret;
        }
        begun = index.saturating_add(1);
    }
    0
}

/// Undo a successfully prepared atomic transaction before its state swap. # C: O(N_planes)
pub(super) extern "C" fn drm_atomic_helper_unprepare_planes(dev: *mut c_void, state: *mut c_void) {
    let Some((state, count)) = transaction(state) else { return; };
    // SAFETY: this transaction's retained device must match the caller's device.
    if unsafe { read(state.add(DRM_ATOMIC_DEV_OFF).cast::<*mut c_void>()) } != dev { return; }
    // SAFETY: end_fb_access has the ABI-pinned plane/new-state signature; a caller-successful prepare means every plane in the transaction ran begin_fb_access.
    let _ = each_plane(state, count, &mut |plane, new, helpers| { let end = callback(helpers, DRM_PLANE_HELPER_END_FB_ACCESS_OFF); if end != 0 { unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut c_void, *mut c_void)>(end)(plane, new); } } 0 });
    // SAFETY: cleanup_fb has the ABI-pinned plane/new-state signature; same fully-prepared transaction as the end_fb_access pass above.
    let _ = each_plane(state, count, &mut |plane, new, helpers| { let cleanup = callback(helpers, DRM_PLANE_HELPER_CLEANUP_FB_OFF); if cleanup != 0 { unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut c_void, *mut c_void)>(cleanup)(plane, new); } } 0 });
}

/// Release framebuffer resources retained by the old state after a published commit. # C: O(N_planes)
pub(super) extern "C" fn drm_atomic_helper_cleanup_planes(dev: *mut c_void, state: *mut c_void) {
    let Some((state, count)) = transaction(state) else { return; };
    // SAFETY: this transaction's retained device must match the caller's device.
    if unsafe { read(state.add(DRM_ATOMIC_DEV_OFF).cast::<*mut c_void>()) } != dev { return; }
    for index in 0..count {
        // SAFETY: index is bounded by the state-owned plane entry array.
        let entry = unsafe { entry(state, index) };
        // SAFETY: object and old-state pointers remain valid until terminal atomic cleanup.
        let (plane, old) = unsafe { (read(entry.add(DRM_ENTRY_OBJECT_OFF).cast::<*mut c_void>()), read(entry.add(DRM_ENTRY_OLD_OFF).cast::<*mut c_void>())) };
        if plane.is_null() || old.is_null() { continue; }
        // SAFETY: the plane helper table remains live for the terminal atomic callback.
        let helpers = unsafe { read(plane.cast::<u8>().add(DRM_PLANE_HELPER_PRIVATE_OFF).cast::<*const u8>()) };
        if helpers.is_null() { continue; }
        let cleanup = callback(helpers, DRM_PLANE_HELPER_CLEANUP_FB_OFF);
        if cleanup != 0 {
            // SAFETY: cleanup_fb has the ABI-pinned plane/old-state signature.
            unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut c_void, *mut c_void)>(cleanup)(plane, old); }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::sync::atomic::{AtomicU8, Ordering};

    static PREPARED: AtomicU8 = AtomicU8::new(0);
    static CLEANED: AtomicU8 = AtomicU8::new(0);
    unsafe extern "C" fn prepare(_plane: *mut c_void, _state: *mut c_void) -> i32 { if PREPARED.fetch_add(1, Ordering::SeqCst) == 0 { 0 } else { -5 } }
    unsafe extern "C" fn cleanup(_plane: *mut c_void, _state: *mut c_void) { CLEANED.fetch_add(1, Ordering::SeqCst); }

    #[test]
    fn prepare_failure_unwinds_only_the_prepared_prefix() {
        let _modules = crate::test_serial::claim(); PREPARED.store(0, Ordering::SeqCst); CLEANED.store(0, Ordering::SeqCst);
        let mut dev = [0u8; 1800]; let mut state = [0u8; 128]; let mut entries = [0u8; 64]; let mut first = [0u8; 1360]; let mut second = [0u8; 1360]; let mut helpers = [0u8; 96]; let mut first_state = [0u8; 184]; let mut second_state = [0u8; 184];
        // SAFETY: buffers reserve every ABI field used by the two-plane transaction and callbacks.
        unsafe { write(state.as_mut_ptr().add(DRM_ATOMIC_DEV_OFF).cast::<*mut u8>(), dev.as_mut_ptr()); write(state.as_mut_ptr().add(DRM_ATOMIC_PLANES_OFF).cast::<*mut u8>(), entries.as_mut_ptr()); write(entries.as_mut_ptr().add(DRM_ENTRY_OBJECT_OFF).cast::<*mut u8>(), first.as_mut_ptr()); write(entries.as_mut_ptr().add(DRM_ENTRY_NEW_OFF).cast::<*mut u8>(), first_state.as_mut_ptr()); write(entries.as_mut_ptr().add(DRM_ATOMIC_PLANE_ENTRY_SIZE + DRM_ENTRY_OBJECT_OFF).cast::<*mut u8>(), second.as_mut_ptr()); write(entries.as_mut_ptr().add(DRM_ATOMIC_PLANE_ENTRY_SIZE + DRM_ENTRY_NEW_OFF).cast::<*mut u8>(), second_state.as_mut_ptr()); write(first.as_mut_ptr().add(DRM_PLANE_HELPER_PRIVATE_OFF).cast::<*mut u8>(), helpers.as_mut_ptr()); write(second.as_mut_ptr().add(DRM_PLANE_HELPER_PRIVATE_OFF).cast::<*mut u8>(), helpers.as_mut_ptr()); write(helpers.as_mut_ptr().add(DRM_PLANE_HELPER_PREPARE_FB_OFF).cast::<usize>(), prepare as *const () as usize); write(helpers.as_mut_ptr().add(DRM_PLANE_HELPER_CLEANUP_FB_OFF).cast::<usize>(), cleanup as *const () as usize); }
        DEVICES.lock().push(DeviceAllocation { dev: dev.as_mut_ptr() as usize, base: 0, layout: Layout::new::<u8>(), refs: 1, mode_config: true, objects: Vec::new(), planes: vec![PlaneRecord { ptr: first.as_mut_ptr() as usize, formats: 0, layout: Layout::new::<u8>() }, PlaneRecord { ptr: second.as_mut_ptr() as usize, formats: 0, layout: Layout::new::<u8>() }], crtcs: Vec::new(), encoders: Vec::new(), connectors: Vec::new(), clients: Vec::new(), vblank: None, primary_master: None, put_pending: false, unplugged: false });
        assert_eq!(drm_atomic_helper_prepare_planes(dev.as_mut_ptr().cast(), state.as_mut_ptr().cast()), -5); assert_eq!(PREPARED.load(Ordering::SeqCst), 2); assert_eq!(CLEANED.load(Ordering::SeqCst), 1); DEVICES.lock().clear();
    }

    #[test]
    fn cleanup_releases_old_state_only_after_publish() {
        let _modules = crate::test_serial::claim(); CLEANED.store(0, Ordering::SeqCst);
        let mut dev = [0u8; 1800]; let mut state = [0u8; 128]; let mut entries = [0u8; 32]; let mut plane = [0u8; 1360]; let mut helpers = [0u8; 96]; let mut old = [0u8; 184]; let mut new = [0u8; 184];
        // SAFETY: fabricated records reserve the one old/new entry and its cleanup callback.
        unsafe { write(state.as_mut_ptr().add(DRM_ATOMIC_DEV_OFF).cast::<*mut u8>(), dev.as_mut_ptr()); write(state.as_mut_ptr().add(DRM_ATOMIC_PLANES_OFF).cast::<*mut u8>(), entries.as_mut_ptr()); write(entries.as_mut_ptr().add(DRM_ENTRY_OBJECT_OFF).cast::<*mut u8>(), plane.as_mut_ptr()); write(entries.as_mut_ptr().add(DRM_ENTRY_OLD_OFF).cast::<*mut u8>(), old.as_mut_ptr()); write(entries.as_mut_ptr().add(DRM_ENTRY_NEW_OFF).cast::<*mut u8>(), new.as_mut_ptr()); write(plane.as_mut_ptr().add(DRM_PLANE_HELPER_PRIVATE_OFF).cast::<*mut u8>(), helpers.as_mut_ptr()); write(helpers.as_mut_ptr().add(DRM_PLANE_HELPER_CLEANUP_FB_OFF).cast::<usize>(), cleanup as *const () as usize); }
        DEVICES.lock().push(DeviceAllocation { dev: dev.as_mut_ptr() as usize, base: 0, layout: Layout::new::<u8>(), refs: 1, mode_config: true, objects: Vec::new(), planes: vec![PlaneRecord { ptr: plane.as_mut_ptr() as usize, formats: 0, layout: Layout::new::<u8>() }], crtcs: Vec::new(), encoders: Vec::new(), connectors: Vec::new(), clients: Vec::new(), vblank: None, primary_master: None, put_pending: false, unplugged: false });
        drm_atomic_helper_cleanup_planes(dev.as_mut_ptr().cast(), state.as_mut_ptr().cast()); assert_eq!(CLEANED.load(Ordering::SeqCst), 1); DEVICES.lock().clear();
    }
}
