//! DRM atomic plane callback and commit-completion stages.

use super::*;

const DEV_OFF: usize = 8; const PLANES_OFF: usize = 32; const CRTCS_OFF: usize = 40; const FAKE_OFF: usize = 88;
const PLANE_ENTRY: usize = 32; const CRTC_ENTRY: usize = 56; const OBJ: usize = 0; const OLD: usize = 16; const NEW: usize = 24;
const PLANE_HELPERS: usize = 1224; const CRTC_HELPERS: usize = 432; const PLANE_UPDATE: usize = 40; const PLANE_ENABLE: usize = 48; const PLANE_DISABLE: usize = 56; const CRTC_BEGIN: usize = 88; const CRTC_FLUSH: usize = 96;
const PLANE_CRTC: usize = 8; const PLANE_COMMIT: usize = 160; const CRTC_COMMIT: usize = 320; const COMMIT_HW: usize = 48; const COMMIT_CLEANUP: usize = 80;

fn counts(dev: *mut c_void) -> Option<(usize, usize)> { let d = DEVICES.lock(); let r = d.iter().find(|r| r.dev == dev as usize && r.mode_config && !r.put_pending && !r.unplugged)?; Some((r.planes.len(), r.crtcs.len())) }
unsafe fn entry(s: *mut u8, off: usize, size: usize, i: usize) -> *mut u8 { unsafe { read(s.add(off).cast::<*mut u8>()).add(i * size) } }
unsafe fn call2(ptr: usize, a: *mut c_void, b: *mut c_void) { if ptr != 0 { unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut c_void, *mut c_void)>(ptr)(a, b); } } }
fn callback(obj: *mut u8, table: usize, off: usize) -> usize { if obj.is_null() { 0 } else { unsafe { let t = read(obj.add(table).cast::<*const u8>()); if t.is_null() { 0 } else { read(t.add(off).cast::<usize>()) } } } }

pub(super) fn export_symbols() { for (n, p) in [("drm_atomic_helper_commit_planes", drm_atomic_helper_commit_planes as *const () as usize), ("drm_atomic_helper_commit_hw_done", drm_atomic_helper_commit_hw_done as *const () as usize), ("drm_atomic_helper_commit_cleanup_done", drm_atomic_helper_commit_cleanup_done as *const () as usize)] { crate::symtab::export(n, p, false); } }

/// Execute CRTC begin, plane update/disable, and CRTC flush callbacks. # C: O(N_objects)
pub(super) extern "C" fn drm_atomic_helper_commit_planes(dev: *mut c_void, state: *mut c_void, _flags: u32) {
    if state.is_null() { return; } let s = state.cast::<u8>(); let Some((planes, crtcs)) = counts(dev) else { return; };
    for i in 0..crtcs { let e = unsafe { entry(s, CRTCS_OFF, CRTC_ENTRY, i) }; let (o, n) = unsafe { (read(e.add(OBJ).cast::<*mut u8>()), read(e.add(NEW).cast::<*mut u8>())) }; if !o.is_null() && !n.is_null() { unsafe { call2(callback(o, CRTC_HELPERS, CRTC_BEGIN), o.cast(), state); } } }
    for i in 0..planes { let e = unsafe { entry(s, PLANES_OFF, PLANE_ENTRY, i) }; let (o, old, new) = unsafe { (read(e.add(OBJ).cast::<*mut u8>()), read(e.add(OLD).cast::<*mut u8>()), read(e.add(NEW).cast::<*mut u8>())) }; if o.is_null() || old.is_null() || new.is_null() { continue; } let (old_crtc, new_crtc) = unsafe { (read(old.add(PLANE_CRTC).cast::<*mut u8>()), read(new.add(PLANE_CRTC).cast::<*mut u8>())) }; let disabling = !old_crtc.is_null() && new_crtc.is_null(); if disabling && callback(o, PLANE_HELPERS, PLANE_DISABLE) != 0 { unsafe { call2(callback(o, PLANE_HELPERS, PLANE_DISABLE), o.cast(), state); } } else if !new_crtc.is_null() || disabling { unsafe { call2(callback(o, PLANE_HELPERS, PLANE_UPDATE), o.cast(), state); if old_crtc.is_null() && !new_crtc.is_null() { call2(callback(o, PLANE_HELPERS, PLANE_ENABLE), o.cast(), state); } } } }
    for i in 0..crtcs { let e = unsafe { entry(s, CRTCS_OFF, CRTC_ENTRY, i) }; let (o, n) = unsafe { (read(e.add(OBJ).cast::<*mut u8>()), read(e.add(NEW).cast::<*mut u8>())) }; if !o.is_null() && !n.is_null() { unsafe { call2(callback(o, CRTC_HELPERS, CRTC_FLUSH), o.cast(), state); } } }
}

/// Signal completion of hardware programming and transfer CRTC commit ownership. # C: O(N_crtcs)
pub(super) extern "C" fn drm_atomic_helper_commit_hw_done(state: *mut c_void) { if state.is_null() { return; } let s = state.cast::<u8>(); let dev = unsafe { read(s.add(DEV_OFF).cast::<*mut c_void>()) }; let Some((_, crtcs)) = counts(dev) else { return; }; for i in 0..crtcs { let e = unsafe { entry(s, CRTCS_OFF, CRTC_ENTRY, i) }; let (old, new) = unsafe { (read(e.add(OLD).cast::<*mut u8>()), read(e.add(NEW).cast::<*mut u8>())) }; if old.is_null() || new.is_null() { continue; } let commit = unsafe { read(new.add(CRTC_COMMIT).cast::<*mut u8>()) }; if commit.is_null() { continue; } let prior = unsafe { read(old.add(CRTC_COMMIT).cast::<*mut u8>()) }; crtc_commit::put(prior); unsafe { write(old.add(CRTC_COMMIT).cast::<*mut u8>(), crtc_commit::get(commit)); crate::linux_sync::complete_all(commit.add(COMMIT_HW).cast()); } } let fake = unsafe { read(s.add(FAKE_OFF).cast::<*mut u8>()) }; if !fake.is_null() { unsafe { crate::linux_sync::complete_all(fake.add(COMMIT_HW).cast()); crate::linux_sync::complete_all(fake.add(16).cast()); } } }

/// Signal terminal cleanup completion after an atomic tail releases old resources. # C: O(N_crtcs)
pub(super) extern "C" fn drm_atomic_helper_commit_cleanup_done(state: *mut c_void) { if state.is_null() { return; } let s = state.cast::<u8>(); let dev = unsafe { read(s.add(DEV_OFF).cast::<*mut c_void>()) }; let Some((_, crtcs)) = counts(dev) else { return; }; for i in 0..crtcs { let e = unsafe { entry(s, CRTCS_OFF, CRTC_ENTRY, i) }; let old = unsafe { read(e.add(OLD).cast::<*mut u8>()) }; if !old.is_null() { let c = unsafe { read(old.add(CRTC_COMMIT).cast::<*mut u8>()) }; if !c.is_null() { unsafe { crate::linux_sync::complete_all(c.add(COMMIT_CLEANUP).cast()); } } } } let fake = unsafe { read(s.add(FAKE_OFF).cast::<*mut u8>()) }; if !fake.is_null() { unsafe { crate::linux_sync::complete_all(fake.add(COMMIT_CLEANUP).cast()); } } }

#[cfg(test)]
mod tests {
    use super::*; use alloc::vec; use core::sync::atomic::{AtomicUsize, Ordering};
    static UPDATES: AtomicUsize = AtomicUsize::new(0); static EXPECTED: AtomicUsize = AtomicUsize::new(0);
    unsafe extern "C" fn update(plane: *mut c_void, _state: *mut c_void) { let current = unsafe { read(plane.cast::<u8>().add(1232).cast::<*mut u8>()) }; assert_eq!(current as usize, EXPECTED.load(Ordering::SeqCst)); UPDATES.fetch_add(1, Ordering::SeqCst); }
    #[test]
    fn plane_update_callback_observes_the_published_atomic_state() {
        let _modules = crate::test_serial::claim(); UPDATES.store(0, Ordering::SeqCst); let mut dev = [0u8; 1]; let mut state = [0u8; 128]; let mut entries = [0u8; 32]; let mut plane = [0u8; 1360]; let mut old = [0u8; 184]; let mut new = [0u8; 184]; let mut helpers = [0u8; 96];
        // SAFETY: fabricated records contain every transaction, plane, state, and helper callback field used by this path.
        unsafe { write(state.as_mut_ptr().add(DEV_OFF).cast::<*mut u8>(), dev.as_mut_ptr()); write(state.as_mut_ptr().add(PLANES_OFF).cast::<*mut u8>(), entries.as_mut_ptr()); write(entries.as_mut_ptr().add(OBJ).cast::<*mut u8>(), plane.as_mut_ptr()); write(entries.as_mut_ptr().add(OLD).cast::<*mut u8>(), old.as_mut_ptr()); write(entries.as_mut_ptr().add(NEW).cast::<*mut u8>(), new.as_mut_ptr()); write(plane.as_mut_ptr().add(PLANE_HELPERS).cast::<*mut u8>(), helpers.as_mut_ptr()); write(helpers.as_mut_ptr().add(PLANE_UPDATE).cast::<usize>(), update as *const () as usize); write(new.as_mut_ptr().add(PLANE_CRTC).cast::<*mut u8>(), 1usize as *mut u8); write(plane.as_mut_ptr().add(1232).cast::<*mut u8>(), new.as_mut_ptr()); } EXPECTED.store(new.as_mut_ptr() as usize, Ordering::SeqCst);
        DEVICES.lock().push(DeviceAllocation { dev: dev.as_mut_ptr() as usize, base: 0, layout: Layout::new::<u8>(), refs: 1, mode_config: true, objects: Vec::new(), planes: vec![PlaneRecord { ptr: plane.as_mut_ptr() as usize, formats: 0, layout: Layout::new::<u8>() }], crtcs: Vec::new(), encoders: Vec::new(), connectors: Vec::new(), clients: Vec::new(), vblank: None, primary_master: None, put_pending: false, unplugged: false }); drm_atomic_helper_commit_planes(dev.as_mut_ptr().cast(), state.as_mut_ptr().cast(), 0); assert_eq!(UPDATES.load(Ordering::SeqCst), 1); DEVICES.lock().clear();
    }
}
