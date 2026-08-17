//! DRM atomic commit-record setup and state reference assignment.

use super::*;

const DRM_ATOMIC_DEV_OFF: usize = 8;
const DRM_ATOMIC_FLAGS_OFF: usize = 16;
const DRM_ATOMIC_PLANES_OFF: usize = 32;
const DRM_ATOMIC_CRTCS_OFF: usize = 40;
const DRM_ATOMIC_NUM_CONNECTOR_OFF: usize = 48;
const DRM_ATOMIC_CONNECTORS_OFF: usize = 56;
const DRM_ATOMIC_FAKE_COMMIT_OFF: usize = 88;
const DRM_ATOMIC_LEGACY_CURSOR: u8 = 1 << 1;
const DRM_PLANE_ENTRY_SIZE: usize = 32;
const DRM_CRTC_ENTRY_SIZE: usize = 56;
const DRM_CONNECTOR_ENTRY_SIZE: usize = 40;
const DRM_ENTRY_OBJECT_OFF: usize = 0;
const DRM_ENTRY_OLD_OFF: usize = 16;
const DRM_ENTRY_NEW_OFF: usize = 24;
const DRM_CRTC_ENTRY_COMMIT_OFF: usize = 32;
const DRM_PLANE_STATE_CRTC_OFF: usize = 8;
const DRM_PLANE_STATE_COMMIT_OFF: usize = 160;
const DRM_CRTC_STATE_ACTIVE_OFF: usize = 9;
const DRM_CRTC_STATE_COMMIT_OFF: usize = 320;
const DRM_CONNECTOR_STATE_CRTC_OFF: usize = 8;
const DRM_CONNECTOR_STATE_COMMIT_OFF: usize = 40;
const DRM_CRTC_COMMIT_FLIP_DONE_OFF: usize = 16;
const LINUX_EBUSY: i32 = 16;
const LINUX_ENOMEM: i32 = 12;

fn counts(dev: *mut c_void) -> Option<(usize, usize)> {
    let devices = DEVICES.lock(); let record = devices.iter().find(|record| record.dev == dev as usize && record.mode_config && !record.put_pending && !record.unplugged)?; Some((record.planes.len(), record.crtcs.len()))
}
unsafe fn entry(state: *mut u8, array_off: usize, size: usize, index: usize) -> *mut u8 {
    // SAFETY: caller bounds index by the state-owned array capacity.
    unsafe { read(state.add(array_off).cast::<*mut u8>()).add(index * size) }
}
fn completed(commit: *mut u8) -> bool {
    if commit.is_null() { return true; }
    // SAFETY: flip_done is the embedded completion in a live commit record.
    unsafe { crate::linux_sync::try_wait_for_completion(commit.add(DRM_CRTC_COMMIT_FLIP_DONE_OFF).cast()) != 0 }
}
fn fake_commit(state: *mut u8) -> *mut u8 {
    // SAFETY: fake_commit is transaction-owned state at a verified ABI offset.
    let existing = unsafe { read(state.add(DRM_ATOMIC_FAKE_COMMIT_OFF).cast::<*mut u8>()) };
    if !existing.is_null() { return existing; }
    let commit = crtc_commit::alloc(core::ptr::null_mut());
    if commit.is_null() { return commit; }
    // SAFETY: freshly allocated fake commit is retained by this transaction until default clear.
    unsafe { write(state.add(DRM_ATOMIC_FAKE_COMMIT_OFF).cast::<*mut u8>(), commit); }
    commit
}

pub(super) fn export_symbols() { crate::symtab::export("drm_atomic_helper_setup_commit", drm_atomic_helper_setup_commit as *const () as usize, false); }

/// Allocate and attach per-object commit tracking before atomic state publication. # C: O(N_objects)
pub(super) extern "C" fn drm_atomic_helper_setup_commit(state: *mut c_void, nonblock: bool) -> i32 {
    if state.is_null() { return -LINUX_ENOMEM; }
    let state = state.cast::<u8>();
    // SAFETY: state retains its allocating live device and ABI-pinned transaction arrays.
    let (dev, connector_count) = unsafe { (read(state.add(DRM_ATOMIC_DEV_OFF).cast::<*mut c_void>()), read(state.add(DRM_ATOMIC_NUM_CONNECTOR_OFF).cast::<i32>()).max(0) as usize) };
    let Some((planes, crtcs)) = counts(dev) else { return -LINUX_ENOMEM; };
    for index in 0..crtcs {
        // SAFETY: index is bounded by this device's fixed CRTC transaction array.
        let slot = unsafe { entry(state, DRM_ATOMIC_CRTCS_OFF, DRM_CRTC_ENTRY_SIZE, index) };
        // SAFETY: old/new state pointers occupy their fixed transaction entry fields.
        let (crtc, old, new) = unsafe { (read(slot.add(DRM_ENTRY_OBJECT_OFF).cast::<*mut c_void>()), read(slot.add(DRM_ENTRY_OLD_OFF).cast::<*mut u8>()), read(slot.add(DRM_ENTRY_NEW_OFF).cast::<*mut u8>())) };
        if crtc.is_null() || old.is_null() || new.is_null() { continue; }
        let commit = crtc_commit::alloc(crtc); if commit.is_null() { return -LINUX_ENOMEM; }
        // SAFETY: new state owns the allocation reference and the entry owns one additional wait reference.
        unsafe { write(new.add(DRM_CRTC_STATE_COMMIT_OFF).cast::<*mut u8>(), commit); write(slot.add(DRM_CRTC_ENTRY_COMMIT_OFF).cast::<*mut u8>(), crtc_commit::get(commit)); }
        // SAFETY: active is a scalar field in each complete old/new CRTC state.
        let inactive = unsafe { !read(old.add(DRM_CRTC_STATE_ACTIVE_OFF).cast::<bool>()) && !read(new.add(DRM_CRTC_STATE_ACTIVE_OFF).cast::<bool>()) };
        // SAFETY: flags belongs solely to the atomic transaction.
        if inactive || unsafe { read(state.add(DRM_ATOMIC_FLAGS_OFF).cast::<u8>()) & DRM_ATOMIC_LEGACY_CURSOR != 0 } { unsafe { crate::linux_sync::complete_all(commit.add(DRM_CRTC_COMMIT_FLIP_DONE_OFF).cast()); } }
    }
    for index in 0..connector_count {
        // SAFETY: index is bounded by connector capacity held in the transaction.
        let slot = unsafe { entry(state, DRM_ATOMIC_CONNECTORS_OFF, DRM_CONNECTOR_ENTRY_SIZE, index) };
        // SAFETY: state pointers are stable transaction fields.
        let (old, new) = unsafe { (read(slot.add(DRM_ENTRY_OLD_OFF).cast::<*mut u8>()), read(slot.add(DRM_ENTRY_NEW_OFF).cast::<*mut u8>())) }; if old.is_null() || new.is_null() { continue; }
        // SAFETY: old is the non-null connector state just read from this entry; commit is its ABI-pinned reference field.
        let old_commit = unsafe { read(old.add(DRM_CONNECTOR_STATE_COMMIT_OFF).cast::<*mut u8>()) }; if nonblock && !completed(old_commit) { return -LINUX_EBUSY; }
        // SAFETY: falls back to old's CRTC pointer only when new's is null; both fields share the same fixed offset on their own non-null states.
        let crtc = unsafe { let n = read(new.add(DRM_CONNECTOR_STATE_CRTC_OFF).cast::<*mut u8>()); if n.is_null() { read(old.add(DRM_CONNECTOR_STATE_CRTC_OFF).cast::<*mut u8>()) } else { n } };
        // SAFETY: entry() bounds i by the same fixed CRTC array as the outer loop; object/new-state fields are the entry's own ABI slots.
        let commit = if crtc.is_null() { fake_commit(state) } else { let found = (0..crtcs).find_map(|i| { let e = unsafe { entry(state, DRM_ATOMIC_CRTCS_OFF, DRM_CRTC_ENTRY_SIZE, i) }; let object = unsafe { read(e.add(DRM_ENTRY_OBJECT_OFF).cast::<*mut u8>()) }; (object == crtc).then(|| unsafe { read(e.add(DRM_ENTRY_NEW_OFF).cast::<*mut u8>()) }) }); found.and_then(|s| (!s.is_null()).then(|| unsafe { read(s.add(DRM_CRTC_STATE_COMMIT_OFF).cast::<*mut u8>()) })).unwrap_or_else(|| fake_commit(state)) };
        // SAFETY: new is the non-null connector state validated above; this stores the commit ref this transaction now owns.
        if commit.is_null() { return -LINUX_ENOMEM; } unsafe { write(new.add(DRM_CONNECTOR_STATE_COMMIT_OFF).cast::<*mut u8>(), crtc_commit::get(commit)); }
    }
    for index in 0..planes {
        // SAFETY: index is bounded by the fixed plane transaction array.
        let slot = unsafe { entry(state, DRM_ATOMIC_PLANES_OFF, DRM_PLANE_ENTRY_SIZE, index) };
        // SAFETY: old/new-state fields occupy the fixed offsets of this plane entry, same layout as the CRTC/connector entries above.
        let (old, new) = unsafe { (read(slot.add(DRM_ENTRY_OLD_OFF).cast::<*mut u8>()), read(slot.add(DRM_ENTRY_NEW_OFF).cast::<*mut u8>())) }; if old.is_null() || new.is_null() { continue; }
        // SAFETY: old is the non-null plane state just read from this entry; commit is its ABI-pinned reference field.
        let old_commit = unsafe { read(old.add(DRM_PLANE_STATE_COMMIT_OFF).cast::<*mut u8>()) }; if nonblock && !completed(old_commit) { return -LINUX_EBUSY; }
        // SAFETY: falls back to old's CRTC pointer only when new's is null; both fields share the same fixed offset on their own non-null states.
        let crtc = unsafe { let n = read(new.add(DRM_PLANE_STATE_CRTC_OFF).cast::<*mut u8>()); if n.is_null() { read(old.add(DRM_PLANE_STATE_CRTC_OFF).cast::<*mut u8>()) } else { n } };
        // SAFETY: entry() bounds i by the same fixed CRTC array as the CRTC loop above; object/new-state fields are the entry's own ABI slots.
        let commit = if crtc.is_null() { fake_commit(state) } else { let found = (0..crtcs).find_map(|i| { let e = unsafe { entry(state, DRM_ATOMIC_CRTCS_OFF, DRM_CRTC_ENTRY_SIZE, i) }; let object = unsafe { read(e.add(DRM_ENTRY_OBJECT_OFF).cast::<*mut u8>()) }; (object == crtc).then(|| unsafe { read(e.add(DRM_ENTRY_NEW_OFF).cast::<*mut u8>()) }) }); found.and_then(|s| (!s.is_null()).then(|| unsafe { read(s.add(DRM_CRTC_STATE_COMMIT_OFF).cast::<*mut u8>()) })).unwrap_or_else(|| fake_commit(state)) };
        // SAFETY: new is the non-null plane state validated above; this stores the commit ref this transaction now owns.
        if commit.is_null() { return -LINUX_ENOMEM; } unsafe { write(new.add(DRM_PLANE_STATE_COMMIT_OFF).cast::<*mut u8>(), crtc_commit::get(commit)); }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn setup_gives_an_inactive_crtc_state_and_entry_retained_commit_references() {
        let _modules = crate::test_serial::claim(); let mut dev = [0u8; 1]; let mut state = [0u8; 128]; let mut entries = [0u8; DRM_CRTC_ENTRY_SIZE]; let mut crtc = [0u8; 1656]; let mut old = [0u8; 336]; let mut new = [0u8; 336];
        // SAFETY: fabricated records reserve every atomic state and CRTC entry field used by setup.
        unsafe { write(state.as_mut_ptr().add(DRM_ATOMIC_DEV_OFF).cast::<*mut u8>(), dev.as_mut_ptr()); write(state.as_mut_ptr().add(DRM_ATOMIC_CRTCS_OFF).cast::<*mut u8>(), entries.as_mut_ptr()); write(entries.as_mut_ptr().add(DRM_ENTRY_OBJECT_OFF).cast::<*mut u8>(), crtc.as_mut_ptr()); write(entries.as_mut_ptr().add(DRM_ENTRY_OLD_OFF).cast::<*mut u8>(), old.as_mut_ptr()); write(entries.as_mut_ptr().add(DRM_ENTRY_NEW_OFF).cast::<*mut u8>(), new.as_mut_ptr()); }
        DEVICES.lock().push(DeviceAllocation { dev: dev.as_mut_ptr() as usize, base: 0, layout: Layout::new::<u8>(), refs: 1, mode_config: true, objects: Vec::new(), planes: Vec::new(), crtcs: vec![CrtcRecord { ptr: crtc.as_mut_ptr() as usize, name: 0, layout: Layout::new::<u8>() }], encoders: Vec::new(), connectors: Vec::new(), clients: Vec::new(), vblank: None, primary_master: None, put_pending: false, unplugged: false });
        assert_eq!(drm_atomic_helper_setup_commit(state.as_mut_ptr().cast(), false), 0);
        // SAFETY: successful setup writes one shared commit into the new state and the entry reference slot.
        let (state_commit, entry_commit) = unsafe { (read(new.as_ptr().add(DRM_CRTC_STATE_COMMIT_OFF).cast::<*mut u8>()), read(entries.as_ptr().add(DRM_CRTC_ENTRY_COMMIT_OFF).cast::<*mut u8>())) }; assert_eq!(state_commit, entry_commit); assert!(completed(state_commit));
        crtc_commit::put(state_commit); crtc_commit::put(entry_commit); DEVICES.lock().clear();
    }
}
