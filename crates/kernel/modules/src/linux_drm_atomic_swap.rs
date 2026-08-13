//! DRM atomic state publication and cleanup ownership transfer.

use super::*;

const DRM_ATOMIC_DEV_OFF: usize = 8;
const DRM_ATOMIC_PLANES_OFF: usize = 32;
const DRM_ATOMIC_CRTCS_OFF: usize = 40;
const DRM_ATOMIC_NUM_CONNECTOR_OFF: usize = 48;
const DRM_ATOMIC_CONNECTORS_OFF: usize = 56;
const DRM_PLANE_ENTRY_SIZE: usize = 32;
const DRM_CRTC_ENTRY_SIZE: usize = 56;
const DRM_CONNECTOR_ENTRY_SIZE: usize = 40;
const DRM_ENTRY_OBJECT_OFF: usize = 0;
const DRM_ENTRY_DESTROY_OFF: usize = 8;
const DRM_ENTRY_OLD_OFF: usize = 16;
const DRM_ENTRY_NEW_OFF: usize = 24;
const DRM_PLANE_STATE_OFF: usize = 1232;
const DRM_CRTC_STATE_OFF: usize = 1488;
const DRM_CONNECTOR_STATE_OFF: usize = 1968;
const DRM_PLANE_STATE_ATOMIC_OFF: usize = 168;
const DRM_CRTC_STATE_ATOMIC_OFF: usize = 328;
const DRM_CONNECTOR_STATE_ATOMIC_OFF: usize = 32;
const DRM_PLANE_STATE_COMMIT_OFF: usize = 160;
const DRM_CRTC_STATE_COMMIT_OFF: usize = 320;
const DRM_CONNECTOR_STATE_COMMIT_OFF: usize = 40;
const DRM_CRTC_COMMIT_HW_DONE_OFF: usize = 48;

fn counts(dev: *mut c_void) -> Option<(usize, usize)> {
    let devices = DEVICES.lock();
    let record = devices.iter().find(|record| record.dev == dev as usize && record.mode_config && !record.put_pending && !record.unplugged)?;
    Some((record.planes.len(), record.crtcs.len()))
}

unsafe fn wait_entries(entries: *mut u8, count: usize, entry_size: usize, commit_off: usize) -> i32 {
    for index in 0..count {
        // SAFETY: the caller provides a complete atomic entry array with `count` entries.
        let entry = unsafe { entries.add(index * entry_size) };
        // SAFETY: old state is an ABI entry pointer, and its commit field is part of the matching state layout.
        let old = unsafe { read(entry.add(DRM_ENTRY_OLD_OFF).cast::<*mut u8>()) };
        if old.is_null() { continue; }
        // SAFETY: a non-null commit pointer names the commit object retained by that old state.
        let commit = unsafe { read(old.add(commit_off).cast::<*mut u8>()) };
        if commit.is_null() { continue; }
        // SAFETY: `hw_done` is the embedded completion in the retained commit record.
        let done = unsafe { commit.add(DRM_CRTC_COMMIT_HW_DONE_OFF).cast::<crate::linux_sync::LinuxCompletion>() };
        let ret = crate::linux_sync::wait_for_completion_interruptible(done);
        if ret != 0 { return ret; }
    }
    0
}

unsafe fn swap_entries(entries: *mut u8, count: usize, entry_size: usize, object_state_off: usize, state_atomic_off: usize, transaction: *mut c_void) {
    for index in 0..count {
        // SAFETY: the caller provides a complete atomic entry array with `count` entries.
        let entry = unsafe { entries.add(index * entry_size) };
        // SAFETY: each entry's object and old/new state fields have the ABI-pinned pointer layout.
        let (object, old, new) = unsafe {
            (read(entry.add(DRM_ENTRY_OBJECT_OFF).cast::<*mut u8>()), read(entry.add(DRM_ENTRY_OLD_OFF).cast::<*mut u8>()), read(entry.add(DRM_ENTRY_NEW_OFF).cast::<*mut u8>()))
        };
        if object.is_null() || old.is_null() || new.is_null() { continue; }
        // SAFETY: current state and state-owner backlinks are valid fields of the corresponding complete records.
        unsafe {
            write(old.add(state_atomic_off).cast::<*mut c_void>(), transaction);
            write(new.add(state_atomic_off).cast::<*mut c_void>(), core::ptr::null_mut());
            write(entry.add(DRM_ENTRY_DESTROY_OFF).cast::<*mut u8>(), old);
            write(object.add(object_state_off).cast::<*mut u8>(), new);
        }
    }
}

pub(super) fn export_symbols() {
    crate::symtab::export("drm_atomic_helper_swap_state", drm_atomic_helper_swap_state as *const () as usize, false);
}

/// Publish checked atomic object states and retain superseded states for cleanup. # C: O(N_objects)
pub(super) extern "C" fn drm_atomic_helper_swap_state(state: *mut c_void, stall: bool) -> i32 {
    if state.is_null() { return 0; }
    let state_u8 = state.cast::<u8>();
    // SAFETY: a live atomic state owns its device and the three ABI-pinned state arrays.
    let (dev, planes, crtcs, connectors, connector_count) = unsafe {
        (read(state_u8.add(DRM_ATOMIC_DEV_OFF).cast::<*mut c_void>()), read(state_u8.add(DRM_ATOMIC_PLANES_OFF).cast::<*mut u8>()), read(state_u8.add(DRM_ATOMIC_CRTCS_OFF).cast::<*mut u8>()), read(state_u8.add(DRM_ATOMIC_CONNECTORS_OFF).cast::<*mut u8>()), read(state_u8.add(DRM_ATOMIC_NUM_CONNECTOR_OFF).cast::<i32>()).max(0) as usize)
    };
    let Some((plane_count, crtc_count)) = counts(dev) else { return 0; };
    if stall {
        // SAFETY: each array has the count recorded by the transaction's owning device or connector capacity.
        let ret = unsafe { wait_entries(crtcs, crtc_count, DRM_CRTC_ENTRY_SIZE, DRM_CRTC_STATE_COMMIT_OFF) };
        if ret != 0 { return ret; }
        // SAFETY: connector capacity is retained by the transaction itself.
        let ret = unsafe { wait_entries(connectors, connector_count, DRM_CONNECTOR_ENTRY_SIZE, DRM_CONNECTOR_STATE_COMMIT_OFF) };
        if ret != 0 { return ret; }
        // SAFETY: plane entries are fixed to the owning device's registered plane graph.
        let ret = unsafe { wait_entries(planes, plane_count, DRM_PLANE_ENTRY_SIZE, DRM_PLANE_STATE_COMMIT_OFF) };
        if ret != 0 { return ret; }
    }
    // SAFETY: each populated entry transfers its old state to this transaction and publishes its new state once.
    unsafe {
        swap_entries(connectors, connector_count, DRM_CONNECTOR_ENTRY_SIZE, DRM_CONNECTOR_STATE_OFF, DRM_CONNECTOR_STATE_ATOMIC_OFF, state);
        swap_entries(crtcs, crtc_count, DRM_CRTC_ENTRY_SIZE, DRM_CRTC_STATE_OFF, DRM_CRTC_STATE_ATOMIC_OFF, state);
        swap_entries(planes, plane_count, DRM_PLANE_ENTRY_SIZE, DRM_PLANE_STATE_OFF, DRM_PLANE_STATE_ATOMIC_OFF, state);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swap_transfers_cleanup_ownership_and_publishes_every_object_kind() {
        let _modules = crate::test_serial::claim();
        let mut plane = [0u8; DRM_PLANE_STATE_OFF + 8]; let mut crtc = [0u8; DRM_CRTC_STATE_OFF + 8]; let mut connector = [0u8; DRM_CONNECTOR_STATE_OFF + 8];
        let mut old_plane = [0u8; DRM_PLANE_STATE_ATOMIC_OFF + 8]; let mut new_plane = [0u8; DRM_PLANE_STATE_ATOMIC_OFF + 8];
        let mut old_crtc = [0u8; DRM_CRTC_STATE_ATOMIC_OFF + 8]; let mut new_crtc = [0u8; DRM_CRTC_STATE_ATOMIC_OFF + 8];
        let mut old_connector = [0u8; DRM_CONNECTOR_STATE_ATOMIC_OFF + 8]; let mut new_connector = [0u8; DRM_CONNECTOR_STATE_ATOMIC_OFF + 8];
        let mut plane_entries = [0u8; DRM_PLANE_ENTRY_SIZE]; let mut crtc_entries = [0u8; DRM_CRTC_ENTRY_SIZE]; let mut connector_entries = [0u8; DRM_CONNECTOR_ENTRY_SIZE]; let mut state = [0u8; 128]; let mut dev = [0u8; 1];
        // SAFETY: fabricated records reserve every ABI pointer field exercised by the swap operation.
        unsafe {
            write(state.as_mut_ptr().add(DRM_ATOMIC_DEV_OFF).cast::<*mut u8>(), dev.as_mut_ptr());
            write(state.as_mut_ptr().add(DRM_ATOMIC_PLANES_OFF).cast::<*mut u8>(), plane_entries.as_mut_ptr()); write(state.as_mut_ptr().add(DRM_ATOMIC_CRTCS_OFF).cast::<*mut u8>(), crtc_entries.as_mut_ptr()); write(state.as_mut_ptr().add(DRM_ATOMIC_CONNECTORS_OFF).cast::<*mut u8>(), connector_entries.as_mut_ptr()); write(state.as_mut_ptr().add(DRM_ATOMIC_NUM_CONNECTOR_OFF).cast::<i32>(), 1);
            for (entry, object, old, new) in [(plane_entries.as_mut_ptr(), plane.as_mut_ptr(), old_plane.as_mut_ptr(), new_plane.as_mut_ptr()), (crtc_entries.as_mut_ptr(), crtc.as_mut_ptr(), old_crtc.as_mut_ptr(), new_crtc.as_mut_ptr()), (connector_entries.as_mut_ptr(), connector.as_mut_ptr(), old_connector.as_mut_ptr(), new_connector.as_mut_ptr())] {
                write(entry.add(DRM_ENTRY_OBJECT_OFF).cast::<*mut u8>(), object); write(entry.add(DRM_ENTRY_OLD_OFF).cast::<*mut u8>(), old); write(entry.add(DRM_ENTRY_NEW_OFF).cast::<*mut u8>(), new); write(entry.add(DRM_ENTRY_DESTROY_OFF).cast::<*mut u8>(), new);
            }
        }
        DEVICES.lock().push(DeviceAllocation { dev: dev.as_mut_ptr() as usize, base: 0, layout: Layout::from_size_align(1, 1).unwrap(), refs: 1, mode_config: true, objects: Vec::new(), planes: alloc::vec![PlaneRecord { ptr: plane.as_mut_ptr() as usize, formats: 0, layout: Layout::from_size_align(1, 1).unwrap() }], crtcs: alloc::vec![CrtcRecord { ptr: crtc.as_mut_ptr() as usize, name: 0, layout: Layout::from_size_align(1, 1).unwrap() }], encoders: Vec::new(), connectors: Vec::new(), clients: Vec::new(), vblank: None, primary_master: None, put_pending: false, unplugged: false });
        assert_eq!(drm_atomic_helper_swap_state(state.as_mut_ptr().cast(), false), 0);
        // SAFETY: all records remain live through assertions and were populated by the swap above.
        unsafe {
            assert_eq!(read(plane.as_ptr().add(DRM_PLANE_STATE_OFF).cast::<*mut u8>()), new_plane.as_mut_ptr()); assert_eq!(read(crtc.as_ptr().add(DRM_CRTC_STATE_OFF).cast::<*mut u8>()), new_crtc.as_mut_ptr()); assert_eq!(read(connector.as_ptr().add(DRM_CONNECTOR_STATE_OFF).cast::<*mut u8>()), new_connector.as_mut_ptr());
            assert_eq!(read(plane_entries.as_ptr().add(DRM_ENTRY_DESTROY_OFF).cast::<*mut u8>()), old_plane.as_mut_ptr()); assert_eq!(read(crtc_entries.as_ptr().add(DRM_ENTRY_DESTROY_OFF).cast::<*mut u8>()), old_crtc.as_mut_ptr()); assert_eq!(read(connector_entries.as_ptr().add(DRM_ENTRY_DESTROY_OFF).cast::<*mut u8>()), old_connector.as_mut_ptr());
            assert_eq!(read(old_plane.as_ptr().add(DRM_PLANE_STATE_ATOMIC_OFF).cast::<*mut c_void>()), state.as_mut_ptr().cast()); assert_eq!(read(old_crtc.as_ptr().add(DRM_CRTC_STATE_ATOMIC_OFF).cast::<*mut c_void>()), state.as_mut_ptr().cast()); assert_eq!(read(old_connector.as_ptr().add(DRM_CONNECTOR_STATE_ATOMIC_OFF).cast::<*mut c_void>()), state.as_mut_ptr().cast());
            assert!(read(new_plane.as_ptr().add(DRM_PLANE_STATE_ATOMIC_OFF).cast::<*mut c_void>()).is_null()); assert!(read(new_crtc.as_ptr().add(DRM_CRTC_STATE_ATOMIC_OFF).cast::<*mut c_void>()).is_null()); assert!(read(new_connector.as_ptr().add(DRM_CONNECTOR_STATE_ATOMIC_OFF).cast::<*mut c_void>()).is_null());
        }
        DEVICES.lock().retain(|record| record.dev != dev.as_mut_ptr() as usize);
    }

    #[test]
    fn swap_is_exported() { let _modules = crate::test_serial::claim(); export_symbols(); assert!(crate::symtab::is_exported("drm_atomic_helper_swap_state")); }
}
