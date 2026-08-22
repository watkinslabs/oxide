//! DRM atomic z-position normalization.

use super::*;

const DRM_ATOMIC_DEV_OFF: usize = 8;
const DRM_ATOMIC_PLANES_OFF: usize = 32;
const DRM_ATOMIC_CRTCS_OFF: usize = 40;
const DRM_STATE_ENTRY_OBJECT_OFF: usize = 0;
const DRM_STATE_ENTRY_OLD_OFF: usize = 16;
const DRM_STATE_ENTRY_NEW_OFF: usize = 24;
const DRM_ATOMIC_PLANE_ENTRY_SIZE: usize = 32;
const DRM_ATOMIC_CRTC_ENTRY_SIZE: usize = 56;
const DRM_PLANE_STATE_CRTC_OFF: usize = 8;
const DRM_PLANE_STATE_ZPOS_OFF: usize = 80;
const DRM_PLANE_STATE_NORMALIZED_ZPOS_OFF: usize = 84;
const DRM_CRTC_STATE_CHANGE_FLAGS_OFF: usize = 10;
const DRM_CRTC_STATE_ZPOS_CHANGED_BIT: u8 = 1 << 4;
const DRM_CRTC_STATE_PLANE_MASK_OFF: usize = 12;
const DRM_PLANE_BASE_OFF: usize = 80;
const DRM_MODE_OBJECT_ID_OFF: usize = 0;
#[cfg(test)] const DRM_PLANE_INDEX_OFF: usize = 1220;
const LINUX_EINVAL: i32 = 22;

fn error_ptr(ptr: *mut c_void) -> Option<i32> { ((ptr as usize) >= usize::MAX - 4095).then_some(ptr as isize as i32) }

fn object_counts(dev: *mut c_void) -> Option<(usize, usize)> {
    let devices = DEVICES.lock();
    let record = devices.iter().find(|record| record.dev == dev as usize && record.mode_config && !record.put_pending && !record.unplugged)?;
    Some((record.planes.len(), record.crtcs.len()))
}

fn entry(state: *mut u8, array_off: usize, entry_size: usize, index: usize) -> *mut u8 {
    // SAFETY: caller validates the live object count against this fixed transaction array.
    unsafe { read(state.add(array_off).cast::<*mut u8>()).add(index * entry_size) }
}

fn mark_zpos_changed(state: *mut u8, crtc: *mut c_void) -> Result<(), i32> {
    if crtc.is_null() { return Ok(()); }
    let new = atomic_acquire::drm_atomic_get_crtc_state(state.cast(), crtc);
    if let Some(errno) = error_ptr(new) { return Err(errno); }
    if new.is_null() { return Err(-LINUX_EINVAL); }
    // SAFETY: the acquired CRTC state is private to this atomic transaction.
    unsafe { *new.cast::<u8>().add(DRM_CRTC_STATE_CHANGE_FLAGS_OFF) |= DRM_CRTC_STATE_ZPOS_CHANGED_BIT; }
    Ok(())
}

fn plane_order(first: (*mut u8, u32, u32), second: (*mut u8, u32, u32)) -> core::cmp::Ordering {
    first.1.cmp(&second.1).then_with(|| first.2.cmp(&second.2))
}

fn normalize_crtc(state: *mut u8, planes: usize, crtc_state: *mut u8) -> Result<(), i32> {
    // SAFETY: the new CRTC state retains its transaction-owned active-plane mask.
    let mask = unsafe { read(crtc_state.add(DRM_CRTC_STATE_PLANE_MASK_OFF).cast::<u32>()) };
    let mut states = Vec::new();
    for index in 0..planes {
        if index >= 32 || mask & (1u32 << index) == 0 { continue; }
        let slot = entry(state, DRM_ATOMIC_PLANES_OFF, DRM_ATOMIC_PLANE_ENTRY_SIZE, index);
        // SAFETY: the fixed plane entry stores its corresponding object pointer.
        let plane = unsafe { read(slot.add(DRM_STATE_ENTRY_OBJECT_OFF).cast::<*mut c_void>()) };
        if plane.is_null() { return Err(-LINUX_EINVAL); }
        let plane_state = atomic_acquire::drm_atomic_get_plane_state(state.cast(), plane);
        if let Some(errno) = error_ptr(plane_state) { return Err(errno); }
        if plane_state.is_null() { return Err(-LINUX_EINVAL); }
        // SAFETY: plane state and plane base remain live under the atomic acquire context.
        let (zpos, id) = unsafe {
            (read(plane_state.cast::<u8>().add(DRM_PLANE_STATE_ZPOS_OFF).cast::<u32>()),
             read(plane.cast::<u8>().add(DRM_PLANE_BASE_OFF + DRM_MODE_OBJECT_ID_OFF).cast::<u32>()))
        };
        states.push((plane_state.cast::<u8>(), zpos, id));
    }
    states.sort_unstable_by(|first, second| plane_order(*first, *second));
    for (normalized, (plane_state, _, _)) in states.into_iter().enumerate() {
        // SAFETY: normalized zpos is transaction-private and bounded by the active plane count.
        unsafe { write(plane_state.add(DRM_PLANE_STATE_NORMALIZED_ZPOS_OFF).cast::<u32>(), normalized as u32); }
    }
    // SAFETY: the CRTC state belongs exclusively to this atomic check transaction.
    unsafe { *crtc_state.add(DRM_CRTC_STATE_CHANGE_FLAGS_OFF) |= DRM_CRTC_STATE_ZPOS_CHANGED_BIT; }
    Ok(())
}

pub(super) fn export_symbols() {
    crate::symtab::export("drm_atomic_normalize_zpos", drm_atomic_normalize_zpos as *const () as usize, false);
}

/// Normalize each changed CRTC's active planes by z position then plane object ID. # C: O(N_planes log N_planes)
pub(super) extern "C" fn drm_atomic_normalize_zpos(dev: *mut c_void, state: *mut c_void) -> i32 {
    if dev.is_null() || state.is_null() { return -LINUX_EINVAL; }
    let state = state.cast::<u8>();
    // SAFETY: an atomic state retains the DRM device that allocated its object arrays.
    if unsafe { read(state.add(DRM_ATOMIC_DEV_OFF).cast::<*mut c_void>()) } != dev { return -LINUX_EINVAL; }
    let Some((planes, crtcs)) = object_counts(dev) else { return -LINUX_EINVAL; };
    for index in 0..planes {
        let slot = entry(state, DRM_ATOMIC_PLANES_OFF, DRM_ATOMIC_PLANE_ENTRY_SIZE, index);
        // SAFETY: object entries pair old and new states at their fixed ABI offsets.
        let (old, new) = unsafe { (read(slot.add(DRM_STATE_ENTRY_OLD_OFF).cast::<*mut u8>()), read(slot.add(DRM_STATE_ENTRY_NEW_OFF).cast::<*mut u8>())) };
        if old.is_null() || new.is_null() { continue; }
        // SAFETY: both plane states are complete records owned by the transaction.
        let (old_zpos, new_zpos, crtc) = unsafe {
            (read(old.add(DRM_PLANE_STATE_ZPOS_OFF).cast::<u32>()), read(new.add(DRM_PLANE_STATE_ZPOS_OFF).cast::<u32>()), read(new.add(DRM_PLANE_STATE_CRTC_OFF).cast::<*mut c_void>()))
        };
        if old_zpos != new_zpos { if let Err(errno) = mark_zpos_changed(state, crtc) { return errno; } }
    }
    for index in 0..crtcs {
        let slot = entry(state, DRM_ATOMIC_CRTCS_OFF, DRM_ATOMIC_CRTC_ENTRY_SIZE, index);
        // SAFETY: object entries pair old and new CRTC states at their fixed ABI offsets.
        let (old, new) = unsafe { (read(slot.add(DRM_STATE_ENTRY_OLD_OFF).cast::<*mut u8>()), read(slot.add(DRM_STATE_ENTRY_NEW_OFF).cast::<*mut u8>())) };
        if old.is_null() || new.is_null() { continue; }
        // SAFETY: CRTC state fields are immutable old and transaction-private new records.
        let changed = unsafe {
            read(old.add(DRM_CRTC_STATE_PLANE_MASK_OFF).cast::<u32>()) != read(new.add(DRM_CRTC_STATE_PLANE_MASK_OFF).cast::<u32>()) ||
            *new.add(DRM_CRTC_STATE_CHANGE_FLAGS_OFF) & DRM_CRTC_STATE_ZPOS_CHANGED_BIT != 0
        };
        if changed { if let Err(errno) = normalize_crtc(state, planes, new) { return errno; } }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn zpos_normalization_orders_equal_positions_by_plane_id() {
        let _modules = crate::test_serial::claim();
        let mut dev = [0u8; 1]; let mut state = [0u8; 128];
        let mut first_plane = [0u8; 1360]; let mut second_plane = [0u8; 1360]; let mut crtc = [0u8; 1656];
        let mut old_first = [0u8; 184]; let mut old_second = [0u8; 184]; let mut new_first = [0u8; 184]; let mut new_second = [0u8; 184];
        let mut old_crtc = [0u8; 336]; let mut new_crtc = [0u8; 336]; let mut plane_entries = [0u8; 64]; let mut crtc_entries = [0u8; 56];
        // SAFETY: these arrays model two registered planes and their paired transaction state records.
        unsafe {
            write(state.as_mut_ptr().add(DRM_ATOMIC_DEV_OFF).cast::<*mut u8>(), dev.as_mut_ptr()); write(state.as_mut_ptr().add(DRM_ATOMIC_PLANES_OFF).cast::<*mut u8>(), plane_entries.as_mut_ptr()); write(state.as_mut_ptr().add(DRM_ATOMIC_CRTCS_OFF).cast::<*mut u8>(), crtc_entries.as_mut_ptr());
            for (index, plane) in [first_plane.as_mut_ptr(), second_plane.as_mut_ptr()].into_iter().enumerate() { write(plane.cast::<*mut u8>(), dev.as_mut_ptr()); write(plane.add(DRM_PLANE_INDEX_OFF).cast::<u32>(), index as u32); write(plane.add(DRM_PLANE_BASE_OFF).cast::<u32>(), if index == 0 { 9 } else { 4 }); }
            write(crtc.as_mut_ptr().cast::<*mut u8>(), dev.as_mut_ptr()); write(crtc.as_mut_ptr().add(144).cast::<u32>(), 0);
            for (index, (plane, old, new)) in [(first_plane.as_mut_ptr(), old_first.as_mut_ptr(), new_first.as_mut_ptr()), (second_plane.as_mut_ptr(), old_second.as_mut_ptr(), new_second.as_mut_ptr())].into_iter().enumerate() { let entry = plane_entries.as_mut_ptr().add(index * DRM_ATOMIC_PLANE_ENTRY_SIZE); write(entry.add(DRM_STATE_ENTRY_OBJECT_OFF).cast::<*mut u8>(), plane); write(entry.add(DRM_STATE_ENTRY_OLD_OFF).cast::<*mut u8>(), old); write(entry.add(DRM_STATE_ENTRY_NEW_OFF).cast::<*mut u8>(), new); write(old.add(DRM_PLANE_STATE_CRTC_OFF).cast::<*mut u8>(), crtc.as_mut_ptr()); write(new.add(DRM_PLANE_STATE_CRTC_OFF).cast::<*mut u8>(), crtc.as_mut_ptr()); write(old.add(DRM_PLANE_STATE_ZPOS_OFF).cast::<u32>(), if index == 0 { 2 } else { 3 }); write(new.add(DRM_PLANE_STATE_ZPOS_OFF).cast::<u32>(), 3); }
            write(crtc_entries.as_mut_ptr().add(DRM_STATE_ENTRY_OBJECT_OFF).cast::<*mut u8>(), crtc.as_mut_ptr()); write(crtc_entries.as_mut_ptr().add(DRM_STATE_ENTRY_OLD_OFF).cast::<*mut u8>(), old_crtc.as_mut_ptr()); write(crtc_entries.as_mut_ptr().add(DRM_STATE_ENTRY_NEW_OFF).cast::<*mut u8>(), new_crtc.as_mut_ptr()); write(old_crtc.as_mut_ptr().add(DRM_CRTC_STATE_PLANE_MASK_OFF).cast::<u32>(), 3); write(new_crtc.as_mut_ptr().add(DRM_CRTC_STATE_PLANE_MASK_OFF).cast::<u32>(), 3);
        }
        DEVICES.lock().push(DeviceAllocation { dev: dev.as_mut_ptr() as usize, base: 0, layout: Layout::new::<u8>(), refs: 1, mode_config: true, objects: Vec::new(), planes: vec![PlaneRecord { ptr: first_plane.as_mut_ptr() as usize, formats: 0, layout: Layout::new::<u8>() }, PlaneRecord { ptr: second_plane.as_mut_ptr() as usize, formats: 0, layout: Layout::new::<u8>() }], crtcs: vec![CrtcRecord { ptr: crtc.as_mut_ptr() as usize, name: 0, layout: Layout::new::<u8>() }], encoders: Vec::new(), connectors: Vec::new(), clients: Vec::new(), vblank: None, primary_master: None, put_pending: false, unplugged: false });
        assert_eq!(drm_atomic_normalize_zpos(dev.as_mut_ptr().cast(), state.as_mut_ptr().cast()), 0);
        // SAFETY: reads back normalize_crtc's written normalized-zpos field; equal zpos (3==3) must tie-break by plane object ID, so first (id 9) sorts after second (id 4).
        assert_eq!(unsafe { read(new_first.as_ptr().add(DRM_PLANE_STATE_NORMALIZED_ZPOS_OFF).cast::<u32>()) }, 1);
        // SAFETY: same normalized-zpos field on the fabricated second-plane new state, within its reserved 184-byte record.
        assert_eq!(unsafe { read(new_second.as_ptr().add(DRM_PLANE_STATE_NORMALIZED_ZPOS_OFF).cast::<u32>()) }, 0);
        assert_ne!(new_crtc[DRM_CRTC_STATE_CHANGE_FLAGS_OFF] & DRM_CRTC_STATE_ZPOS_CHANGED_BIT, 0);
        DEVICES.lock().clear();
    }

    #[test]
    fn zpos_normalization_export_and_null_contract() {
        let _modules = crate::test_serial::claim();
        export_symbols(); assert!(crate::symtab::is_exported("drm_atomic_normalize_zpos"));
        assert_eq!(drm_atomic_normalize_zpos(core::ptr::null_mut(), core::ptr::null_mut()), -LINUX_EINVAL);
    }
}
