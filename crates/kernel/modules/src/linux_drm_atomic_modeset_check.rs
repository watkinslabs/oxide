//! DRM atomic modeset routing and affected-object checks.

use super::*;

const DRM_ATOMIC_DEV_OFF: usize = 8;
const DRM_ATOMIC_CRTCS_OFF: usize = 40;
const DRM_ATOMIC_NUM_CONNECTOR_OFF: usize = 48;
const DRM_ATOMIC_CONNECTORS_OFF: usize = 56;
const DRM_CRTC_ENTRY_SIZE: usize = 56;
const DRM_CONNECTOR_ENTRY_SIZE: usize = 40;
const DRM_ENTRY_OBJECT_OFF: usize = 0;
const DRM_ENTRY_OLD_OFF: usize = 16;
const DRM_ENTRY_NEW_OFF: usize = 24;
const DRM_CRTC_STATE_CHANGE_FLAGS_OFF: usize = 10;
const DRM_CRTC_STATE_MODESET_MASK: u8 = (1 << 1) | (1 << 3);
const DRM_CONNECTOR_HELPER_PRIVATE_OFF: usize = 1576;
const DRM_CONNECTOR_HELPER_ATOMIC_CHECK_OFF: usize = 48;
const DRM_CONNECTOR_STATE_CRTC_OFF: usize = 8;
const DRM_CONNECTOR_STATE_BEST_ENCODER_OFF: usize = 16;
const DRM_ENCODER_HELPER_PRIVATE_OFF: usize = 112;
const DRM_ENCODER_HELPER_ATOMIC_CHECK_OFF: usize = 64;
const DRM_ENCODER_HELPER_MODE_VALID_OFF: usize = 8;
const DRM_ENCODER_HELPER_MODE_FIXUP_OFF: usize = 16;
const DRM_CRTC_HELPER_PRIVATE_OFF: usize = 432;
const DRM_CRTC_HELPER_MODE_VALID_OFF: usize = 8;
const DRM_CRTC_HELPER_MODE_FIXUP_OFF: usize = 16;
const DRM_CRTC_STATE_ADJUSTED_MODE_OFF: usize = 24;
const DRM_CRTC_STATE_MODE_OFF: usize = 144;
const DRM_MODE_STATUS_OK: i32 = 0;
const LINUX_EINVAL: i32 = 22;

pub(super) fn export_symbols() {
    crate::symtab::export("drm_atomic_helper_check_modeset", drm_atomic_helper_check_modeset as *const () as usize, false);
}

fn connector_check(connector: *mut c_void, state: *mut c_void) -> i32 {
    // SAFETY: connector helper_private is an ABI-pinned callback table for this live KMS object.
    let table = unsafe { read(connector.cast::<u8>().add(DRM_CONNECTOR_HELPER_PRIVATE_OFF).cast::<*const u8>()) };
    if table.is_null() { return 0; }
    // SAFETY: the optional atomic_check callback has the documented connector/transaction signature.
    let callback = unsafe { read(table.add(DRM_CONNECTOR_HELPER_ATOMIC_CHECK_OFF).cast::<usize>()) };
    if callback == 0 { 0 } else { unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut c_void, *mut c_void) -> i32>(callback)(connector, state) } }
}

fn encoder_check(state: *mut c_void, connector_state: *mut u8) -> i32 {
    // SAFETY: connector state retains its selected encoder and CRTC relation for this transaction.
    let (encoder, crtc) = unsafe { (read(connector_state.add(DRM_CONNECTOR_STATE_BEST_ENCODER_OFF).cast::<*mut u8>()), read(connector_state.add(DRM_CONNECTOR_STATE_CRTC_OFF).cast::<*mut c_void>())) };
    if encoder.is_null() || crtc.is_null() { return 0; }
    let crtc_state = atomic_acquire::drm_atomic_get_crtc_state(state, crtc);
    if (crtc_state as usize) >= usize::MAX - 4095 { return crtc_state as isize as i32; }
    if crtc_state.is_null() { return -LINUX_EINVAL; }
    // SAFETY: encoder helper_private is an ABI-pinned helper vtable pointer.
    let table = unsafe { read(encoder.add(DRM_ENCODER_HELPER_PRIVATE_OFF).cast::<*const u8>()) };
    if table.is_null() { return 0; }
    // SAFETY: optional encoder atomic_check receives encoder, new CRTC state, and new connector state.
    let callback = unsafe { read(table.add(DRM_ENCODER_HELPER_ATOMIC_CHECK_OFF).cast::<usize>()) };
    if callback == 0 { 0 } else { unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> i32>(callback)(encoder.cast(), crtc_state, connector_state.cast()) } }
}

fn mode_validate_and_fixup(state: *mut c_void, connector_state: *mut u8) -> i32 {
    // SAFETY: selected relation pointers live in the transaction-owned connector state.
    let (encoder, crtc) = unsafe { (read(connector_state.add(DRM_CONNECTOR_STATE_BEST_ENCODER_OFF).cast::<*mut u8>()), read(connector_state.add(DRM_CONNECTOR_STATE_CRTC_OFF).cast::<*mut c_void>())) };
    if encoder.is_null() || crtc.is_null() { return 0; }
    let crtc_state = atomic_acquire::drm_atomic_get_crtc_state(state, crtc);
    if (crtc_state as usize) >= usize::MAX - 4095 { return crtc_state as isize as i32; }
    if crtc_state.is_null() { return -LINUX_EINVAL; }
    let crtc_state = crtc_state.cast::<u8>();
    // SAFETY: state contains ABI-pinned requested and adjusted display mode records.
    let (mode, adjusted) = (crtc_state.wrapping_add(DRM_CRTC_STATE_MODE_OFF).cast::<c_void>(), crtc_state.wrapping_add(DRM_CRTC_STATE_ADJUSTED_MODE_OFF).cast::<c_void>());
    // SAFETY: encoder helpers use the documented mode validation/fixup slots.
    let enc_table = unsafe { read(encoder.add(DRM_ENCODER_HELPER_PRIVATE_OFF).cast::<*const u8>()) };
    if !enc_table.is_null() {
        let valid = unsafe { read(enc_table.add(DRM_ENCODER_HELPER_MODE_VALID_OFF).cast::<usize>()) };
        if valid != 0 && unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut c_void, *mut c_void) -> i32>(valid)(encoder.cast(), mode) } != DRM_MODE_STATUS_OK { return -LINUX_EINVAL; }
        let fixup = unsafe { read(enc_table.add(DRM_ENCODER_HELPER_MODE_FIXUP_OFF).cast::<usize>()) };
        if fixup != 0 && !unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> bool>(fixup)(encoder.cast(), mode, adjusted) } { return -LINUX_EINVAL; }
    }
    // SAFETY: CRTC helper table and callbacks remain live under the transaction modeset locks.
    let crtc_table = unsafe { read(crtc.cast::<u8>().add(DRM_CRTC_HELPER_PRIVATE_OFF).cast::<*const u8>()) };
    if crtc_table.is_null() { return 0; }
    let valid = unsafe { read(crtc_table.add(DRM_CRTC_HELPER_MODE_VALID_OFF).cast::<usize>()) };
    if valid != 0 && unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut c_void, *mut c_void) -> i32>(valid)(crtc, mode) } != DRM_MODE_STATUS_OK { return -LINUX_EINVAL; }
    let fixup = unsafe { read(crtc_table.add(DRM_CRTC_HELPER_MODE_FIXUP_OFF).cast::<usize>()) };
    if fixup != 0 && !unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> bool>(fixup)(crtc, mode, adjusted) } { return -LINUX_EINVAL; }
    0
}

/// Route connectors, expand affected state, and validate encoder clone masks. # C: O(N_objects)
pub(super) extern "C" fn drm_atomic_helper_check_modeset(dev: *mut c_void, state: *mut c_void) -> i32 {
    if dev.is_null() || state.is_null() { return -LINUX_EINVAL; }
    let state_bytes = state.cast::<u8>();
    // SAFETY: each atomic state retains the device that allocated its state arrays.
    if unsafe { read(state_bytes.add(DRM_ATOMIC_DEV_OFF).cast::<*mut c_void>()) } != dev { return -LINUX_EINVAL; }
    // SAFETY: connector entry count and storage belong exclusively to this transaction.
    let (connectors, entries) = unsafe { (read(state_bytes.add(DRM_ATOMIC_NUM_CONNECTOR_OFF).cast::<i32>()).max(0) as usize, read(state_bytes.add(DRM_ATOMIC_CONNECTORS_OFF).cast::<*mut u8>())) };
    if connectors != 0 && entries.is_null() { return -LINUX_EINVAL; }
    for index in 0..connectors {
        // SAFETY: index is bounded by the transaction-owned connector entry capacity.
        let entry = unsafe { entries.add(index * DRM_CONNECTOR_ENTRY_SIZE) };
        // SAFETY: object and paired old/new state fields share the fixed entry ABI.
        let (connector, old, new) = unsafe { (read(entry.add(DRM_ENTRY_OBJECT_OFF).cast::<*mut c_void>()), read(entry.add(DRM_ENTRY_OLD_OFF).cast::<*mut c_void>()), read(entry.add(DRM_ENTRY_NEW_OFF).cast::<*mut c_void>())) };
        if connector.is_null() || old.is_null() || new.is_null() { continue; }
        let ret = update_connector_routing(state, connector, old, new); if ret != 0 { return ret; }
        let ret = connector_check(connector, state); if ret != 0 { return ret; }
    }
    // SAFETY: CRTC entries are fixed at atomic-state allocation and state-private through checking.
    let entries = unsafe { read(state_bytes.add(DRM_ATOMIC_CRTCS_OFF).cast::<*mut u8>()) };
    if entries.is_null() { return -LINUX_EINVAL; }
    let count = { let devices = DEVICES.lock(); devices.iter().find(|record| record.dev == dev as usize && record.mode_config && !record.put_pending && !record.unplugged).map_or(0, |record| record.crtcs.len()) };
    for index in 0..count {
        // SAFETY: index is bounded by the live graph's fixed CRTC array capacity.
        let entry = unsafe { entries.add(index * DRM_CRTC_ENTRY_SIZE) };
        // SAFETY: CRTC entry object/new state fields have ABI-pinned offsets.
        let (crtc, new) = unsafe { (read(entry.add(DRM_ENTRY_OBJECT_OFF).cast::<*mut c_void>()), read(entry.add(DRM_ENTRY_NEW_OFF).cast::<*mut u8>())) };
        if crtc.is_null() || new.is_null() { continue; }
        // SAFETY: change flags are transaction-private CRTC state.
        if unsafe { *new.add(DRM_CRTC_STATE_CHANGE_FLAGS_OFF) & DRM_CRTC_STATE_MODESET_MASK } == 0 { continue; }
        let ret = atomic_affected::drm_atomic_add_affected_connectors(state, crtc); if ret != 0 { return ret; }
        let ret = atomic_affected::drm_atomic_add_affected_planes(state, crtc); if ret != 0 { return ret; }
        let ret = check_valid_clones(state, crtc); if ret != 0 { return ret; }
    }
    // A modeset may have acquired connector states after their first check; validate every
    // acquired connector once more before encoder and CRTC validation consume that state.
    // SAFETY: affected-connector acquisition may have grown this transaction-owned entry array.
    let (connectors, entries) = unsafe { (read(state_bytes.add(DRM_ATOMIC_NUM_CONNECTOR_OFF).cast::<i32>()).max(0) as usize, read(state_bytes.add(DRM_ATOMIC_CONNECTORS_OFF).cast::<*mut u8>())) };
    if connectors != 0 && entries.is_null() { return -LINUX_EINVAL; }
    for index in 0..connectors {
        // SAFETY: index is bounded by the transaction-owned connector-entry capacity.
        let entry = unsafe { entries.add(index * DRM_CONNECTOR_ENTRY_SIZE) };
        // SAFETY: connector and new state occupy ABI-pinned entry fields.
        let (connector, new) = unsafe { (read(entry.add(DRM_ENTRY_OBJECT_OFF).cast::<*mut c_void>()), read(entry.add(DRM_ENTRY_NEW_OFF).cast::<*mut c_void>())) };
        if connector.is_null() || new.is_null() { continue; }
        let ret = connector_check(connector, state); if ret != 0 { return ret; }
        let ret = encoder_check(state, new.cast()); if ret != 0 { return ret; }
        let ret = mode_validate_and_fixup(state, new.cast()); if ret != 0 { return ret; }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn modeset_check_exports_and_rejects_missing_state() {
        export_symbols();
        assert!(crate::symtab::is_exported("drm_atomic_helper_check_modeset"));
        assert_eq!(drm_atomic_helper_check_modeset(core::ptr::null_mut(), core::ptr::null_mut()), -LINUX_EINVAL);
    }
}
