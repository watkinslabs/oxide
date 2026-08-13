//! DRM atomic connector-to-encoder routing.

use super::*;

const DRM_ATOMIC_DEV_OFF: usize = 8;
const DRM_ATOMIC_CRTCS_OFF: usize = 40;
const DRM_ATOMIC_NUM_CONNECTOR_OFF: usize = 48;
const DRM_ATOMIC_CONNECTORS_OFF: usize = 56;
const DRM_ATOMIC_CRTC_ENTRY_SIZE: usize = 56;
const DRM_ATOMIC_CONNECTOR_ENTRY_SIZE: usize = 40;
const DRM_ATOMIC_ENTRY_NEW_OFF: usize = 24;
const DRM_CRTC_INDEX_OFF: usize = 144;
const DRM_CRTC_STATE_CONNECTORS_CHANGED_OFF: usize = 10;
const DRM_CRTC_STATE_CONNECTORS_CHANGED_BIT: u8 = 1 << 3;
const DRM_CRTC_STATE_ENCODER_MASK_OFF: usize = 20;
const DRM_CONNECTOR_HELPER_PRIVATE_OFF: usize = 1576;
const DRM_CONNECTOR_POSSIBLE_ENCODERS_OFF: usize = 1736;
const DRM_CONNECTOR_STATE_CRTC_OFF: usize = 8;
const DRM_CONNECTOR_STATE_BEST_ENCODER_OFF: usize = 16;
const DRM_CONNECTOR_STATE_OFF: usize = 1968;
const DRM_ENCODER_INDEX_OFF: usize = 68;
const DRM_ENCODER_POSSIBLE_CRTCS_OFF: usize = 72;
const DRM_CONNECTOR_HELPER_BEST_ENCODER_OFF: usize = 32;
const DRM_CONNECTOR_HELPER_ATOMIC_BEST_ENCODER_OFF: usize = 40;
const LINUX_EINVAL: i32 = 22;

fn error_ptr(ptr: *mut c_void) -> Option<i32> { ((ptr as usize) >= usize::MAX - 4095).then_some(ptr as isize as i32) }

fn transaction_device(state: *mut u8) -> *mut c_void {
    // SAFETY: every atomic state retains the device used to allocate its fixed object arrays.
    unsafe { read(state.add(DRM_ATOMIC_DEV_OFF).cast::<*mut c_void>()) }
}

fn encoder_mask(encoder: *mut u8) -> Result<u32, i32> {
    // SAFETY: published encoders carry an immutable device-relative index.
    let index = unsafe { read(encoder.add(DRM_ENCODER_INDEX_OFF).cast::<u32>()) };
    if index >= 32 { Err(-LINUX_EINVAL) } else { Ok(1u32 << index) }
}

fn new_crtc_state(state: *mut u8, crtc: *mut c_void) -> Result<*mut u8, i32> {
    if crtc.is_null() { return Err(-LINUX_EINVAL); }
    // SAFETY: registered CRTCs have a stable index selecting their fixed transaction entry.
    let index = unsafe { read(crtc.cast::<u8>().add(DRM_CRTC_INDEX_OFF).cast::<u32>()) as usize };
    // SAFETY: the fixed CRTC transaction array contains one ABI-sized entry per registered CRTC.
    let entries = unsafe { read(state.add(DRM_ATOMIC_CRTCS_OFF).cast::<*mut u8>()) };
    if !entries.is_null() {
        // SAFETY: index is validated by the atomic acquisition fallback before its entry is used.
        let result = unsafe { read(entries.add(index * DRM_ATOMIC_CRTC_ENTRY_SIZE + DRM_ATOMIC_ENTRY_NEW_OFF).cast::<*mut u8>()) };
        if !result.is_null() { return Ok(result); }
    }
    let result = atomic_acquire::drm_atomic_get_crtc_state(state.cast(), crtc);
    if let Some(errno) = error_ptr(result) { Err(errno) } else if result.is_null() { Err(-LINUX_EINVAL) } else { Ok(result.cast()) }
}

fn mark_connectors_changed(state: *mut u8, crtc: *mut c_void) -> Result<(), i32> {
    let crtc_state = new_crtc_state(state, crtc)?;
    // SAFETY: transaction-private CRTC state stores its change flags in this ABI byte.
    unsafe { *crtc_state.add(DRM_CRTC_STATE_CONNECTORS_CHANGED_OFF) |= DRM_CRTC_STATE_CONNECTORS_CHANGED_BIT; }
    Ok(())
}

fn pick_single_encoder(dev: *mut c_void, connector: *mut u8) -> Option<*mut u8> {
    // SAFETY: the connector's possible-encoder mask is immutable while its device graph is live.
    let allowed = unsafe { read(connector.add(DRM_CONNECTOR_POSSIBLE_ENCODERS_OFF).cast::<u32>()) };
    let devices = DEVICES.lock();
    let record = devices.iter().find(|record| record.dev == dev as usize && record.mode_config && !record.put_pending && !record.unplugged)?;
    let mut selected: *mut u8 = core::ptr::null_mut();
    for entry in &record.encoders {
        let encoder = entry.ptr as *mut u8;
        let mask = encoder_mask(encoder).ok()?;
        if allowed & mask == 0 { continue; }
        if !selected.is_null() { return None; }
        selected = encoder;
    }
    (!selected.is_null()).then_some(selected)
}

unsafe fn selected_encoder(state: *mut u8, connector: *mut u8) -> *mut u8 {
    // SAFETY: connector helper_private is a pinned pointer to the complete helper callback table.
    let helpers = unsafe { read(connector.add(DRM_CONNECTOR_HELPER_PRIVATE_OFF).cast::<*const u8>()) };
    if !helpers.is_null() {
        // SAFETY: callback slots are ABI-pinned and nonzero functions use their documented signatures.
        let atomic = unsafe { read(helpers.add(DRM_CONNECTOR_HELPER_ATOMIC_BEST_ENCODER_OFF).cast::<usize>()) };
        if atomic != 0 { return unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void>(atomic)(connector.cast(), state.cast()).cast() }; }
        // SAFETY: callback slots are ABI-pinned and nonzero functions use their documented signatures.
        let legacy = unsafe { read(helpers.add(DRM_CONNECTOR_HELPER_BEST_ENCODER_OFF).cast::<usize>()) };
        if legacy != 0 { return unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut c_void) -> *mut c_void>(legacy)(connector.cast()).cast() }; }
    }
    pick_single_encoder(transaction_device(state), connector).unwrap_or(core::ptr::null_mut()).cast()
}

fn set_best_encoder(state: *mut u8, new_connector: *mut u8, encoder: *mut u8) -> Result<(), i32> {
    // SAFETY: connector state owns its selected encoder pointer for this transaction.
    let previous = unsafe { read(new_connector.add(DRM_CONNECTOR_STATE_BEST_ENCODER_OFF).cast::<*mut u8>()) };
    if !previous.is_null() {
        // SAFETY: committed connector state identifies the old CRTC used for the old encoder mask.
        let connector = unsafe { read(new_connector.cast::<*mut u8>()) };
        let committed = unsafe { read(connector.add(DRM_CONNECTOR_STATE_OFF).cast::<*mut u8>()) };
        if !committed.is_null() {
            // SAFETY: committed connector state stores its CRTC relation at the common state offset.
            let old_crtc = unsafe { read(committed.add(DRM_CONNECTOR_STATE_CRTC_OFF).cast::<*mut c_void>()) };
            if !old_crtc.is_null() {
                let old_state = new_crtc_state(state, old_crtc)?;
                let mask = encoder_mask(previous)?;
                // SAFETY: the new CRTC state owns the encoder-membership bitmask for this transaction.
                unsafe { *old_state.add(DRM_CRTC_STATE_ENCODER_MASK_OFF).cast::<u32>() &= !mask; }
            }
        }
    }
    if !encoder.is_null() {
        // SAFETY: target connector state stores the requested CRTC relation.
        let crtc = unsafe { read(new_connector.add(DRM_CONNECTOR_STATE_CRTC_OFF).cast::<*mut c_void>()) };
        if crtc.is_null() { return Err(-LINUX_EINVAL); }
        let crtc_state = new_crtc_state(state, crtc)?;
        let mask = encoder_mask(encoder)?;
        // SAFETY: the new CRTC state owns the encoder-membership bitmask for this transaction.
        unsafe { *crtc_state.add(DRM_CRTC_STATE_ENCODER_MASK_OFF).cast::<u32>() |= mask; }
    }
    // SAFETY: selection is published only after both old and new CRTC masks were updated.
    unsafe { write(new_connector.add(DRM_CONNECTOR_STATE_BEST_ENCODER_OFF).cast::<*mut u8>(), encoder); }
    Ok(())
}

fn steal_encoder(state: *mut u8, encoder: *mut u8) -> Result<(), i32> {
    // SAFETY: connector entry count and pointer are private fields of this transaction.
    let (count, entries) = unsafe { (read(state.add(DRM_ATOMIC_NUM_CONNECTOR_OFF).cast::<i32>()).max(0) as usize, read(state.add(DRM_ATOMIC_CONNECTORS_OFF).cast::<*mut u8>())) };
    if entries.is_null() { return Ok(()); }
    for index in 0..count {
        // SAFETY: index is bounded by transaction-owned connector entry capacity.
        let new = unsafe { read(entries.add(index * DRM_ATOMIC_CONNECTOR_ENTRY_SIZE + DRM_ATOMIC_ENTRY_NEW_OFF).cast::<*mut u8>()) };
        if new.is_null() || unsafe { read(new.add(DRM_CONNECTOR_STATE_BEST_ENCODER_OFF).cast::<*mut u8>()) } != encoder { continue; }
        // SAFETY: old state is the current transaction's selected connector relation.
        let old_crtc = unsafe { read(new.add(DRM_CONNECTOR_STATE_CRTC_OFF).cast::<*mut c_void>()) };
        set_best_encoder(state, new, core::ptr::null_mut())?;
        if !old_crtc.is_null() { mark_connectors_changed(state, old_crtc)?; }
        return Ok(());
    }
    Ok(())
}

/// Update one connector's encoder routing inside an already acquired atomic transaction. # C: O(N_connectors)
pub(crate) fn update_connector_routing(state: *mut c_void, connector: *mut c_void, old: *mut c_void, new: *mut c_void) -> i32 {
    if state.is_null() || connector.is_null() || old.is_null() || new.is_null() { return -LINUX_EINVAL; }
    let (state, connector, old, new) = (state.cast::<u8>(), connector.cast::<u8>(), old.cast::<u8>(), new.cast::<u8>());
    let dev = transaction_device(state); if dev.is_null() { return -LINUX_EINVAL; }
    // SAFETY: old/new connector states are paired transaction-owned records.
    let (old_crtc, new_crtc) = unsafe { (read(old.add(DRM_CONNECTOR_STATE_CRTC_OFF).cast::<*mut c_void>()), read(new.add(DRM_CONNECTOR_STATE_CRTC_OFF).cast::<*mut c_void>())) };
    if old_crtc != new_crtc {
        if !old_crtc.is_null() { if let Err(errno) = mark_connectors_changed(state, old_crtc) { return errno; } }
        if !new_crtc.is_null() { if let Err(errno) = mark_connectors_changed(state, new_crtc) { return errno; } }
    }
    if new_crtc.is_null() { return set_best_encoder(state, new, core::ptr::null_mut()).map_or_else(|errno| errno, |_| 0); }
    // SAFETY: helper callback selection reads only immutable connector graph data and transaction state.
    let encoder = unsafe { selected_encoder(state, connector) }.cast::<u8>();
    if encoder.is_null() { return -LINUX_EINVAL; }
    // SAFETY: selected encoder compatibility is its immutable CRTC mask and target CRTC index.
    let compatible = unsafe { let index = read(new_crtc.cast::<u8>().add(DRM_CRTC_INDEX_OFF).cast::<u32>()); index < 32 && read(encoder.add(DRM_ENCODER_POSSIBLE_CRTCS_OFF).cast::<u32>()) & (1u32 << index) != 0 };
    if !compatible { return -LINUX_EINVAL; }
    // SAFETY: selection pointer is transaction-private connector state.
    if unsafe { read(new.add(DRM_CONNECTOR_STATE_BEST_ENCODER_OFF).cast::<*mut u8>()) } != encoder {
        if let Err(errno) = steal_encoder(state, encoder) { return errno; }
    }
    if let Err(errno) = set_best_encoder(state, new, encoder) { return errno; }
    mark_connectors_changed(state, new_crtc).map_or_else(|errno| errno, |_| 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn routing_selects_the_single_compatible_encoder_and_updates_masks() {
        let _modules = crate::test_serial::claim();
        let mut dev = [0u8; 1]; let mut state = [0u8; 128]; let mut crtc = [0u8; 1656]; let mut encoder = [0u8; 160]; let mut connector = [0u8; 2280];
        let mut old_connector = [0u8; 440]; let mut new_connector = [0u8; 440]; let mut crtc_new = [0u8; 336]; let mut crtc_entries = [0u8; DRM_ATOMIC_CRTC_ENTRY_SIZE]; let mut connector_entries = [0u8; DRM_ATOMIC_CONNECTOR_ENTRY_SIZE];
        // SAFETY: test records reserve each ABI field that the routing primitive reads or writes.
        unsafe {
            write(state.as_mut_ptr().add(DRM_ATOMIC_DEV_OFF).cast::<*mut u8>(), dev.as_mut_ptr()); write(state.as_mut_ptr().add(DRM_ATOMIC_CRTCS_OFF).cast::<*mut u8>(), crtc_entries.as_mut_ptr()); write(state.as_mut_ptr().add(DRM_ATOMIC_NUM_CONNECTOR_OFF).cast::<i32>(), 1); write(state.as_mut_ptr().add(DRM_ATOMIC_CONNECTORS_OFF).cast::<*mut u8>(), connector_entries.as_mut_ptr());
            write(crtc.as_mut_ptr().cast::<*mut u8>(), dev.as_mut_ptr()); write(crtc.as_mut_ptr().add(DRM_CRTC_INDEX_OFF).cast::<u32>(), 0); write(crtc_entries.as_mut_ptr().add(DRM_ATOMIC_ENTRY_NEW_OFF).cast::<*mut u8>(), crtc_new.as_mut_ptr());
            write(encoder.as_mut_ptr().add(DRM_ENCODER_INDEX_OFF).cast::<u32>(), 0); write(encoder.as_mut_ptr().add(DRM_ENCODER_POSSIBLE_CRTCS_OFF).cast::<u32>(), 1); write(connector.as_mut_ptr().add(DRM_CONNECTOR_POSSIBLE_ENCODERS_OFF).cast::<u32>(), 1);
            write(old_connector.as_mut_ptr().cast::<*mut u8>(), connector.as_mut_ptr()); write(new_connector.as_mut_ptr().cast::<*mut u8>(), connector.as_mut_ptr()); write(new_connector.as_mut_ptr().add(DRM_CONNECTOR_STATE_CRTC_OFF).cast::<*mut u8>(), crtc.as_mut_ptr()); write(connector_entries.as_mut_ptr().add(DRM_ATOMIC_ENTRY_NEW_OFF).cast::<*mut u8>(), new_connector.as_mut_ptr());
        }
        DEVICES.lock().push(DeviceAllocation { dev: dev.as_mut_ptr() as usize, base: 0, layout: Layout::new::<u8>(), refs: 1, mode_config: true, objects: Vec::new(), planes: Vec::new(), crtcs: vec![CrtcRecord { ptr: crtc.as_mut_ptr() as usize, name: 0, layout: Layout::new::<u8>() }], encoders: vec![EncoderRecord { ptr: encoder.as_mut_ptr() as usize, name: 0, layout: Layout::new::<u8>() }], connectors: Vec::new(), clients: Vec::new(), vblank: None, primary_master: None, put_pending: false, unplugged: false });
        assert_eq!(update_connector_routing(state.as_mut_ptr().cast(), connector.as_mut_ptr().cast(), old_connector.as_mut_ptr().cast(), new_connector.as_mut_ptr().cast()), 0);
        assert_eq!(unsafe { read(new_connector.as_ptr().add(DRM_CONNECTOR_STATE_BEST_ENCODER_OFF).cast::<*mut u8>()) }, encoder.as_mut_ptr()); assert_eq!(unsafe { read(crtc_new.as_ptr().add(DRM_CRTC_STATE_ENCODER_MASK_OFF).cast::<u32>()) }, 1); assert_ne!(crtc_new[DRM_CRTC_STATE_CONNECTORS_CHANGED_OFF] & DRM_CRTC_STATE_CONNECTORS_CHANGED_BIT, 0);
        DEVICES.lock().clear();
    }
}
