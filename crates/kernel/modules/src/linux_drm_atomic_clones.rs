//! DRM atomic encoder clone-mask validation.

use super::*;

const DRM_ATOMIC_DEV_OFF: usize = 8;
const DRM_ATOMIC_CRTCS_OFF: usize = 40;
const DRM_ATOMIC_CRTC_ENTRY_SIZE: usize = 56;
const DRM_ATOMIC_ENTRY_NEW_OFF: usize = 24;
const DRM_CRTC_INDEX_OFF: usize = 144;
const DRM_CRTC_STATE_ENCODER_MASK_OFF: usize = 20;
const DRM_ENCODER_INDEX_OFF: usize = 68;
const DRM_ENCODER_POSSIBLE_CLONES_OFF: usize = 76;
const LINUX_EINVAL: i32 = 22;

/// Validate that all encoders attached to one CRTC mutually permit cloning. # C: O(N_encoders)
pub(crate) fn check_valid_clones(state: *mut c_void, crtc: *mut c_void) -> i32 {
    if state.is_null() || crtc.is_null() { return -LINUX_EINVAL; }
    let state = state.cast::<u8>();
    // SAFETY: CRTC index is immutable after KMS graph publication.
    let index = unsafe { read(crtc.cast::<u8>().add(DRM_CRTC_INDEX_OFF).cast::<u32>()) as usize };
    // SAFETY: the atomic state owns a fixed entry array matching its retained device graph.
    let (dev, entries) = unsafe { (read(state.add(DRM_ATOMIC_DEV_OFF).cast::<*mut c_void>()), read(state.add(DRM_ATOMIC_CRTCS_OFF).cast::<*mut u8>())) };
    if dev.is_null() || entries.is_null() { return -LINUX_EINVAL; }
    let devices = DEVICES.lock();
    let Some(record) = devices.iter().find(|record| record.dev == dev as usize && record.mode_config && !record.put_pending && !record.unplugged) else { return -LINUX_EINVAL; };
    if index >= record.crtcs.len() { return -LINUX_EINVAL; }
    // SAFETY: checked CRTC index selects this transaction's new state entry.
    let crtc_state = unsafe { read(entries.add(index * DRM_ATOMIC_CRTC_ENTRY_SIZE + DRM_ATOMIC_ENTRY_NEW_OFF).cast::<*mut u8>()) };
    if crtc_state.is_null() { return -LINUX_EINVAL; }
    // SAFETY: encoder membership is transaction-owned CRTC state.
    let active = unsafe { read(crtc_state.add(DRM_CRTC_STATE_ENCODER_MASK_OFF).cast::<u32>()) };
    for entry in &record.encoders {
        let encoder = entry.ptr as *mut u8;
        // SAFETY: registered encoder index and clone mask are immutable graph fields.
        let (encoder_index, clones) = unsafe { (read(encoder.add(DRM_ENCODER_INDEX_OFF).cast::<u32>()), read(encoder.add(DRM_ENCODER_POSSIBLE_CLONES_OFF).cast::<u32>())) };
        if encoder_index >= 32 || active & (1u32 << encoder_index) == 0 || clones == 0 { continue; }
        if active & clones != active { return -LINUX_EINVAL; }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn clone_validation_rejects_a_routed_encoder_without_the_peer_bit() {
        let _modules = crate::test_serial::claim();
        let mut dev = [0u8; 1]; let mut state = [0u8; 128]; let mut crtc = [0u8; 1656]; let mut crtc_state = [0u8; 336]; let mut entries = [0u8; DRM_ATOMIC_CRTC_ENTRY_SIZE]; let mut first = [0u8; 160]; let mut second = [0u8; 160];
        // SAFETY: test storage covers every ABI field read by clone validation.
        unsafe { write(state.as_mut_ptr().add(DRM_ATOMIC_DEV_OFF).cast::<*mut u8>(), dev.as_mut_ptr()); write(state.as_mut_ptr().add(DRM_ATOMIC_CRTCS_OFF).cast::<*mut u8>(), entries.as_mut_ptr()); write(crtc.as_mut_ptr().add(DRM_CRTC_INDEX_OFF).cast::<u32>(), 0); write(entries.as_mut_ptr().add(DRM_ATOMIC_ENTRY_NEW_OFF).cast::<*mut u8>(), crtc_state.as_mut_ptr()); write(crtc_state.as_mut_ptr().add(DRM_CRTC_STATE_ENCODER_MASK_OFF).cast::<u32>(), 3); write(first.as_mut_ptr().add(DRM_ENCODER_INDEX_OFF).cast::<u32>(), 0); write(first.as_mut_ptr().add(DRM_ENCODER_POSSIBLE_CLONES_OFF).cast::<u32>(), 1); write(second.as_mut_ptr().add(DRM_ENCODER_INDEX_OFF).cast::<u32>(), 1); write(second.as_mut_ptr().add(DRM_ENCODER_POSSIBLE_CLONES_OFF).cast::<u32>(), 3); }
        DEVICES.lock().push(DeviceAllocation { dev: dev.as_mut_ptr() as usize, base: 0, layout: Layout::new::<u8>(), refs: 1, mode_config: true, objects: Vec::new(), planes: Vec::new(), crtcs: vec![CrtcRecord { ptr: crtc.as_mut_ptr() as usize, name: 0, layout: Layout::new::<u8>() }], encoders: vec![EncoderRecord { ptr: first.as_mut_ptr() as usize, name: 0, layout: Layout::new::<u8>() }, EncoderRecord { ptr: second.as_mut_ptr() as usize, name: 0, layout: Layout::new::<u8>() }], connectors: Vec::new(), clients: Vec::new(), vblank: None, primary_master: None, put_pending: false, unplugged: false });
        assert_eq!(check_valid_clones(state.as_mut_ptr().cast(), crtc.as_mut_ptr().cast()), -LINUX_EINVAL);
        // SAFETY: widens the fabricated first encoder's clone mask to include the second, reusing the same reserved field.
        unsafe { write(first.as_mut_ptr().add(DRM_ENCODER_POSSIBLE_CLONES_OFF).cast::<u32>(), 3); } assert_eq!(check_valid_clones(state.as_mut_ptr().cast(), crtc.as_mut_ptr().cast()), 0); DEVICES.lock().clear();
    }
}
