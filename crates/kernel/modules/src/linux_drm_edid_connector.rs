//! Linux DRM connector EDID-property ownership and base detailed timings.

use super::*;

const LINUX_EINVAL: i32 = 22;
const EDID_BLOCK: usize = 128;
const DETAILED_START: usize = 54;
const DETAILED_SIZE: usize = 18;
const DETAILED_COUNT: usize = 4;
// Verified against the Fedora 6.19.14 BTF used by the audited Bochs module.
const DRM_CONNECTOR_EDID_BLOB_OFF: usize = 424;
const DRM_CONNECTOR_EPOCH_OFF: usize = 1728;
const DRM_PROPERTY_BLOB_HEADER: usize = 88;
const DRM_PROPERTY_BLOB_LENGTH_OFF: usize = 72;
const DRM_PROPERTY_BLOB_DATA_OFF: usize = 80;

pub(super) fn export_symbols() {
    crate::symtab::export("drm_edid_connector_update", drm_edid_connector_update as *const () as usize, false);
    crate::symtab::export("drm_edid_connector_add_modes", drm_edid_connector_add_modes as *const () as usize, false);
}

/// Replace the connector's EDID property with an owned Linux-shaped blob. # C: O(EDID_size)
pub(super) extern "C" fn drm_edid_connector_update(connector: *mut c_void, edid: *const c_void) -> i32 {
    if connector.is_null() { return -LINUX_EINVAL; }
    let replacement = if edid.is_null() { core::ptr::null_mut() } else { blob_from_edid(edid) };
    if !edid.is_null() && replacement.is_null() { return -LINUX_EINVAL; }
    // SAFETY: the connector is a complete external ABI object; its EDID property slot is BTF-verified.
    let slot = unsafe { connector.cast::<u8>().add(DRM_CONNECTOR_EDID_BLOB_OFF).cast::<*mut u8>() };
    // SAFETY: slot was just computed from the same connector object above and
    // points at its BTF-verified EDID blob pointer field.
    let old = unsafe { read(slot) };
    if !old.is_null() && !replacement.is_null() && !blob_equal(old, replacement) {
        // SAFETY: epoch_counter is a BTF-verified u64 field, changed only with this property replacement.
        unsafe { let epoch = connector.cast::<u8>().add(DRM_CONNECTOR_EPOCH_OFF).cast::<u64>(); write(epoch, read(epoch).wrapping_add(1)); }
    }
    // SAFETY: publication replaces the sole connector-owned blob after its complete allocation is initialized.
    unsafe { write(slot, replacement); }
    blob_free(old);
    0
}

/// Publish all valid base-block detailed timings from the current EDID blob. # C: O(4)
pub(super) extern "C" fn drm_edid_connector_add_modes(connector: *mut c_void) -> i32 {
    if connector.is_null() { return 0; }
    // SAFETY: connector EDID slot is the BTF-verified property-blob pointer initialized by update above.
    let blob = unsafe { read(connector.cast::<u8>().add(DRM_CONNECTOR_EDID_BLOB_OFF).cast::<*mut u8>()) };
    if blob.is_null() { return 0; }
    // SAFETY: blob is the connector's own property blob, allocated by blob_from_edid
    // with a DRM_PROPERTY_BLOB_HEADER-sized layout, so its length/data fields are populated.
    let (length, raw) = unsafe { (read(blob.add(DRM_PROPERTY_BLOB_LENGTH_OFF).cast::<usize>()), blob.add(DRM_PROPERTY_BLOB_DATA_OFF)) };
    if length < EDID_BLOCK { return 0; }
    let mut count = 0;
    for index in 0..DETAILED_COUNT {
        // SAFETY: length was just checked >= EDID_BLOCK (128); the highest detailed
        // descriptor read (index 3) ends at DETAILED_START + 4*DETAILED_SIZE = 126, in bounds.
        let timing = unsafe { core::slice::from_raw_parts(raw.add(DETAILED_START + index * DETAILED_SIZE), DETAILED_SIZE) };
        if add_detailed_mode(connector, timing, index == 0) { count += 1; }
    }
    count
}

/// Drop the private EDID property blob during connector teardown. # C: O(1)
pub(super) fn release_connector(connector: *mut c_void) {
    if connector.is_null() { return; }
    // SAFETY: connector cleanup owns this final property slot and clears it before the object is reused.
    let slot = unsafe { connector.cast::<u8>().add(DRM_CONNECTOR_EDID_BLOB_OFF).cast::<*mut u8>() };
    // SAFETY: slot is this connector's own EDID blob field, computed just above.
    let blob = unsafe { read(slot) };
    // SAFETY: same slot; clearing it before freeing blob prevents a second
    // release from observing the about-to-be-freed pointer.
    unsafe { write(slot, core::ptr::null_mut()); }
    blob_free(blob);
}

fn blob_from_edid(edid: *const c_void) -> *mut u8 {
    let raw = edid_owner::drm_edid_raw(edid);
    if raw.is_null() { return core::ptr::null_mut(); }
    // SAFETY: drm_edid_raw returns non-null only when the owner holds at least
    // a full EDID_LENGTH=128-byte base block, so byte 126 (extension count) is in bounds.
    let blocks = unsafe { *raw.add(126) as usize + 1 };
    let Some(length) = blocks.checked_mul(EDID_BLOCK) else { return core::ptr::null_mut(); };
    let Some(total) = DRM_PROPERTY_BLOB_HEADER.checked_add(length) else { return core::ptr::null_mut(); };
    let Some(layout) = Layout::from_size_align(total, core::mem::align_of::<u64>()).ok() else { return core::ptr::null_mut(); };
    // SAFETY: layout was just computed above with a non-zero total size and valid alignment.
    let blob = unsafe { alloc_zeroed(layout) };
    if blob.is_null() { return core::ptr::null_mut(); }
    // SAFETY: raw is validated by drm_edid_raw for all extension blocks, and blob reserves its exact payload extent.
    unsafe { write(blob.add(DRM_PROPERTY_BLOB_LENGTH_OFF).cast::<usize>(), length); core::ptr::copy_nonoverlapping(raw, blob.add(DRM_PROPERTY_BLOB_DATA_OFF), length); }
    blob
}

fn blob_equal(left: *const u8, right: *const u8) -> bool {
    // SAFETY: both pointers are property blobs created by blob_from_edid and retain their immutable extents.
    let (left_len, right_len) = unsafe { (read(left.add(DRM_PROPERTY_BLOB_LENGTH_OFF).cast::<usize>()), read(right.add(DRM_PROPERTY_BLOB_LENGTH_OFF).cast::<usize>())) };
    // SAFETY: left_len/right_len are each blob's own stored length, matching the
    // payload extent blob_from_edid allocated for that blob at DRM_PROPERTY_BLOB_DATA_OFF.
    left_len == right_len && unsafe { core::slice::from_raw_parts(left.add(DRM_PROPERTY_BLOB_DATA_OFF), left_len) == core::slice::from_raw_parts(right.add(DRM_PROPERTY_BLOB_DATA_OFF), right_len) }
}

fn blob_free(blob: *mut u8) {
    if blob.is_null() { return; }
    // SAFETY: blob was allocated by blob_from_edid with the stored payload length and no other owner remains.
    let length = unsafe { read(blob.add(DRM_PROPERTY_BLOB_LENGTH_OFF).cast::<usize>()) };
    // SAFETY: total/layout are recomputed here from blob's own stored length,
    // reproducing the exact layout blob_from_edid allocated it with.
    if let Some(total) = DRM_PROPERTY_BLOB_HEADER.checked_add(length) { if let Ok(layout) = Layout::from_size_align(total, core::mem::align_of::<u64>()) { unsafe { dealloc(blob, layout); } } }
}

fn add_detailed_mode(connector: *mut c_void, timing: &[u8], preferred: bool) -> bool {
    let pixel_clock = u16::from_le_bytes([timing[0], timing[1]]) as i32 * 10;
    if pixel_clock == 0 { return false; }
    let hdisplay = timing[2] as u16 | ((timing[4] as u16 & 0xf0) << 4);
    let hblank = timing[3] as u16 | ((timing[4] as u16 & 0x0f) << 8);
    let vdisplay = timing[5] as u16 | ((timing[7] as u16 & 0xf0) << 4);
    let vblank = timing[6] as u16 | ((timing[7] as u16 & 0x0f) << 8);
    let hsync_offset = timing[8] as u16 | ((timing[11] as u16 & 0xc0) << 2);
    let hsync_width = timing[9] as u16 | ((timing[11] as u16 & 0x30) << 4);
    let vsync_offset = (timing[10] >> 4) as u16 | ((timing[11] as u16 & 0x0c) << 2);
    let vsync_width = (timing[10] & 0x0f) as u16 | ((timing[11] as u16 & 0x03) << 4);
    let Some(hsync_start) = hdisplay.checked_add(hsync_offset) else { return false; };
    let Some(hsync_end) = hsync_start.checked_add(hsync_width) else { return false; };
    let Some(htotal) = hdisplay.checked_add(hblank) else { return false; };
    let Some(vsync_start) = vdisplay.checked_add(vsync_offset) else { return false; };
    let Some(vsync_end) = vsync_start.checked_add(vsync_width) else { return false; };
    let Some(vtotal) = vdisplay.checked_add(vblank) else { return false; };
    if hdisplay == 0 || vdisplay == 0 || hsync_start > hsync_end || hsync_end > htotal || vsync_start > vsync_end || vsync_end > vtotal { return false; }
    let mut flags = 0u32;
    if timing[17] & 0x80 != 0 { flags |= 1 << 4; }
    if timing[17] & 0x18 == 0x18 { if timing[17] & 0x02 != 0 { flags |= 1; } else { flags |= 1 << 1; } if timing[17] & 0x04 != 0 { flags |= 1 << 2; } else { flags |= 1 << 3; } }
    mode::edid_detailed_add(connector, pixel_clock, hdisplay, hsync_start, hsync_end, htotal, vdisplay, vsync_start, vsync_end, vtotal, flags, preferred)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_a_non_timing_descriptor() { assert!(!add_detailed_mode(core::ptr::null_mut(), &[0; DETAILED_SIZE], true)); }

    #[test]
    fn update_replaces_the_exact_blob_and_tracks_a_real_change() {
        let mut connector = [0u64; 300]; let mut first = [0u8; EDID_BLOCK]; let mut second = [0u8; EDID_BLOCK];
        first[..8].copy_from_slice(&[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0]); second[..8].copy_from_slice(&[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0]); first[18] = 1; second[18] = 1; second[20] = 1;
        let one = edid_owner::drm_edid_alloc(first.as_ptr().cast(), first.len()); let two = edid_owner::drm_edid_alloc(second.as_ptr().cast(), second.len()); assert!(!one.is_null() && !two.is_null());
        // SAFETY: connector is a local stack array sized past both fixed offsets read
        // below; blob is the property allocation drm_edid_connector_update just published.
        assert_eq!(drm_edid_connector_update(connector.as_mut_ptr().cast(), one), 0); let blob = unsafe { read(connector.as_ptr().cast::<u8>().add(DRM_CONNECTOR_EDID_BLOB_OFF).cast::<*mut u8>()) }; assert!(!blob.is_null()); assert_eq!(unsafe { read(blob.add(DRM_PROPERTY_BLOB_LENGTH_OFF).cast::<usize>()) }, EDID_BLOCK);
        // SAFETY: same local connector array; epoch_counter was just bumped by the
        // second update call since the two blobs' contents differ.
        assert_eq!(drm_edid_connector_update(connector.as_mut_ptr().cast(), two), 0); assert_eq!(unsafe { read(connector.as_ptr().cast::<u8>().add(DRM_CONNECTOR_EPOCH_OFF).cast::<u64>()) }, 1);
        // SAFETY: same local connector array; the null-edid update clears the blob slot.
        assert_eq!(drm_edid_connector_update(connector.as_mut_ptr().cast(), core::ptr::null()), 0); assert!(unsafe { read(connector.as_ptr().cast::<u8>().add(DRM_CONNECTOR_EDID_BLOB_OFF).cast::<*mut u8>()) }.is_null()); edid_owner::drm_edid_free(one); edid_owner::drm_edid_free(two);
    }

    #[test]
    fn connector_edid_entry_points_are_module_exports() { let _modules = crate::test_serial::claim(); export_symbols(); assert!(crate::symtab::is_exported("drm_edid_connector_update")); assert!(crate::symtab::is_exported("drm_edid_connector_add_modes")); }
}
