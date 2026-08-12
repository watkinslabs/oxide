use super::*;

pub(super) const DRM_DISPLAY_MODE_SIZE: usize = 120;
pub(super) const DRM_DISPLAY_MODE_HEAD_OFF: usize = 64;
const DRM_DISPLAY_MODE_CLOCK_OFF: usize = 0;
const DRM_DISPLAY_MODE_HDISPLAY_OFF: usize = 4;
const DRM_DISPLAY_MODE_HTOTAL_OFF: usize = 10;
const DRM_DISPLAY_MODE_VDISPLAY_OFF: usize = 14;
const DRM_DISPLAY_MODE_VTOTAL_OFF: usize = 20;
const DRM_DISPLAY_MODE_VSCAN_OFF: usize = 22;
const DRM_DISPLAY_MODE_FLAGS_OFF: usize = 24;
const DRM_DISPLAY_MODE_NAME_OFF: usize = 80;
const DRM_DISPLAY_MODE_NAME_LEN: usize = 32;
const DRM_MODE_FLAG_INTERLACE: u32 = 1 << 4;
const DRM_MODE_FLAG_DBLSCAN: u32 = 1 << 5;
const DRM_DISPLAY_MODE_TYPE_OFF: usize = 62;
const DRM_MODE_TYPE_PREFERRED: u8 = 1 << 3;
pub(super) const DRM_CONNECTOR_MODES_OFF: usize = 168;
pub(super) const DRM_CONNECTOR_PROBED_MODES_OFF: usize = 184;

pub(super) fn export_symbols() {
    crate::symtab::export("drm_mode_create", drm_mode_create as *const () as usize, false);
    crate::symtab::export("drm_mode_destroy", drm_mode_destroy as *const () as usize, false);
    crate::symtab::export("drm_mode_probed_add", drm_mode_probed_add as *const () as usize, false);
    crate::symtab::export("drm_mode_set_name", drm_mode_set_name as *const () as usize, false);
    crate::symtab::export("drm_mode_vrefresh", drm_mode_vrefresh as *const () as usize, false);
    crate::symtab::export("drm_mode_copy", drm_mode_copy as *const () as usize, false);
    crate::symtab::export("drm_mode_init", drm_mode_init as *const () as usize, false);
    crate::symtab::export("drm_mode_duplicate", drm_mode_duplicate as *const () as usize, false);
    crate::symtab::export("drm_add_modes_noedid", drm_add_modes_noedid as *const () as usize, false);
    crate::symtab::export("drm_set_preferred_mode", drm_set_preferred_mode as *const () as usize, false);
    crate::symtab::export("drm_connector_list_update", drm_connector_list_update as *const () as usize, false);
}

pub(super) fn mode_layout() -> Layout { Layout::from_size_align(DRM_DISPLAY_MODE_SIZE, core::mem::align_of::<u64>()).unwrap() }

/// Allocate one zeroed display-mode object. # C: O(1)
pub(super) extern "C" fn drm_mode_create(_dev: *mut c_void) -> *mut c_void {
    // SAFETY: mode_layout names the complete ABI-verified display-mode allocation.
    unsafe { alloc_zeroed(mode_layout()).cast() }
}

/// Destroy one display-mode object and unlink it from a connector when published. # C: O(N_connectors + N_modes)
pub(super) extern "C" fn drm_mode_destroy(_dev: *mut c_void, mode: *mut c_void) {
    if mode.is_null() { return; }
    let mut devices = DEVICES.lock();
    for rec in devices.iter_mut() {
        for connector in rec.connectors.iter_mut() {
            let list = if connector.modes.iter().any(|entry| *entry == mode as usize) { &mut connector.modes } else if connector.probed_modes.iter().any(|entry| *entry == mode as usize) { &mut connector.probed_modes } else { continue; };
            let pos = list.iter().position(|entry| *entry == mode as usize).unwrap(); list.remove(pos);
            // SAFETY: the recorded mode was linked by drm_mode_probed_add and has a valid list node.
            unsafe { unlink_mode(mode); dealloc(mode.cast(), mode_layout()); }
            return;
        }
    }
    drop(devices);
    // SAFETY: callers destroy exactly objects returned by drm_mode_create or compatible core allocations.
    unsafe { dealloc(mode.cast(), mode_layout()); }
}

/// Append a newly probed mode to one connector's pending mode list. # C: O(N_connectors)
pub(super) extern "C" fn drm_mode_probed_add(connector: *mut c_void, mode: *mut c_void) {
    if connector.is_null() || mode.is_null() { return; }
    let dev = unsafe { *(connector.cast::<*mut c_void>()) };
    let mut devices = DEVICES.lock();
    if devices.iter().any(|record| record.connectors.iter().any(|entry| entry.modes.iter().chain(entry.probed_modes.iter()).any(|ptr| *ptr == mode as usize))) { return; }
    let Some(record) = devices.iter_mut().find(|rec| rec.dev == dev as usize && !rec.put_pending && !rec.unplugged) else { return; };
    let Some(entry) = record.connectors.iter_mut().find(|entry| entry.ptr == connector as usize) else { return; };
    // SAFETY: mode is a caller-owned display mode and connector's initialized probed list is serialized here.
    unsafe { link_tail(connector.cast::<u8>().add(DRM_CONNECTOR_PROBED_MODES_OFF), mode.cast::<u8>().add(DRM_DISPLAY_MODE_HEAD_OFF)); }
    entry.probed_modes.push(mode as usize);
}

/// Name a mode from its visible dimensions and interlace flag. # C: O(1)
pub(super) extern "C" fn drm_mode_set_name(mode: *mut c_void) {
    if mode.is_null() { return; }
    // SAFETY: a non-null mode names the ABI-verified fields written below.
    unsafe { let ptr = mode.cast::<u8>(); let out = ptr.add(DRM_DISPLAY_MODE_NAME_OFF); let mut written = decimal(out, *(ptr.add(DRM_DISPLAY_MODE_HDISPLAY_OFF).cast::<u16>()) as u32); *out.add(written) = b'x'; written += 1; written += decimal(out.add(written), *(ptr.add(DRM_DISPLAY_MODE_VDISPLAY_OFF).cast::<u16>()) as u32); if *(ptr.add(DRM_DISPLAY_MODE_FLAGS_OFF).cast::<u32>()) & DRM_MODE_FLAG_INTERLACE != 0 { *out.add(written) = b'i'; written += 1; } *out.add(written.min(DRM_DISPLAY_MODE_NAME_LEN - 1)) = 0; }
}

/// Return a mode's rounded refresh frequency in hertz. # C: O(1)
pub(super) extern "C" fn drm_mode_vrefresh(mode: *const c_void) -> i32 {
    if mode.is_null() { return 0; }
    // SAFETY: a non-null mode names the ABI-verified timing scalar fields.
    unsafe { let ptr = mode.cast::<u8>(); let htotal = *(ptr.add(DRM_DISPLAY_MODE_HTOTAL_OFF).cast::<u16>()) as u64; let vtotal = *(ptr.add(DRM_DISPLAY_MODE_VTOTAL_OFF).cast::<u16>()) as u64; if htotal == 0 || vtotal == 0 { return 0; } let flags = *(ptr.add(DRM_DISPLAY_MODE_FLAGS_OFF).cast::<u32>()); let mut num = 1u64; let mut den = 1u64; if flags & DRM_MODE_FLAG_INTERLACE != 0 { num = 2; } if flags & DRM_MODE_FLAG_DBLSCAN != 0 { den = 2; } let vscan = *(ptr.add(DRM_DISPLAY_MODE_VSCAN_OFF).cast::<u16>()) as u64; if vscan > 1 { let Some(value) = den.checked_mul(vscan) else { return 0; }; den = value; } let clock = *(ptr.add(DRM_DISPLAY_MODE_CLOCK_OFF).cast::<i32>()) as u32 as u64; let Some(num) = clock.checked_mul(num) else { return 0; }; let Some(den) = htotal.checked_mul(vtotal).and_then(|value| value.checked_mul(den)) else { return 0; }; let Some(value) = num.checked_mul(1000) else { return 0; }; ((value + den / 2) / den).min(i32::MAX as u64) as i32 }
}

/// Copy a mode while retaining the destination list linkage. # C: O(1)
pub(super) extern "C" fn drm_mode_copy(dst: *mut c_void, src: *const c_void) {
    if dst.is_null() || src.is_null() { return; }
    // SAFETY: caller supplies complete non-overlapping display-mode objects; linkage is restored after the value copy.
    unsafe { let mut head = [0u8; core::mem::size_of::<*mut c_void>() * 2]; core::ptr::copy_nonoverlapping(dst.cast::<u8>().add(DRM_DISPLAY_MODE_HEAD_OFF), head.as_mut_ptr(), head.len()); core::ptr::copy_nonoverlapping(src.cast::<u8>(), dst.cast::<u8>(), DRM_DISPLAY_MODE_SIZE); core::ptr::copy_nonoverlapping(head.as_ptr(), dst.cast::<u8>().add(DRM_DISPLAY_MODE_HEAD_OFF), head.len()); }
}

/// Initialize a mode from another value with an empty list linkage. # C: O(1)
pub(super) extern "C" fn drm_mode_init(dst: *mut c_void, src: *const c_void) {
    if dst.is_null() || src.is_null() { return; }
    // SAFETY: caller supplies complete non-overlapping display-mode objects; the destination is cleared before copying.
    unsafe { core::ptr::write_bytes(dst.cast::<u8>(), 0, DRM_DISPLAY_MODE_SIZE); drm_mode_copy(dst, src); }
}

/// Allocate and copy one display mode. # C: O(1)
pub(super) extern "C" fn drm_mode_duplicate(dev: *mut c_void, src: *const c_void) -> *mut c_void {
    if src.is_null() { return core::ptr::null_mut(); }
    let mode = drm_mode_create(dev); if mode.is_null() { return mode; } drm_mode_copy(mode, src); mode
}

/// Add every standard fallback mode within the requested display bounds. # C: O(N_dmt)
pub(super) extern "C" fn drm_add_modes_noedid(connector: *mut c_void, max_h: u32, max_v: u32) -> i32 {
    if connector.is_null() { return 0; } let dev = unsafe { *(connector.cast::<*mut c_void>()) };
    if !DEVICES.lock().iter().any(|record| record.dev == dev as usize && record.connectors.iter().any(|entry| entry.ptr == connector as usize)) { return 0; }
    let mut count = 0;
    for &(clock,h,hs,he,ht,sk,v,vs,ve,vt,scan,flags) in &dmt::DMT { if max_h != 0 && max_v != 0 && (h as u32 > max_h || v as u32 > max_v) { continue; } let mode = drm_mode_create(dev); if mode.is_null() { continue; }
        // SAFETY: mode is a newly allocated complete display-mode object; every written field is ABI-verified.
        unsafe { let ptr = mode.cast::<u8>(); write(ptr.add(DRM_DISPLAY_MODE_CLOCK_OFF).cast::<i32>(), clock); write(ptr.add(DRM_DISPLAY_MODE_HDISPLAY_OFF).cast::<u16>(), h); write(ptr.add(6).cast::<u16>(), hs); write(ptr.add(8).cast::<u16>(), he); write(ptr.add(DRM_DISPLAY_MODE_HTOTAL_OFF).cast::<u16>(), ht); write(ptr.add(12).cast::<u16>(), sk); write(ptr.add(DRM_DISPLAY_MODE_VDISPLAY_OFF).cast::<u16>(), v); write(ptr.add(16).cast::<u16>(), vs); write(ptr.add(18).cast::<u16>(), ve); write(ptr.add(DRM_DISPLAY_MODE_VTOTAL_OFF).cast::<u16>(), vt); write(ptr.add(DRM_DISPLAY_MODE_VSCAN_OFF).cast::<u16>(), scan); write(ptr.add(DRM_DISPLAY_MODE_FLAGS_OFF).cast::<u32>(), flags); write(ptr.add(62), 1 << 6); } drm_mode_set_name(mode); drm_mode_probed_add(connector, mode); count += 1; }
    count
}

/// Mark every pending mode matching the requested visible resolution preferred. # C: O(N_modes)
pub(super) extern "C" fn drm_set_preferred_mode(connector: *mut c_void, hpref: i32, vpref: i32) {
    if connector.is_null() { return; } let dev = unsafe { *(connector.cast::<*mut c_void>()) }; let devices = DEVICES.lock();
    let Some(record) = devices.iter().find(|record| record.dev == dev as usize) else { return; }; let Some(entry) = record.connectors.iter().find(|entry| entry.ptr == connector as usize) else { return; };
    for &mode in &entry.modes { unsafe { let ptr = mode as *mut u8; if *(ptr.add(DRM_DISPLAY_MODE_HDISPLAY_OFF).cast::<u16>()) as i32 == hpref && *(ptr.add(DRM_DISPLAY_MODE_VDISPLAY_OFF).cast::<u16>()) as i32 == vpref { let ty = ptr.add(DRM_DISPLAY_MODE_TYPE_OFF); write(ty, *ty | DRM_MODE_TYPE_PREFERRED); } } }
}

/// Move new probed modes into the connector's live mode list. # C: O(N_probed * N_modes)
pub(super) extern "C" fn drm_connector_list_update(connector: *mut c_void) {
    if connector.is_null() { return; } let dev = unsafe { *(connector.cast::<*mut c_void>()) }; let mut devices = DEVICES.lock(); let Some(record) = devices.iter_mut().find(|record| record.dev == dev as usize) else { return; }; let Some(entry) = record.connectors.iter_mut().find(|entry| entry.ptr == connector as usize) else { return; };
    let probed = core::mem::take(&mut entry.probed_modes); for mode in probed { if entry.modes.iter().any(|&old| unsafe { same_timing(old as *const u8, mode as *const u8) }) { unsafe { unlink_mode(mode as *mut c_void); dealloc(mode as *mut u8, mode_layout()); } } else { unsafe { unlink_mode(mode as *mut c_void); link_tail(connector.cast::<u8>().add(DRM_CONNECTOR_MODES_OFF), (mode as *mut u8).add(DRM_DISPLAY_MODE_HEAD_OFF)); } entry.modes.push(mode); } }
}

pub(super) unsafe fn connector_get_modes(connector: *mut c_void) -> i32 {
    const HELPER_PRIVATE_OFF: usize = 2248;
    // SAFETY: helper_private names a live helper vtable whose first member is the get_modes callback.
    unsafe { let table = *(connector.cast::<u8>().add(HELPER_PRIVATE_OFF).cast::<*const c_void>()); if table.is_null() { return 0; } let callback = table.cast::<extern "C" fn(*mut c_void) -> i32>().read(); let count = callback(connector); if count < 0 { 0 } else { count } }
}

unsafe fn same_timing(left: *const u8, right: *const u8) -> bool {
    // SAFETY: both pointers are tracked complete display-mode allocations.
    unsafe { core::ptr::read_unaligned(left.cast::<i32>()) == core::ptr::read_unaligned(right.cast::<i32>()) && core::ptr::read_unaligned(left.add(DRM_DISPLAY_MODE_HDISPLAY_OFF).cast::<u16>()) == core::ptr::read_unaligned(right.add(DRM_DISPLAY_MODE_HDISPLAY_OFF).cast::<u16>()) && core::ptr::read_unaligned(left.add(DRM_DISPLAY_MODE_VDISPLAY_OFF).cast::<u16>()) == core::ptr::read_unaligned(right.add(DRM_DISPLAY_MODE_VDISPLAY_OFF).cast::<u16>()) && core::ptr::read_unaligned(left.add(DRM_DISPLAY_MODE_HTOTAL_OFF).cast::<u16>()) == core::ptr::read_unaligned(right.add(DRM_DISPLAY_MODE_HTOTAL_OFF).cast::<u16>()) && core::ptr::read_unaligned(left.add(DRM_DISPLAY_MODE_VTOTAL_OFF).cast::<u16>()) == core::ptr::read_unaligned(right.add(DRM_DISPLAY_MODE_VTOTAL_OFF).cast::<u16>()) }
}

unsafe fn decimal(out: *mut u8, mut value: u32) -> usize {
    // SAFETY: caller supplies at least five writable bytes in the fixed display-mode name field.
    unsafe { let mut digits = [0u8; 5]; let mut count = 0; loop { digits[count] = b'0' + (value % 10) as u8; count += 1; value /= 10; if value == 0 { break; } } for index in 0..count { *out.add(index) = digits[count - index - 1]; } count }
}

pub(super) unsafe fn initialize_mode_lists(connector: *mut u8) {
    // SAFETY: connector points at the ABI-sized connector object and these are its two list heads.
    unsafe { initialize_list(connector.add(DRM_CONNECTOR_MODES_OFF)); initialize_list(connector.add(DRM_CONNECTOR_PROBED_MODES_OFF)); }
}

unsafe fn initialize_list(head: *mut u8) {
    // SAFETY: head is an aligned list_head field in a live connector object.
    unsafe { write(head.cast::<*mut c_void>(), head.cast()); write(head.cast::<*mut c_void>().add(1), head.cast()); }
}

unsafe fn link_tail(head: *mut u8, node: *mut u8) {
    // SAFETY: head is initialized and node is an unlinked display-mode list node.
    unsafe { let previous = *(head.cast::<*mut c_void>().add(1)); write(node.cast::<*mut c_void>(), head.cast()); write(node.cast::<*mut c_void>().add(1), previous); write(previous.cast::<*mut c_void>(), node.cast()); write(head.cast::<*mut c_void>().add(1), node.cast()); }
}

pub(super) unsafe fn unlink_mode(mode: *mut c_void) {
    // SAFETY: mode is tracked as linked by drm_mode_probed_add, so its list node has live neighbours.
    unsafe { let node = mode.cast::<u8>().add(DRM_DISPLAY_MODE_HEAD_OFF).cast::<*mut c_void>(); let next = *node; let previous = *node.add(1); write(previous.cast::<*mut c_void>(), next); write(next.cast::<*mut c_void>().add(1), previous); }
}
