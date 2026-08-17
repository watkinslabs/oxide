use super::*;

const NO_EDID_MAX_WIDTH: u32 = 1024;
const NO_EDID_MAX_HEIGHT: u32 = 768;

pub(super) fn export_symbols() { crate::symtab::export("drm_helper_probe_single_connector_modes", drm_helper_probe_single_connector_modes as *const () as usize, false); }

/// Probe, reconcile, and retain the usable mode list for one connector. # C: O(N_modes)
pub(super) extern "C" fn drm_helper_probe_single_connector_modes(connector: *mut c_void, max_width: u32, max_height: u32) -> i32 {
    if connector.is_null() { return 0; }
    mode::mark_live_modes_stale(connector);
    let status = connector::drm_helper_probe_detect(connector, core::ptr::null_mut(), true);
    // SAFETY: connector status is a verified enum field in a live connector object.
    unsafe { write(connector.cast::<u8>().add(connector::DRM_CONNECTOR_STATUS_OFF).cast::<i32>(), status); }
    if status == connector::DRM_CONNECTOR_STATUS_DISCONNECTED { mode::prune_invalid_live_modes(connector, max_width, max_height); return 0; }
    // SAFETY: connector was null-checked on entry and is the same live pointer
    // just written to by the status field above, unchanged since.
    let mut count = unsafe { mode::connector_get_modes(connector) };
    if count == 0 && [connector::DRM_CONNECTOR_STATUS_CONNECTED, connector::DRM_CONNECTOR_STATUS_UNKNOWN].contains(&status) { count = mode::drm_add_modes_noedid(connector, NO_EDID_MAX_WIDTH, NO_EDID_MAX_HEIGHT); }
    if count != 0 { mode::drm_connector_list_update(connector); }
    mode::prune_invalid_live_modes(connector, max_width, max_height);
    if mode::live_mode_count(connector) == 0 { 0 } else { count }
}
