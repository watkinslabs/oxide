// D5a read-only modeset info ioctls. Real CRTC/connector/encoder/
// plane objects built from the registered DrmDriver (virtio-gpu's
// enabled scanouts). No scanout change — pure information.
//
// All user copies bounds-check the pointer (< hal::USER_VA_END) and
// use volatile writes through the caller's address space at CPL=0.

use alloc::sync::Arc;
use alloc::vec::Vec;
use syscall::errno::Errno;

use crate::{
    DrmDriver, DrmModeCardRes, DrmModeCrtc, DrmModeGetConnector,
    DrmModeGetEncoder, DrmModeGetPlane, DrmModeGetPlaneRes, DrmModeModeinfo,
    crtc_idx_of, connector_idx_of, encoder_idx_of, plane_idx_of,
    DRM_MODE_SUBPIXEL_UNKNOWN, DRM_MODE_CONNECTOR_VIRTUAL,
    DRM_FORMAT_XRGB8888, DRM_FORMAT_ARGB8888,
};

fn einval() -> i64 { -(Errno::Einval.as_i32() as i64) }

/// True iff `[ptr, ptr+len)` is a usable user range. # C: O(1)
fn user_ok(ptr: u64, len: u64) -> bool {
    ptr != 0 && ptr < hal::USER_VA_END && ptr.checked_add(len).is_some_and(|end| end <= hal::USER_VA_END)
}

/// Copy a `u32` id array out to a user pointer, capped at `cap`
/// elements. # C: O(min(ids.len, cap))
fn write_ids(ptr: u64, ids: &[u32], cap: u32) {
    let n = (ids.len() as u32).min(cap) as usize;
    if !user_ok(ptr, (n as u64) * 4) { return; }
    // SAFETY: range [ptr, ptr+n*4) validated < USER_VA_END; aligned-by-4 u32 stores through caller's AS at CPL=0.
    unsafe {
        for i in 0..n {
            core::ptr::write_volatile((ptr + (i as u64) * 4) as *mut u32, ids[i]);
        }
    }
}

/// `MODE_GETRESOURCES` — Linux 2-pass: write back real counts +
/// min/max dims always; copy each id array out only when the user
/// count is >= real count and the ptr is non-null. # C: O(objects)
pub fn get_resources(card: &Arc<dyn DrmDriver>, arg: u64) -> i64 {
    // SAFETY: arg validated < USER_VA_END by caller; drm_mode_card_res is 64 B; aligned struct read.
    let res: DrmModeCardRes = unsafe { core::ptr::read_volatile(arg as *const DrmModeCardRes) };
    let crtcs = card.crtc_ids();
    let conns = card.connector_ids();
    let encs  = card.encoder_ids();
    let (cf, cc, cn, ce) = card.resource_counts();
    let (min_w, max_w, min_h, max_h) = card.dim_bounds();
    // fbs: v1 has none until ADDFB (D5b); honor the count field only.
    if res.crtc_id_ptr != 0 && res.count_crtcs >= cc {
        write_ids(res.crtc_id_ptr, &crtcs, res.count_crtcs);
    }
    if res.connector_id_ptr != 0 && res.count_connectors >= cn {
        write_ids(res.connector_id_ptr, &conns, res.count_connectors);
    }
    if res.encoder_id_ptr != 0 && res.count_encoders >= ce {
        write_ids(res.encoder_id_ptr, &encs, res.count_encoders);
    }
    let _ = cf;
    // SAFETY: arg validated; struct is 64 B; aligned u32 stores at the documented offsets.
    unsafe {
        core::ptr::write_volatile((arg + 32) as *mut u32, 0); // count_fbs
        core::ptr::write_volatile((arg + 36) as *mut u32, cc);
        core::ptr::write_volatile((arg + 40) as *mut u32, cn);
        core::ptr::write_volatile((arg + 44) as *mut u32, ce);
        core::ptr::write_volatile((arg + 48) as *mut u32, min_w);
        core::ptr::write_volatile((arg + 52) as *mut u32, max_w);
        core::ptr::write_volatile((arg + 56) as *mut u32, min_h);
        core::ptr::write_volatile((arg + 60) as *mut u32, max_h);
    }
    0
}

/// `MODE_GETCRTC` — validate crtc_id, fill `drm_mode_crtc`.
/// # C: O(1)
pub fn get_crtc(card: &Arc<dyn DrmDriver>, arg: u64) -> i64 {
    // SAFETY: arg validated < USER_VA_END; drm_mode_crtc is 104 B; aligned struct read.
    let mut c: DrmModeCrtc = unsafe { core::ptr::read_volatile(arg as *const DrmModeCrtc) };
    let count = card.crtc_ids().len();
    let idx = match crtc_idx_of(c.crtc_id, count) { Some(i) => i, None => return einval() };
    let info = match card.crtc_info(idx) { Some(i) => i, None => return einval() };
    c.fb_id      = info.fb_id;
    c.x          = info.x;
    c.y          = info.y;
    c.gamma_size = info.gamma_size;
    c.mode_valid = info.mode_valid;
    c.mode       = info.mode;
    c.count_connectors = 0;
    // SAFETY: arg validated; struct is 104 B; aligned struct write through caller's AS at CPL=0.
    unsafe { core::ptr::write_volatile(arg as *mut DrmModeCrtc, c); }
    0
}

/// `MODE_GETCONNECTOR` — validate connector_id, fill facts + copy
/// the (single) mode list when the user passes room. 2-pass on
/// count_modes/modes_ptr. # C: O(1)
pub fn get_connector(card: &Arc<dyn DrmDriver>, arg: u64) -> i64 {
    // SAFETY: arg validated < USER_VA_END; drm_mode_get_connector is 80 B; aligned struct read.
    let mut g: DrmModeGetConnector = unsafe { core::ptr::read_volatile(arg as *const DrmModeGetConnector) };
    let count = card.connector_ids().len();
    let idx = match connector_idx_of(g.connector_id, count) { Some(i) => i, None => return einval() };
    let info = match card.connector_info(idx) { Some(i) => i, None => return einval() };
    let mode = card.mode_for(idx);
    // Copy the mode list out only if the user advertised room.
    if g.modes_ptr != 0 && g.count_modes >= 1 {
        if user_ok(g.modes_ptr, core::mem::size_of::<DrmModeModeinfo>() as u64) {
            // SAFETY: modes_ptr range validated; one drm_mode_modeinfo (68 B) write through caller's AS at CPL=0.
            unsafe { core::ptr::write_volatile(g.modes_ptr as *mut DrmModeModeinfo, mode); }
        }
    }
    // We expose one encoder per connector; copy its id when asked.
    if g.encoders_ptr != 0 && g.count_encoders >= 1 {
        write_ids(g.encoders_ptr, &[info.encoder_id], 1);
    }
    g.count_modes      = info.mode_count;
    g.count_props      = 0;
    g.count_encoders   = 1;
    g.encoder_id       = info.encoder_id;
    g.connector_type   = info.connector_type;
    g.connector_type_id = (idx as u32) + 1;
    g.connection       = info.connection;
    g.mm_width         = info.mm_width;
    g.mm_height        = info.mm_height;
    g.subpixel         = DRM_MODE_SUBPIXEL_UNKNOWN;
    let _ = DRM_MODE_CONNECTOR_VIRTUAL;
    // SAFETY: arg validated; struct is 80 B; aligned struct write through caller's AS at CPL=0.
    unsafe { core::ptr::write_volatile(arg as *mut DrmModeGetConnector, g); }
    0
}

/// `MODE_GETENCODER` — validate encoder_id, fill `drm_mode_get_encoder`.
/// # C: O(1)
pub fn get_encoder(card: &Arc<dyn DrmDriver>, arg: u64) -> i64 {
    // SAFETY: arg validated < USER_VA_END; drm_mode_get_encoder is 20 B; aligned struct read.
    let mut e: DrmModeGetEncoder = unsafe { core::ptr::read_volatile(arg as *const DrmModeGetEncoder) };
    let count = card.encoder_ids().len();
    let idx = match encoder_idx_of(e.encoder_id, count) { Some(i) => i, None => return einval() };
    let info = match card.encoder_info(idx) { Some(i) => i, None => return einval() };
    e.encoder_type    = info.encoder_type;
    e.crtc_id         = info.crtc_id;
    e.possible_crtcs  = info.possible_crtcs;
    e.possible_clones = info.possible_clones;
    // SAFETY: arg validated; struct is 20 B; aligned struct write through caller's AS at CPL=0.
    unsafe { core::ptr::write_volatile(arg as *mut DrmModeGetEncoder, e); }
    0
}

/// `MODE_GETPLANERESOURCES` — 2-pass plane id list (one primary
/// plane per CRTC). # C: O(planes)
pub fn get_plane_res(card: &Arc<dyn DrmDriver>, arg: u64) -> i64 {
    // SAFETY: arg validated < USER_VA_END; drm_mode_get_plane_res is 16 B; aligned struct read.
    let r: DrmModeGetPlaneRes = unsafe { core::ptr::read_volatile(arg as *const DrmModeGetPlaneRes) };
    let planes = card.plane_ids();
    if r.plane_id_ptr != 0 && r.count_planes >= planes.len() as u32 {
        write_ids(r.plane_id_ptr, &planes, r.count_planes);
    }
    // SAFETY: arg validated; struct is 16 B; count_planes at +8.
    unsafe { core::ptr::write_volatile((arg + 8) as *mut u32, planes.len() as u32); }
    0
}

/// `MODE_GETPLANE` — validate plane_id, fill `drm_mode_get_plane`
/// + the XRGB8888/ARGB8888 format list. # C: O(1)
pub fn get_plane(card: &Arc<dyn DrmDriver>, arg: u64) -> i64 {
    // SAFETY: arg validated < USER_VA_END; drm_mode_get_plane is 32 B; aligned struct read.
    let mut p: DrmModeGetPlane = unsafe { core::ptr::read_volatile(arg as *const DrmModeGetPlane) };
    let count = card.plane_ids().len();
    let idx = match plane_idx_of(p.plane_id, count) { Some(i) => i, None => return einval() };
    let info = match card.plane_info(idx) { Some(i) => i, None => return einval() };
    let fmts: [u32; 2] = [DRM_FORMAT_XRGB8888, DRM_FORMAT_ARGB8888];
    if p.format_type_ptr != 0 && p.count_format_types >= fmts.len() as u32 {
        write_ids(p.format_type_ptr, &fmts, p.count_format_types);
    }
    p.crtc_id            = info.crtc_id;
    p.fb_id              = info.fb_id;
    p.possible_crtcs     = info.possible_crtcs;
    p.gamma_size         = 0;
    p.count_format_types = fmts.len() as u32;
    // SAFETY: arg validated; struct is 32 B; aligned struct write through caller's AS at CPL=0.
    unsafe { core::ptr::write_volatile(arg as *mut DrmModeGetPlane, p); }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConnectorInfo, CrtcInfo, EncoderInfo, PlaneInfo,
                crtc_id_for, connector_id_for, encoder_id_for, plane_id_for,
                mode_from_rect, DRM_MODE_CONNECTED, DRM_MODE_ENCODER_VIRTUAL};

    // A 1-scanout 800x600 driver to validate idx-mapping/EINVAL logic
    // (the actual user-pointer copies need a boot).
    struct OneScanout;
    impl DrmDriver for OneScanout {
        fn name(&self) -> &'static str { "t" }
        fn version(&self) -> (u32, u32, u32) { (0, 1, 0) }
        fn date(&self) -> &'static str { "20260611" }
        fn desc(&self) -> &'static str { "t" }
        fn unique(&self) -> &str { "t" }
        fn resource_counts(&self) -> (u32, u32, u32, u32) { (0, 1, 1, 1) }
        fn dim_bounds(&self) -> (u32, u32, u32, u32) { (1, 4096, 1, 2160) }
        fn cap(&self, c: u64) -> u64 { crate::default_cap(c) }
        fn crtc_ids(&self) -> Vec<u32> { alloc::vec![crtc_id_for(0)] }
        fn connector_ids(&self) -> Vec<u32> { alloc::vec![connector_id_for(0)] }
        fn encoder_ids(&self) -> Vec<u32> { alloc::vec![encoder_id_for(0)] }
        fn plane_ids(&self) -> Vec<u32> { alloc::vec![plane_id_for(0)] }
        fn mode_for(&self, _i: usize) -> DrmModeModeinfo { mode_from_rect(800, 600) }
        fn connector_info(&self, i: usize) -> Option<ConnectorInfo> {
            if i != 0 { return None; }
            Some(ConnectorInfo { connection: DRM_MODE_CONNECTED,
                connector_type: DRM_MODE_CONNECTOR_VIRTUAL, encoder_id: encoder_id_for(0),
                mm_width: 211, mm_height: 158, mode_count: 1 })
        }
        fn crtc_info(&self, i: usize) -> Option<CrtcInfo> {
            if i != 0 { return None; }
            Some(CrtcInfo { mode_valid: 1, fb_id: 0, x: 0, y: 0, gamma_size: 256,
                mode: mode_from_rect(800, 600) })
        }
        fn encoder_info(&self, i: usize) -> Option<EncoderInfo> {
            if i != 0 { return None; }
            Some(EncoderInfo { encoder_type: DRM_MODE_ENCODER_VIRTUAL, crtc_id: crtc_id_for(0),
                possible_crtcs: 1, possible_clones: 0 })
        }
        fn plane_info(&self, i: usize) -> Option<PlaneInfo> {
            if i != 0 { return None; }
            Some(PlaneInfo { crtc_id: crtc_id_for(0), fb_id: 0, possible_crtcs: 1 })
        }
    }

    fn card() -> Arc<dyn DrmDriver> { Arc::new(OneScanout) }

    #[test]
    fn idx_validation_rejects_unknown() {
        let c = card();
        assert_eq!(crtc_idx_of(0, c.crtc_ids().len()), None);
        assert_eq!(crtc_idx_of(crtc_id_for(0), 1), Some(0));
        assert_eq!(connector_idx_of(connector_id_for(0), 1), Some(0));
        assert_eq!(encoder_idx_of(encoder_id_for(0), 1), Some(0));
        assert_eq!(plane_idx_of(plane_id_for(0), 1), Some(0));
        // wrong namespaces
        assert_eq!(connector_idx_of(crtc_id_for(0), 1), None);
        assert_eq!(plane_idx_of(encoder_id_for(0), 1), None);
    }

    #[test]
    fn write_ids_caps_at_user_count() {
        // cap below available → nothing copied (cap path is bounds-checked,
        // and user_ok rejects a null/0 ptr, so this just must not panic).
        write_ids(0, &[1, 2, 3], 0);
    }

    #[test]
    fn info_present_for_first_object() {
        let c = card();
        assert!(c.crtc_info(0).is_some());
        assert!(c.connector_info(0).is_some());
        assert!(c.encoder_info(0).is_some());
        assert!(c.plane_info(0).is_some());
        assert!(c.crtc_info(1).is_none());
    }
}
