//! Atomic state validation and scanout commit.

extern crate alloc;

use alloc::sync::Arc;
use syscall::errno::Errno;

use super::{mode_blob, props};
use crate::{DrmDriver, DRM_MODE_ATOMIC_ALLOW_MODESET, DRM_MODE_ATOMIC_TEST_ONLY,
            DRM_MODE_PAGE_FLIP_EVENT, DRM_MODE_PROP_IMMUTABLE};

fn einval() -> i64 { -(Errno::Einval.as_i32() as i64) }

/// Validate an atomic property set then apply its effective primary-plane
/// state.
///
/// Rejection order follows `drm_mode_atomic_ioctl` → `drm_atomic_set_property`:
/// an unknown object/property pair and any write to a property carrying
/// `DRM_MODE_PROP_IMMUTABLE` are both EINVAL, and a state change that alters
/// the mode requires `ALLOW_MODESET`. # C: O(tuples)
pub fn commit(card_id: u32, card: &Arc<dyn DrmDriver>, token: u64, flags: u32, user_data: u64,
    tuples: &[(u32, u32, u64)]) -> i64 {
    let primary = match card.plane_ids().first().copied() { Some(id) => id, None => return einval() };
    let crtc = match card.crtc_ids().first().copied() { Some(id) => id, None => return einval() };
    let connector = match card.connector_ids().first().copied() { Some(id) => id, None => return einval() };
    let mut fb = None;
    let mut plane_crtc = None;
    let mut active = None;
    let mut mode_id = None;
    let mut mode_change = false;
    let mut connector_crtc = None;
    for &(obj, prop, value) in tuples {
        if !props::valid_tuple(card, obj, prop) { return einval(); }
        // Immutable properties enumerate but never accept a write.
        if props::desc(prop).is_some_and(|d| d.flags & DRM_MODE_PROP_IMMUTABLE != 0) { return einval(); }
        match (obj, prop) {
            (id, props::PROP_PLANE_FB_ID) if id == primary => fb = Some(value as u32),
            (id, props::PROP_PLANE_CRTC_ID) if id == primary => plane_crtc = Some(value as u32),
            (id, props::PROP_CRTC_ACTIVE) if id == crtc => {
                if value > 1 { return einval(); }
                active = Some(value != 0); mode_change = true;
            }
            (id, props::PROP_CRTC_MODE_ID) if id == crtc => {
                if value != 0 {
                    let Some(mode) = mode_blob(value as u32) else { return einval(); };
                    if !card.mode_valid(0, &mode) { return einval(); }
                }
                mode_id = Some(value as u32); mode_change = true;
            }
            // The virtio GPU has no variable refresh; only the reported value
            // (disabled) is accepted, as a driver without VRR support behaves.
            (id, props::PROP_CRTC_VRR_ENABLED) if id == crtc => { if value != 0 { return einval(); } }
            (id, props::PROP_CONN_CRTC_ID) if id == connector => { connector_crtc = Some(value as u32); mode_change = true; }
            _ => {}
        }
    }
    if mode_change && flags & DRM_MODE_ATOMIC_ALLOW_MODESET == 0 { return einval(); }
    if let Some(id) = plane_crtc { if id != 0 && id != crtc { return einval(); } }
    if let Some(id) = connector_crtc { if id != 0 && id != crtc { return einval(); } }
    let target_fb = if active == Some(false) { 0 } else { fb.unwrap_or_else(|| crate::crtc::current_fb(card_id)) };
    if flags & DRM_MODE_ATOMIC_TEST_ONLY != 0 { return 0; }
    let rv = crate::kms_ext::atomic_primary(card_id, card, crtc, target_fb, token);
    if rv != 0 { return rv; }
    // A disabling commit clears the mode with the framebuffer (see
    // `crtc::clear_current_fb`); only a live scanout records its mode blob.
    if target_fb != 0 {
        if let Some(blob) = mode_id { crate::crtc::set_current_mode_blob(card_id, blob); }
    }
    if flags & DRM_MODE_PAGE_FLIP_EVENT != 0 {
        crate::crtc::queue_flip_event(card_id, token, crtc, user_data);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConnectorInfo, CrtcInfo, EncoderInfo, PlaneInfo, DrmModeModeinfo,
                connector_id_for, crtc_id_for, encoder_id_for, fixed_mode_dimensions_valid,
                mode_from_rect, plane_id_for, DRM_MODE_ATOMIC_ALLOW_MODESET,
                DRM_MODE_ATOMIC_TEST_ONLY, DRM_MODE_CONNECTED, DRM_MODE_CONNECTOR_UNKNOWN,
                DRM_MODE_ENCODER_NONE};

    struct FixedScanout;

    impl DrmDriver for FixedScanout {
        fn name(&self) -> &'static str { "fixed" }
        fn version(&self) -> (u32, u32, u32) { (1, 0, 0) }
        fn date(&self) -> &'static str { "20260813" }
        fn desc(&self) -> &'static str { "fixed scanout test" }
        fn unique(&self) -> &str { "fixed" }
        fn resource_counts(&self) -> (u32, u32, u32, u32) { (0, 1, 1, 1) }
        fn dim_bounds(&self) -> (u32, u32, u32, u32) { (1920, 1920, 1080, 1080) }
        fn cap(&self, cap: u64) -> u64 { crate::default_cap(cap) }
        fn crtc_ids(&self) -> alloc::vec::Vec<u32> { alloc::vec![crtc_id_for(0)] }
        fn connector_ids(&self) -> alloc::vec::Vec<u32> { alloc::vec![connector_id_for(0)] }
        fn encoder_ids(&self) -> alloc::vec::Vec<u32> { alloc::vec![encoder_id_for(0)] }
        fn plane_ids(&self) -> alloc::vec::Vec<u32> { alloc::vec![plane_id_for(0)] }
        fn mode_for(&self, _idx: usize) -> DrmModeModeinfo { mode_from_rect(1920, 1080) }
        fn mode_valid(&self, idx: usize, mode: &DrmModeModeinfo) -> bool {
            idx == 0 && fixed_mode_dimensions_valid(mode, 1920, 1080)
        }
        fn connector_info(&self, idx: usize) -> Option<ConnectorInfo> {
            (idx == 0).then_some(ConnectorInfo { connection: DRM_MODE_CONNECTED,
                connector_type: DRM_MODE_CONNECTOR_UNKNOWN, encoder_id: encoder_id_for(0), mm_width: 0, mm_height: 0 })
        }
        fn crtc_info(&self, idx: usize) -> Option<CrtcInfo> {
            (idx == 0).then_some(CrtcInfo { mode_valid: 1, fb_id: 0, x: 0, y: 0, gamma_size: 0,
                mode: mode_from_rect(1920, 1080) })
        }
        fn encoder_info(&self, idx: usize) -> Option<EncoderInfo> {
            (idx == 0).then_some(EncoderInfo { encoder_type: DRM_MODE_ENCODER_NONE,
                crtc_id: crtc_id_for(0), possible_crtcs: 1, possible_clones: 0 })
        }
        fn plane_info(&self, idx: usize) -> Option<PlaneInfo> {
            (idx == 0).then_some(PlaneInfo { crtc_id: crtc_id_for(0), fb_id: 0, possible_crtcs: 1 })
        }
    }

    fn commit_mode(mode: DrmModeModeinfo) -> i64 {
        let card: Arc<dyn DrmDriver> = Arc::new(FixedScanout);
        let blob = super::super::blobs::insert_mode_for_tests(mode);
        commit(0, &card, 1, DRM_MODE_ATOMIC_ALLOW_MODESET | DRM_MODE_ATOMIC_TEST_ONLY, 0,
            &[(crtc_id_for(0), props::PROP_CRTC_MODE_ID, blob as u64)])
    }

    #[test]
    fn fixed_scanout_rejects_resized_atomic_mode_blob() {
        assert_eq!(commit_mode(mode_from_rect(1920, 1080)), 0);
        assert_eq!(commit_mode(mode_from_rect(1280, 720)), einval());
    }
}
