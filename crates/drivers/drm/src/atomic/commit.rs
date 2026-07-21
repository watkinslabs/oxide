//! Atomic state validation and scanout commit.

extern crate alloc;

use alloc::sync::Arc;
use syscall::errno::Errno;

use super::{mode_blob, props};
use crate::{DrmDriver, DRM_MODE_ATOMIC_ALLOW_MODESET, DRM_MODE_ATOMIC_TEST_ONLY, DRM_MODE_PAGE_FLIP_EVENT};

fn einval() -> i64 { -(Errno::Einval.as_i32() as i64) }

/// Validate an atomic property set then apply its effective primary-plane state. # C: O(tuples)
pub fn commit(card_id: u32, card: &Arc<dyn DrmDriver>, token: u64, flags: u32, user_data: u64,
    tuples: &[(u32, u32, u64)]) -> i64 {
    let primary = match card.plane_ids().first().copied() { Some(id) => id, None => return einval() };
    let crtc = match card.crtc_ids().first().copied() { Some(id) => id, None => return einval() };
    let connector = match card.connector_ids().first().copied() { Some(id) => id, None => return einval() };
    let mut fb = None;
    let mut plane_crtc = None;
    let mut active = None;
    let mut mode_change = false;
    let mut connector_crtc = None;
    for &(obj, prop, value) in tuples {
        if !props::valid_tuple(card, obj, prop) { return einval(); }
        match (obj, prop) {
            (id, props::PROP_PLANE_FB_ID) if id == primary => fb = Some(value as u32),
            (id, props::PROP_PLANE_CRTC_ID) if id == primary => plane_crtc = Some(value as u32),
            (id, props::PROP_CRTC_ACTIVE) if id == crtc => {
                if value > 1 { return einval(); }
                active = Some(value != 0); mode_change = true;
            }
            (id, props::PROP_CRTC_MODE_ID) if id == crtc => {
                if value != 0 && !mode_blob(value as u32) { return einval(); }
                mode_change = true;
            }
            (id, props::PROP_CONN_CRTC_ID) if id == connector => { connector_crtc = Some(value as u32); mode_change = true; }
            // Immutable fields have passed tuple validation but are never writable.
            (_, props::PROP_PLANE_TYPE | props::PROP_PLANE_IN_FORMATS | props::PROP_CONN_EDID) => return einval(),
            _ => {}
        }
    }
    if mode_change && flags & DRM_MODE_ATOMIC_ALLOW_MODESET == 0 { return einval(); }
    if let Some(id) = plane_crtc { if id != 0 && id != crtc { return einval(); } }
    if let Some(id) = connector_crtc { if id != 0 && id != crtc { return einval(); } }
    let target_fb = if active == Some(false) { 0 } else { fb.unwrap_or_else(|| crate::crtc::current_fb(card_id)) };
    if flags & DRM_MODE_ATOMIC_TEST_ONLY != 0 { return 0; }
    let rv = crate::kms_ext::atomic_primary(card_id, card, crtc, target_fb, token);
    if rv == 0 && flags & DRM_MODE_PAGE_FLIP_EVENT != 0 {
        crate::crtc::queue_flip_event(card_id, token, crtc, user_data);
    }
    rv
}
