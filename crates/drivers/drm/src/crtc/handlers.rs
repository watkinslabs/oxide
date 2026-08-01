// SETCRTC / PAGE_FLIP / framebuffer-to-scanout binding. Split out of the
// `crtc` manifest, which owns scanout ownership, the current-fb record and
// the flip-event queue; this file owns the ioctl handlers that drive a
// framebuffer onto the scanout.

use super::*;
use crate::node::scanout_ops;
use crate::{crtc_idx_of, DrmModeCrtc};

// ============================================================
// SETCRTC / PAGE_FLIP handlers
// ============================================================

/// Resolve an FB id → its primary dumb buffer's (pa, w, h, fourcc).
/// `None` if the fb or its handle is unknown. # C: O(n)
fn fb_to_scanout(card_id: u32, fb_id: u32) -> Option<(u64, u32, u32, u32, u32)> {
    let t = crate::dumb::TABLES.lock();
    let fb = t.find_fb(card_id, fb_id)?;
    let buf = t.find_buf(card_id, fb.handles[0])?;
    Some((buf.pa, fb.w, fb.h, fb.pixel_format, fb.scanout_res_id))
}

fn release_new_scanout_resource(card_id: u32, res_id: u32) {
    if let Some(ops) = scanout_ops(card_id) {
        let _ = (ops.destroy_resource)(ops.driver_key, res_id);
    }
}

pub(crate) fn fb_scanout_resource(card_id: u32, ops: crate::node::ScanoutOps, fb_id: u32) -> Option<(u32, u32, u32)> {
    let (pa, w, h, fmt, existing) = fb_to_scanout(card_id, fb_id)?;
    if existing != 0 {
        return Some((existing, w, h));
    }
    let res_id = (ops.create_from_pa)(ops.driver_key, pa, w, h, fmt)?;
    if !crate::dumb::bind_fb_scanout_resource(card_id, fb_id, res_id) {
        release_new_scanout_resource(card_id, res_id);
        return None;
    }
    Some((res_id, w, h))
}

/// `MODE_SETCRTC` — parse `drm_mode_crtc`, validate crtc_id + fb_id,
/// drive the scanout. `token` identifies the owning open description.
///
/// - fb_id == 0  → disable the CRTC: restore the boot fbcon scanout,
///   clear the owner. Returns 0.
/// - else        → look up the FB → (pa,w,h,fmt), create a virtio-gpu
///   resource over the contiguous PA, switch scanout 0 to it, record
///   `token` as the scanout owner. Returns 0.
///
/// Honest -EINVAL on a bad crtc_id / unknown fb_id / unsupported format
/// / no virtio-gpu scanout backend installed. # C: O(1) + O(scanout).
pub fn set_crtc(card_id: u32, card: &alloc::sync::Arc<dyn crate::DrmDriver>, arg: u64, token: u64) -> i64 {
    if !user_ok(arg, core::mem::size_of::<DrmModeCrtc>() as u64) { return einval(); }
    // SAFETY: arg range validated < USER_VA_END; drm_mode_crtc is 104 bytes; aligned struct read through the caller's AS at CPL=0.
    let c: DrmModeCrtc = unsafe { core::ptr::read_volatile(arg as *const DrmModeCrtc) };
    // DIAG: mutter's legacy modeset drives the scanout switch through here. One
    // line names whether it's called, whether the virtio-gpu scanout backend is
    // wired for THIS card_id, and the crtc/fb it targets — so a console-never-
    // leaves-fbcon symptom is traced to SETCRTC vs. a missing backend.
    klog::write_raw(b"[DRM-SETCRTC] card="); klog::write_hex_u64(card_id as u64);
    klog::write_raw(b" crtc="); klog::write_hex_u64(c.crtc_id as u64);
    klog::write_raw(b" fb=");   klog::write_hex_u64(c.fb_id as u64);
    klog::write_raw(if scanout_ops(card_id).is_some() { b" ops=present" } else { b" ops=ABSENT" });
    klog::write_raw(b"\n");
    // Validate the crtc id against the registered card.
    let count = card.crtc_ids().len();
    if crtc_idx_of(c.crtc_id, count).is_none() {
        klog::write_raw(b"[DRM-SETCRTC] -> EINVAL bad crtc_id (count="); klog::write_hex_u64(count as u64); klog::write_raw(b")\n");
        return einval();
    }
    let ops = match scanout_ops(card_id) { Some(o) => o, None => { klog::write_raw(b"[DRM-SETCRTC] -> EINVAL no scanout backend for card\n"); return einval(); } };

    if c.fb_id == 0 {
        // Disable / detach: restore the console scanout if WE owned it.
        if is_owner(card_id, token) {
            (ops.restore_console)(ops.driver_key);
            clear_owner(card_id);
            clear_current_fb(card_id);
        } else if owner(card_id) == 0 {
            // No client owns it; SETCRTC(fb=0) is a no-op disable.
            (ops.restore_console)(ops.driver_key);
            clear_current_fb(card_id);
        }
        return 0;
    }

    let (res_id, w, h) = match fb_scanout_resource(card_id, ops, c.fb_id) { Some(v) => v, None => return einval() };
    // Optionally validate the connector array pointer is sane when set.
    if c.set_connectors_ptr != 0
        && !user_ok(c.set_connectors_ptr, (c.count_connectors as u64) * 4) {
        return einval();
    }
    if !(ops.present)(ops.driver_key, res_id, w, h, crate::node::DamageRect::full(w, h)) { return einval(); }
    crate::diag::record(crate::diag::Present::SetCrtc, c.fb_id, res_id);
    set_current_fb(card_id, c.fb_id);
    set_owner(card_id, token);
    0
}

/// `MODE_PAGE_FLIP` — parse `drm_mode_crtc_page_flip`, re-scanout the
/// given fb on the crtc. virtio-gpu has no true double-buffer flip, so
/// flip = SET_SCANOUT + transfer + flush of the new fb (immediate).
/// If `flags & DRM_MODE_PAGE_FLIP_EVENT`, queue a DRM_EVENT_FLIP_COMPLETE
/// the card fd's read() returns. Honest -EINVAL on bad ids / no backend.
/// # C: O(1) + O(scanout).
pub fn page_flip(card_id: u32, card: &alloc::sync::Arc<dyn crate::DrmDriver>, arg: u64, token: u64) -> i64 {
    if !user_ok(arg, core::mem::size_of::<DrmModeCrtcPageFlip>() as u64) { return einval(); }
    // SAFETY: arg range validated < USER_VA_END; drm_mode_crtc_page_flip is 24 bytes; aligned struct read through the caller's AS at CPL=0.
    let f: DrmModeCrtcPageFlip = unsafe { core::ptr::read_volatile(arg as *const DrmModeCrtcPageFlip) };
    let count = card.crtc_ids().len();
    if crtc_idx_of(f.crtc_id, count).is_none() { return einval(); }
    if f.fb_id == 0 { return einval(); }
    let ops = match scanout_ops(card_id) { Some(o) => o, None => return einval() };
    let (res_id, w, h) = match fb_scanout_resource(card_id, ops, f.fb_id) { Some(v) => v, None => return einval() };
    if !(ops.present)(ops.driver_key, res_id, w, h, crate::node::DamageRect::full(w, h)) { return einval(); }
    crate::diag::record(crate::diag::Present::Flip, f.fb_id, res_id);
    set_current_fb(card_id, f.fb_id);
    set_owner(card_id, token);
    if (f.flags & crate::DRM_MODE_PAGE_FLIP_EVENT) != 0 {
        queue_flip_event(card_id, token, f.crtc_id, f.user_data);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_flip_layout() {
        // 4×u32 (16) + u64 (8) = 24.
        assert_eq!(core::mem::size_of::<DrmModeCrtcPageFlip>(), 24);
        assert_eq!(core::mem::offset_of!(DrmModeCrtcPageFlip, fb_id), 4);
        assert_eq!(core::mem::offset_of!(DrmModeCrtcPageFlip, flags), 8);
        assert_eq!(core::mem::offset_of!(DrmModeCrtcPageFlip, user_data), 16);
    }

    #[test]
    fn owner_token_logic() {
        clear_owner(0);
        clear_owner(1);
        clear_current_fb(0);
        clear_current_fb(1);
        assert_eq!(owner(0), 0);
        assert_eq!(owner(1), 0);
        assert_eq!(current_fb(0), 0);
        assert_eq!(current_fb(1), 0);
        assert!(!is_owner(0, 0));       // 0 token never "owns"
        assert!(!is_owner(0, 0x1000));
        set_owner(0, 0x1000);
        set_current_fb(0, 7);
        assert_eq!(owner(0), 0x1000);
        assert_eq!(current_fb(0), 7);
        assert_eq!(owner(1), 0);
        assert!(is_owner(0, 0x1000));
        assert!(!is_owner(1, 0x1000));
        assert!(!is_owner(0, 0x2000));  // a different fd doesn't own it
        detach_fb(0, 8);
        assert_eq!(current_fb(0), 7);
        detach_fb(0, 7);
        clear_owner(0);
        assert_eq!(owner(0), 0);
        assert_eq!(current_fb(0), 0);
        assert!(!is_owner(0, 0x1000));
    }

    #[test]
    fn flip_event_queue_drain() {
        const TOKEN_A: u64 = 0xA11C_E001;
        const TOKEN_B: u64 = 0xB22C_E002;
        // Drain any residue from other tests first.
        let mut scratch = [0u8; 4096];
        let _ = drain_events(0, TOKEN_A, &mut scratch);
        let _ = drain_events(0, TOKEN_B, &mut scratch);
        let _ = drain_events(1, TOKEN_A, &mut scratch);
        assert!(!has_events(0, TOKEN_A));
        assert!(!has_events(0, TOKEN_B));
        assert!(!has_events(1, TOKEN_A));
        queue_flip_event(0, TOKEN_A, 1, 0xDEAD_BEEF);
        queue_flip_event(0, TOKEN_A, 1, 0x1234_5678);
        queue_flip_event(0, TOKEN_B, 1, 0xFEED_FACE);
        assert!(has_events(0, TOKEN_A));
        assert!(has_events(0, TOKEN_B));
        assert!(!has_events(1, TOKEN_A));
        let rec = core::mem::size_of::<crate::DrmEventVblank>();
        // A buffer too small for one record drains nothing.
        let mut tiny = [0u8; 4];
        assert_eq!(drain_events(0, TOKEN_A, &mut tiny), 0);
        assert!(has_events(0, TOKEN_A));
        // A buffer big enough for both drains only TOKEN_A's records.
        let mut buf = [0u8; 4096];
        let n = drain_events(0, TOKEN_A, &mut buf);
        assert_eq!(n, 2 * rec);
        assert!(!has_events(0, TOKEN_A));
        assert!(has_events(0, TOKEN_B));
        // First record's type + user_data decode correctly.
        let ty = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(ty, crate::DRM_EVENT_FLIP_COMPLETE);
        let len = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        assert_eq!(len as usize, rec);
        let ud = u64::from_le_bytes([buf[8], buf[9], buf[10], buf[11],
                                     buf[12], buf[13], buf[14], buf[15]]);
        assert_eq!(ud, 0xDEAD_BEEF);
        assert_eq!(drain_events(0, TOKEN_B, &mut buf), rec);
        assert!(!has_events(0, TOKEN_B));
    }

    #[test]
    fn drain_partial_leaves_remainder() {
        const TOKEN: u64 = 0xD0D0;
        let mut scratch = [0u8; 4096];
        let _ = drain_events(0, TOKEN, &mut scratch);
        let rec = core::mem::size_of::<crate::DrmEventVblank>();
        queue_flip_event(0, TOKEN, 1, 1);
        queue_flip_event(0, TOKEN, 1, 2);
        queue_flip_event(0, TOKEN, 1, 3);
        // Buffer fits exactly two records → drains two, leaves one.
        let mut two = alloc::vec![0u8; 2 * rec];
        assert_eq!(drain_events(0, TOKEN, &mut two), 2 * rec);
        assert!(has_events(0, TOKEN));
        let mut one = alloc::vec![0u8; rec];
        assert_eq!(drain_events(0, TOKEN, &mut one), rec);
        assert!(!has_events(0, TOKEN));
    }

    #[test]
    fn clear_card_state_drops_owner_and_events() {
        const TOKEN: u64 = 0xCAFE_BABE;
        let mut scratch = [0u8; 4096];
        let _ = drain_events(2, TOKEN, &mut scratch);
        set_owner(2, 0x2000);
        set_current_fb(2, 17);
        queue_flip_event(2, TOKEN, 1, 0xCAFE);
        assert_eq!(owner(2), 0x2000);
        assert_eq!(current_fb(2), 17);
        assert!(has_events(2, TOKEN));
        clear_card_state(2);
        assert_eq!(owner(2), 0);
        assert_eq!(current_fb(2), 0);
        assert!(!has_events(2, TOKEN));
        assert_eq!(drain_events(2, TOKEN, &mut scratch), 0);
    }
}
