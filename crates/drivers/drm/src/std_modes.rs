// Standard mode list for a virtual connector.
//
// A KMS connector that reports a single mode gives a compositor no choice:
// it takes the preferred mode and the display is stuck at whatever size the
// device happened to power on with. Linux drivers with no EDID timing data
// still publish a table of common modes so userspace can pick, and that is
// what this table is for.
//
// Two constraints bound the table, both enforced by `list_for`:
//   - the device's own dimension bounds (a mode larger than the device
//     accepts would fail at SET_SCANOUT, after the compositor committed);
//   - `PACKED_WIDTH_ALIGN`, because a dumb buffer's pitch is padded while a
//     2D scanout resource derives its stride from the width. Only widths
//     whose packed row is already pitch-aligned keep the two in agreement;
//     any other width would scan out skewed.

use crate::core_api::mode_from_rect;
use crate::uapi::{DrmModeModeinfo, DRM_MODE_TYPE_DRIVER};
use alloc::vec::Vec;

/// Pitch alignment a dumb buffer applies, in bytes.
pub const DUMB_PITCH_ALIGN: u32 = 64;

/// Bytes per pixel of the scanout formats this driver posts.
pub const BYTES_PER_PIXEL: u32 = 4;

/// Widths must be a multiple of this for `width * bpp` to be pitch-aligned,
/// so the dumb pitch and the resource stride agree.
pub const PACKED_WIDTH_ALIGN: u32 = DUMB_PITCH_ALIGN / BYTES_PER_PIXEL;

/// Largest mode area offered, in pixels. Bounds the dumb buffer a compositor
/// is invited to allocate for a mode this table advertises.
pub const MAX_MODE_AREA: u64 = 3840 * 2160;

/// Common display sizes, widest first so a compositor scanning the list finds
/// the largest usable mode early. 4:3, 16:10 and 16:9 families.
pub const STD_SIZES: &[(u32, u32)] = &[
    (3840, 2160),
    (2560, 1600),
    (2560, 1440),
    (1920, 1200),
    (1920, 1080),
    (1680, 1050),
    (1600, 1200),
    (1600, 900),
    (1440, 900),
    (1280, 1024),
    (1280, 800),
    (1280, 720),
    (1152, 864),
    (1024, 768),
    (800, 600),
    (640, 480),
];

/// Upper bound on how many modes `list_for` can return: every standard size
/// plus the preferred mode when it is not one of them.
pub const MAX_MODES: usize = STD_SIZES.len() + 1;

/// A width whose packed row is already pitch-aligned. # C: O(1)
pub fn width_is_packed(w: u32) -> bool {
    w != 0 && w % PACKED_WIDTH_ALIGN == 0
}

/// A size the device accepts, whose row packs cleanly and whose area is
/// within `MAX_MODE_AREA`. # C: O(1)
pub fn size_is_offerable(w: u32, h: u32, min_w: u32, max_w: u32, min_h: u32, max_h: u32) -> bool {
    if w < min_w || w > max_w || h < min_h || h > max_h { return false; }
    if !width_is_packed(w) { return false; }
    (w as u64) * (h as u64) <= MAX_MODE_AREA
}

/// Mode list for a connector whose current/native size is `pref_w` x `pref_h`,
/// on a device accepting `min_w..=max_w` by `min_h..=max_h`.
///
/// Entry 0 is always the preferred mode, tagged `DRM_MODE_TYPE_PREFERRED`, so
/// a compositor that takes the head keeps today's behaviour. The remainder are
/// standard sizes tagged driver-only, deduplicated against the preferred one.
/// # C: O(STD_SIZES)
pub fn list_for(pref_w: u32, pref_h: u32, min_w: u32, max_w: u32, min_h: u32, max_h: u32) -> Vec<DrmModeModeinfo> {
    let mut out = Vec::with_capacity(MAX_MODES);
    let (pw, ph) = (pref_w.max(1), pref_h.max(1));
    out.push(mode_from_rect(pw, ph));
    for &(w, h) in STD_SIZES.iter() {
        if w == pw && h == ph { continue; }
        if !size_is_offerable(w, h, min_w, max_w, min_h, max_h) { continue; }
        let mut m = mode_from_rect(w, h);
        m.ty = DRM_MODE_TYPE_DRIVER;
        out.push(m);
    }
    out
}

/// The preferred mode alone, for callers wanting the connector's native size.
/// # C: O(1)
pub fn preferred(pref_w: u32, pref_h: u32) -> DrmModeModeinfo {
    mode_from_rect(pref_w.max(1), pref_h.max(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uapi::DRM_MODE_TYPE_PREFERRED;

    const MIN_W: u32 = 1;
    const MAX_W: u32 = 4096;
    const MIN_H: u32 = 1;
    const MAX_H: u32 = 2160;

    fn default_list(w: u32, h: u32) -> Vec<DrmModeModeinfo> {
        list_for(w, h, MIN_W, MAX_W, MIN_H, MAX_H)
    }

    #[test]
    fn head_is_the_preferred_mode_and_only_it_is_tagged_preferred() {
        let l = default_list(1280, 800);
        assert_eq!(l[0].hdisplay, 1280);
        assert_eq!(l[0].vdisplay, 800);
        assert_ne!(l[0].ty & DRM_MODE_TYPE_PREFERRED, 0);
        for m in l.iter().skip(1) {
            assert_eq!(m.ty & DRM_MODE_TYPE_PREFERRED, 0, "only the head may be preferred");
            assert_ne!(m.ty & DRM_MODE_TYPE_DRIVER, 0);
        }
    }

    #[test]
    fn offers_more_than_one_mode_so_a_compositor_can_choose() {
        let l = default_list(1280, 800);
        assert!(l.len() > 1, "a single-mode connector leaves userspace no choice");
        assert!(l.iter().any(|m| m.hdisplay == 1920 && m.vdisplay == 1080));
    }

    #[test]
    fn preferred_size_appears_exactly_once() {
        // 1280x800 is also in STD_SIZES, so the dedup is load-bearing.
        let l = default_list(1280, 800);
        let n = l.iter().filter(|m| m.hdisplay == 1280 && m.vdisplay == 800).count();
        assert_eq!(n, 1);
    }

    #[test]
    fn every_offered_width_packs_to_an_aligned_pitch() {
        // A width whose packed row is not pitch-aligned would scan out skewed,
        // because the dumb pitch pads while the resource stride does not.
        for m in default_list(1280, 800) {
            let w = m.hdisplay as u32;
            assert_eq!((w * BYTES_PER_PIXEL) % DUMB_PITCH_ALIGN, 0, "width {w} pads");
        }
    }

    #[test]
    fn device_bounds_exclude_modes_the_device_would_reject() {
        let l = list_for(800, 600, MIN_W, 1280, MIN_H, 800);
        assert!(l.iter().all(|m| m.hdisplay <= 1280 && m.vdisplay <= 800));
        assert!(!l.iter().any(|m| m.hdisplay == 1920));
    }

    #[test]
    fn preferred_is_offered_even_when_bounds_would_exclude_it() {
        // The device is already scanning it out, so it is by definition valid.
        let l = list_for(1366, 768, MIN_W, 1024, MIN_H, 768);
        assert_eq!(l[0].hdisplay, 1366);
    }

    #[test]
    fn unpacked_width_is_rejected() {
        assert!(!width_is_packed(1366));
        assert!(width_is_packed(1280));
        assert!(width_is_packed(1920));
        assert!(!default_list(1280, 800).iter().skip(1).any(|m| m.hdisplay == 1366));
    }

    #[test]
    fn list_never_exceeds_its_declared_bound() {
        assert!(default_list(1366, 768).len() <= MAX_MODES);
        assert!(default_list(1280, 800).len() <= MAX_MODES);
    }

    #[test]
    fn zero_preferred_size_is_clamped_not_panicking() {
        let l = default_list(0, 0);
        assert_eq!(l[0].hdisplay, 1);
        assert_eq!(l[0].vdisplay, 1);
    }
}
