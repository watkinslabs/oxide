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

/// A mode this scanout can actually drive, on a device accepting `min_w..=max_w`
/// by `min_h..=max_h`. Interlaced modes are declined because the scanout does
/// not produce them; unpacked widths are declined because a dumb buffer's pitch
/// is padded while the resource stride is not, so the row would scan out
/// skewed. # C: O(1)
pub fn mode_is_offerable(m: &DrmModeModeinfo, min_w: u32, max_w: u32, min_h: u32, max_h: u32)
    -> bool {
    if m.flags & crate::uapi::DRM_MODE_FLAG_INTERLACE != 0 { return false; }
    size_is_offerable(m.hdisplay as u32, m.vdisplay as u32, min_w, max_w, min_h, max_h)
}

/// The display's own preferred timing, when this scanout can drive it. # C: O(1)
pub fn preferred_from_edid(edid: &[u8]) -> Option<DrmModeModeinfo> {
    let mode = crate::edid::preferred_mode(edid)?;
    if mode.flags & crate::uapi::DRM_MODE_FLAG_INTERLACE != 0 { return None; }
    if !width_is_packed(mode.hdisplay as u32) { return None; }
    if mode.vdisplay == 0 { return None; }
    Some(mode)
}

/// Mode list for a connector whose display published `edid`.
///
/// Every mode the display asserted — detailed, established, and standard
/// timings alike — is offered, in the standard's own ranking, less the ones
/// this scanout cannot drive. The generic table follows as a fallback for
/// sizes the display did not name, so a compositor is never left with fewer
/// choices than before an EDID arrived.
///
/// Entry 0 is the display's preferred timing when it named a usable one, and
/// the device's current rectangle otherwise; it is the only mode tagged
/// preferred. # C: O(modes squared)
pub fn list_with_edid(edid: Option<&[u8]>, pref_w: u32, pref_h: u32,
    min_w: u32, max_w: u32, min_h: u32, max_h: u32) -> Vec<DrmModeModeinfo> {
    let published = edid.map(crate::edid::all_modes).unwrap_or_default();
    let head = edid.and_then(preferred_from_edid);
    let (pw, ph) = match head.as_ref() {
        Some(m) => (m.hdisplay as u32, m.vdisplay as u32),
        None => (pref_w.max(1), pref_h.max(1)),
    };
    let mut out = Vec::with_capacity(published.len() + MAX_MODES);
    // The head is offered whatever the device bounds say: the display asked for
    // it, or the device is already scanning it out.
    out.push(match head {
        Some(m) => m,
        None => mode_from_rect(pw, ph),
    });
    let add = |mut m: DrmModeModeinfo, out: &mut Vec<DrmModeModeinfo>| {
        if out.iter().any(|have| have.hdisplay == m.hdisplay && have.vdisplay == m.vdisplay
            && have.vrefresh == m.vrefresh) { return; }
        m.ty = DRM_MODE_TYPE_DRIVER;
        out.push(m);
    };
    for m in published {
        if !mode_is_offerable(&m, min_w, max_w, min_h, max_h) { continue; }
        add(m, &mut out);
    }
    for &(w, h) in STD_SIZES.iter() {
        if !size_is_offerable(w, h, min_w, max_w, min_h, max_h) { continue; }
        add(mode_from_rect(w, h), &mut out);
    }
    out
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

    use crate::edid::tests::block_for;

    #[test]
    fn the_displays_own_timing_becomes_the_preferred_mode() {
        let e = block_for(2560, 1440, false);
        let m = preferred_from_edid(&e).expect("a packed progressive timing is usable");
        assert_eq!((m.hdisplay, m.vdisplay), (2560, 1440));
        // The display's own timings, not a synthesised rectangle.
        assert!(m.htotal > m.hdisplay && m.vtotal > m.vdisplay);
        assert_ne!(m.ty & DRM_MODE_TYPE_PREFERRED, 0);
    }

    #[test]
    fn an_unpacked_edid_width_is_declined() {
        // 1366 * 4 is not a multiple of the dumb pitch alignment, so honouring
        // it would scan out skewed however clearly the display asks for it.
        assert!(!width_is_packed(1366));
        assert!(preferred_from_edid(&block_for(1366, 768, false)).is_none());
    }

    #[test]
    fn an_interlaced_edid_timing_is_declined() {
        assert!(preferred_from_edid(&block_for(1920, 1080, true)).is_none());
    }

    #[test]
    fn a_corrupt_or_absent_edid_is_declined() {
        let mut e = block_for(1920, 1080, false);
        e[1] ^= 0xff;   // breaks both the header and the checksum
        assert!(preferred_from_edid(&e).is_none());
        assert!(preferred_from_edid(&[]).is_none());
    }

    #[test]
    fn edid_list_heads_with_the_display_and_keeps_the_alternatives() {
        let e = block_for(2560, 1440, false);
        let l = list_with_edid(Some(&e), 1024, 768, MIN_W, MAX_W, MIN_H, MAX_H);
        assert_eq!((l[0].hdisplay, l[0].vdisplay), (2560, 1440));
        assert_ne!(l[0].ty & DRM_MODE_TYPE_PREFERRED, 0);
        assert!(l.len() > 1);
        // The size the EDID named is offered once, not twice.
        assert_eq!(l.iter().filter(|m| m.hdisplay == 2560 && m.vdisplay == 1440).count(), 1);
        for m in l.iter().skip(1) { assert_eq!(m.ty & DRM_MODE_TYPE_PREFERRED, 0); }
    }

    #[test]
    fn without_a_usable_edid_the_device_rectangle_stays_preferred() {
        let bad = block_for(1366, 768, false);
        for edid in [None, Some(&bad[..])] {
            let l = list_with_edid(edid, 1024, 768, MIN_W, MAX_W, MIN_H, MAX_H);
            assert_eq!((l[0].hdisplay, l[0].vdisplay), (1024, 768));
            assert_ne!(l[0].ty & DRM_MODE_TYPE_PREFERRED, 0);
        }
    }

    use crate::edid::tests::{build_full, dtd_for};

    #[test]
    fn every_mode_the_display_published_is_offered() {
        // A display asserting a preferred timing, a second detailed timing, an
        // established mode, and a standard timing entry.
        let mut est = [0u8; 3];
        est[1] = 1 << 3;                    // 1024x768 at 60 Hz
        let e = build_full(4, &[&dtd_for(2560, 1440, false), &dtd_for(1280, 720, false)],
            est, &[(((1920 - 248) / 8) as u8, 0xc0)]);
        let l = list_with_edid(Some(&e), 800, 600, MIN_W, MAX_W, MIN_H, MAX_H);
        for (w, h) in [(2560u16, 1440u16), (1280, 720), (1024, 768), (1920, 1080)] {
            assert!(l.iter().any(|m| m.hdisplay == w && m.vdisplay == h),
                "the display asserted {w}x{h} and it must be offered");
        }
        // The generic table still fills in sizes the display did not name.
        assert!(l.iter().any(|m| m.hdisplay == 1600 && m.vdisplay == 1200));
    }

    #[test]
    fn a_published_mode_keeps_the_displays_own_timings() {
        let e = build_full(4, &[&dtd_for(2560, 1440, false)], [0; 3], &[]);
        let l = list_with_edid(Some(&e), 800, 600, MIN_W, MAX_W, MIN_H, MAX_H);
        let head = l[0];
        assert_eq!((head.hdisplay, head.vdisplay), (2560, 1440));
        assert_eq!(head.htotal, 2560 + 2560 / 8, "the descriptor's own blanking, not a guess");
    }

    #[test]
    fn published_modes_the_scanout_cannot_drive_are_left_out() {
        // An unpacked width and an interlaced timing, both asserted as detailed
        // descriptors alongside a usable one.
        let e = build_full(4, &[&dtd_for(2560, 1440, false), &dtd_for(1366, 768, false),
            &dtd_for(1920, 1080, true)], [0; 3], &[]);
        let l = list_with_edid(Some(&e), 800, 600, MIN_W, MAX_W, MIN_H, MAX_H);
        assert!(!l.iter().any(|m| m.hdisplay == 1366));
        assert!(l.iter().all(|m| m.flags & crate::uapi::DRM_MODE_FLAG_INTERLACE == 0));
        assert_eq!((l[0].hdisplay, l[0].vdisplay), (2560, 1440));
    }

    #[test]
    fn a_published_mode_beyond_the_device_bounds_is_left_out() {
        let e = build_full(4, &[&dtd_for(1280, 720, false), &dtd_for(2560, 1440, false)],
            [0; 3], &[]);
        let l = list_with_edid(Some(&e), 800, 600, MIN_W, 1920, MIN_H, 1080);
        assert!(!l.iter().any(|m| m.hdisplay == 2560));
        assert_eq!((l[0].hdisplay, l[0].vdisplay), (1280, 720));
    }

    #[test]
    fn only_the_head_is_tagged_preferred_in_an_edid_list() {
        let e = build_full(4, &[&dtd_for(2560, 1440, false), &dtd_for(1280, 720, false)],
            [0xff, 0xff, 0x80], &[]);
        let l = list_with_edid(Some(&e), 800, 600, MIN_W, MAX_W, MIN_H, MAX_H);
        assert_ne!(l[0].ty & DRM_MODE_TYPE_PREFERRED, 0);
        for m in l.iter().skip(1) {
            assert_eq!(m.ty & DRM_MODE_TYPE_PREFERRED, 0);
            assert_ne!(m.ty & crate::uapi::DRM_MODE_TYPE_DRIVER, 0);
        }
    }

    #[test]
    fn no_size_and_rate_is_offered_twice() {
        let e = build_full(4, &[&dtd_for(1920, 1080, false)], [0xff, 0xff, 0x80],
            &[(((1920 - 248) / 8) as u8, 0xc0)]);
        let l = list_with_edid(Some(&e), 1920, 1080, MIN_W, MAX_W, MIN_H, MAX_H);
        for (i, a) in l.iter().enumerate() {
            for b in l[i + 1..].iter() {
                assert!(!(a.hdisplay == b.hdisplay && a.vdisplay == b.vdisplay
                    && a.vrefresh == b.vrefresh), "{}x{} offered twice", a.hdisplay, a.vdisplay);
            }
        }
    }

    #[test]
    fn every_width_an_edid_list_offers_still_packs() {
        let e = block_for(1920, 1080, false);
        for m in list_with_edid(Some(&e), 800, 600, MIN_W, MAX_W, MIN_H, MAX_H) {
            let w = m.hdisplay as u32;
            assert_eq!((w * BYTES_PER_PIXEL) % DUMB_PITCH_ALIGN, 0, "width {w} pads");
        }
    }
}
