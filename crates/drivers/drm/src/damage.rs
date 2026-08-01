// Damage-clip arithmetic: turn the rectangles userspace reports into the one
// region the driver uploads.
//
// Both DIRTYFB and the atomic damage-clips property describe what changed as a
// list of clip rectangles. The scanout path uploads a single rectangle, so the
// list collapses to its bounding box: strictly more than the union of the
// clips, never less, which is what keeps the result correct when the clips are
// disjoint.
//
// Pure arithmetic, no user memory and no device state, so every clamp is
// host-testable — the reason this is not inline in the ioctl handlers.

use crate::node::DamageRect;

/// Clip rectangle userspace passes in a damage list: an inclusive-exclusive
/// box in framebuffer pixels. Matches the DRM UAPI layout, 8 bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct DrmClipRect {
    pub x1: u16,
    pub y1: u16,
    pub x2: u16,
    pub y2: u16,
}

/// Most clips read from a damage list. A caller reporting more than this is
/// describing a scattered update whose bounding box would approach the whole
/// surface anyway, so the driver presents the surface instead of walking them.
pub const MAX_DAMAGE_CLIPS: u32 = 256;

/// Convert one clip to a rect, dropping inverted or empty boxes.
/// # C: O(1)
pub fn rect_of_clip(c: DrmClipRect) -> Option<DamageRect> {
    if c.x2 <= c.x1 || c.y2 <= c.y1 { return None; }
    Some(DamageRect {
        x: c.x1 as u32,
        y: c.y1 as u32,
        w: (c.x2 - c.x1) as u32,
        h: (c.y2 - c.y1) as u32,
    })
}

/// Bounding box of `clips`, clamped to a `w` x `h` surface. `None` when no
/// clip survives, which the caller treats as nothing to present.
/// # C: O(clips)
pub fn bounding_rect(clips: &[DrmClipRect], w: u32, h: u32) -> Option<DamageRect> {
    let mut acc: Option<DamageRect> = None;
    for c in clips {
        let Some(r) = rect_of_clip(*c) else { continue };
        let Some(r) = clamp(r, w, h) else { continue };
        acc = Some(match acc { Some(a) => a.union(r), None => r });
    }
    acc
}

/// Clamp a rect to a `w` x `h` surface. # C: O(1)
pub fn clamp(r: DamageRect, w: u32, h: u32) -> Option<DamageRect> {
    if w == 0 || h == 0 || r.x >= w || r.y >= h { return None; }
    let cw = r.w.min(w - r.x);
    let ch = r.h.min(h - r.y);
    if cw == 0 || ch == 0 { return None; }
    Some(DamageRect { x: r.x, y: r.y, w: cw, h: ch })
}

/// Whether a clip count is worth walking rather than presenting the surface.
/// # C: O(1)
pub fn clip_count_is_usable(num_clips: u32) -> bool {
    num_clips > 0 && num_clips <= MAX_DAMAGE_CLIPS
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: u32 = 1920;
    const H: u32 = 1080;

    fn clip(x1: u16, y1: u16, x2: u16, y2: u16) -> DrmClipRect {
        DrmClipRect { x1, y1, x2, y2 }
    }

    #[test]
    fn clip_layout_matches_the_uapi() {
        assert_eq!(core::mem::size_of::<DrmClipRect>(), 8);
        assert_eq!(core::mem::offset_of!(DrmClipRect, x1), 0);
        assert_eq!(core::mem::offset_of!(DrmClipRect, y1), 2);
        assert_eq!(core::mem::offset_of!(DrmClipRect, x2), 4);
        assert_eq!(core::mem::offset_of!(DrmClipRect, y2), 6);
    }

    #[test]
    fn a_clip_is_an_inclusive_exclusive_box() {
        assert_eq!(rect_of_clip(clip(10, 20, 30, 25)),
                   Some(DamageRect { x: 10, y: 20, w: 20, h: 5 }));
    }

    #[test]
    fn degenerate_and_inverted_clips_are_dropped() {
        assert_eq!(rect_of_clip(clip(10, 10, 10, 20)), None);
        assert_eq!(rect_of_clip(clip(10, 10, 20, 10)), None);
        assert_eq!(rect_of_clip(clip(30, 10, 10, 20)), None);
    }

    #[test]
    fn disjoint_clips_collapse_to_a_box_covering_both() {
        // Uploading the union would miss the gap; the bounding box may upload
        // more than changed, but never less.
        let r = bounding_rect(&[clip(0, 0, 10, 10), clip(100, 200, 110, 210)], W, H).unwrap();
        assert_eq!(r, DamageRect { x: 0, y: 0, w: 110, h: 210 });
    }

    #[test]
    fn a_single_clip_is_carried_through_unchanged() {
        assert_eq!(bounding_rect(&[clip(64, 32, 192, 48)], W, H),
                   Some(DamageRect { x: 64, y: 32, w: 128, h: 16 }));
    }

    #[test]
    fn clips_are_clamped_to_the_surface() {
        assert_eq!(bounding_rect(&[clip(1900, 1070, 2000, 1200)], W, H),
                   Some(DamageRect { x: 1900, y: 1070, w: 20, h: 10 }));
    }

    #[test]
    fn clips_entirely_outside_the_surface_are_dropped() {
        assert_eq!(bounding_rect(&[clip(1920, 0, 1930, 10)], W, H), None);
        assert_eq!(bounding_rect(&[clip(0, 1080, 10, 1090)], W, H), None);
    }

    #[test]
    fn an_empty_list_reports_nothing_to_present() {
        assert_eq!(bounding_rect(&[], W, H), None);
    }

    #[test]
    fn union_ignores_an_empty_operand() {
        let r = DamageRect { x: 5, y: 5, w: 10, h: 10 };
        let empty = DamageRect { x: 0, y: 0, w: 0, h: 0 };
        assert_eq!(r.union(empty), r);
        assert_eq!(empty.union(r), r);
    }

    #[test]
    fn nested_clips_do_not_grow_the_box() {
        let r = bounding_rect(&[clip(0, 0, 100, 100), clip(10, 10, 20, 20)], W, H).unwrap();
        assert_eq!(r, DamageRect { x: 0, y: 0, w: 100, h: 100 });
    }

    #[test]
    fn clip_counts_beyond_the_cap_are_not_walked() {
        assert!(!clip_count_is_usable(0));
        assert!(clip_count_is_usable(1));
        assert!(clip_count_is_usable(MAX_DAMAGE_CLIPS));
        assert!(!clip_count_is_usable(MAX_DAMAGE_CLIPS + 1));
    }
}
