// Command sequence for presenting a resource on a scanout.
//
// Three separate defects lived in the old "always SET_SCANOUT, then transfer,
// then flush" sequence, and this module is the single place the correct order
// is decided so it can be tested without a device:
//
//   1. SET_SCANOUT ran BEFORE the resource's contents were uploaded. The
//      scanout was pointed at a resource whose host-side copy still held the
//      previous (or, for a freshly created resource, undefined/blank)
//      contents. The spec's pageflip recipe transfers to the not-yet-visible
//      resource FIRST, then binds and flushes it.
//   2. SET_SCANOUT ran on EVERY frame, including frames that present the same
//      resource at the same rect. Binding a scanout is setup, not part of the
//      per-frame update loop, which the spec describes as transfer-then-flush.
//   3. The transfer and flush always covered the whole frame even when the
//      caller knew the damaged rectangle. Both commands carry a rectangle.
//
// `Rect` is in resource pixel coordinates; `offset` is the byte position of
// the rect's top-left pixel inside the backing, which is what the transfer
// command carries.

/// Damaged region of a presentation, in resource pixels.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
}

impl Rect {
    /// Whole-surface rect for a `w` x `h` resource. # C: O(1)
    pub fn full(w: u32, h: u32) -> Self { Rect { x: 0, y: 0, w, h } }

    /// Byte offset of the rect's top-left pixel in a tightly packed backing.
    /// # C: O(1)
    pub fn backing_offset(&self, surface_w: u32, bytes_per_pixel: u32) -> u64 {
        (self.y as u64) * (surface_w as u64) * (bytes_per_pixel as u64)
            + (self.x as u64) * (bytes_per_pixel as u64)
    }

    /// Nothing to present. # C: O(1)
    pub fn is_empty(&self) -> bool { self.w == 0 || self.h == 0 }
}

/// What a scanout is currently bound to.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Binding {
    pub res_id: u32,
    pub w: u32,
    pub h: u32,
}

/// One device command in a presentation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Step {
    /// Upload `rect` of the resource from its guest backing.
    Transfer { rect: Rect, offset: u64 },
    /// Bind the scanout to the resource at its full rect.
    SetScanout,
    /// Make `rect` visible.
    Flush { rect: Rect },
}

/// Longest sequence `plan` can produce.
pub const MAX_STEPS: usize = 3;

/// Command sequence presenting `damage` of `next` on a scanout currently bound
/// to `cur`. Transfer always precedes any bind, the bind is emitted only when
/// the binding actually changes, and the flush is last.
///
/// `damage` is honoured only while the binding is UNCHANGED. A presentation
/// that rebinds is the first time this resource reaches the screen in its
/// current role, and only the caller's own previous frames ever wrote its host
/// copy — a partial upload would leave the rest of the frame holding whatever
/// that copy last held, or nothing at all for a resource the device just
/// created. So a rebind widens to the whole surface.
///
/// An empty damage rect with an unchanged binding is a no-op — the caller then
/// issues no device command at all. # C: O(1)
pub fn plan(cur: Option<Binding>, next: Binding, damage: Rect, bytes_per_pixel: u32)
    -> ([Step; MAX_STEPS], usize)
{
    let rebind = cur != Some(next);
    let rect = if rebind { Rect::full(next.w, next.h) } else { damage };
    let mut steps = [Step::SetScanout; MAX_STEPS];
    let mut n = 0;
    if !rect.is_empty() {
        steps[n] = Step::Transfer { rect, offset: rect.backing_offset(next.w, bytes_per_pixel) };
        n += 1;
    }
    if rebind {
        steps[n] = Step::SetScanout;
        n += 1;
    }
    if !rect.is_empty() {
        steps[n] = Step::Flush { rect };
        n += 1;
    }
    (steps, n)
}

/// Clamp a caller's damage rect to a `w` x `h` surface, so a rect that runs
/// off the resource cannot be handed to the device. `None` when nothing
/// survives. # C: O(1)
pub fn clamp_rect(rect: Rect, w: u32, h: u32) -> Option<Rect> {
    if w == 0 || h == 0 || rect.x >= w || rect.y >= h { return None; }
    let cw = rect.w.min(w - rect.x);
    let ch = rect.h.min(h - rect.y);
    if cw == 0 || ch == 0 { return None; }
    Some(Rect { x: rect.x, y: rect.y, w: cw, h: ch })
}

#[cfg(test)]
mod tests {
    use super::*;

    const BPP: u32 = 4;
    const W: u32 = 1280;
    const H: u32 = 800;

    fn bind(res_id: u32) -> Binding { Binding { res_id, w: W, h: H } }

    fn steps(cur: Option<Binding>, next: Binding, rect: Rect) -> alloc::vec::Vec<Step> {
        let (s, n) = plan(cur, next, rect, BPP);
        s[..n].to_vec()
    }

    #[test]
    fn contents_are_uploaded_before_the_scanout_is_bound_to_them() {
        // Binding first would show whatever the host copy held, which for a
        // freshly created resource is not the frame the caller rendered.
        let s = steps(Some(bind(2)), bind(3), Rect::full(W, H));
        let t = s.iter().position(|x| matches!(x, Step::Transfer { .. })).unwrap();
        let b = s.iter().position(|x| matches!(x, Step::SetScanout)).unwrap();
        assert!(t < b, "transfer must precede set_scanout: {s:?}");
    }

    #[test]
    fn flush_is_last() {
        let s = steps(Some(bind(2)), bind(3), Rect::full(W, H));
        assert!(matches!(s.last().unwrap(), Step::Flush { .. }));
    }

    #[test]
    fn presenting_the_same_binding_does_not_rebind_the_scanout() {
        // Re-binding an unchanged scanout every frame is what makes a host
        // replace its display surface per frame.
        let s = steps(Some(bind(2)), bind(2), Rect::full(W, H));
        assert!(!s.iter().any(|x| matches!(x, Step::SetScanout)), "{s:?}");
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn first_present_binds_because_nothing_is_bound_yet() {
        let s = steps(None, bind(2), Rect::full(W, H));
        assert!(s.iter().any(|x| matches!(x, Step::SetScanout)));
    }

    #[test]
    fn a_resolution_change_rebinds_even_at_the_same_resource() {
        let cur = Binding { res_id: 2, w: W, h: H };
        let next = Binding { res_id: 2, w: 1920, h: 1080 };
        let s = steps(Some(cur), next, Rect::full(1920, 1080));
        assert!(s.iter().any(|x| matches!(x, Step::SetScanout)));
    }

    #[test]
    fn a_page_flip_between_two_buffers_rebinds_each_time() {
        assert!(steps(Some(bind(2)), bind(3), Rect::full(W, H))
            .iter().any(|x| matches!(x, Step::SetScanout)));
        assert!(steps(Some(bind(3)), bind(2), Rect::full(W, H))
            .iter().any(|x| matches!(x, Step::SetScanout)));
    }

    #[test]
    fn damage_rect_is_carried_by_both_transfer_and_flush() {
        let r = Rect { x: 64, y: 32, w: 128, h: 16 };
        let s = steps(Some(bind(2)), bind(2), r);
        assert_eq!(s[0], Step::Transfer { rect: r, offset: r.backing_offset(W, BPP) });
        assert_eq!(s[1], Step::Flush { rect: r });
    }

    #[test]
    fn backing_offset_is_the_rects_top_left_pixel() {
        let r = Rect { x: 10, y: 2, w: 4, h: 4 };
        assert_eq!(r.backing_offset(W, BPP), (2 * W as u64 + 10) * BPP as u64);
        assert_eq!(Rect::full(W, H).backing_offset(W, BPP), 0);
    }

    #[test]
    fn empty_damage_on_an_unchanged_binding_issues_nothing() {
        let s = steps(Some(bind(2)), bind(2), Rect { x: 0, y: 0, w: 0, h: 0 });
        assert!(s.is_empty(), "{s:?}");
    }

    #[test]
    fn a_rebind_uploads_the_whole_surface_not_just_the_damage() {
        // The incoming resource's host copy is not known to hold the rest of
        // this frame, so a partial upload would show stale or blank pixels
        // outside the damage rect.
        let r = Rect { x: 64, y: 32, w: 128, h: 16 };
        let s = steps(Some(bind(2)), bind(3), r);
        assert_eq!(s[0], Step::Transfer { rect: Rect::full(W, H), offset: 0 });
        assert_eq!(s[2], Step::Flush { rect: Rect::full(W, H) });
    }

    #[test]
    fn empty_damage_still_uploads_and_binds_when_the_binding_changed() {
        // Even with nothing reported damaged, a rebind must land a full frame.
        let s = steps(Some(bind(2)), bind(3), Rect { x: 0, y: 0, w: 0, h: 0 });
        assert_eq!(s, alloc::vec![
            Step::Transfer { rect: Rect::full(W, H), offset: 0 },
            Step::SetScanout,
            Step::Flush { rect: Rect::full(W, H) },
        ]);
    }

    #[test]
    fn clamp_keeps_a_rect_inside_the_surface() {
        assert_eq!(clamp_rect(Rect { x: 1270, y: 790, w: 100, h: 100 }, W, H),
                   Some(Rect { x: 1270, y: 790, w: 10, h: 10 }));
        assert_eq!(clamp_rect(Rect { x: W, y: 0, w: 4, h: 4 }, W, H), None);
        assert_eq!(clamp_rect(Rect { x: 0, y: H, w: 4, h: 4 }, W, H), None);
        assert_eq!(clamp_rect(Rect::full(W, H), W, H), Some(Rect::full(W, H)));
    }

    #[test]
    fn plan_never_exceeds_its_declared_step_bound() {
        let (_, n) = plan(None, bind(2), Rect::full(W, H), BPP);
        assert!(n <= MAX_STEPS);
    }
}
