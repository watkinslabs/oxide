//! Scroll geometry: which pixels move, where they land, and what is left
//! needing repaint (`NtUserScrollDC`, `NtUserScrollWindowEx`).
use ipc::win32_window::{PaintRegion, WindowRect};

pub(crate) const SCROLL_DC: u64 = 0x152a;
pub(crate) const SCROLL_WINDOW_EX: u64 = 0x152b;

pub(crate) const SW_SCROLLCHILDREN: u32 = 0x0001;
pub(crate) const SW_INVALIDATE: u32 = 0x0002;
pub(crate) const SW_ERASE: u32 = 0x0004;
pub(crate) const SW_NODCCACHE: u32 = 0x0008;

/// Redraw flags the scroll performs on the region it could not move.
/// # C: O(1)
pub(crate) const fn redraw_flags(flags: u32) -> u32 {
    if flags & SW_ERASE != 0 && flags & SW_INVALIDATE != 0 {
        ipc::win32_window::RDW_INVALIDATE | ipc::win32_window::RDW_ERASE
    } else { ipc::win32_window::RDW_INVALIDATE }
}

/// Whether the caller wants the region that still needs painting. # C: O(1)
pub(crate) const fn wants_update(update_rgn: u64, update_rect: u64, flags: u32) -> bool {
    update_rgn != 0 || update_rect != 0 || flags & (SW_INVALIDATE | SW_ERASE) != 0
}

/// # C: O(1)
pub(crate) const fn is_empty(rect: WindowRect) -> bool { rect.left >= rect.right || rect.top >= rect.bottom }

/// # C: O(1)
pub(crate) fn intersect(a: WindowRect, b: WindowRect) -> WindowRect {
    let rect = WindowRect { left: a.left.max(b.left), top: a.top.max(b.top), right: a.right.min(b.right), bottom: a.bottom.min(b.bottom) };
    if is_empty(rect) { WindowRect { left: 0, top: 0, right: 0, bottom: 0 } } else { rect }
}

/// # C: O(1)
pub(crate) fn offset(rect: WindowRect, dx: i32, dy: i32) -> WindowRect {
    WindowRect { left: rect.left.saturating_add(dx), top: rect.top.saturating_add(dy),
        right: rect.right.saturating_add(dx), bottom: rect.bottom.saturating_add(dy) }
}

/// # C: O(1)
pub(crate) fn union(a: WindowRect, b: WindowRect) -> WindowRect {
    if is_empty(a) { return b; }
    if is_empty(b) { return a; }
    WindowRect { left: a.left.min(b.left), top: a.top.min(b.top), right: a.right.max(b.right), bottom: a.bottom.max(b.bottom) }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct Plan {
    /// Pixels that move, at their source position.
    pub source: WindowRect,
    /// Where those pixels land.
    pub destination: WindowRect,
    /// The whole area the scroll covers, from which the destination is removed.
    pub covered: WindowRect,
}

/// Only pixels inside both the clipping rectangle and its own copy shifted
/// back by the scroll distance survive the move; naming a scroll rectangle
/// narrows that further. The area needing repaint is the covered area minus
/// where the moved pixels landed. # C: O(1)
pub(crate) fn plan(clip_box: WindowRect, scroll: Option<WindowRect>, clip: Option<WindowRect>, dx: i32, dy: i32) -> Plan {
    let clip_rect = clip.unwrap_or(clip_box);
    let mut source = intersect(clip_rect, offset(clip_rect, -dx, -dy));
    if let Some(scroll) = scroll { source = intersect(source, scroll); }
    let covered = match (scroll, clip) {
        (Some(scroll), Some(clip)) => intersect(clip, scroll),
        (Some(scroll), None) => scroll,
        (None, Some(clip)) => clip,
        (None, None) => clip_box,
    };
    Plan { source, destination: offset(source, dx, dy), covered }
}

/// The area the scroll leaves needing repaint. # C: O(N_rects²)
pub(crate) fn update_region(plan: Plan) -> Result<PaintRegion, ()> {
    let mut region = PaintRegion::from_rect(plan.covered).map_err(|_| ())?;
    if !is_empty(plan.destination) {
        let landed = PaintRegion::from_rect(plan.destination).map_err(|_| ())?;
        region.subtract(&landed).map_err(|_| ())?;
    }
    Ok(region)
}

/// A scroll longer than the area it moves within leaves a second area behind:
/// where the original content would have landed. # C: O(1)
pub(crate) fn overshoots(area: WindowRect, dx: i32, dy: i32) -> bool {
    dx.unsigned_abs() > area.right.abs_diff(area.left) || dy.unsigned_abs() > area.bottom.abs_diff(area.top)
}

#[cfg(test)]
#[path = "tests/dc_raw.rs"]
mod tests;
