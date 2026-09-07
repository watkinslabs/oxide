//! Which item of a menu bar a screen point names.
//!
//! A bar is drawn in place on its owner's window rather than in a popup window
//! of its own, so a point is resolved against the owner's window rectangle and
//! the very item rectangles the bar was measured and drawn with. Sharing those
//! rectangles is the point: the highlight the drawing plan paints and the item
//! the hit test names can never disagree.
use super::popup::PopupHit;
use super::{MenuId, MenuManager, MenuRect};

/// Cell metrics one bar is measured, drawn and hit-tested with.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BarMetrics { pub char_width: i32, pub char_height: i32, pub bar_height: i32 }

/// Name what a screen point falls on in one window's menu bar. The band the
/// bar occupies spans the whole width of the window; a point in the band that
/// no item covers is the bar's own background, and a point outside the band
/// names nothing the bar owns. # C: O(N_items^2)
pub fn bar_hit_test(menus: &MenuManager, menu: MenuId, window: MenuRect, point: (i32, i32), metrics: BarMetrics) -> PopupHit {
    let Ok(bar) = menus.bar_rect(menu, window, metrics.char_width, metrics.char_height, metrics.bar_height) else { return PopupHit::Nowhere; };
    if point.0 < window.left || point.0 >= window.right { return PopupHit::Nowhere; }
    if point.1 < window.top || point.1 >= bar.bottom { return PopupHit::Nowhere; }
    match menus.item_from_point(menu, point, window, metrics.char_width, metrics.char_height, metrics.bar_height) {
        Ok(Some(position)) => PopupHit::Item(position as u32),
        _ => PopupHit::Border,
    }
}

#[cfg(test)]
#[path = "tests/bar_hit.rs"]
mod tests;
