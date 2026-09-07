//! Popup-menu geometry: the rectangle each item occupies inside the popup
//! window, the popup's own size, where that popup lands against the work
//! area, and which item a screen point names.
use alloc::vec::Vec;
use super::{MenuError, MenuId, MenuManager, MenuRect, MF_BYPOSITION, MF_SEPARATOR};

/// Track-popup flags. `TPM_LEFTALIGN`, `TPM_TOPALIGN` and `TPM_LEFTBUTTON`
/// are the zero defaults and carry no bit.
pub const TPM_RIGHTBUTTON: u32 = 0x0000_0002;
pub const TPM_CENTERALIGN: u32 = 0x0000_0004;
pub const TPM_RIGHTALIGN: u32 = 0x0000_0008;
pub const TPM_VCENTERALIGN: u32 = 0x0000_0010;
pub const TPM_BOTTOMALIGN: u32 = 0x0000_0020;
pub const TPM_NONOTIFY: u32 = 0x0000_0080;
pub const TPM_RETURNCMD: u32 = 0x0000_0100;
pub const TPM_LAYOUTRTL: u32 = 0x0000_4000;
/// Tracking-private flags, never accepted from a caller: the menu is a popup
/// rather than a bar, and tracking began on a button already down.
pub const TPM_POPUPMENU: u32 = 0x2000_0000;
pub const TPM_BUTTONDOWN: u32 = 0x4000_0000;
/// Tracking-private: end the loop as soon as it is entered.
pub const TF_ENDMENU: u32 = 0x0001_0000;
/// Tracking-private: a button-up already arrived for the tracked bar item.
pub const TF_RCVD_BTN_UP: u32 = 0x0008_0000;

/// The position no item occupies.
pub const NO_SELECTED_ITEM: u32 = 0xffff;

/// Popup border thickness on every edge, in pixels.
pub const POPUP_BORDER: i32 = 3;
/// Column reserved left of the text for the check mark or item bitmap.
pub const CHECK_WIDTH: i32 = 12;
/// Column reserved right of the text for a submenu arrow.
pub const ARROW_WIDTH: i32 = 12;
/// A separator is drawn as a rule, not a line of text.
pub const SEPARATOR_HEIGHT: i32 = 5;

/// Text and cell metrics one popup is measured with.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PopupMetrics { pub char_width: i32, pub char_height: i32 }

/// Where every item sits inside the popup window, and the window's own size.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PopupLayout { pub width: i32, pub height: i32, pub items: Vec<MenuRect> }

/// What a point inside the popup window names.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PopupHit { Nowhere, Border, Item(u32) }

/// Displayed length of an item's text, stopping at the terminator. # C: O(len)
pub fn text_len(text: &[u16]) -> usize { text.iter().position(|unit| *unit == 0).unwrap_or(text.len()) }

impl MenuManager {
    /// Measure one popup: a single column of items, each a text line except a
    /// separator, clipped to `max_height` rows. The check and arrow columns
    /// are always reserved so the text of every item starts in one place.
    /// # C: O(N_items)
    pub fn popup_layout(&self, menu: MenuId, metrics: PopupMetrics, max_height: i32) -> Result<PopupLayout, MenuError> {
        let count = self.count(menu)?;
        let mut widest = 0;
        let mut items = Vec::new();
        items.try_reserve(count).map_err(|_| MenuError::NoSuchMenu)?;
        let mut y = POPUP_BORDER;
        for position in 0..count {
            let item = self.item(menu, position as u32, MF_BYPOSITION)?;
            let separator = item.state & MF_SEPARATOR != 0;
            let height = if separator { SEPARATOR_HEIGHT } else { metrics.char_height };
            let width = CHECK_WIDTH.saturating_add((text_len(&item.text) as i32).saturating_mul(metrics.char_width)).saturating_add(ARROW_WIDTH);
            if width > widest { widest = width; }
            items.push(MenuRect { left: POPUP_BORDER, top: y, right: POPUP_BORDER, bottom: y.saturating_add(height) });
            y = y.saturating_add(height);
        }
        let height = y.saturating_add(POPUP_BORDER).min(max_height.max(POPUP_BORDER * 2));
        let width = widest.saturating_add(POPUP_BORDER * 2);
        for rect in &mut items { rect.right = width.saturating_sub(POPUP_BORDER); }
        Ok(PopupLayout { width, height, items })
    }
}

/// Place a popup of this size for a request at `(x, y)`: the alignment flags
/// move the popup off the point, then the anchor rectangle and the work area
/// pull it back on screen. A right-to-left layout mirrors the horizontal
/// alignment. # C: O(1)
pub fn popup_origin(flags: u32, mut x: i32, mut y: i32, width: i32, height: i32, work: MenuRect,
    xanchor: i32, yanchor: i32) -> (i32, i32) {
    let flags = if flags & TPM_LAYOUTRTL != 0 { flags ^ TPM_RIGHTALIGN } else { flags };
    if flags & TPM_RIGHTALIGN != 0 { x -= width; }
    if flags & TPM_CENTERALIGN != 0 { x -= width / 2; }
    if flags & TPM_BOTTOMALIGN != 0 { y -= height; }
    if flags & TPM_VCENTERALIGN != 0 { y -= height / 2; }
    if x.saturating_add(width) > work.right {
        if xanchor != 0 && x >= width.saturating_sub(xanchor) { x -= width.saturating_sub(xanchor); }
        if x.saturating_add(width) > work.right { x = work.right.saturating_sub(width); }
    }
    if x < work.left { x = work.left; }
    if y.saturating_add(height) > work.bottom {
        if yanchor != 0 && y >= height.saturating_add(yanchor) { y -= height.saturating_add(yanchor); }
        if y.saturating_add(height) > work.bottom { y = work.bottom.saturating_sub(height); }
    }
    if y < work.top { y = work.top; }
    (x, y)
}

/// Name the item a screen point falls on. A point outside the popup window is
/// nowhere; a point inside it that no item covers is the border. # C: O(N_items)
pub fn hit_test(layout: &PopupLayout, window: MenuRect, point: (i32, i32)) -> PopupHit {
    if point.0 < window.left || point.0 >= window.right || point.1 < window.top || point.1 >= window.bottom { return PopupHit::Nowhere; }
    let local = (point.0 - window.left, point.1 - window.top);
    for (position, rect) in layout.items.iter().enumerate() {
        if local.0 >= rect.left && local.0 < rect.right && local.1 >= rect.top && local.1 < rect.bottom {
            return PopupHit::Item(position as u32);
        }
    }
    PopupHit::Border
}

#[cfg(test)]
#[path = "tests/popup.rs"]
mod tests;
