//! Popup-menu geometry: the rectangle each item occupies inside the popup
//! window, the popup's own size, where that popup lands against the work
//! area, and which item a screen point names.
use alloc::vec::Vec;
use super::mnemonic::label_halves;
use super::{MenuError, MenuId, MenuManager, MenuMetrics, MenuRect, MF_BYPOSITION, MF_SEPARATOR};

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
/// Column reserved right of the text for a submenu arrow, which is the width
/// of the bitmap the arrow is drawn from.
pub const ARROW_WIDTH: i32 = 12;
/// Pixels the reference leaves between the check column and the text, ahead of
/// the one character size that follows it.
const CHECK_GAP: i32 = 4;
/// Pixels the reference adds to a popup row for the text itself, beside the
/// extent of the label.
const TEXT_MARGIN: i32 = 2;
/// Rows a popup row clears above the face's own cell.
const ROW_MARGIN: i32 = 2;
/// Rows a popup row clears above the face's character height, which floors the
/// row whatever the cell reports.
const ROW_FLOOR: i32 = 4;

/// Width of the check-mark column: the face's cell rounded up to the next odd
/// number of pixels, so a mark centred in it has one column on each side.
/// # C: O(1)
pub fn check_width(cell_height: i32) -> i32 {
    if cell_height <= 0 { return DEFAULT_CHECK_WIDTH; }
    ((cell_height.saturating_add(1)) / 2).saturating_mul(2).saturating_sub(1)
}

/// Check-mark column a face reporting no cell height falls back to.
const DEFAULT_CHECK_WIDTH: i32 = 13;

/// Height one separator row claims: half the band a bar of the same face
/// claims. # C: O(1)
pub fn separator_height(bar_height: i32) -> i32 { (bar_height.saturating_sub(1) / 2).max(1) }

/// Where every item sits inside the popup window, the window's own size, the
/// check column each row reserves, and the two columns every row's text and
/// accelerator half are placed against, as offsets from an item rectangle's
/// left edge.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PopupLayout { pub width: i32, pub height: i32, pub check: i32, pub text: i32, pub tab: i32, pub items: Vec<MenuRect> }

/// What a point inside the popup window names.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PopupHit { Nowhere, Border, Item(u32) }

impl MenuManager {
    /// Measure one popup, the way the reference measures one column of items:
    /// every row reserves the check column, the gap and one character size
    /// before its text, and the arrow column behind it; the label itself is
    /// measured under the menu face and an accelerator half is set off from
    /// the name by one more character size. Every row then takes the widest
    /// width the column reached, and the accelerator column of every row is
    /// the widest name, so the accelerators line up. A row is as tall as the
    /// taller of its own text and the face's character height, and a separator
    /// is half a band. # C: O(N_items)
    pub fn popup_layout(&self, menu: MenuId, metrics: &MenuMetrics, max_height: i32) -> Result<PopupLayout, MenuError> {
        let count = self.count(menu)?;
        let (mut widest, mut widest_tab, mut widest_accel) = (0, 0, 0);
        let mut items = Vec::new();
        items.try_reserve(count).map_err(|_| MenuError::NoSuchMenu)?;
        let mut y = POPUP_BORDER;
        let lead = check_width(metrics.char_height).saturating_add(CHECK_GAP).saturating_add(metrics.char_width);
        for position in 0..count {
            let item = self.item(menu, position as u32, MF_BYPOSITION)?;
            let separator = item.state & MF_SEPARATOR != 0;
            if separator {
                items.push(MenuRect { left: POPUP_BORDER, top: y, right: POPUP_BORDER,
                    bottom: y.saturating_add(separator_height(metrics.bar_height)) });
                y = y.saturating_add(separator_height(metrics.bar_height));
                let width = ARROW_WIDTH.saturating_add(metrics.char_width);
                if width > widest { widest = width; }
                continue;
            }
            let halves = label_halves(&item.text);
            let name = metrics.cells.extent(&halves.name.units);
            let accel = match &halves.accel {
                Some((_, drawn)) => metrics.char_width.saturating_add(metrics.cells.extent(&drawn.units)),
                None => 0,
            };
            let tab = lead.saturating_add(name);
            let right = tab.saturating_add(ARROW_WIDTH).saturating_add(TEXT_MARGIN).saturating_add(accel);
            let height = metrics.char_height.saturating_add(ROW_MARGIN)
                .max(metrics.cells.height().saturating_add(ROW_FLOOR));
            if right > widest { widest = right; }
            if tab > widest_tab { widest_tab = tab; }
            if right.saturating_sub(tab) > widest_accel { widest_accel = right.saturating_sub(tab); }
            items.push(MenuRect { left: POPUP_BORDER, top: y, right: POPUP_BORDER, bottom: y.saturating_add(height) });
            y = y.saturating_add(height);
        }
        let widest = widest.max(widest_tab.saturating_add(widest_accel));
        let height = y.saturating_add(POPUP_BORDER).min(max_height.max(POPUP_BORDER * 2));
        let width = widest.saturating_add(POPUP_BORDER * 2);
        for rect in &mut items { rect.right = width.saturating_sub(POPUP_BORDER); }
        Ok(PopupLayout { width, height, check: check_width(metrics.char_height), text: lead, tab: widest_tab.max(lead), items })
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
