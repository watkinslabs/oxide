//! What a menu paints: the ordered fill, glyph and text operations one popup
//! window or one menu bar produces. The decisions here — colours per item
//! state, the edge each border draws, where the text of an item starts — are
//! the drawing contract; the pixels are written by the caller that walks the
//! plan against a device context.
use alloc::vec::Vec;
use super::mnemonic::{label_halves, AccelAlign};
use super::popup::{PopupLayout, ARROW_WIDTH};
use super::{MenuError, MenuId, MenuManager, MenuRect, MF_BYPOSITION, MF_CHECKED, MF_GRAYED, MF_HILITE, MF_SEPARATOR};
use crate::win32_gdi::SystemColor;

/// Edge kinds, as the caller's `EDGE_*`/`BDR_*` encoding: the low nibble
/// selects the inner and outer edge colour pair.
pub const BDR_RAISEDOUTER: u32 = 0x0001;
pub const BDR_SUNKENOUTER: u32 = 0x0002;
pub const BDR_RAISEDINNER: u32 = 0x0004;
pub const BDR_SUNKENINNER: u32 = 0x0008;
pub const EDGE_RAISED: u32 = BDR_RAISEDOUTER | BDR_RAISEDINNER;
pub const EDGE_ETCHED: u32 = BDR_SUNKENOUTER | BDR_RAISEDINNER;
pub const EDGE_SUNKEN: u32 = BDR_SUNKENOUTER | BDR_SUNKENINNER;
const EDGE_MASK: u32 = 0x000f;

pub const BF_LEFT: u32 = 0x0001;
pub const BF_TOP: u32 = 0x0002;
pub const BF_RIGHT: u32 = 0x0004;
pub const BF_BOTTOM: u32 = 0x0008;
pub const BF_RECT: u32 = BF_LEFT | BF_TOP | BF_RIGHT | BF_BOTTOM;

/// Points one menu glyph polygon carries: the check mark is six, the submenu
/// arrow three.
pub const GLYPH_POINTS: usize = 6;
/// Gap between the item rectangle and the start of its text.
pub const TEXT_GAP: i32 = 4;
/// Height of the etched rule a separator draws.
pub const SEPARATOR_RULE: i32 = 1;

/// Which run of an item's label a text step draws: the item name, or the
/// accelerator half behind the label's split unit.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MenuTextHalf { Name, Accelerator }

/// How one run sits in the rectangle it is given.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MenuTextAlign { Left, Center, Right }

/// One drawing step of a menu.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MenuDrawOp {
    /// Solid fill of one rectangle in a system colour.
    Fill { rect: MenuRect, color: SystemColor },
    /// One run of one item's label, drawn inside this rectangle. A bar item
    /// centres its name; a popup item starts at the left edge and its
    /// accelerator half is placed against the menu's tab column, from it
    /// rightwards after a tab and against it after a flush-right unit. The
    /// default item is bold.
    Text { rect: MenuRect, position: u32, half: MenuTextHalf, color: SystemColor, align: MenuTextAlign, bold: bool },
    /// A filled glyph: the check mark and the submenu arrow.
    Glyph { points: [(i32, i32); GLYPH_POINTS], count: usize, color: SystemColor },
}

/// Inner and outer colours one edge kind draws on its top-left and its
/// bottom-right sides. # C: O(1)
const fn edge_colors(edge: u32) -> (Option<SystemColor>, Option<SystemColor>, Option<SystemColor>, Option<SystemColor>) {
    let (lt_inner, lt_outer, rb_inner, rb_outer) = match edge & EDGE_MASK {
        BDR_RAISEDOUTER => (None, Some(SystemColor::Light), None, Some(SystemColor::DarkShadow)),
        BDR_SUNKENOUTER => (None, Some(SystemColor::ButtonShadow), None, Some(SystemColor::ButtonHighlight)),
        BDR_RAISEDINNER => (Some(SystemColor::ButtonHighlight), None, Some(SystemColor::ButtonShadow), None),
        BDR_SUNKENINNER => (Some(SystemColor::DarkShadow), None, Some(SystemColor::Light), None),
        EDGE_RAISED => (Some(SystemColor::ButtonHighlight), Some(SystemColor::Light), Some(SystemColor::ButtonShadow), Some(SystemColor::DarkShadow)),
        EDGE_ETCHED => (Some(SystemColor::ButtonHighlight), Some(SystemColor::ButtonShadow), Some(SystemColor::ButtonShadow), Some(SystemColor::ButtonHighlight)),
        EDGE_SUNKEN => (Some(SystemColor::DarkShadow), Some(SystemColor::ButtonShadow), Some(SystemColor::Light), Some(SystemColor::ButtonHighlight)),
        _ => (None, None, None, None),
    };
    (lt_inner, lt_outer, rb_inner, rb_outer)
}

/// How far inside its rectangle one edge drawn at `width` reaches: an edge
/// with an inner line is drawn in the second band and so reaches twice as
/// far. A caller that draws an edge and then keeps drawing inside it takes
/// this off the rectangle, and a caller that reserves room for one reserves
/// this much. # C: O(1)
pub const fn edge_extent(edge: u32, width: i32) -> i32 {
    let (lt_inner, lt_outer, _, _) = edge_colors(edge);
    if lt_inner.is_some() { width * 2 } else if lt_outer.is_some() { width } else { 0 }
}

/// Append the fills one edge of `rect` draws: the outer edge on every named
/// side first, then the inner edge inside it. # C: O(1)
pub fn rect_edge(rect: MenuRect, edge: u32, flags: u32, width: i32, into: &mut Vec<MenuDrawOp>) {
    let (lt_inner, lt_outer, rb_inner, rb_outer) = edge_colors(edge);
    let mut fill = |rect: MenuRect, color: Option<SystemColor>| { if let Some(color) = color { into.push(MenuDrawOp::Fill { rect, color }); } };
    if flags & BF_TOP != 0 { fill(MenuRect { bottom: rect.top.saturating_add(width), ..rect }, lt_outer); }
    if flags & BF_LEFT != 0 { fill(MenuRect { right: rect.left.saturating_add(width), ..rect }, lt_outer); }
    if flags & BF_BOTTOM != 0 { fill(MenuRect { top: rect.bottom.saturating_sub(width), ..rect }, rb_outer); }
    if flags & BF_RIGHT != 0 { fill(MenuRect { left: rect.right.saturating_sub(width), ..rect }, rb_outer); }
    let offset = |side: u32| if flags & side == side { width } else { 0 };
    let (top_left, top_right, bottom_left, bottom_right) = (offset(BF_LEFT | BF_TOP), offset(BF_TOP | BF_RIGHT), offset(BF_BOTTOM | BF_LEFT), offset(BF_BOTTOM | BF_RIGHT));
    if flags & BF_TOP != 0 {
        fill(MenuRect { left: rect.left.saturating_add(top_left), top: rect.top.saturating_add(width),
            right: rect.right.saturating_sub(top_right), bottom: rect.top.saturating_add(width * 2) }, lt_inner);
    }
    if flags & BF_LEFT != 0 {
        fill(MenuRect { left: rect.left.saturating_add(width), top: rect.top.saturating_add(top_left),
            right: rect.left.saturating_add(width * 2), bottom: rect.bottom.saturating_sub(bottom_left) }, lt_inner);
    }
    if flags & BF_BOTTOM != 0 {
        fill(MenuRect { left: rect.left.saturating_add(bottom_left), top: rect.bottom.saturating_sub(width * 2),
            right: rect.right.saturating_sub(bottom_right), bottom: rect.bottom.saturating_sub(width) }, rb_inner);
    }
    if flags & BF_RIGHT != 0 {
        fill(MenuRect { left: rect.right.saturating_sub(width * 2), top: rect.top.saturating_add(top_right),
            right: rect.right.saturating_sub(width), bottom: rect.bottom.saturating_sub(bottom_right) }, rb_inner);
    }
}

/// The tick one checked item draws, as a filled polygon inside a square cell.
/// # C: O(1)
pub fn check_glyph(cell: MenuRect, color: SystemColor) -> MenuDrawOp {
    let size = (cell.right - cell.left).min(cell.bottom - cell.top).max(1);
    let across = |numerator: i32| cell.left + numerator * size / 1000;
    let down = |numerator: i32| cell.top + numerator * size / 1000;
    let thickness = 3 * size / 16;
    let (x0, y0) = (across(253), down(445));
    let (x1, y1) = (across(409), y0 + (across(409) - x0));
    let (x2, y2) = (across(690), y1 - (across(690) - x1));
    let points = [(x0, y0), (x1, y1), (x2, y2), (x2, y2 + thickness), (x1, y1 + thickness), (x0, y0 + thickness)];
    MenuDrawOp::Glyph { points, count: GLYPH_POINTS, color }
}

/// The triangle one submenu item draws at its right edge. # C: O(1)
pub fn arrow_glyph(cell: MenuRect, color: SystemColor) -> MenuDrawOp {
    let size = (cell.right - cell.left).min(cell.bottom - cell.top).max(1);
    let reach = 187 * size / 750;
    let tip = (cell.left + 468 * size / 750, cell.top + 352 * size / 750 + 1);
    let points = [(tip.0 - reach, tip.1 - reach), (tip.0 - reach, tip.1 + reach), tip, tip, tip, tip];
    MenuDrawOp::Glyph { points, count: 3, color }
}

/// The text colour one item draws in, given whether it is highlighted and
/// whether it sits on a bar. A bar highlight keeps the menu text colour and
/// marks the item with a sunken edge instead. # C: O(1)
pub const fn item_text_color(state: u32, bar: bool) -> SystemColor {
    if state & MF_GRAYED != 0 { return SystemColor::GrayText; }
    if state & MF_HILITE != 0 && !bar { return SystemColor::HighlightText; }
    SystemColor::MenuText
}

impl MenuManager {
    /// The steps one popup window paints: its background and raised border,
    /// then every item over them. # C: O(N_items)
    pub fn popup_draw_plan(&self, menu: MenuId, layout: &PopupLayout) -> Result<Vec<MenuDrawOp>, MenuError> {
        let client = MenuRect { left: 0, top: 0, right: layout.width, bottom: layout.height };
        let mut ops = Vec::new();
        ops.try_reserve(self.count(menu)? * 5 + 8).map_err(|_| MenuError::NoSuchMenu)?;
        ops.push(MenuDrawOp::Fill { rect: client, color: SystemColor::Menu });
        rect_edge(client, EDGE_RAISED, BF_RECT, 1, &mut ops);
        for (position, rect) in layout.items.iter().enumerate() {
            let item = self.item(menu, position as u32, MF_BYPOSITION)?;
            if item.state & MF_SEPARATOR != 0 {
                let middle = (rect.top + rect.bottom) / 2;
                let rule = MenuRect { left: rect.left + 1, top: middle, right: rect.right - 1, bottom: middle + SEPARATOR_RULE * 2 };
                rect_edge(rule, EDGE_ETCHED, BF_TOP, SEPARATOR_RULE, &mut ops);
                continue;
            }
            let hilite = item.state & MF_HILITE != 0;
            ops.push(MenuDrawOp::Fill { rect: *rect, color: if hilite { SystemColor::Highlight } else { SystemColor::Menu } });
            let color = item_text_color(item.state, false);
            if item.state & MF_CHECKED != 0 {
                let side = (rect.bottom - rect.top).min(layout.check);
                let top = rect.top + ((rect.bottom - rect.top) - side) / 2;
                ops.push(check_glyph(MenuRect { left: rect.left, top, right: rect.left + side, bottom: top + side }, color));
            }
            if item.submenu.is_some() {
                let side = (rect.bottom - rect.top).min(ARROW_WIDTH);
                let top = rect.top + ((rect.bottom - rect.top) - side) / 2;
                ops.push(arrow_glyph(MenuRect { left: rect.right - side - 1, top, right: rect.right - 1, bottom: top + side }, color));
            }
            let bold = item.state & super::MF_DEFAULT != 0;
            let text = MenuRect { left: rect.left + layout.text, top: rect.top, right: rect.right - ARROW_WIDTH, bottom: rect.bottom };
            ops.push(MenuDrawOp::Text { rect: text, position: position as u32, half: MenuTextHalf::Name, color, align: MenuTextAlign::Left, bold });
            // The accelerator half is drawn as its own run against the column
            // the whole menu was measured to share.
            if let Some((align, _)) = label_halves(&item.text).accel {
                let column = rect.left + layout.tab;
                let (accel, align) = match align {
                    AccelAlign::Tab => (MenuRect { left: column, ..text }, MenuTextAlign::Left),
                    AccelAlign::FlushRight => (MenuRect { right: column, ..text }, MenuTextAlign::Right),
                };
                ops.push(MenuDrawOp::Text { rect: accel, position: position as u32, half: MenuTextHalf::Accelerator, color, align, bold });
            }
        }
        Ok(ops)
    }

    /// The steps one menu bar paints inside `origin`: its background, the face
    /// line closing it off, then every item. A separator draws nothing on a
    /// bar. # C: O(N_items)
    pub fn bar_draw_plan(&self, menu: MenuId, origin: MenuRect, metrics: &super::MenuMetrics) -> Result<Vec<MenuDrawOp>, MenuError> {
        let count = self.count(menu)?;
        let mut ops = Vec::new();
        ops.try_reserve(count * 3 + 4).map_err(|_| MenuError::NoSuchMenu)?;
        let bar = self.bar_rect(menu, origin, metrics)?;
        let full = MenuRect { left: origin.left, top: origin.top, right: origin.right, bottom: bar.bottom };
        ops.push(MenuDrawOp::Fill { rect: full, color: SystemColor::Menu });
        ops.push(MenuDrawOp::Fill { rect: MenuRect { top: full.bottom, bottom: full.bottom + 1, ..full }, color: SystemColor::Face });
        for position in 0..count {
            let item = self.item(menu, position as u32, MF_BYPOSITION)?;
            if item.state & MF_SEPARATOR != 0 { continue; }
            let rect = self.bar_item_rect(menu, position, origin, metrics)?;
            if item.state & MF_HILITE != 0 { rect_edge(rect, BDR_SUNKENOUTER, BF_RECT, 1, &mut ops); }
            else { ops.push(MenuDrawOp::Fill { rect, color: SystemColor::Menu }); }
            let text = MenuRect { left: rect.left + metrics.char_width, top: rect.top, right: rect.right - metrics.char_width, bottom: rect.bottom };
            ops.push(MenuDrawOp::Text { rect: text, position: position as u32, half: MenuTextHalf::Name, color: item_text_color(item.state, true),
                align: MenuTextAlign::Center, bold: item.state & super::MF_DEFAULT != 0 });
        }
        Ok(ops)
    }
}

#[cfg(test)]
#[path = "tests/draw.rs"]
mod tests;
