//! The frame a window draws for itself: what it takes off its own window
//! rectangle before the client area starts, and the fills that put it on the
//! surface. Both answers come from one place, so a frame that is drawn and a
//! band that is reserved for it cannot disagree.
//!
//! A window server that decorates a window it manages draws part of that frame
//! itself - a title bar, a resize border - outside anything the application
//! owns. Those parts are named here and taken out of the styles the window
//! draws for itself, exactly as the styles a decorating server draws are taken
//! out of the rectangle a client surface is given.

use alloc::vec::Vec;
use crate::win32_gdi::SystemColor;
use crate::win32_menu::draw::{edge_extent, rect_edge, MenuDrawOp, BDR_SUNKENOUTER, BF_RECT, EDGE_RAISED, EDGE_SUNKEN};
use crate::win32_menu::MenuRect;
use super::styles::{WS_BORDER, WS_CAPTION, WS_DLGFRAME, WS_EX_CLIENTEDGE, WS_EX_DLGMODALFRAME, WS_EX_STATICEDGE, WS_MINIMIZE, WS_THICKFRAME};

/// Frame dimensions, in pixels, from the metric owner: the resize border, the
/// dialog frame inside it, one edge of a raised or sunken border, and the
/// padding a resize border carries beyond the dialog frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameMetrics { pub frame: i32, pub dlg_frame: i32, pub edge: i32, pub padded_border: i32 }

/// Styles whose frame a decorating window server draws for a window it
/// manages: the title bar and the resize border around it.
pub const SERVER_STYLES: u32 = WS_CAPTION | WS_THICKFRAME;
/// Extended styles of that same server-drawn border.
pub const SERVER_EX_STYLES: u32 = WS_EX_DLGMODALFRAME;

/// The styles whose frame the window draws for itself. A window the server
/// decorates keeps only the parts the server does not draw; every other
/// window draws its whole frame. # C: O(1)
pub const fn own_styles(style: u32, ex_style: u32, decorated: bool) -> (u32, u32) {
    if decorated { (style & !SERVER_STYLES, ex_style & !SERVER_EX_STYLES) } else { (style, ex_style) }
}

/// A static outer frame is the one border drawn before any other, and only
/// when no modal frame replaces it. # C: O(1)
pub const fn static_outer_frame(ex_style: u32) -> bool {
    ex_style & (WS_EX_DLGMODALFRAME | WS_EX_STATICEDGE) == WS_EX_STATICEDGE
}

/// Whether the window carries the raised outer edge a sizing or dialog frame
/// is drawn inside. # C: O(1)
pub const fn big_frame(style: u32, ex_style: u32) -> bool {
    style & (WS_THICKFRAME | WS_DLGFRAME) != 0 || ex_style & WS_EX_DLGMODALFRAME != 0
}

/// How far the client area sits inside the window rectangle for the frame the
/// window draws itself, before any menu bar. Minimised windows have no client
/// area to inset. # C: O(1)
pub const fn client_inset(style: u32, ex_style: u32, m: FrameMetrics) -> i32 {
    if style & WS_MINIMIZE != 0 { return 0; }
    let mut inset = if ex_style & (WS_EX_STATICEDGE | WS_EX_DLGMODALFRAME) == WS_EX_STATICEDGE { 1 }
        else if ex_style & WS_EX_DLGMODALFRAME != 0 || style & (WS_THICKFRAME | WS_DLGFRAME) != 0 { 2 } else { 0 };
    if style & WS_THICKFRAME != 0 { inset += m.frame - m.dlg_frame + m.padded_border; }
    if style & (WS_BORDER | WS_DLGFRAME) != 0 || ex_style & WS_EX_DLGMODALFRAME != 0 { inset += 1; }
    if ex_style & WS_EX_CLIENTEDGE != 0 { inset += m.edge; }
    inset
}

/// The colour the border inside the outer edge is drawn in. # C: O(1)
const fn border_color(style: u32, ex_style: u32) -> SystemColor {
    if ex_style & (WS_EX_DLGMODALFRAME | WS_EX_CLIENTEDGE) != 0 { SystemColor::Face }
    else if ex_style & WS_EX_STATICEDGE != 0 { SystemColor::WindowFrame }
    else if style & (WS_DLGFRAME | WS_THICKFRAME) != 0 { SystemColor::Face }
    else { SystemColor::WindowFrame }
}

/// One band of `width` around the inside of `rect`, in `color`. # C: O(1)
fn band(rect: MenuRect, width: i32, height: i32, color: SystemColor, into: &mut Vec<MenuDrawOp>) {
    if width <= 0 || height <= 0 { return; }
    let mut push = |rect: MenuRect| into.push(MenuDrawOp::Fill { rect, color });
    push(MenuRect { bottom: rect.top.saturating_add(height), ..rect });
    push(MenuRect { right: rect.left.saturating_add(width), ..rect });
    push(MenuRect { top: rect.bottom.saturating_sub(height), ..rect });
    push(MenuRect { left: rect.right.saturating_sub(width), ..rect });
}

/// Shrink a rectangle by one drawn border on every side. # C: O(1)
const fn deflate(rect: MenuRect, width: i32, height: i32) -> MenuRect {
    MenuRect { left: rect.left + width, top: rect.top + height, right: rect.right - width, bottom: rect.bottom - height }
}

/// The frame's fills, in the order they are drawn, and the rectangle left
/// inside them: the outer edge first, then the resize border, then the border
/// or dialog frame inside it. The caller draws its caption and menu bar in
/// what is left before calling `client_edge` for the rest.
/// # C: O(1)
pub fn frame_ops(rect: MenuRect, style: u32, ex_style: u32, active: bool, m: FrameMetrics, into: &mut Vec<MenuDrawOp>) -> MenuRect {
    let mut rect = rect;
    if static_outer_frame(ex_style) {
        rect_edge(rect, BDR_SUNKENOUTER, BF_RECT, 1, into);
        rect = deflate(rect, edge_extent(BDR_SUNKENOUTER, 1), edge_extent(BDR_SUNKENOUTER, 1));
    } else if big_frame(style, ex_style) {
        rect_edge(rect, EDGE_RAISED, BF_RECT, 1, into);
        rect = deflate(rect, edge_extent(EDGE_RAISED, 1), edge_extent(EDGE_RAISED, 1));
    }
    if style & WS_THICKFRAME != 0 {
        let (width, height) = (m.frame - m.dlg_frame, m.frame - m.dlg_frame);
        band(rect, width, height, if active { SystemColor::ActiveBorder } else { SystemColor::InactiveBorder }, into);
        rect = deflate(rect, width, height);
    }
    if style & (WS_BORDER | WS_DLGFRAME) != 0 || ex_style & WS_EX_DLGMODALFRAME != 0 {
        let (width, height) = (m.dlg_frame - m.edge, m.dlg_frame - m.edge);
        band(rect, width, height, border_color(style, ex_style), into);
        rect = deflate(rect, width, height);
    }
    rect
}

/// The sunken edge a client edge draws around what is left of the frame,
/// after the caption and the menu bar have taken their bands. # C: O(1)
pub fn client_edge_ops(rect: MenuRect, ex_style: u32, into: &mut Vec<MenuDrawOp>) -> MenuRect {
    if ex_style & WS_EX_CLIENTEDGE == 0 { return rect; }
    rect_edge(rect, EDGE_SUNKEN, BF_RECT, 1, into);
    deflate(rect, edge_extent(EDGE_SUNKEN, 1), edge_extent(EDGE_SUNKEN, 1))
}

#[cfg(test)]
#[path = "tests/nonclient_frame.rs"]
mod tests;
