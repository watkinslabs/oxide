//! One window's own nonclient frame: the band it reserves at a size
//! calculation and the pixels it draws there at a nonclient paint.
//!
//! Both come from the one owner of what a frame is, so a control whose sunken
//! edge is drawn and a client area that was never inset for it cannot happen:
//! the edge would be drawn under the control's own content and read as no
//! edge at all.
use alloc::vec::Vec;
use ipc::win32_menu::MenuRect;
use ipc::win32_window::nonclient_frame::{client_edge_ops, client_inset, frame_ops, own_styles, FrameMetrics};
use ipc::win32_window::WindowId;
use super::owner::with_entry;

/// `SM_CXFRAME`, `SM_CXDLGFRAME`, `SM_CXEDGE`, `SM_CXPADDEDBORDER`: the frame
/// dimensions in the metric owner's own units.
const SM_CXDLGFRAME: i32 = 7;
const SM_CXFRAME: i32 = 32;
const SM_CXEDGE: i32 = 45;
const SM_CXPADDEDBORDER: i32 = 92;
/// Bytes of the `RECT` a nonclient size calculation is handed.
const NCCALCSIZE_CLIENT_RECT: usize = 16;

/// # C: O(1)
fn metrics() -> FrameMetrics {
    let metric = |index| ipc::win32_gdi::system_metric_default(index).unwrap_or(0);
    FrameMetrics { frame: metric(SM_CXFRAME), dlg_frame: metric(SM_CXDLGFRAME), edge: metric(SM_CXEDGE), padded_border: metric(SM_CXPADDEDBORDER) }
}

/// The frame one window draws for itself: the styles left after the window
/// manager's own decoration, the window's rectangle in its own coordinates,
/// and whether it holds activation. Absent when the window is gone.
/// # C: O(N_windows)
fn frame_of(hwnd: u64) -> Option<(u32, u32, MenuRect, bool)> {
    let window = WindowId::from_raw(u32::try_from(hwnd).ok()?)?;
    with_entry(|entry| {
        let record = entry.state.get(window)?;
        let (style, ex_style) = (record.style, record.ex_style);
        let rect = entry.state.rect(window)?;
        let decorated = syscall::nt_compositor::managed::at_creation(style, ex_style);
        let (style, ex_style) = own_styles(style, ex_style, decorated);
        let active = entry.state.active_window() == Some(window);
        Some((style, ex_style, MenuRect { left: 0, top: 0, right: rect.right - rect.left, bottom: rect.bottom - rect.top }, active))
    }).flatten()
}

/// Draw one window's own frame into its window-wide device context, before
/// the menu bar takes its band and the client edge is drawn inside what is
/// left. A window whose frame is entirely the window manager's draws nothing
/// and says so, leaving the nonclient message to whatever draws next.
/// # C: O(N_windows + frame pixels)
#[inline(never)]
pub(crate) fn nc_paint_for_current(hwnd: u64) -> Option<()> {
    let (style, ex_style, rect, active) = frame_of(hwnd)?;
    let (width, height) = (rect.right, rect.bottom);
    if width <= 0 || height <= 0 { return None; }
    let mut ops = Vec::new();
    let inside = frame_ops(rect, style, ex_style, active, metrics(), &mut ops);
    // The menu bar owns the band under the frame; the client edge is drawn
    // around what is left after it, which is where the client area starts.
    let bar = super::menu_raw::bar::height_for_current(hwnd, inside.right - inside.left).max(0);
    let inside = MenuRect { top: inside.top.saturating_add(bar), ..inside };
    client_edge_ops(inside, ex_style, &mut ops);
    if ops.is_empty() { return None; }
    let window = u32::try_from(hwnd).ok()?;
    let dc = crate::nt_gdi::get_dc_ex_for_current(window,0,ipc::win32_gdi::DCX_WINDOW|ipc::win32_gdi::DCX_USESTYLE);
    let handle = u32::try_from(dc).ok().filter(|handle| *handle != 0)?;
    for op in &ops {
        if let ipc::win32_menu::draw::MenuDrawOp::Fill { rect, color } = op { super::menu_draw::fill(dc, *rect, *color); }
    }
    let _ = crate::nt_gdi::release_dc_lease_for_current(handle);
    Some(())
}

/// Take the frame's own band off the rectangle one `WM_NCCALCSIZE` is
/// computing. The menu bar takes its own band from the same rectangle after
/// this, exactly as it is drawn under the frame.
/// # C: O(N_windows + usercopy)
#[inline(never)]
pub(crate) fn nc_calc_size_for_current(hwnd: u64, lparam: u64) -> Option<()> {
    if lparam == 0 { return None; }
    let (style, ex_style, _, _) = frame_of(hwnd)?;
    let inset = client_inset(style, ex_style, metrics());
    if inset <= 0 { return None; }
    let mut bytes = [0u8; NCCALCSIZE_CLIENT_RECT];
    if uaccess::copy_from_user(&mut bytes, lparam).is_err() { return None; }
    let value = |index: usize| i32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap());
    let (left, top, right, bottom) = (value(0), value(1), value(2), value(3));
    // A rectangle with no room for the frame keeps the client area it has:
    // a client rectangle turned inside out names no pixels at all.
    let (left, top) = (left.checked_add(inset)?, top.checked_add(inset)?);
    let (right, bottom) = (right.checked_sub(inset)?, bottom.checked_sub(inset)?);
    if left >= right || top >= bottom { return None; }
    for (index, value) in [left, top, right, bottom].into_iter().enumerate() {
        if uaccess::copy_to_user(lparam + index as u64 * 4, &value.to_le_bytes()).is_err() { return None; }
    }
    Some(())
}
