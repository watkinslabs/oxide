//! Walk one menu drawing plan against a device context: the fills and glyphs
//! are written into the backing surface here, and every text run is handed to
//! the font backend the same way any other kernel-owned text run is.
use alloc::vec::Vec;
use ipc::win32_menu::draw::MenuDrawOp;
use ipc::win32_menu::mnemonic::{display_text, DisplayText};
use ipc::win32_menu::{MenuId, MenuRect, MF_BYPOSITION};
use ipc::win32_gdi::SystemColor;

/// `PATCOPY`: the pattern brush replaces the destination.
const PATCOPY: u32 = 0x00f0_0021;
/// `TRANSPARENT` leaves the fill behind the glyphs of a text run.
const TRANSPARENT: u32 = syscall::nt_native_gdi::TRANSPARENT;

/// Trace of the runs one menu plan issues and the launch status each takes.
macro_rules! bar_trace {
    ($($body:tt)*) => { #[cfg(feature = "debug-menubar")] { $($body)* } };
}

/// Move one plan rectangle into the device context's own coordinates.
fn shifted(rect: MenuRect, origin: (i32, i32)) -> MenuRect {
    MenuRect { left: rect.left + origin.0, top: rect.top + origin.1, right: rect.right + origin.0, bottom: rect.bottom + origin.1 }
}

/// Paint one rectangle of the plan. # C: O(pixels)
fn fill(dc: u64, rect: MenuRect, color: SystemColor) {
    let Ok(brush) = crate::nt_gdi::system_color_brush_for_current(color) else { return; };
    let Ok(previous) = crate::nt_gdi::select_brush_for_current(dc, u64::from(brush)) else { return; };
    let _ = crate::nt_gdi::pat_blt_for_current(dc, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top, PATCOPY);
    let _ = crate::nt_gdi::select_brush_for_current(dc, u64::from(previous));
}

/// Queue one item's text for the font backend, centred in its rectangle both
/// ways for a bar item and left-aligned in a popup. An item that marks a
/// mnemonic gets the rule under that character first, in the text colour. The run is measured with
/// the same cell metrics the layout was built from. `Some` is the redirect
/// status the syscall this pass runs under must return, so the backend enters
/// its callback with the payload the launch placed. # C: O(text units)
fn text(dc: u64, rect: MenuRect, drawn: &DisplayText, color: SystemColor, centered: bool) -> Option<u64> {
    let units = &drawn.units[..];
    if units.is_empty() { return None; }
    let state = crate::nt_gdi::text_snapshot_for_current(dc).ok()?;
    let metrics = crate::nt_gdi::text_metrics_for_current(dc).ok()?;
    if let Some(mnemonic) = drawn.mnemonic {
        let rule = crate::nt_menu_text::underline(rect, units.len(), mnemonic, centered, metrics.height, metrics.ascent);
        fill(dc, rule, color);
    }
    let foreground = crate::nt_gdi::system_color_value(color);
    let saved = crate::nt_gdi::set_text_attribute_for_current(dc, ipc::win32_gdi::TextAttribute::Foreground, foreground).ok();
    let saved_mode = crate::nt_gdi::set_text_attribute_for_current(dc, ipc::win32_gdi::TextAttribute::BackgroundMode, TRANSPARENT).ok();
    let request = crate::nt_menu_text::request(dc, rect, units.len(), centered, foreground, &state, metrics.height);
    // The run does not rasterize inside this call: it enters the font backend
    // after the syscall returns, so it goes through the thread's ordered
    // queue, which also holds this paint's present until it lands.
    let status = crate::nt_text_order::submit_for_current(request, units);
    bar_trace! {
        klog::write_raw(b"[WINDOWS-MENU-BAR] run dc="); klog::write_hex_u64(dc);
        klog::write_raw(b" units="); klog::write_hex_u64(units.len() as u64);
        klog::write_raw(b" x="); klog::write_hex_u64(request.x as i64 as u64);
        klog::write_raw(b" y="); klog::write_hex_u64(request.y as i64 as u64);
        klog::write_raw(b" height="); klog::write_hex_u64(request.height as i64 as u64);
        klog::write_raw(b" fg="); klog::write_hex_u64(u64::from(foreground));
        klog::write_raw(b" sized="); klog::write_hex_u64(request.kernel_payload_bytes().unwrap_or(0) as u64);
        klog::write_raw(b" launched="); klog::write_hex_u64(status.map_or(u64::MAX, |value| value));
        klog::write_raw(b"\n");
    }
    if let Some(value) = saved { let _ = crate::nt_gdi::set_text_attribute_for_current(dc, ipc::win32_gdi::TextAttribute::Foreground, value); }
    if let Some(value) = saved_mode { let _ = crate::nt_gdi::set_text_attribute_for_current(dc, ipc::win32_gdi::TextAttribute::BackgroundMode, value); }
    status
}

/// The displayed text of one item of one menu, under the prefix rules its
/// stored label carries. # C: O(N_items + text units)
fn item_text(menu: MenuId, position: u32) -> Option<DisplayText> {
    super::menu_raw::with_entry(|entry| {
        let item = entry.menus.item(menu, position, MF_BYPOSITION).ok()?;
        Some(display_text(&item.text))
    }).flatten()
}

/// Draw one plan, with every rectangle shifted by `origin` into the device
/// context's coordinates. `Some` is the redirect status of the one run that
/// entered the font backend from this pass; the runs behind it wait in the
/// thread's ordered queue. # C: O(N_ops * pixels)
pub(crate) fn run(dc: u64, menu: MenuId, ops: &[MenuDrawOp], origin: (i32, i32)) -> Option<u64> {
    let mut launched = None;
    for op in ops {
        match op {
            MenuDrawOp::Fill { rect, color } => fill(dc, shifted(*rect, origin), *color),
            MenuDrawOp::Glyph { points, count, color } => {
                let mut run = Vec::new();
                if run.try_reserve(*count).is_err() { continue; }
                for point in points.iter().take(*count) { run.push((point.0 + origin.0, point.1 + origin.1)); }
                let _ = crate::nt_gdi::fill_polygon_for_current(dc, &run, crate::nt_gdi::system_color_value(*color));
            }
            MenuDrawOp::Text { rect, position, color, centered, .. } => {
                let Some(drawn) = item_text(menu, *position) else { continue; };
                let status = text(dc, shifted(*rect, origin), &drawn, *color, *centered);
                if launched.is_none() { launched = status; }
            }
        }
    }
    launched
}
