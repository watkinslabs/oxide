//! Walk one menu drawing plan against a device context: the fills and glyphs
//! are written into the backing surface here, and every text run is handed to
//! the font backend the same way any other kernel-owned text run is.
use alloc::vec::Vec;
use ipc::win32_menu::draw::MenuDrawOp;
use ipc::win32_menu::{MenuId, MenuRect, MF_BYPOSITION};
use ipc::win32_gdi::SystemColor;
use syscall::nt_native_gdi::TextRequest;

/// `PATCOPY`: the pattern brush replaces the destination.
const PATCOPY: u32 = 0x00f0_0021;
/// `TRANSPARENT` leaves the fill behind the glyphs of a text run.
const TRANSPARENT: u32 = 1;

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

/// Hand one item's text to the font backend, centred in its rectangle both
/// ways for a bar item and left-aligned in a popup. The run is measured with
/// the same cell metrics the layout was built from. # C: O(text units)
fn text(dc: u64, rect: MenuRect, units: &[u16], color: SystemColor, centered: bool) {
    if units.is_empty() { return; }
    let Ok(state) = crate::nt_gdi::text_snapshot_for_current(dc) else { return; };
    let Ok(metrics) = crate::nt_gdi::text_metrics_for_current(dc) else { return; };
    let (height, width, weight, italic) = state.font.map(|font| (font.height, font.width, font.weight, font.italic as u32))
        .unwrap_or((metrics.height, 0, 0, 0));
    let foreground = crate::nt_gdi::system_color_value(color);
    let saved = crate::nt_gdi::set_text_attribute_for_current(dc, ipc::win32_gdi::TextAttribute::Foreground, foreground).ok();
    let saved_mode = crate::nt_gdi::set_text_attribute_for_current(dc, ipc::win32_gdi::TextAttribute::BackgroundMode, TRANSPARENT).ok();
    let run = (units.len() as i32).saturating_mul(ipc::win32_gdi::MENU_CHAR_WIDTH);
    let x = if centered { rect.left + ((rect.right - rect.left) - run).max(0) / 2 } else { rect.left };
    let y = rect.top + ((rect.bottom - rect.top) - metrics.height).max(0) / 2;
    let request = TextRequest { version: syscall::nt_native_gdi::VERSION, size: core::mem::size_of::<TextRequest>() as u32,
        dc, x, y, flags: 0, count: units.len() as u32, text: 0, advances: 0, rect: [0; 4], height, width, weight, italic,
        foreground, background: state.attributes.background, has_rect: 0, reserved: 0,
        background_mode: TRANSPARENT, alignment: state.attributes.alignment,
        current_x: state.attributes.current_position.0, current_y: state.attributes.current_position.1,
        break_extra: state.break_extra, break_rem: state.break_rem };
    let _ = crate::nt_native_gdi::begin_kernel_text(request, units);
    if let Some(value) = saved { let _ = crate::nt_gdi::set_text_attribute_for_current(dc, ipc::win32_gdi::TextAttribute::Foreground, value); }
    if let Some(value) = saved_mode { let _ = crate::nt_gdi::set_text_attribute_for_current(dc, ipc::win32_gdi::TextAttribute::BackgroundMode, value); }
}

/// The displayed text of one item of one menu. # C: O(N_items + text units)
fn item_text(menu: MenuId, position: u32) -> Option<Vec<u16>> {
    super::menu_raw::with_entry(|entry| {
        let item = entry.menus.item(menu, position, MF_BYPOSITION).ok()?;
        let end = item.text.iter().position(|unit| *unit == 0).unwrap_or(item.text.len());
        let mut owned = Vec::new();
        owned.try_reserve(end).ok()?;
        owned.extend_from_slice(&item.text[..end]);
        Some(owned)
    }).flatten()
}

/// Draw one plan, with every rectangle shifted by `origin` into the device
/// context's coordinates. # C: O(N_ops * pixels)
pub(crate) fn run(dc: u64, menu: MenuId, ops: &[MenuDrawOp], origin: (i32, i32)) {
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
                let Some(units) = item_text(menu, *position) else { continue; };
                text(dc, shifted(*rect, origin), &units, *color, *centered);
            }
        }
    }
}
