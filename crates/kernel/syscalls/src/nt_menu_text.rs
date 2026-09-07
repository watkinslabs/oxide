//! The kernel-owned text run one menu item draws: where its glyphs start
//! inside the item rectangle, and the record the font backend is entered
//! with. Ungated, so the placement and the record are checked without the
//! Task binding the run itself needs (`53§2`).
use ipc::win32_gdi::{Font, TextState};
use ipc::win32_menu::MenuRect;
use syscall::nt_native_gdi::{TextRequest, TRANSPARENT, VERSION};

/// Glyph advance one menu character occupies. The layout that produced the
/// item rectangles is measured with the same cell.
pub(crate) const CHAR_WIDTH: i32 = ipc::win32_gdi::MENU_CHAR_WIDTH;

/// Width one run of `units` characters covers. # C: O(1)
pub(crate) fn run_width(units: usize) -> i32 { (units as i32).saturating_mul(CHAR_WIDTH) }

/// Where one run's glyphs start inside `rect`: a bar item centres its text,
/// a popup item starts at the left edge, and both centre it vertically on the
/// glyph height the device context reports. # C: O(1)
pub(crate) fn origin(rect: MenuRect, units: usize, centered: bool, glyph_height: i32) -> (i32, i32) {
    let x = if centered { rect.left + ((rect.right - rect.left) - run_width(units)).max(0) / 2 } else { rect.left };
    let y = rect.top + ((rect.bottom - rect.top) - glyph_height).max(0) / 2;
    (x, y)
}

/// The face one run is rasterized in: the device context's selected font, or
/// the glyph height its metrics report when it has none. # C: O(1)
fn face(font: Option<Font>, glyph_height: i32) -> (i32, i32, i32, u32) {
    match font {
        Some(font) => (font.height, font.width, font.weight, font.italic as u32),
        None => (glyph_height, 0, 0, 0),
    }
}

/// The record one menu text run enters the font backend with. The unit
/// pointer stays null here: a kernel-owned run carries its units in the
/// callback payload, which is placed after the record is built, so this
/// record is admitted by `kernel_payload_bytes` and not by the user-facing
/// `valid`. # C: O(1)
pub(crate) fn request(dc: u64, rect: MenuRect, units: usize, centered: bool, foreground: u32,
    state: &TextState, glyph_height: i32) -> TextRequest {
    let (height, width, weight, italic) = face(state.font, glyph_height);
    let (x, y) = origin(rect, units, centered, glyph_height);
    TextRequest { version: VERSION, size: core::mem::size_of::<TextRequest>() as u32,
        dc, x, y, flags: 0, count: units as u32, text: 0, advances: 0, rect: [0; 4],
        height, width, weight, italic, foreground, background: state.attributes.background,
        has_rect: 0, reserved: 0, background_mode: TRANSPARENT, alignment: state.attributes.alignment,
        current_x: state.attributes.current_position.0, current_y: state.attributes.current_position.1,
        break_extra: state.break_extra, break_rem: state.break_rem }
}

#[cfg(test)]
#[path = "nt_menu_text/tests.rs"]
mod tests;
