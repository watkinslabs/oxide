//! The kernel-owned text run one menu item draws: where its glyphs start
//! inside the item rectangle, and the record the font backend is entered
//! with. Ungated, so the placement and the record are checked without the
//! Task binding the run itself needs (`53§2`).
use ipc::win32_gdi::{Font, MenuCells, TextState};
use ipc::win32_menu::draw::MenuTextAlign;
use ipc::win32_menu::MenuRect;
use syscall::nt_native_gdi::{TextRequest, TRANSPARENT, VERSION};

/// Thickness of the rule drawn under a mnemonic character.
pub(crate) const UNDERLINE_RULE: i32 = 1;
/// Rows between the run's baseline and the rule under it.
const UNDERLINE_DROP: i32 = 1;

/// Width one run covers under the menu face's own advances, which is the same
/// extent the layout that produced the item rectangles measured the label
/// with. # C: O(N_units)
pub(crate) fn run_width(units: &[u16], cells: &MenuCells) -> i32 { cells.extent(units) }

/// Where one run's glyphs start inside `rect`: a bar item centres its text, a
/// popup name starts at the left edge, an accelerator half flushed right ends
/// at the right edge, and every run is centred vertically on the glyph height
/// the device context reports. # C: O(1)
pub(crate) fn origin(rect: MenuRect, units: &[u16], align: MenuTextAlign, cells: &MenuCells, glyph_height: i32) -> (i32, i32) {
    let width = run_width(units, cells);
    let x = match align {
        MenuTextAlign::Left => rect.left,
        MenuTextAlign::Center => rect.left + ((rect.right - rect.left) - width).max(0) / 2,
        MenuTextAlign::Right => rect.right.saturating_sub(width).max(rect.left),
    };
    let y = rect.top + ((rect.bottom - rect.top) - glyph_height).max(0) / 2;
    (x, y)
}

/// The rule drawn under the mnemonic character of one run: it spans that
/// character's own advance less its last pixel column, one row below the
/// baseline the ascent names. The characters ahead of it are measured by their
/// own advances, so the rule sits under the marked glyph and not under
/// whatever a fixed cell would place there. # C: O(N_units)
pub(crate) fn underline(rect: MenuRect, units: &[u16], mnemonic: usize, align: MenuTextAlign, cells: &MenuCells, glyph_height: i32, ascent: i32) -> MenuRect {
    let (x, y) = origin(rect, units, align, cells, glyph_height);
    let left = x.saturating_add(run_width(units.get(..mnemonic).unwrap_or(units), cells));
    let width = run_width(units.get(mnemonic..mnemonic + 1).unwrap_or(&[]), cells);
    let top = y.saturating_add(ascent).saturating_add(UNDERLINE_DROP);
    MenuRect { left, top, right: left.saturating_add(width).saturating_sub(1), bottom: top.saturating_add(UNDERLINE_RULE) }
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
pub(crate) fn request(dc: u64, rect: MenuRect, units: &[u16], align: MenuTextAlign, cells: &MenuCells, foreground: u32,
    state: &TextState, glyph_height: i32) -> TextRequest {
    let (height, width, weight, italic) = face(state.font, glyph_height);
    let (x, y) = origin(rect, units, align, cells, glyph_height);
    TextRequest { version: VERSION, size: core::mem::size_of::<TextRequest>() as u32,
        dc, x, y, flags: 0, count: units.len() as u32, text: 0, advances: 0, rect: [0; 4],
        height, width, weight, italic, foreground, background: state.attributes.background,
        has_rect: 0, reserved: 0, background_mode: TRANSPARENT, alignment: state.attributes.alignment,
        current_x: state.attributes.current_position.0, current_y: state.attributes.current_position.1,
        break_extra: state.break_extra, break_rem: state.break_rem }
}

#[cfg(test)]
#[path = "nt_menu_text/tests.rs"]
mod tests;
