//! Live caption drawing: background fill, then the caption text.
use super::super::*;
use super::raw::{background_color, draws_text, text_color, ORDINAL};
use ipc::win32_gdi::{SystemColor, TextAttribute};

/// `PATCOPY`: the pattern brush replaces the destination. Named here because
/// the raster-operation encoding is an ABI value, not a local constant.
const PATCOPY: u32 = 0x00f0_0021;
/// `TRANSPARENT` background mode leaves the filled caption behind the glyphs.
const TRANSPARENT: u32 = 1;
/// The caption text starts two pixels inside the drawn rectangle.
const TEXT_INSET: i32 = 2;
/// The entry reports failure even when it has drawn, which callers rely on.
const ALWAYS_FALSE: u64 = 0;

/// Route `NtUserDrawCaptionTemp`. # C: O(1) plus one fill and one text run
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    if ordinal != ORDINAL { return None; }
    let arg = |index: usize| args.get(index).copied().unwrap_or(0);
    Some(draw(arg(1), arg(2), arg(3), arg(5), arg(6) as u32))
}

fn read_rect(address: u64) -> Option<[i32; 4]> {
    if address == 0 { return None; }
    let mut bytes = [0u8; 16];
    uaccess::copy_from_user(&mut bytes, address).ok()?;
    let mut rect = [0i32; 4];
    for (index, slot) in rect.iter_mut().enumerate() { *slot = i32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap()); }
    Some(rect)
}

/// # C: O(1) plus one fill and one text run
fn draw(dc: u64, rect: u64, font: u64, text: u64, flags: u32) -> u64 {
    let Some(rect) = read_rect(rect) else { return ALWAYS_FALSE; };
    fill(dc, rect, background_color(flags));
    if draws_text(flags) && text != 0 { write_text(dc, rect, font, text, flags); }
    ALWAYS_FALSE
}

fn fill(dc: u64, rect: [i32; 4], color: SystemColor) {
    let Ok(brush) = crate::nt_gdi::system_color_brush_for_current(color) else { return; };
    let Ok(previous) = crate::nt_gdi::select_brush_for_current(dc, brush as u64) else { return; };
    let _ = crate::nt_gdi::pat_blt_for_current(dc, rect[0], rect[1], rect[2] - rect[0], rect[3] - rect[1], PATCOPY);
    let _ = crate::nt_gdi::select_brush_for_current(dc, previous as u64);
}

fn write_text(dc: u64, rect: [i32; 4], font: u64, text: u64, flags: u32) {
    let previous_font = if font != 0 { crate::nt_gdi::select_font_current(dc, font) } else { None };
    let foreground = crate::nt_gdi::system_color_value(text_color(flags));
    let saved = crate::nt_gdi::set_text_attribute_for_current(dc, TextAttribute::Foreground, foreground).ok();
    let saved_mode = crate::nt_gdi::set_text_attribute_for_current(dc, TextAttribute::BackgroundMode, TRANSPARENT).ok();
    let height = crate::nt_gdi::text_metrics_for_current(dc).map(|metrics| metrics.height).unwrap_or(0);
    let top = rect[1] + ((rect[3] - rect[1]) - height).max(0) / 2;
    let count = count_utf16(text);
    let _ = crate::nt_wine_window::gdi_raw::kernel::ext_text_out(dc, rect[0] + TEXT_INSET, top, 0, 0, text, count, 0, 0);
    if let Some(value) = saved { let _ = crate::nt_gdi::set_text_attribute_for_current(dc, TextAttribute::Foreground, value); }
    if let Some(value) = saved_mode { let _ = crate::nt_gdi::set_text_attribute_for_current(dc, TextAttribute::BackgroundMode, value); }
    if let Some(previous) = previous_font { let _ = crate::nt_gdi::select_font_current(dc, previous); }
}

/// The caption string is NUL-terminated; the text writer needs its length.
/// # C: O(N_characters)
fn count_utf16(address: u64) -> u32 {
    const LIMIT: u32 = 1024;
    let mut count = 0;
    while count < LIMIT {
        let Some(slot) = address.checked_add(count as u64 * 2) else { break; };
        match uaccess::get_user_u16(slot) { Ok(0) | Err(_) => break, Ok(_) => count += 1 }
    }
    count
}
