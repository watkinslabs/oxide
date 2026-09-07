//! Canonical immutable default nonclient profile derived from stock font metadata; 31ge§7.
use super::{stock_object, Font, StockDescription, FontRecord, GdiError};
pub const NONCLIENT_BYTES: usize = 504;
pub const NONCLIENT_LEGACY_BYTES: usize = 500;
const DEFAULT_GUI_FONT: u32 = 17;
const FONT_OFFSETS: [usize; 5] = [24, 124, 224, 316, 408];
const BORDER: i32 = 1;
const SCROLL: i32 = 16;
const CAPTION: i32 = 18;
const SMALL_CAPTION: i32 = 15;
/// Height, in pixels, the profile reserves for one menu band before the menu
/// font's own cell is measured against it.
pub const MENU_HEIGHT: i32 = 18;
/// Weight the profile gives its caption face; every other face is regular.
const CAPTION_WEIGHT: i32 = 700;
const BODY_WEIGHT: i32 = 400;
/// Half-extent, in pixels, a pointer may travel from a button press before the
/// movement counts as a drag rather than a click.
const DRAG: i32 = 4;
/// Full width and height, in pixels, of the rectangle a second click must fall
/// inside for the pair to count as a double click.
const DOUBLE_CLICK: i32 = 4;

/// Non-display scalar defaults from the same immutable profile as nonclient settings.
/// # C: O(1)
pub fn system_metric_default(index: i32) -> Option<i32> {
    Some(match index {
        2 | 3 | 9 | 10 | 20 | 21 => SCROLL.max(8),
        5 | 6 => 1, 7 | 8 => 3,
        11 | 12 | 13 | 14 => 32,
        30 => CAPTION.max(8), 32 | 33 => 3 + BORDER.max(1),
        36 | 37 => DOUBLE_CLICK,
        45 | 46 => 2, 49 | 50 => 16, 52 => SMALL_CAPTION, 54 => CAPTION,
        68 | 69 => DRAG,
        _ => return None,
    })
}

/// Snapshot the canonical default profile without creating any DC/font/brush identities.
/// # C: O(1), fixed 504-byte output
pub fn nonclient_defaults(size: u32) -> Result<[u8; NONCLIENT_BYTES], GdiError> {
    if size != NONCLIENT_BYTES as u32 && size != NONCLIENT_LEGACY_BYTES as u32 { return Err(GdiError::InvalidDimensions); }
    let Some(stock) = stock_object(DEFAULT_GUI_FONT) else { return Err(GdiError::NoSuchObject); };
    let StockDescription::Font(font) = stock.description else { return Err(GdiError::NoSuchObject); };
    let mut bytes = [0; NONCLIENT_BYTES];
    bytes[..4].copy_from_slice(&size.to_le_bytes());
    for (offset, value) in [(4, BORDER), (8, SCROLL), (12, SCROLL), (16, CAPTION), (20, CAPTION),
        (116, SMALL_CAPTION), (120, SMALL_CAPTION), (216, MENU_HEIGHT), (220, MENU_HEIGHT)] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    for (index, offset) in FONT_OFFSETS.into_iter().enumerate() {
        let mut logical = font.logical;
        logical.weight = if index == 0 { CAPTION_WEIGHT } else { BODY_WEIGHT };
        let mut record = FontRecord::from_font(logical)?.bytes();
        record[23] = 1;
        record[27] = font.pitch_and_family;
        for (i, unit) in font.face.encode_utf16().take(31).enumerate() {
            record[28 + i * 2..30 + i * 2].copy_from_slice(&unit.to_le_bytes());
        }
        bytes[offset..offset + record.len()].copy_from_slice(&record);
    }
    Ok(bytes)
}

/// Logical font the profile names for menu text. It is the same face the
/// profile's own `lfMenuFont` carries, so the face a menu is measured with and
/// the face a caller reads out of the profile are one description.
/// # C: O(1)
pub fn menu_font() -> Option<Font> {
    let StockDescription::Font(font) = stock_object(DEFAULT_GUI_FONT)?.description else { return None; };
    let mut logical = font.logical;
    logical.weight = BODY_WEIGHT;
    Some(logical)
}

#[cfg(test)]
#[path = "tests/nonclient.rs"]
mod tests;
