//! Canonical immutable default nonclient profile derived from stock font metadata; 31ge§7.
use super::{stock_object, Font, StockDescription, FontRecord, GdiError, LOGFONTW_BYTES};
/// `LOGFONTW` field offsets this profile writes past the metric fields the
/// font record itself owns: the charset byte, the pitch-and-family byte, and
/// the face-name array with its unit capacity.
const CHARSET: usize = 23;
const PITCH_AND_FAMILY: usize = 27;
const FACE: usize = 28;
const FACE_UNITS: usize = 31;
pub const NONCLIENT_BYTES: usize = 504;
pub const NONCLIENT_LEGACY_BYTES: usize = 500;
const DEFAULT_GUI_FONT: u32 = 17;
use super::super::win32_sysparams::{default_pixels, table::slot, NONCLIENT_FACE_OFFSETS as FONT_OFFSETS};
/// Every dimension the profile quotes is the settings owner's own default for
/// that setting, so a client that reads one through the system-parameter entry
/// point and the profile it is drawn with cannot disagree.
const BORDER: i32 = default_pixels(slot::BORDER);
const SCROLL: i32 = default_pixels(slot::SCROLL_WIDTH);
const CAPTION: i32 = default_pixels(slot::CAPTION_HEIGHT);
const SMALL_CAPTION: i32 = default_pixels(slot::SM_CAPTION_HEIGHT);
/// Height, in pixels, the profile reserves for one menu band before the menu
/// font's own cell is measured against it.
pub const MENU_HEIGHT: i32 = default_pixels(slot::MENU_HEIGHT);
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
    let mut bytes = [0; NONCLIENT_BYTES];
    bytes[..4].copy_from_slice(&size.to_le_bytes());
    for (offset, value) in [(4, BORDER), (8, SCROLL), (12, SCROLL), (16, CAPTION), (20, CAPTION),
        (116, SMALL_CAPTION), (120, SMALL_CAPTION), (216, MENU_HEIGHT), (220, MENU_HEIGHT)] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    for (index, offset) in FONT_OFFSETS.into_iter().enumerate() {
        let record = logfont(NonclientFont::AT_OFFSET[index])?;
        bytes[offset..offset + record.len()].copy_from_slice(&record);
    }
    Ok(bytes)
}

/// One face of the nonclient profile, in the order the profile stores them.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NonclientFont { Caption, SmallCaption, Menu, Status, Message }

impl NonclientFont {
    /// Profile order, so a face and the offset it is written at cannot drift.
    pub const AT_OFFSET: [Self; 5] = [Self::Caption, Self::SmallCaption, Self::Menu, Self::Status, Self::Message];
}

/// The `LOGFONTW` record one profile face carries. The caption face is the
/// only bold one; every other face is the stock GUI description at regular
/// weight, so a caller that reads a face out of the profile and one that asks
/// for the same face by itself read one description.
/// # C: O(1)
pub fn logfont(role: NonclientFont) -> Result<[u8; LOGFONTW_BYTES], GdiError> {
    let Some(stock) = stock_object(DEFAULT_GUI_FONT) else { return Err(GdiError::NoSuchObject); };
    let StockDescription::Font(font) = stock.description else { return Err(GdiError::NoSuchObject); };
    let mut logical = font.logical;
    logical.weight = if role == NonclientFont::Caption { CAPTION_WEIGHT } else { BODY_WEIGHT };
    let mut record = FontRecord::from_font(logical)?.bytes();
    record[CHARSET] = 1;
    record[PITCH_AND_FAMILY] = font.pitch_and_family;
    for (i, unit) in font.face.encode_utf16().take(FACE_UNITS).enumerate() {
        record[FACE + i * 2..FACE + 2 + i * 2].copy_from_slice(&unit.to_le_bytes());
    }
    Ok(record)
}

/// Logical font the profile names for menu text: the live `lfMenuFont` while a
/// client has written one, and the stock description until then. It is the
/// same face the profile's own `lfMenuFont` carries, so the face a menu is
/// measured with and the face a caller reads out of the profile are one
/// description. # C: O(1)
pub fn menu_font() -> Option<Font> {
    if let Some(font) = written_face(super::super::win32_sysparams::NONCLIENT_MENU_FACE) { return Some(font); }
    stock_face()
}

/// The stock description every profile face starts from. # C: O(1)
fn stock_face() -> Option<Font> {
    let StockDescription::Font(font) = stock_object(DEFAULT_GUI_FONT)?.description else { return None; };
    let mut logical = font.logical;
    logical.weight = BODY_WEIGHT;
    Some(logical)
}

/// The face a client wrote into one profile slot, read from the settings owner
/// so a written face and the layout drawn with it cannot disagree. Absent
/// while nothing has written that slot. # C: O(1)
fn written_face(index: usize) -> Option<Font> {
    let record = *super::super::win32_sysparams::parameters().lock().nonclient_font(index)?;
    Some(FontRecord::from_bytes(record).ok()?.metrics())
}

#[cfg(test)]
#[path = "tests/nonclient.rs"]
mod tests;
