//! Immutable canonical stock descriptions; no allocation or mutable registry.
use super::{Font, GdiManager, TYPE_FONT};

pub const STOCK_BIT: u32 = 0x0080_0000;
pub const FIRST_STOCK_SLOT: u32 = 32;
pub const SYSTEM_FONT: u32 = 13;
pub const DEFAULT_DC_FONT_HANDLE: u32 = STOCK_BIT | TYPE_FONT | (FIRST_STOCK_SLOT + SYSTEM_FONT);
const TYPE_BRUSH: u32 = 0x10_0000;
const TYPE_PEN: u32 = 0x30_0000;
const ANSI_CHARSET: u8 = 0;
const OEM_CHARSET: u8 = 255;
const FIXED_MODERN: u8 = 0x31;
const VARIABLE_SWISS: u8 = 0x22;
const WHITE: u32 = 0x00ff_ffff;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StockFont {
    pub logical: Font, pub face: &'static str, pub charset: u8, pub pitch_and_family: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StockStyle { Solid, Null }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StockBrush { pub style: StockStyle, pub color: u32, pub dc_color: bool }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StockPen { pub style: StockStyle, pub width: i32, pub color: u32, pub dc_color: bool }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StockDescription { Font(StockFont), Brush(StockBrush), Pen(StockPen) }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StockObject { pub index: u32, pub handle: u32, pub description: StockDescription }

fn font(height: i32, width: i32, weight: i32, face: &'static str, charset: u8, pitch: u8) -> StockDescription {
    StockDescription::Font(StockFont { logical: Font { height, width, weight, italic: false }, face, charset, pitch_and_family: pitch })
}

/// Describe one supported public stock index without materializing mutable objects. # C: O(1)
pub fn stock_object(index: u32) -> Option<StockObject> {
    let description = match index {
        0..=5 | 18 => StockDescription::Brush(StockBrush {
            style: if index == 5 { StockStyle::Null } else { StockStyle::Solid },
            color: match index { 0 | 18 => WHITE, 1 => 0x00c0_c0c0, 2 => 0x0080_8080, 3 => 0x0040_4040, _ => 0 },
            dc_color: index == 18,
        }),
        6..=8 | 19 => StockDescription::Pen(StockPen {
            style: if index == 8 { StockStyle::Null } else { StockStyle::Solid },
            width: 0, color: if index == 6 { WHITE } else { 0 }, dc_color: index == 19,
        }),
        10 => font(12, 0, 400, "", OEM_CHARSET, FIXED_MODERN),
        11 => font(12, 0, 400, "Courier", ANSI_CHARSET, FIXED_MODERN),
        12 => font(12, 0, 400, "MS Sans Serif", ANSI_CHARSET, VARIABLE_SWISS),
        13 => font(16, 7, 700, "System", ANSI_CHARSET, VARIABLE_SWISS),
        14 => font(16, 0, 700, "System", ANSI_CHARSET, VARIABLE_SWISS),
        16 => font(16, 0, 400, "Courier", ANSI_CHARSET, FIXED_MODERN),
        17 => font(-11, 0, 400, "MS Shell Dlg", ANSI_CHARSET, VARIABLE_SWISS),
        _ => return None,
    };
    let kind = match description { StockDescription::Font(_) => TYPE_FONT, StockDescription::Brush(_) => TYPE_BRUSH, StockDescription::Pen(_) => TYPE_PEN };
    Some(StockObject { index, handle: STOCK_BIT | kind | (FIRST_STOCK_SLOT + index), description })
}

/// Stock identity requires exact slot, type and stock bit, not merely a matching low word. # C: O(1)
pub fn stock_by_handle(handle: u32) -> Option<StockObject> {
    let index = (handle & super::SLOT_MASK).checked_sub(FIRST_STOCK_SLOT)?;
    stock_object(index).filter(|object| object.handle == handle)
}

impl GdiManager {
    /// Immutable stock lookup shares this owner without allocating a second object table. # C: O(1)
    pub fn stock_object(&self, index: u32) -> Option<StockObject> { stock_object(index) }
    /// Return exact stock metadata for parent selection/deletion/client projection hooks. # C: O(1)
    pub fn stock_description(&self, handle: u32) -> Option<StockDescription> { stock_by_handle(handle).map(|object| object.description) }
    /// Selected stock font resolves to its real logical description. # C: O(1)
    pub fn stock_font(&self, handle: u32) -> Option<Font> {
        match self.stock_description(handle)? { StockDescription::Font(font) => Some(font.logical), _ => None }
    }
}

#[cfg(test)]
#[path = "tests/stock.rs"]
mod tests;
