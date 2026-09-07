//! Extended pen admission: the style, width and brush combinations a pen may
//! carry, decided before any handle is allocated.
use super::{GdiManager, GdiError, DashPattern, PS_NULL};

/// Which of the nine line styles the pen draws.
pub const PS_STYLE_MASK: u32 = 0x0000_000f;
/// Whether the pen is cosmetic or geometric.
pub const PS_TYPE_MASK: u32 = 0x000f_0000;
/// A geometric pen scales with the world transform and may carry a brush.
pub const PS_GEOMETRIC: u32 = 0x0001_0000;
/// The caller supplies its own dash pattern.
pub const PS_USERSTYLE: u32 = 7;
/// One-pixel alternating dashes; cosmetic pens only.
pub const PS_ALTERNATE: u32 = 8;
/// Inside-frame line style; geometric pens only.
pub const PS_INSIDEFRAME: u32 = 6;

/// Solid brush fill.
pub const BS_SOLID: u32 = 0;
/// No brush fill at all.
pub const BS_NULL: u32 = 1;

/// The longest dash pattern a user-styled pen may carry.
pub const MAX_STYLE_ENTRIES: usize = 16;
/// The only width a cosmetic pen may have.
const COSMETIC_WIDTH: u32 = 1;
/// An alternating pen draws the geometric dot pattern: one unit on, one off.
const ALTERNATE_PATTERN: [u32; 2] = [1, 1];
/// A cosmetic user style is measured in three-unit steps.
const COSMETIC_STYLE_SCALE: u32 = 3;

/// What an extended pen request resolves to before any object is created.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtPenRequest {
    /// The request names the stock null pen rather than a new object.
    Null,
    /// Create a pen with this line style, width and colour.
    Create { style: u32, width: u32, color: u32 },
}

/// Decide an extended pen request. A user style is admitted only for the
/// user-style line style, only up to sixteen entries, and — for a geometric pen
/// — only when no entry is negative and at least one is non-zero. A cosmetic
/// pen must be one unit wide and solid-brushed; a geometric one with a null
/// brush is the stock null pen. # C: O(N_style_entries)
pub fn admit_ext_pen(style: u32, width: u32, brush_style: u32, color: u32, style_entries: &[u32])
    -> Result<ExtPenRequest, GdiError> {
    let geometric = style & PS_TYPE_MASK == PS_GEOMETRIC;
    if !style_entries.is_empty() && style & PS_STYLE_MASK != PS_USERSTYLE { return Err(GdiError::InvalidDimensions); }
    match style & PS_STYLE_MASK {
        PS_NULL => return Ok(ExtPenRequest::Null),
        0..=4 => {}
        PS_USERSTYLE => {
            if style_entries.is_empty() { return Err(GdiError::InvalidDimensions); }
            if style_entries.len() > MAX_STYLE_ENTRIES { return Err(GdiError::InvalidDimensions); }
            if geometric {
                let negative = style_entries.iter().any(|entry| (*entry as i32) < 0);
                let all_zero = style_entries.iter().all(|entry| *entry == 0);
                if negative || all_zero { return Err(GdiError::InvalidDimensions); }
            }
        }
        PS_INSIDEFRAME => if !geometric { return Err(GdiError::InvalidDimensions); },
        PS_ALTERNATE => if geometric { return Err(GdiError::InvalidDimensions); },
        _ => return Err(GdiError::InvalidDimensions),
    }
    if geometric {
        if brush_style == BS_NULL { return Ok(ExtPenRequest::Null); }
    } else {
        if width != COSMETIC_WIDTH { return Err(GdiError::InvalidDimensions); }
        if brush_style != BS_SOLID { return Err(GdiError::InvalidDimensions); }
    }
    Ok(ExtPenRequest::Create { style: style & PS_STYLE_MASK, width: (width as i32).unsigned_abs(), color })
}

impl GdiManager {
    /// Create an extended pen, or report the stock null pen the request
    /// resolves to. # C: O(N_style_entries + pens)
    pub fn create_ext_pen(&mut self, style: u32, width: u32, brush_style: u32, color: u32,
        style_entries: &[u32]) -> Result<u32, GdiError> {
        let geometric = style & PS_TYPE_MASK == PS_GEOMETRIC;
        match admit_ext_pen(style, width, brush_style, color, style_entries)? {
            ExtPenRequest::Null => self.create_pen(PS_NULL as i32, 0, color),
            ExtPenRequest::Create { style, width, color } => {
                // The two extended line styles carry their dashes with them:
                // an alternating pen is the geometric dot pattern, and a
                // user-styled cosmetic pen scales its entries threefold.
                let pattern = match style {
                    PS_ALTERNATE => DashPattern::new(&ALTERNATE_PATTERN, 1),
                    PS_USERSTYLE => DashPattern::new(style_entries, if geometric { 1 } else { COSMETIC_STYLE_SCALE }),
                    _ => DashPattern::default(),
                };
                self.create_pen_pattern(style, width as i32, color, pattern)
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/ext.rs"]
mod tests;
