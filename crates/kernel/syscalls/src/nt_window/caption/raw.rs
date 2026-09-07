//! Caption-drawing colour selection. The flags choose one background and one
//! text colour; the geometry belongs to the caller's rectangle.
use ipc::win32_gdi::SystemColor;

pub(crate) const ORDINAL: u64 = 0x1399;

pub(crate) const DC_ACTIVE: u32 = 0x0001;
pub(crate) const DC_SMALLCAP: u32 = 0x0002;
pub(crate) const DC_ICON: u32 = 0x0004;
pub(crate) const DC_TEXT: u32 = 0x0008;
pub(crate) const DC_INBUTTON: u32 = 0x0010;
pub(crate) const DC_GRADIENT: u32 = 0x0020;
pub(crate) const DC_BUTTONS: u32 = 0x1000;

/// A caption drawn inside a button takes the dialog face; otherwise it takes
/// the active or inactive caption colour. # C: O(1)
pub(crate) const fn background_color(flags: u32) -> SystemColor {
    if flags & DC_INBUTTON != 0 { return SystemColor::Face; }
    if flags & DC_ACTIVE != 0 { SystemColor::ActiveCaption } else { SystemColor::InactiveCaption }
}

/// # C: O(1)
pub(crate) const fn text_color(flags: u32) -> SystemColor {
    if flags & DC_INBUTTON != 0 { return SystemColor::ButtonText; }
    if flags & DC_ACTIVE != 0 { SystemColor::CaptionText } else { SystemColor::InactiveCaptionText }
}

/// # C: O(1)
pub(crate) const fn draws_text(flags: u32) -> bool { flags & DC_TEXT != 0 }

#[cfg(test)]
#[path = "../tests/caption_raw.rs"]
mod tests;
