//! Text attributes belong to the same canonical DC as its pixels and font.
use super::{Font, GdiError, GdiManager};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TextAttributes {
    /// Internal colors are XRGB, not Win32 COLORREF byte order.
    pub foreground: u32,
    pub background: u32,
    pub background_mode: u32,
    pub alignment: u32,
    pub current_position: (i32, i32),
}

impl Default for TextAttributes {
    fn default() -> Self {
        Self { foreground: 0, background: 0x00ff_ffff, background_mode: 2,
            alignment: 0, current_position: (0, 0) }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TextState { pub font: Option<Font>, pub attributes: TextAttributes, pub width: i32, pub height: i32 }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextAttribute { Foreground, Background, BackgroundMode, Alignment }

impl GdiManager {
    /// An owned snapshot remains valid after the caller releases the GDI lock.
    /// # C: O(DCs + fonts)
    pub fn text_state(&self, dc: u32) -> Result<TextState, GdiError> {
        let (_, state) = self.dcs.iter().find(|(handle, _)| *handle == dc).ok_or(GdiError::NoSuchObject)?;
        state.ensure_active()?;
        Ok(TextState { font: self.font_for(dc)?, attributes: state.text, width: state.width, height: state.height })
    }

    /// Return the previous value; invalid input leaves the DC unchanged.
    /// # C: O(DCs)
    pub fn set_text_attribute(&mut self, dc: u32, attribute: TextAttribute, value: u32) -> Result<u32, GdiError> {
        let (_, state) = self.dcs.iter_mut().find(|(handle, _)| *handle == dc).ok_or(GdiError::NoSuchObject)?;
        state.ensure_active()?;
        let field = match attribute {
            TextAttribute::Foreground if value <= 0x00ff_ffff => &mut state.text.foreground,
            TextAttribute::Background if value <= 0x00ff_ffff => &mut state.text.background,
            TextAttribute::BackgroundMode if value == 1 || value == 2 => &mut state.text.background_mode,
            TextAttribute::Alignment if valid_alignment(value) => &mut state.text.alignment,
            _ => return Err(GdiError::InvalidText),
        };
        Ok(core::mem::replace(field, value))
    }

    /// MoveTo/current-position updates use the same DC owner. # C: O(DCs)
    pub fn set_text_position(&mut self, dc: u32, position: (i32, i32)) -> Result<(i32, i32), GdiError> {
        let (_, state) = self.dcs.iter_mut().find(|(handle, _)| *handle == dc).ok_or(GdiError::NoSuchObject)?;
        state.ensure_active()?;
        Ok(core::mem::replace(&mut state.text.current_position, position))
    }
}

fn valid_alignment(value: u32) -> bool {
    value & !0x011f == 0 && matches!(value & 6, 0 | 2 | 6) && matches!(value & 0x18, 0 | 8 | 0x18)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_selected_font_are_snapshots_of_one_owner() {
        let mut gdi = GdiManager::new();
        let dc = gdi.create_dc(20, 30).unwrap();
        let old = gdi.text_state(dc).unwrap();
        assert_eq!(old.attributes, TextAttributes::default());
        let font = Font { height: 22, width: 11, weight: 700, italic: true };
        let handle = gdi.create_font(font).unwrap();
        gdi.select_font(dc, handle).unwrap();
        assert_eq!(gdi.text_state(dc).unwrap().font, Some(font));
        assert_eq!(old.font, gdi.stock_font(super::super::DEFAULT_DC_FONT_HANDLE));
        gdi.delete_object(handle).unwrap();
        assert_eq!(gdi.text_state(dc).unwrap().font, Some(font));
        gdi.select_font(dc, super::super::DEFAULT_DC_FONT_HANDLE).unwrap();
        assert_eq!(gdi.text_state(dc).unwrap().font, old.font);
    }

    #[test]
    fn mutation_returns_old_value_and_invalid_requests_are_atomic() {
        let mut gdi = GdiManager::new();
        let dc = gdi.create_dc(1, 1).unwrap();
        assert_eq!(gdi.set_text_attribute(dc, TextAttribute::Foreground, 0x123456), Ok(0));
        assert_eq!(gdi.set_text_attribute(dc, TextAttribute::BackgroundMode, 1), Ok(2));
        assert_eq!(gdi.set_text_position(dc, (-3, 4)), Ok((0, 0)));
        let old = gdi.text_state(dc).unwrap();
        for (kind, value) in [(TextAttribute::BackgroundMode, 3), (TextAttribute::Alignment, 4),
            (TextAttribute::Foreground, 0x0100_0000), (TextAttribute::Alignment, u32::MAX)] {
            assert_eq!(gdi.set_text_attribute(dc, kind, value), Err(GdiError::InvalidText));
            assert_eq!(gdi.text_state(dc).unwrap(), old);
        }
        assert_eq!(gdi.text_state(0), Err(GdiError::NoSuchObject));
        gdi.delete_object(dc).unwrap();
        assert_eq!(gdi.text_state(dc), Err(GdiError::NoSuchObject));
    }
}
