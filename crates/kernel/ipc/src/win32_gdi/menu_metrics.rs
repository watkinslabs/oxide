//! Cells one menu bar and its popups are measured with, taken from the
//! nonclient profile's menu font rather than from the face a device context
//! happens to carry. The same font is selected into the device context the
//! items draw through, so an item rectangle and the run inside it are
//! measured by one face.
//!
//! The reference measures each label with the selected menu font's own text
//! extent. A real proportional extent here would have to be answered by the
//! font backend, which the kernel can only reach through an asynchronous
//! redirect, and the nonclient calculation that needs the band height runs
//! inside the caller's message. The measurement therefore reads the selected
//! font's published metrics, which is the same owner `GetTextExtentPoint32W`
//! answers a caller from, so the layout and a caller's own measurement of the
//! same label cannot disagree.
use super::{font_text_metrics, menu_font, Font, GdiError, GdiManager, MENU_HEIGHT};

/// Rows the menu band clears above the menu font's own cell. The normalized
/// profile floors its stored menu height by the same margin over the face's
/// cell height.
const BAND_MARGIN: i32 = 2;

/// Rows the band adds above the tallest item it holds.
const BAND_BORDER: i32 = 1;

/// Cells one menu is measured with, and the band a bar of them claims.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MenuMetrics { pub char_width: i32, pub char_height: i32, pub bar_height: i32 }

/// Measure one face for menu use: the average advance and cell height it
/// reports, and the band a bar drawn in it claims. The band is the profile's
/// menu height, raised when the face is too tall to sit in it, plus the one
/// row of top border a bar begins with. # C: O(1)
pub fn menu_metrics(font: Option<Font>) -> MenuMetrics {
    let metrics = font_text_metrics(font);
    let menu_height = MENU_HEIGHT.max(BAND_MARGIN.saturating_add(metrics.height));
    MenuMetrics { char_width: metrics.character_width, char_height: metrics.height,
        bar_height: menu_height.saturating_add(BAND_BORDER) }
}

/// Cells the profile's menu font measures every menu with. # C: O(1)
pub fn menu_bar_metrics() -> MenuMetrics { menu_metrics(menu_font()) }

impl GdiManager {
    /// The process's menu font object, created once and reused by every menu
    /// paint the way the reference keeps one menu `HFONT` per process. A
    /// deleted or restyled face is replaced rather than handed back.
    /// # C: O(N_objects)
    pub fn menu_face(&mut self) -> Result<u32, GdiError> {
        let font = menu_font().ok_or(GdiError::NoSuchObject)?;
        if let Some((handle, cached)) = self.menu_face {
            if cached == font && self.contains_object(handle) { return Ok(handle); }
        }
        let handle = self.create_font(font)?;
        self.menu_face = Some((handle, font));
        Ok(handle)
    }
}

#[cfg(test)]
#[path = "tests/menu_metrics.rs"]
mod tests;
