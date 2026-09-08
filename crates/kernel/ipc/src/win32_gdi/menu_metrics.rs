//! Cells one menu bar and its popups are measured with, taken from the
//! nonclient profile's menu font rather than from the face a device context
//! happens to carry. The same font is selected into the device context the
//! items draw through, so an item rectangle and the run inside it are
//! measured by one face.
//!
//! The reference measures each label with the selected menu font's own text
//! extent and pads the item by twice the face's character size, which it
//! reaches through one measurement of a fifty-two letter sample. Both numbers
//! come from `menu_cells` here: the face's advances are fetched once through
//! the font backend and every later measurement sums them in place, because
//! the nonclient calculation that needs the band height runs inside the
//! caller's own message and cannot wait on a callback. A face nothing has
//! measured yet answers its published average advance for every character,
//! which is the estimate this layout used before any face was measured.
use super::{font_text_metrics, menu_font, Font, GdiError, GdiManager, MENU_HEIGHT};
use super::menu_cells::MenuCells;
use sync::{Spinlock, TaskList};

/// Rows the menu band clears above the menu font's own cell. The normalized
/// profile floors its stored menu height by the same margin over the face's
/// cell height.
const BAND_MARGIN: i32 = 2;

/// Rows the band adds above the tallest item it holds.
const BAND_BORDER: i32 = 1;

/// The measured advances of one face, kept until the face changes. One table,
/// so the layout of a menu and the run drawn inside it are measured by the
/// same numbers.
static MEASURED: Spinlock<Option<(Font, MenuCells)>, TaskList> = Spinlock::new(None);

/// Take the advances the font backend measured for one face. # C: O(N_cells)
pub fn publish_measured_cells(font: Font, cells: MenuCells) { *MEASURED.lock() = Some((font, cells)); }

/// The advances measured for one face, absent while nothing has measured it.
/// # C: O(1)
pub fn measured_cells(font: Font) -> Option<MenuCells> {
    MEASURED.lock().filter(|(measured, _)| *measured == font).map(|(_, cells)| cells)
}

/// Whether the face a menu is measured with still has no measured advances,
/// which is what a caller checks before asking the backend for them.
/// # C: O(1)
pub fn menu_cells_wanted() -> Option<Font> {
    let font = menu_font()?;
    if measured_cells(font).is_some() { None } else { Some(font) }
}

/// Cells one menu is measured with, and the band a bar of them claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MenuMetrics { pub char_width: i32, pub char_height: i32, pub bar_height: i32, pub cells: MenuCells }

impl MenuMetrics {
    /// Cells of a face whose advance is one width for every character, which
    /// is what an unmeasured face reports. # C: O(N_cells)
    pub fn uniform(char_width: i32, char_height: i32, bar_height: i32) -> Self {
        Self { char_width, char_height, bar_height, cells: MenuCells::uniform(char_width, char_height) }
    }

    /// Cells of a face whose advances have been measured: the character size
    /// is the one the sample quotes, never a caller's guess. # C: O(1)
    pub fn measured(cells: MenuCells, bar_height: i32) -> Self {
        let (char_width, char_height) = cells.char_size();
        Self { char_width, char_height, bar_height, cells }
    }
}

/// Measure one face for menu use: the character size and cell height it
/// reports, and the band a bar drawn in it claims. The band is the profile's
/// menu height, raised when the face is too tall to sit in it, plus the one
/// row of top border a bar begins with. # C: O(N_cells)
pub fn menu_metrics(font: Option<Font>) -> MenuMetrics {
    let metrics = font_text_metrics(font);
    let cells = font.and_then(measured_cells)
        .unwrap_or_else(|| MenuCells::uniform(metrics.character_width, metrics.height));
    let (char_width, char_height) = cells.char_size();
    let menu_height = MENU_HEIGHT.max(BAND_MARGIN.saturating_add(metrics.height));
    MenuMetrics { char_width, char_height, bar_height: menu_height.saturating_add(BAND_BORDER), cells }
}

/// Cells the profile's menu font measures every menu with. # C: O(N_cells)
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

/// Serialises the tests that read the session-wide menu face against the one
/// that replaces it, because the face is one record for the whole session.
#[cfg(test)]
pub fn face_test_lock() -> &'static Spinlock<(), TaskList> {
    static LOCK: Spinlock<(), TaskList> = Spinlock::new(());
    &LOCK
}

#[cfg(test)]
#[path = "tests/menu_metrics.rs"]
mod tests;
