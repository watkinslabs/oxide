//! Shared OEM cursor handles and the input cursor the pointer displays.
//!
//! A cursor loaded shared from an OEM resource id answers the same handle for
//! every load, so a class registered against IDC_ARROW and a default
//! WM_SETCURSOR that reloads IDC_ARROW name one object.
use super::{WindowError, WindowManager};

pub const IDC_ARROW: u32 = 32512;
pub const IDC_IBEAM: u32 = 32513;
pub const IDC_SIZENWSE: u32 = 32642;
pub const IDC_SIZENESW: u32 = 32643;
pub const IDC_SIZEWE: u32 = 32644;
pub const IDC_SIZENS: u32 = 32645;

/// First handle handed out for a shared OEM cursor. Cursor handles share no
/// numbering with window handles, so a stray HCURSOR can never name a window.
pub const OEM_CURSOR_BASE: u64 = 0x0001_0000;
const MAX_SHARED_CURSORS: usize = 32;

/// Cursor ids the builtin classes and the default WM_SETCURSOR name. # C: O(1)
pub const fn is_oem_cursor(id: u32) -> bool {
    matches!(id, IDC_ARROW | IDC_IBEAM | IDC_SIZENWSE | IDC_SIZENESW | IDC_SIZEWE | IDC_SIZENS)
}

impl WindowManager {
    /// Load one shared OEM cursor, answering the handle a previous load of the
    /// same id produced. # C: O(N_shared_cursors)
    pub fn shared_oem_cursor(&mut self, id: u32) -> Result<u64, WindowError> {
        if !is_oem_cursor(id) { return Err(WindowError::InvalidParent); }
        if let Some((_, handle)) = self.cursors.iter().find(|(cached, _)| *cached == id) { return Ok(*handle); }
        if self.cursors.len() >= MAX_SHARED_CURSORS { return Err(WindowError::NoMemory); }
        let handle = OEM_CURSOR_BASE + self.cursors.len() as u64;
        self.cursors.try_reserve(1).map_err(|_| WindowError::NoMemory)?;
        self.cursors.push((id, handle));
        Ok(handle)
    }
    /// OEM id a shared cursor handle was loaded from. # C: O(N_shared_cursors)
    pub fn oem_cursor_id(&self, handle: u64) -> Option<u32> {
        self.cursors.iter().find(|(_, cached)| *cached == handle).map(|(id, _)| *id)
    }
    /// Displayed cursor; zero when the pointer carries none. # C: O(1)
    pub fn current_cursor(&self) -> u64 { self.current_cursor }
    /// Install the displayed cursor and answer the previous one. An unknown
    /// handle is refused, matching a server-side handle validation. # C: O(N_shared_cursors)
    pub fn set_current_cursor(&mut self, handle: u64) -> Result<u64, WindowError> {
        if handle != 0 && self.oem_cursor_id(handle).is_none() { return Err(WindowError::NoSuchWindow); }
        Ok(core::mem::replace(&mut self.current_cursor, handle))
    }
}

#[cfg(test)]
#[path = "tests/cursor.rs"]
mod tests;
