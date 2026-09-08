//! The displayed cursor, the show-count, and shared OEM cursor loading.
//!
//! A cursor loaded shared from an OEM resource id answers the same handle for
//! every load, so a class registered against IDC_ARROW and a default
//! WM_SETCURSOR that reloads IDC_ARROW name one object. Every handle here is
//! an object in the process cursor/icon table; no second registry exists.
use super::{WindowError, WindowManager};
use super::cursor_object::{CursorFrame, CursorIconDesc, FrameInfo, IconInfo, LR_SHARED};

pub const IDC_ARROW: u32 = 32512;
pub const IDC_IBEAM: u32 = 32513;
pub const IDC_SIZENWSE: u32 = 32642;
pub const IDC_SIZENESW: u32 = 32643;
pub const IDC_SIZEWE: u32 = 32644;
pub const IDC_SIZENS: u32 = 32645;

/// Square edge of a builtin OEM cursor image, in pixels.
const OEM_CURSOR_EDGE: i32 = 32;

/// Cursor ids the builtin classes and the default WM_SETCURSOR name. # C: O(1)
pub const fn is_oem_cursor(id: u32) -> bool {
    matches!(id, IDC_ARROW | IDC_IBEAM | IDC_SIZENWSE | IDC_SIZENESW | IDC_SIZEWE | IDC_SIZENS)
}

/// Hotspot of one builtin OEM cursor. The arrow points from its top-left
/// corner; every other builtin is centred on its image. # C: O(1)
const fn oem_hotspot(id: u32) -> (i32, i32) {
    match id { IDC_ARROW => (0, 0), _ => (OEM_CURSOR_EDGE / 2, OEM_CURSOR_EDGE / 2) }
}

impl WindowManager {
    /// Load one shared OEM cursor, answering the handle a previous load of the
    /// same id produced. # C: O(N_cursor_objects)
    pub fn shared_oem_cursor(&mut self, id: u32) -> Result<u64, WindowError> {
        if !is_oem_cursor(id) { return Err(WindowError::InvalidParent); }
        if let Some(handle) = self.cursors.oem(id) { return Ok(handle); }
        let handle = self.cursors.alloc(false)?;
        let (hotspot_x, hotspot_y) = oem_hotspot(id);
        let frame = CursorFrame { width: OEM_CURSOR_EDGE, height: OEM_CURSOR_EDGE,
            hotspot_x, hotspot_y, color: 0, mask: 0, alpha: 0 };
        let desc = CursorIconDesc { delay: 0, num_steps: 0, num_frames: 1, frames: &[frame],
            frame_seq: &[], frame_rates: &[], flags: LR_SHARED, rsrc: id as u64 };
        self.cursors.set_data(handle, &[], None, u16::try_from(id).ok(), &desc)?;
        self.cursors.mark_oem(handle, id)?;
        Ok(handle)
    }
    /// OEM id a shared cursor handle was loaded from. # C: O(N_cursor_objects)
    pub fn oem_cursor_id(&self, handle: u64) -> Option<u32> { self.cursors.oem_id(handle) }
    /// Displayed cursor; zero when the pointer carries none. # C: O(1)
    pub fn current_cursor(&self) -> u64 { if self.cursor_count < 0 { 0 } else { self.current_cursor } }
    /// Install the displayed cursor and answer the previous one. An unknown
    /// handle is refused, matching the server-side object validation.
    /// # C: O(N_cursor_objects)
    pub fn set_current_cursor(&mut self, handle: u64) -> Result<u64, WindowError> {
        if handle != 0 && !self.cursors.contains(handle) { return Err(WindowError::NoSuchWindow); }
        Ok(core::mem::replace(&mut self.current_cursor, handle))
    }
    /// Adjust the show-count and answer the count after the change. The cursor
    /// is displayed while the count is not negative. # C: O(1)
    pub fn show_cursor(&mut self, show: bool) -> i32 {
        let increment = if show { 1 } else { -1 };
        self.cursor_count = self.cursor_count.saturating_add(increment);
        self.cursor_count
    }
    /// # C: O(1)
    pub fn cursor_showing(&self) -> bool { self.cursor_count >= 0 }
    /// Allocate one empty cursor or icon object. # C: O(N_cursor_objects)
    pub fn create_cursor_icon(&mut self, is_icon: bool) -> Result<u64, WindowError> { self.cursors.alloc(is_icon) }
    /// Fill one empty object with its frames and resource identity.
    /// # C: O(N_cursor_objects * N_steps)
    pub fn set_cursor_icon_data(&mut self, handle: u64, module: &[u16], res_name: Option<&[u16]>,
        res_id: Option<u16>, desc: &CursorIconDesc<'_>) -> Result<(), WindowError> {
        self.cursors.set_data(handle, module, res_name, res_id, desc)
    }
    /// # C: O(N_cursor_objects * N_module)
    pub fn find_existing_cursor_icon(&self, module: &[u16], rsrc: u64) -> Option<u64> { self.cursors.find_existing(module, rsrc) }
    /// # C: O(N_cursor_objects)
    pub fn icon_info(&self, handle: u64) -> Option<IconInfo> { self.cursors.icon_info(handle) }
    /// # C: O(N_cursor_objects)
    pub fn icon_resource(&self, handle: u64) -> Option<(&[u16], &[u16], Option<u16>)> { self.cursors.resource(handle) }
    /// # C: O(N_cursor_objects)
    pub fn icon_size(&self, handle: u64, step: u32) -> Option<(i32, i32)> { self.cursors.icon_size(handle, step) }
    /// # C: O(N_cursor_objects)
    pub fn icon_frame(&self, handle: u64, step: u32) -> Option<CursorFrame> { self.cursors.frame(handle, step) }
    /// # C: O(N_cursor_objects)
    pub fn cursor_frame_info(&self, handle: u64, step: u32) -> Option<FrameInfo> { self.cursors.frame_info(handle, step) }
    /// # C: O(N_cursor_objects)
    pub fn icon_param(&self, handle: u64) -> u64 { self.cursors.param(handle) }
    /// # C: O(N_cursor_objects)
    pub fn set_icon_param(&mut self, handle: u64, param: u64) -> u64 { self.cursors.set_param(handle, param) }
    /// # C: O(N_cursor_objects)
    pub fn set_icon_free_params(&mut self, handle: u64, callback: u64, param: u64) -> u64 { self.cursors.set_free_params(handle, callback, param) }
    /// # C: O(N_cursor_objects)
    pub fn icon_free_callback(&self, handle: u64) -> u64 { self.cursors.free_callback(handle) }
    /// Destroy one cursor object. The answer reports that the destroyed cursor
    /// was not the displayed one, and a shared object is never freed.
    /// # C: O(N_cursor_objects)
    pub fn destroy_cursor(&mut self, handle: u64) -> bool {
        if !self.cursors.contains(handle) { return false; }
        let displayed = self.current_cursor == handle;
        self.cursors.destroy(handle);
        !displayed
    }
}

#[cfg(test)]
#[path = "tests/cursor.rs"]
mod tests;
