//! Mouse capture: the window that receives pointer input regardless of where
//! the pointer is, plus the menu-mode and move/size roles the same request
//! carries.

use super::{WinMessage, WindowError, WindowId, WindowManager};

const WM_CAPTURECHANGED: u32 = 0x0215;
/// The capture request also claims the menu-tracking role.
pub const CAPTURE_MENU: u32 = 0x0001;
/// The capture request also claims the move/size-tracking role.
pub const CAPTURE_MOVESIZE: u32 = 0x0002;

impl WindowManager {
    /// # C: O(1)
    pub fn capture_window(&self) -> Option<WindowId> { self.capture }
    /// # C: O(1)
    pub fn menu_owner(&self) -> Option<WindowId> { self.menu_owner }
    /// # C: O(1)
    pub fn move_size_window(&self) -> Option<WindowId> { self.move_size }

    /// Install or clear the capture window and answer the previous one.
    ///
    /// A window the calling thread does not own is refused; clearing is always
    /// admitted. While a menu owns the capture, only a request that also claims
    /// the menu role may change it. The previous capture window is told with
    /// WM_CAPTURECHANGED naming the new one.
    /// # C: O(N_windows + N_queues); # Sleeps: no
    pub fn set_capture_window(&mut self, tid: u64, hwnd: Option<WindowId>, flags: u32) -> Result<Option<WindowId>, WindowError> {
        if let Some(id) = hwnd {
            let record = self.get(id).ok_or(WindowError::NoSuchWindow)?;
            if record.owner_tid != tid { return Err(WindowError::WrongThread); }
        }
        if self.menu_owner.is_some() && flags & CAPTURE_MENU == 0 { return Err(WindowError::WrongThread); }
        let previous = self.capture;
        if let Some(old) = previous.filter(|old| Some(*old) != hwnd) { self.check_message_capacity(old, 1)?; }
        self.capture = hwnd;
        self.menu_owner = if flags & CAPTURE_MENU != 0 { hwnd } else { None };
        self.move_size = if flags & CAPTURE_MOVESIZE != 0 { hwnd } else { None };
        if let Some(old) = previous.filter(|old| Some(*old) != hwnd) {
            let lparam = hwnd.map_or(0, |id| id.raw() as i64);
            self.post_to_window(old, WinMessage { hwnd: Some(old), message: WM_CAPTURECHANGED, wparam: 0, lparam })?;
        }
        Ok(previous)
    }
}

#[cfg(test)]
#[path = "tests/capture.rs"]
mod tests;
