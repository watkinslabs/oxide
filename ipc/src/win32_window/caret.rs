//! Canonical thread-owned caret state.

use super::WindowId;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CaretState {
    pub hwnd: Option<WindowId>,
    pub width: i32,
    pub height: i32,
    pub x: i32,
    pub y: i32,
    pub hide_depth: u32,
    pub on: bool,
}

impl Default for CaretState { fn default() -> Self { Self::new() } }

impl CaretState {
    pub const fn new() -> Self { Self { hwnd: None, width: 0, height: 0, x: 0, y: 0, hide_depth: 0, on: false } }
    pub const fn visible(self) -> bool { self.hwnd.is_some() && self.hide_depth == 0 && self.on }
    pub fn create(&mut self, hwnd: WindowId, width: i32, height: i32) { *self = Self { hwnd: Some(hwnd), width, height, x: 0, y: 0, hide_depth: 0, on: false }; }
    pub fn destroy(&mut self) { *self = Self::new(); }
    pub fn set_pos(&mut self, x: i32, y: i32) -> bool { if self.hwnd.is_none() { return false; } self.x = x; self.y = y; self.on = true; true }
    pub fn show(&mut self, hwnd: WindowId) -> bool { if self.hwnd != Some(hwnd) { return false; } self.hide_depth = self.hide_depth.saturating_sub(1); self.on = true; true }
    pub fn hide(&mut self, hwnd: WindowId) -> bool { if self.hwnd != Some(hwnd) { return false; } self.hide_depth = self.hide_depth.saturating_add(1); self.on = false; true }
}

#[cfg(test)]
#[path = "caret/tests.rs"]
mod tests;
