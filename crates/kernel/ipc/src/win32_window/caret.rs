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

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CaretTransition {
    pub old_hwnd: Option<WindowId>,
    pub hwnd: Option<WindowId>,
    pub old_visible: bool,
    pub new_visible: bool,
    pub old_rect: (i32, i32, i32, i32),
    pub new_rect: (i32, i32, i32, i32),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CaretError { InvalidWindow, WrongThread, NoCaret, NoQueue }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CaretCommit { pub transition: CaretTransition, pub generation: u64 }

impl Default for CaretState { fn default() -> Self { Self::new() } }

impl CaretState {
    pub const fn new() -> Self { Self { hwnd: None, width: 0, height: 0, x: 0, y: 0, hide_depth: 0, on: false } }
    pub const fn visible(self) -> bool { self.hwnd.is_some() && self.hide_depth == 0 && self.on }
    fn rect(self) -> (i32, i32, i32, i32) { (self.x, self.y, self.x.saturating_add(self.width), self.y.saturating_add(self.height)) }
    fn transition(old: Self, new: Self) -> CaretTransition { CaretTransition { old_hwnd: old.hwnd, hwnd: new.hwnd.or(old.hwnd), old_visible: old.visible(), new_visible: new.visible(), old_rect: old.rect(), new_rect: new.rect() } }
    pub fn create(&mut self, hwnd: WindowId, width: i32, height: i32) -> CaretTransition { let old = *self; let (x, y) = if old.hwnd == Some(hwnd) { (old.x, old.y) } else { (0, 0) }; *self = Self { hwnd: Some(hwnd), width, height, x, y, hide_depth: 1, on: false }; Self::transition(old, *self) }
    pub fn destroy(&mut self) -> Option<CaretTransition> { if self.hwnd.is_none() { return None; } let old = *self; *self = Self::new(); Some(Self::transition(old, *self)) }
    pub fn set_pos(&mut self, x: i32, y: i32) -> Option<CaretTransition> { if self.hwnd.is_none() { return None; } let old = *self; if old.x != x || old.y != y { self.x = x; self.y = y; self.on = true; } Some(Self::transition(old, *self)) }
    fn matches(&self, hwnd: Option<WindowId>) -> bool { hwnd.map_or(self.hwnd.is_some(), |hwnd| self.hwnd == Some(hwnd)) }
    pub fn show(&mut self, hwnd: Option<WindowId>) -> Option<CaretTransition> { if !self.matches(hwnd) { return None; } let old = *self; self.hide_depth = self.hide_depth.saturating_sub(1); self.on = true; Some(Self::transition(old, *self)) }
    pub fn hide(&mut self, hwnd: Option<WindowId>) -> Option<CaretTransition> { if !self.matches(hwnd) { return None; } let old = *self; self.hide_depth = self.hide_depth.saturating_add(1); self.on = false; Some(Self::transition(old, *self)) }
}

#[path = "caret/owner.rs"]
pub(crate) mod owner;

#[cfg(test)]
#[path = "caret/tests.rs"]
mod tests;
