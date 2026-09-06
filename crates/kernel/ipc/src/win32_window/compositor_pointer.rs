//! Absolute compositor input mutates the canonical cursor, buttons and queues.
use super::*;

const WM_XBUTTONDOWN: u32 = 0x020b;
const WM_XBUTTONUP: u32 = 0x020c;
const MK_SHIFT: u16 = 0x0004;
const MK_CONTROL: u16 = 0x0008;
const MK_XBUTTON1: u16 = 0x0020;
const MK_XBUTTON2: u16 = 0x0040;
const XBUTTON1: u32 = 1;
const XBUTTON2: u32 = 2;
const MODIFIERS: u16 = MK_SHIFT | MK_CONTROL;
const BUTTONS: u16 = MK_LBUTTON | MK_RBUTTON | MK_MBUTTON | MK_XBUTTON1 | MK_XBUTTON2;
const POINTER_FLAGS: u32 = (MODIFIERS | BUTTONS) as u32;
const MAX_MESSAGES: usize = 7;
const TRANSITIONS: [(u16, u32, u32, u32); 5] = [
    (MK_LBUTTON, WM_LBUTTONDOWN, WM_LBUTTONUP, 0),
    (MK_RBUTTON, WM_RBUTTONDOWN, WM_RBUTTONUP, 0),
    (MK_MBUTTON, WM_MBUTTONDOWN, WM_MBUTTONUP, 0),
    (MK_XBUTTON1, WM_XBUTTONDOWN, WM_XBUTTONUP, XBUTTON1),
    (MK_XBUTTON2, WM_XBUTTONDOWN, WM_XBUTTONUP, XBUTTON2),
];

impl WindowManager {
    /// Client-relative source coordinates become screen cursor state; capture
    /// redirects delivery, not coordinate origin. Wheel lParam stays screen-relative.
    /// Queue capacity is admitted before any cursor/button/message mutation.
    /// # C: O(windows + queues); # Sleeps: no
    pub fn post_compositor_pointer(&mut self, source: WindowId, x: i32, y: i32, buttons: u32, wheel_delta: i32) -> Result<(), WindowError> {
        self.get(source).ok_or(WindowError::NoSuchWindow)?;
        let origin = self.rect(source).ok_or(WindowError::NoSuchWindow)?;
        if buttons & !POINTER_FLAGS != 0 || i16::try_from(wheel_delta).is_err() { return Err(WindowError::InvalidParent); }
        let screen = (origin.left.checked_add(x).ok_or(WindowError::InvalidParent)?,
            origin.top.checked_add(y).ok_or(WindowError::InvalidParent)?);
        let target = self.capture.unwrap_or(source);
        let owner = self.get(target).ok_or(WindowError::NoSuchWindow)?.owner_tid;
        let bounds = self.rect(target).ok_or(WindowError::NoSuchWindow)?;
        let client = (screen.0.checked_sub(bounds.left).ok_or(WindowError::InvalidParent)?,
            screen.1.checked_sub(bounds.top).ok_or(WindowError::InvalidParent)?);
        let buttons = buttons as u16;
        let mut flags = (self.buttons & BUTTONS) | (buttons & MODIFIERS);
        let mut messages = [WinMessage { hwnd: Some(target), message: 0, wparam: 0, lparam: 0 }; MAX_MESSAGES];
        let mut count = 0;
        let mut append = |message, wparam, point: (i32, i32)| {
            messages[count] = WinMessage { hwnd: Some(target), message, wparam, lparam: mouse_lparam(point.0, point.1) };
            count += 1;
        };
        if screen != self.cursor || (self.buttons ^ buttons) & MODIFIERS != 0 {
            append(WM_MOUSEMOVE, flags as u64, client);
        }
        for (bit, down, up, xbutton) in TRANSITIONS {
            if (self.buttons ^ buttons) & bit == 0 { continue; }
            let pressed = buttons & bit != 0;
            if pressed { flags |= bit; } else { flags &= !bit; }
            append(if pressed { down } else { up }, flags as u64 | ((xbutton as u64) << 16), client);
        }
        if wheel_delta != 0 {
            append(WM_MOUSEWHEEL, buttons as u64 | (((wheel_delta as i16 as u16) as u64) << 16), screen);
        }
        if !self.queue_has_capacity(owner, count) { return Err(WindowError::QueueFull); }
        for message in &messages[..count] { self.post_to_window(target, *message)?; }
        self.cursor = screen; self.buttons = buttons;
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/compositor_pointer.rs"]
mod tests;
