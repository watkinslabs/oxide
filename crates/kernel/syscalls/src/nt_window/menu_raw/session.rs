//! One menu-tracking session: which popup window shows which menu, whether
//! cancellation has been requested, and what the modal loop must do with the
//! message it just took off the queue.
extern crate alloc;
use alloc::vec::Vec;

pub(crate) const WM_MOUSEFIRST: u32 = 0x0200;
pub(crate) const WM_MOUSELAST: u32 = 0x0209;
pub(crate) const WM_MOUSEMOVE: u32 = 0x0200;
pub(crate) const WM_LBUTTONDOWN: u32 = 0x0201;
pub(crate) const WM_LBUTTONUP: u32 = 0x0202;
pub(crate) const WM_LBUTTONDBLCLK: u32 = 0x0203;
pub(crate) const WM_RBUTTONDOWN: u32 = 0x0204;
pub(crate) const WM_RBUTTONUP: u32 = 0x0205;
pub(crate) const WM_RBUTTONDBLCLK: u32 = 0x0206;
pub(crate) const WM_KEYFIRST: u32 = 0x0100;
pub(crate) const WM_KEYLAST: u32 = 0x0108;
pub(crate) const WM_KEYDOWN: u32 = 0x0100;
pub(crate) const WM_CHAR: u32 = 0x0102;
pub(crate) const WM_SYSKEYDOWN: u32 = 0x0104;
pub(crate) const WM_SYSCHAR: u32 = 0x0106;

pub(crate) const VK_ESCAPE: u32 = 0x1b;
pub(crate) const VK_MENU: u32 = 0x12;
pub(crate) const VK_END: u32 = 0x23;
pub(crate) const VK_HOME: u32 = 0x24;
pub(crate) const VK_LEFT: u32 = 0x25;
pub(crate) const VK_UP: u32 = 0x26;
pub(crate) const VK_RIGHT: u32 = 0x27;
pub(crate) const VK_DOWN: u32 = 0x28;
pub(crate) const VK_F10: u32 = 0x79;

/// What the modal loop does with one retrieved message.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum LoopAction {
    /// `NtUserEndMenu` asked for the loop to end.
    Cancel,
    /// A pointer event at a screen point; `down`/`up` name the transition.
    ButtonDown { point: (i32, i32), right: bool },
    ButtonUp { point: (i32, i32), right: bool },
    Move { point: (i32, i32) },
    /// Another pointer message inside the tracked range, consumed silently.
    Pointer,
    Key { vk: u32 },
    Char { ch: u16 },
    /// Anything else: taken off the queue and dropped by the loop.
    Other,
}

/// Classify one message. Pointer coordinates come from the message parameter
/// rather than the queue point, so a synthesised event is placed where it
/// says it is. # C: O(1)
pub(crate) fn classify(message: u32, wparam: u64, lparam: i64) -> LoopAction {
    if message == ipc::win32_menu::track::WM_CANCELMODE { return LoopAction::Cancel; }
    if (WM_MOUSEFIRST..=WM_MOUSELAST).contains(&message) {
        let point = ((lparam as u64 as u16 as i16) as i32, ((lparam as u64 >> 16) as u16 as i16) as i32);
        return match message {
            WM_LBUTTONDOWN | WM_LBUTTONDBLCLK => LoopAction::ButtonDown { point, right: false },
            WM_RBUTTONDOWN | WM_RBUTTONDBLCLK => LoopAction::ButtonDown { point, right: true },
            WM_LBUTTONUP => LoopAction::ButtonUp { point, right: false },
            WM_RBUTTONUP => LoopAction::ButtonUp { point, right: true },
            WM_MOUSEMOVE => LoopAction::Move { point },
            _ => LoopAction::Pointer,
        };
    }
    if (WM_KEYFIRST..=WM_KEYLAST).contains(&message) {
        return match message {
            WM_KEYDOWN | WM_SYSKEYDOWN => LoopAction::Key { vk: wparam as u32 },
            WM_CHAR | WM_SYSCHAR => LoopAction::Char { ch: wparam as u16 },
            _ => LoopAction::Other,
        };
    }
    LoopAction::Other
}

/// The cancellation record the tracking thread publishes: which window owns
/// the menu, and whether `NtUserEndMenu` has asked the loop to stop. The open
/// popup windows are the loop's own; this record carries nothing they carry.
pub(crate) struct MenuCancel { pub owner: u64, pub exit: bool }

/// The popup windows one tracking session has open, innermost last.
pub(crate) struct MenuSession { pub owner: u64, open: Vec<(u32, u64)> }

impl MenuSession {
    /// # C: O(1)
    pub(crate) fn new(owner: u64) -> Self { Self { owner, open: Vec::new() } }

    /// Retain the window showing one menu. # C: O(N_open)
    pub(crate) fn opened(&mut self, menu: u32, hwnd: u64) {
        self.open.retain(|(candidate, _)| *candidate != menu);
        self.open.push((menu, hwnd));
    }

    /// Forget the window showing one menu, reporting it. # C: O(N_open)
    pub(crate) fn closed(&mut self, menu: u32) -> Option<u64> {
        let index = self.open.iter().position(|(candidate, _)| *candidate == menu)?;
        Some(self.open.remove(index).1)
    }

    /// # C: O(N_open)
    pub(crate) fn window_of(&self, menu: u32) -> Option<u64> {
        self.open.iter().find(|(candidate, _)| *candidate == menu).map(|(_, hwnd)| *hwnd)
    }

    /// Every open popup, innermost first: the order the chain is searched for
    /// the menu a point falls on and unwound when tracking ends. # C: O(N_open)
    pub(crate) fn innermost_first(&self) -> Vec<(u32, u64)> {
        let mut chain = self.open.clone();
        chain.reverse();
        chain
    }
}

#[cfg(test)]
#[path = "../tests/menu_session.rs"]
mod tests;
