//! Which message one hardware key transition becomes, and the character
//! message the text that follows it becomes.
//!
//! The keyboard source reports a transition, never a message: the decision
//! between the ordinary and the system form of a key message belongs to the
//! owner of the desktop's key state, because it reads the state as it stood
//! *before* the transition, while the lParam context bit reports the state
//! *after* it. A source that sampled its own modifier state could only report
//! one of the two, so it reports neither.

/// Ordinary and system key messages, and the two character messages the text
/// following a key transition becomes.
pub(crate) const WM_KEYDOWN: u32 = 0x0100;
pub(crate) const WM_KEYUP: u32 = 0x0101;
pub(crate) const WM_CHAR: u32 = 0x0102;
pub(crate) const WM_SYSKEYDOWN: u32 = 0x0104;
pub(crate) const WM_SYSKEYUP: u32 = 0x0105;
pub(crate) const WM_SYSCHAR: u32 = 0x0106;

/// The lParam context bit: the Alt state after this transition.
pub(crate) const KEY_ALT: u32 = 1 << 29;

const VK_MENU: u8 = 0x12;
const VK_F10: u8 = 0x79;
const VK_LCONTROL: u8 = 0xa2;
const VK_RCONTROL: u8 = 0xa3;
const VK_LMENU: u8 = 0xa4;
const VK_RMENU: u8 = 0xa5;
const VK_CONTROL: u8 = 0x11;

/// The message one transition becomes, and the Alt context bit its lParam
/// carries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KeyDecision { pub message: u32, pub alt_context: bool }

/// Desktop-wide modifier state, plus the latch that says an Alt press has not
/// been broken by another key. Alt is released as a system key only while that
/// latch stands, which is what keeps a shortcut's Alt release from opening a
/// menu.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct SysKeyLatch {
    lmenu: bool, rmenu: bool, lcontrol: bool, rcontrol: bool,
    alt_pressed: bool,
    /// The key-down this process last decided, which the characters that
    /// follow it are translated against.
    pending_char: Option<(bool, i64)>,
}

impl SysKeyLatch {
    /// # C: O(1)
    fn alt(&self) -> bool { self.lmenu || self.rmenu }
    /// # C: O(1)
    fn control(&self) -> bool { self.lcontrol || self.rcontrol }
    /// # C: O(1)
    fn track(&mut self, vk: u8, pressed: bool) {
        match vk {
            VK_LMENU => self.lmenu = pressed,
            VK_RMENU => self.rmenu = pressed,
            VK_MENU => { self.lmenu = pressed; self.rmenu = pressed && self.rmenu; }
            VK_LCONTROL => self.lcontrol = pressed,
            VK_RCONTROL => self.rcontrol = pressed,
            VK_CONTROL => { self.lcontrol = pressed; self.rcontrol = pressed && self.rcontrol; }
            _ => {}
        }
    }

    /// Decide one key transition. The state read is the state before the
    /// transition; the context bit reported is the state after it.
    /// # C: O(1)
    pub(crate) fn key(&mut self, vk: u8, pressed: bool) -> KeyDecision {
        let ordinary = if pressed { WM_KEYDOWN } else { WM_KEYUP };
        let system = if pressed { WM_SYSKEYDOWN } else { WM_SYSKEYUP };
        let message = match vk {
            VK_LMENU | VK_RMENU | VK_MENU => {
                if pressed {
                    // Alt held with Control is the level-three modifier of a
                    // layout, not a system key.
                    if self.control() { ordinary } else { self.alt_pressed = true; system }
                } else if self.alt() && self.alt_pressed { self.alt_pressed = false; system } else { ordinary }
            }
            VK_LCONTROL | VK_RCONTROL | VK_CONTROL => {
                if !pressed && self.alt() { self.alt_pressed = false; system } else { ordinary }
            }
            VK_F10 => { self.alt_pressed = false; system }
            _ => {
                if !self.control() && self.alt() { self.alt_pressed = false; system } else { ordinary }
            }
        };
        self.track(vk, pressed);
        KeyDecision { message, alt_context: self.alt() }
    }

    /// Remember the key-down the following text belongs to. # C: O(1)
    pub(crate) fn note_key_message(&mut self, message: u32, lparam: i64) {
        self.pending_char = match message {
            WM_KEYDOWN => Some((false, lparam)),
            WM_SYSKEYDOWN => Some((true, lparam)),
            _ => None,
        };
    }

    /// The character message the text following the last key-down becomes, and
    /// the lParam it carries. Text with no key-down before it is an ordinary
    /// character with a single repeat count. # C: O(1)
    pub(crate) fn char_message(&mut self) -> (u32, i64) {
        match self.pending_char.take() {
            Some((true, lparam)) => (WM_SYSCHAR, lparam),
            Some((false, lparam)) => (WM_CHAR, lparam),
            None => (WM_CHAR, 1),
        }
    }
}

#[cfg(test)]
#[path = "tests/key_message.rs"]
mod tests;
