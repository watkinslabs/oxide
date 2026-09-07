//! What one queued keyboard message becomes before the application sees it:
//! the side-specific virtual keys collapse onto their generic form, and a
//! removing retrieval turns three of them into a message of their own.
use super::uapi::*;
use super::ladder::ProcCall;
use super::super::WinMessage;

/// What the retrieval does with the message the stage prepared.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyOutcome {
    /// Outside the caller's message range: drop it and retrieve again.
    Filtered,
    Deliver,
}

/// The extra message a removing retrieval makes out of one key, and whether it
/// is posted to the queue or sent straight into the window procedure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyExtra { pub call: ProcCall, pub post: bool }

/// What the keyboard stage reads beyond the message itself. # C: O(1)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyContext {
    /// The retrieval removes the message rather than only looking at it; only
    /// a removing retrieval makes the extra messages.
    pub remove: bool,
    /// The message names the desktop window, which takes no help key.
    pub desktop: bool,
    /// Menu tracking is running, which owns the applications key itself.
    pub menu_active: bool,
    pub first: u32,
    pub last: u32,
}

/// One prepared keyboard message and the decision that goes with it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyPrepared { pub outcome: KeyOutcome, pub message: WinMessage, pub extra: Option<KeyExtra> }

/// Collapse the side-specific modifiers onto the generic key the application
/// is told about. # C: O(1)
pub const fn generic_key(vkey: u64) -> u64 {
    match vkey {
        VK_LSHIFT | VK_RSHIFT => VK_SHIFT,
        VK_LCONTROL | VK_RCONTROL => VK_CONTROL,
        VK_LMENU | VK_RMENU => VK_MENU,
        other => other,
    }
}

/// # C: O(1)
const fn is_key_transition(message: u32) -> bool { matches!(message, WM_KEYDOWN | WM_KEYUP | WM_SYSKEYDOWN | WM_SYSKEYUP) }

/// Prepare one queued keyboard message. # C: O(1)
pub fn prepare(queued: WinMessage, ctx: &KeyContext) -> KeyPrepared {
    let mut message = queued;
    if is_key_transition(queued.message) { message.wparam = generic_key(queued.wparam); }
    if message.message < ctx.first || message.message > ctx.last {
        return KeyPrepared { outcome: KeyOutcome::Filtered, message, extra: None };
    }
    let extra = if ctx.remove { extra_for(message, ctx) } else { None };
    KeyPrepared { outcome: KeyOutcome::Deliver, message, extra }
}

/// The three keys a removing retrieval turns into a message of their own: the
/// help key, the application-command keys, and the applications key. # C: O(1)
fn extra_for(message: WinMessage, ctx: &KeyContext) -> Option<KeyExtra> {
    let hwnd = message.hwnd?.raw();
    if message.message == WM_KEYDOWN && message.wparam == VK_F1 && !ctx.desktop {
        return Some(KeyExtra { call: ProcCall { hwnd, message: WM_KEYF1, wparam: 0, lparam: 0 }, post: true });
    }
    if message.message == WM_KEYDOWN && (VK_BROWSER_BACK..=VK_LAUNCH_APP2).contains(&message.wparam) {
        let command = (message.wparam - VK_BROWSER_BACK + 1) as u32;
        return Some(KeyExtra { call: ProcCall { hwnd, message: WM_APPCOMMAND, wparam: hwnd as u64,
            lparam: make_point(0, (FAPPCOMMAND_KEY | command) as i32) }, post: false });
    }
    if message.message == WM_KEYUP && message.wparam == VK_APPS && !ctx.menu_active {
        return Some(KeyExtra { call: ProcCall { hwnd, message: WM_CONTEXTMENU, wparam: hwnd as u64, lparam: -1 }, post: true });
    }
    None
}
