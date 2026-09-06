//! Pure Win32 window/message state used by the native GUI adapter.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

#[path = "win32_window/compositor_pointer.rs"]
mod compositor_pointer;
#[path = "win32_window/presentation.rs"]
mod presentation;
#[path = "win32_window/compositor_queue.rs"]
mod compositor_queue;
#[path = "win32_window/keyboard.rs"]
mod keyboard;
use keyboard::{KeyboardState, QueuedMessage};
#[path = "win32_window/focus.rs"]
mod focus;
#[path = "win32_window/position.rs"]
mod position;
pub use position::{PositionOrder, WindowPosition};
#[path = "win32_window/thread_exit.rs"]
mod thread_exit;
#[path = "win32_window/class.rs"]
mod class;
#[path = "win32_window/control.rs"]
mod control;
#[path = "win32_window/extra.rs"]
mod extra;
pub use extra::GWLP_HINSTANCE;
#[path = "win32_window/property.rs"]
mod property;
#[path = "win32_window/scroll.rs"]
mod scroll;
#[path = "win32_window/caret.rs"]
mod caret;
#[path = "win32_window/paint_damage.rs"]
mod paint_damage;
pub use paint_damage::{PaintDamage, PaintRegion, RDW_INVALIDATE, RDW_INTERNALPAINT, RDW_ERASE, RDW_VALIDATE,
    RDW_NOINTERNALPAINT, RDW_NOERASE, RDW_NOCHILDREN, RDW_ALLCHILDREN, RDW_UPDATENOW, RDW_ERASENOW, RDW_FRAME, RDW_NOFRAME};
#[path = "win32_window/caret/blink.rs"]
mod caret_blink;
pub use caret_blink::{CaretBlink, ExpiredCaretCommit, CaretBlinkError, DEFAULT_CARET_BLINK_MS};
#[path = "win32_window/settings.rs"]
mod settings;
pub use settings::UserSettings;
#[path = "win32_window/dc_lease.rs"]
mod dc_lease;
pub use dc_lease::DcLeaseContext;
#[path = "win32_window/redraw.rs"]
mod redraw;
#[path = "win32_window/paint_session.rs"]
mod paint_session;
pub use paint_session::{PaintSession, PaintSessionError};
pub use redraw::PaintChildren;
pub use caret::{CaretState, CaretTransition, CaretCommit, CaretError};
pub use scroll::{ScrollInfo, ScrollState, ScrollAction, ScrollOutcome, ScrollError, SB_HORZ, SB_VERT, SB_CTL, SIF_RANGE, SIF_PAGE, SIF_POS, SIF_DISABLENOSCROLL, SIF_TRACKPOS, SIF_ALL, SIF_RETURNPREV, SCROLLINFO_BYTES, valid_bar};
pub use property::{WindowProperties, WindowProperty, PropertyName, PropertyOrigin, MAX_PROPERTY_NAME};
pub use extra::{OwnedWindow, WindowExtra, LongPtrError};
#[path = "win32_window/class_long.rs"]
mod class_long;
pub use class_long::{GCL_MENUNAME, GCLP_HBRBACKGROUND, GCLP_HCURSOR, GCLP_HICON, GCLP_HMODULE, GCL_CBWNDEXTRA, GCL_CBCLSEXTRA, GCLP_WNDPROC, GCL_STYLE, GCW_ATOM, GCLP_HICONSM};
#[path = "win32_window/cursor.rs"]
mod cursor;
#[path = "win32_window/set_cursor.rs"]
mod set_cursor;
pub use set_cursor::{SetCursorAction, SetCursorTarget, set_cursor_action, parent_gets_first_chance, split_lparam, WM_SETCURSOR};
pub use cursor::{OEM_CURSOR_BASE, IDC_ARROW, IDC_IBEAM, IDC_SIZENWSE, IDC_SIZENESW, IDC_SIZEWE, IDC_SIZENS};

pub const WM_CLOSE: u32 = 0x0010;
pub const WM_DESTROY: u32 = 0x0002;
pub const WM_MOVE: u32 = 0x0003;
pub const WM_SIZE: u32 = 0x0005;
pub const WM_KILLFOCUS: u32 = 0x0008;
pub const WM_KEYDOWN: u32 = 0x0100;
pub const WM_KEYUP: u32 = 0x0101;
pub const WM_MOUSEMOVE: u32 = 0x0200;
pub const WM_LBUTTONDOWN: u32 = 0x0201;
pub const WM_LBUTTONUP: u32 = 0x0202;
pub const WM_RBUTTONDOWN: u32 = 0x0204;
pub const WM_RBUTTONUP: u32 = 0x0205;
pub const WM_MBUTTONDOWN: u32 = 0x0207;
pub const WM_MBUTTONUP: u32 = 0x0208;
pub const WM_MOUSEWHEEL: u32 = 0x020a;
/// Sent before a window's nonclient area is created. The default handling must
/// answer TRUE: a FALSE return from this message is the documented way to
/// abort creation, so treating it as an unhandled message destroys every
/// window an application tries to open.
pub const WM_NCCREATE: u32 = 0x0081;
/// Sent as the last message of a window's life. The default handling answers
/// zero, which the unhandled arm already does.
pub const WM_NCDESTROY: u32 = 0x0082;
pub const WM_NCHITTEST: u32 = 0x0084;
pub const WM_NCACTIVATE: u32 = 0x0086;
pub const WM_PAINT: u32 = 0x000f;
pub const WM_QUIT: u32 = 0x0012;
pub const WM_SETFOCUS: u32 = 0x0007;
pub const WM_TIMER: u32 = 0x0113;
const KEY_REPEAT_COUNT_MASK: u32 = 0xffff;
const KEY_PREVIOUS_STATE: u32 = 1 << 30;
const KEY_TRANSITION_STATE: u32 = 1 << 31;
pub const HTCLIENT: i64 = 1;
pub const HTNOWHERE: i64 = 0;
pub const SW_HIDE: u32 = 0;
pub const WS_VISIBLE: u32 = 0x1000_0000;
pub const EV_KEY: u16 = 0x01;
pub const EV_REL: u16 = 0x02;
pub const REL_X: u16 = 0x00;
pub const REL_Y: u16 = 0x01;
pub const REL_WHEEL: u16 = 0x08;
pub const BTN_LEFT: u16 = 0x110;
pub const BTN_RIGHT: u16 = 0x111;
pub const BTN_MIDDLE: u16 = 0x112;
pub const MK_LBUTTON: u16 = 0x0001;
pub const MK_RBUTTON: u16 = 0x0002;
pub const MK_MBUTTON: u16 = 0x0010;

/// Encode signed client coordinates in the Win32 mouse-message lParam. # C: O(1)
pub const fn mouse_lparam(x: i32, y: i32) -> i64 {
    (((y as u16 as u32) << 16) | x as u16 as u32) as i64
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WindowId(u32);
impl WindowId {
    pub fn raw(self) -> u32 { self.0 }
    pub fn from_raw(raw: u32) -> Option<Self> { (raw != 0).then_some(Self(raw)) }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WinMessage {
    pub hwnd: Option<WindowId>,
    pub message: u32,
    pub wparam: u64,
    pub lparam: i64,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MessageFilter { pub hwnd: Option<WindowId>, pub first: u32, pub last: u32 }

/// Encode the fixed Windows keyboard `lParam` fields for one transition.
/// # C: O(1)
pub const fn key_lparam(pressed: bool, repeat: bool) -> i64 {
    let count = if repeat { 2 } else { 1 };
    let mut value = count & KEY_REPEAT_COUNT_MASK;
    if repeat || !pressed { value |= KEY_PREVIOUS_STATE; }
    if !pressed { value |= KEY_TRANSITION_STATE; }
    value as i64
}

impl MessageFilter {
    fn matches(self, message: WinMessage) -> bool {
        let last = if self.first == 0 && self.last == 0 { u32::MAX } else { self.last };
        (self.hwnd.is_none() || self.hwnd == message.hwnd)
            && message.message >= self.first && message.message <= last
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum QueueError { Full }

const MESSAGE_QUEUE_LIMIT: usize = 10_000;

#[derive(Default)]
pub struct MessageQueue { messages: VecDeque<QueuedMessage>, quit: Option<i32>, keyboard: KeyboardState, caret: CaretState, caret_generation: u64, caret_blink: CaretBlink }

impl MessageQueue {
    pub fn post(&mut self, message: WinMessage) -> Result<(), QueueError> {
        if self.messages.len() >= MESSAGE_QUEUE_LIMIT { return Err(QueueError::Full); }
        self.messages.push_back(QueuedMessage { message, key: None });
        Ok(())
    }
    pub fn peek(&mut self, filter: MessageFilter, remove: bool) -> Option<WinMessage> {
        let index = self.messages.iter().position(|entry| filter.matches(entry.message))?;
        self.read_entry(index, remove)
    }
    fn peek_matching<F>(&mut self, matches: F, remove: bool) -> Option<WinMessage>
    where F: Fn(WinMessage) -> bool {
        let index = self.messages.iter().position(|entry| matches(entry.message))?;
        self.read_entry(index, remove)
    }
    pub fn len(&self) -> usize { self.messages.len() }
    fn cleanup_window(&mut self, id: WindowId) {
        self.messages.retain(|entry| entry.message.hwnd != Some(id));
        if self.caret.hwnd == Some(id) { self.caret.destroy(); self.caret_generation = self.caret_generation.saturating_add(1); }
    }
    pub fn post_quit(&mut self, code: i32) { self.quit = Some(code); }
    fn quit_pending(&self) -> bool { self.quit.is_some() }
    fn quit_message(&mut self, filter: MessageFilter, remove: bool) -> Option<WinMessage> {
        let code = self.quit?;
        let message = WinMessage { hwnd: None, message: WM_QUIT, wparam: code as u64, lparam: 0 };
        if !filter.matches(message) { return None; }
        if remove { self.quit = None; }
        Some(message)
    }
    fn take_quit_matching<F>(&mut self, matches: F) -> Option<i32>
    where F: Fn(WinMessage) -> bool {
        let code = self.quit?;
        let message = WinMessage { hwnd: None, message: WM_QUIT, wparam: code as u64, lparam: 0 };
        if !matches(message) { return None; }
        self.quit = None;
        Some(code)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WindowRecord { pub owner_tid: u64, pub parent: Option<WindowId>, pub owner: Option<WindowId>, pub wndproc: u64, pub unicode: bool, pub class_atom: Option<u16>, pub visible: bool, pub menu: Option<u32>, pub id_menu: u64, pub presentation_ready: bool, pub style: u32, pub ex_style: u32, pub last_focus: Option<WindowId>, pub client_rect: Option<WindowRect> }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowClass { pub name: Vec<u16>, pub wndproc: u64, pub unicode: bool, pub atom: u16, pub cb_wnd_extra: u32, pub style: u32,
    /// Raw WNDCLASSEX hbrBackground: a brush handle, or a system colour index plus one.
    pub background: u64,
    /// WNDCLASSEX hCursor. The default window procedure answers WM_SETCURSOR
    /// over HTCLIENT with it, and a class registered without one declines.
    pub cursor: u64,
    pub icon: u64, pub icon_sm: u64, pub module: u64,
    /// cbClsExtra bytes, shared by every window of the class.
    pub extra: WindowExtra }

/// One WNDCLASSEXW registration. The telescoping helpers below fill the
/// fields a caller does not carry.
pub struct ClassRegistration<'a> { pub name: &'a [u16], pub wndproc: u64, pub cb_cls_extra: i32, pub cb_wnd_extra: i32,
    pub unicode: bool, pub style: u32, pub background: u64, pub cursor: u64, pub icon: u64, pub icon_sm: u64, pub module: u64 }

impl<'a> ClassRegistration<'a> {
    /// # C: O(1)
    pub const fn new(name: &'a [u16], wndproc: u64) -> Self {
        Self { name, wndproc, cb_cls_extra: 0, cb_wnd_extra: 0, unicode: true, style: 0, background: 0,
            cursor: 0, icon: 0, icon_sm: 0, module: 0 }
    }
}

const USER_ATOM_BASE: u16 = 0xc000;
const USER_ATOM_CAPACITY: usize = 0x4000;
const USER_ATOM_MAX_LENGTH: usize = 255;

/// System-wide string atoms used by RegisterWindowMessageW and the Win32
/// window-station boundary. GUI process state remains separate from this table.
struct AtomName { name: Vec<u16>, permanent: bool, property_refs: usize }

pub struct UserAtomTable { names: Vec<Option<AtomName>> }

impl UserAtomTable {
    /// Create an empty system-wide user atom table. # C: O(1)
    pub const fn new() -> Self { Self { names: Vec::new() } }

    /// Add one message name or return its existing atom. # C: O(N_atoms * N_name)
    pub fn register(&mut self, name: &[u16]) -> Option<u16> {
        if name.is_empty() || name.len() > USER_ATOM_MAX_LENGTH { return None; }
        if let Some(index) = self.names.iter().position(|entry| entry.as_ref().is_some_and(|entry| same_name(&entry.name, name))) {
            self.names[index].as_mut().unwrap().permanent = true;
            return USER_ATOM_BASE.checked_add(index as u16 + 1);
        }
        let index = self.names.iter().position(Option::is_none).unwrap_or(self.names.len());
        if index >= USER_ATOM_CAPACITY - 1 { return None; }
        let entry = Some(AtomName { name: name.to_vec(), permanent: true, property_refs: 0 });
        if index == self.names.len() { self.names.push(entry); } else { self.names[index] = entry; }
        USER_ATOM_BASE.checked_add(index as u16 + 1)
    }
}

impl Default for UserAtomTable { fn default() -> Self { Self::new() } }

/// Shared clipboard admission state for one window station.
///
/// Clipboard data is intentionally not stored here yet; this owner records
/// the server-side open transaction so later format operations cannot invent
/// a second lock beside the canonical window-station state.
pub struct ClipboardManager { open_thread: Option<u64>, open_window: Option<WindowId> }

impl ClipboardManager {
    /// Create an unopened clipboard state. # C: O(1)
    pub const fn new() -> Self { Self { open_thread: None, open_window: None } }

    /// Admit one `OpenClipboard` request using its window-station lock rule.
    /// # C: O(1)
    pub fn open(&mut self, thread: u64, window: Option<WindowId>) -> bool {
        if self.open_thread.is_some() && self.open_window != window { return false; }
        self.open_thread = Some(thread);
        self.open_window = window;
        true
    }

    /// Close the clipboard only from the thread that currently opened it.
    /// # C: O(1)
    pub fn close(&mut self, thread: u64) -> bool {
        if self.open_thread != Some(thread) { return false; }
        self.open_thread = None;
        self.open_window = None;
        true
    }

    /// Return whether this state has an active open transaction. # C: O(1)
    pub const fn is_open(&self) -> bool { self.open_thread.is_some() }
}

impl Default for ClipboardManager { fn default() -> Self { Self::new() } }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WindowRect { pub left: i32, pub top: i32, pub right: i32, pub bottom: i32 }

/// Canonical compositor input for one visible window paint transaction.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WindowPresentRecord { pub window: WindowId, pub bounds: WindowRect, pub damage: Option<WindowRect> }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WindowError { NoSuchWindow, NoMemory, InvalidParent, ClassInUse, WrongThread, NoFocus, QueueFull, PaintActive, PaintNotActive, NotVisible }

pub struct WindowManager { next: u32, next_atom: u16, classes: Vec<WindowClass>, windows: Vec<(WindowId, OwnedWindow)>, rects: Vec<(WindowId, WindowRect)>, texts: Vec<(WindowId, Vec<u16>)>, dirty: Vec<(WindowId, PaintDamage)>, painting: Vec<(WindowId, PaintSession)>, queues: Vec<(u64, MessageQueue)>, timers: Vec<WindowTimer>, focus: Option<WindowId>, capture: Option<WindowId>, cursor: (i32, i32), buttons: u16, destroying: Vec<WindowId>, keyboard: KeyboardState, active: Option<WindowId>,
    /// Shared OEM cursor cache and the cursor the pointer displays.
    cursors: Vec<(u32, u64)>, current_cursor: u64 }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct WindowTimer { owner_tid: u64, hwnd: Option<WindowId>, id: u64, period_ns: u64, due_ns: u64, proc: u64 }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum QueueResult { Message(WinMessage), Quit(i32), Empty }

impl Default for WindowManager { fn default() -> Self { Self::new() } }

#[path = "win32_window/state.rs"]
mod state;

fn message_matches_in_windows(windows: &[(WindowId, OwnedWindow)], filter: MessageFilter, message: WinMessage) -> bool {
    let range = MessageFilter { hwnd: None, first: filter.first, last: filter.last };
    if !range.matches(message) { return false; }
    let Some(filter_window) = filter.hwnd else { return true; };
    let Some(message_window) = message.hwnd else { return false; };
    let mut current = Some(message_window);
    while let Some(window) = current {
        if window == filter_window { return true; }
        current = windows.iter().find(|(candidate, _)| *candidate == window).and_then(|(_, record)| record.parent);
    }
    false
}

fn same_name(left: &[u16], right: &[u16]) -> bool {
    left.len() == right.len() && left.iter().zip(right).all(|(left, right)| {
        let fold = |unit: u16| if (b'A' as u16..=b'Z' as u16).contains(&unit) { unit + 32 } else { unit };
        fold(*left) == fold(*right)
    })
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DefaultWindowResult {
    Return(i64),
    RequestDestroy,
    /// Default WM_PAINT handling begins and ends a paint that draws nothing:
    /// the background is erased, the damage validated and the result
    /// presented. Without it the damage survives and the message is offered
    /// again immediately.
    ValidatePaint,
}

/// Return whether DispatchMessage must enter a window procedure. WM_QUIT is
/// consumed by the message loop and is never delivered to a window procedure.
/// # C: O(1)
pub const fn dispatches_to_window_proc(message: u32) -> bool { message != WM_QUIT }

pub fn default_window_proc(message: u32) -> DefaultWindowResult {
    match message {
        WM_CLOSE => DefaultWindowResult::RequestDestroy,
        WM_NCCREATE => DefaultWindowResult::Return(1),
        WM_PAINT => DefaultWindowResult::ValidatePaint,

        WM_NCHITTEST => DefaultWindowResult::Return(HTCLIENT),
        WM_NCACTIVATE => DefaultWindowResult::Return(1),
        _ => DefaultWindowResult::Return(0),
    }
}

/// Apply default handling that depends on canonical window geometry. # C: O(1)
pub fn default_window_proc_for_rect(message: u32, rect: WindowRect, lparam: i64) -> DefaultWindowResult {
    if message != WM_NCHITTEST { return default_window_proc(message); }
    let point = lparam as u64;
    let x = (point as u16 as i16) as i32;
    let y = ((point >> 16) as u16 as i16) as i32;
    let inside = x >= rect.left && x < rect.right && y >= rect.top && y < rect.bottom;
    DefaultWindowResult::Return(if inside { HTCLIENT } else { HTNOWHERE })
}

#[cfg(test)]
#[path = "win32_window/tests/state.rs"]
mod tests;
#[cfg(test)]
#[path = "win32_window/tests/lifecycle.rs"]
mod lifecycle_tests;
