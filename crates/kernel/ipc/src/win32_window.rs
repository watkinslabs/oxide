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
pub use control::{is_effective_child, menu_of};
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
pub use paint_damage::{PaintDamage, PaintRegion, region_complexity, RDW_INVALIDATE, RDW_INTERNALPAINT, RDW_ERASE, RDW_VALIDATE,
    RDW_NOINTERNALPAINT, RDW_NOERASE, RDW_NOCHILDREN, RDW_ALLCHILDREN, RDW_UPDATENOW, RDW_ERASENOW, RDW_FRAME, RDW_NOFRAME, FRAME_REDRAW};
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
#[path = "win32_window/pump_profile.rs"]
pub mod pump_profile;
#[path = "win32_window/hung.rs"]
mod hung;
pub use hung::HUNG_QUEUE_NS;
#[path = "win32_window/imc_assoc.rs"]
mod imc_assoc;
#[path = "win32_window/paint_session.rs"]
mod paint_session;
pub use paint_session::{PaintSession, PaintSessionError};
pub use redraw::PaintChildren;
pub use caret::{CaretState, CaretTransition, CaretCommit, CaretError};
pub use scroll::owner as scroll_owner;
pub use scroll::{ScrollInfo, ScrollState, ScrollAction, ScrollOutcome, ScrollError, SB_HORZ, SB_VERT, SB_CTL, SB_BOTH, ESB_ENABLE_BOTH, ESB_DISABLE_LTUP, ESB_DISABLE_RTDN, ESB_DISABLE_BOTH, SIF_RANGE, SIF_PAGE, SIF_POS, SIF_DISABLENOSCROLL, SIF_TRACKPOS, SIF_ALL, SIF_RETURNPREV, SCROLLINFO_BYTES, valid_bar};
pub use property::{WindowProperties, WindowProperty, PropertyName, PropertyOrigin, MAX_PROPERTY_NAME};
pub use extra::{OwnedWindow, WindowExtra, LongPtrError};
#[path = "win32_window/class_long.rs"]
mod class_long;
pub use class_long::{GCL_MENUNAME, GCLP_MENUNAME, GCLP_HBRBACKGROUND, GCLP_HCURSOR, GCLP_HICON, GCLP_HMODULE, GCL_CBWNDEXTRA, GCL_CBCLSEXTRA, GCLP_WNDPROC, GCL_STYLE, GCW_ATOM, GCLP_HICONSM};
#[path = "win32_window/styles.rs"]
pub mod styles;
#[path = "win32_window/tree.rs"]
mod tree;
pub use tree::{point_in_rect, HwndListFilter, CWP_ALL, CWP_SKIPDISABLED, CWP_SKIPINVISIBLE,
    CWP_SKIPTRANSPARENT, GA_PARENT, GA_ROOT, GA_ROOTOWNER, HTCLIENT, HTERROR, HTNOWHERE, HTTRANSPARENT};
#[path = "win32_window/defer.rs"]
mod defer;
pub use defer::{DeferBatches, DeferError, DeferredPosition, SWP_FRAMECHANGED, SWP_HIDEWINDOW,
    SWP_NOACTIVATE, SWP_NOCOPYBITS, SWP_NOMOVE, SWP_NOOWNERZORDER, SWP_NOREDRAW, SWP_NOSIZE,
    SWP_NOZORDER, SWP_SHOWWINDOW};
#[path = "win32_window/attributes.rs"]
mod attributes;
pub use attributes::{title_bar_state, EnableOutcome, LayeredAttributes, WindowAttributes,
    LWA_ALPHA, LWA_COLORKEY, STATE_SYSTEM_FOCUSABLE, STATE_SYSTEM_INVISIBLE, STATE_SYSTEM_UNAVAILABLE,
    TITLE_BAR_ELEMENTS, ULW_ALPHA, ULW_COLORKEY, ULW_EX_NORESIZE, ULW_OPAQUE, WDA_NONE};
#[path = "win32_window/clipboard.rs"]
mod clipboard;
pub use clipboard::{ClipboardError, ClipboardManager, ClipboardNotify, ClipFormat,
    CF_BITMAP, CF_DIB, CF_DIBV5, CF_ENHMETAFILE, CF_LOCALE, CF_MAX, CF_METAFILEPICT,
    CF_OEMTEXT, CF_PALETTE, CF_TEXT, CF_UNICODETEXT};
#[path = "win32_window/cursor.rs"]
mod cursor;
#[path = "win32_window/window_icon.rs"]
pub mod window_icon;
pub use window_icon::{get_icon, set_icon, IconSideEffect, WindowIcons, WindowIconTable, ICON_BIG, ICON_SMALL, ICON_SMALL2};
#[path = "win32_window/cursor_object.rs"]
pub mod cursor_object;
pub use cursor_object::{CursorFrame, CursorIconDesc, CursorIcons, FrameInfo, IconInfo, LR_SHARED, MAX_ANI_STEPS, OEM_CURSOR_BASE};
#[path = "win32_window/cursor_pos.rs"]
pub mod cursor_pos;
pub use cursor_pos::{clip_within, move_points_from, CursorPos, CURSOR_HISTORY};
#[path = "win32_window/capture.rs"]
pub mod capture;
pub use capture::{CAPTURE_MENU, CAPTURE_MOVESIZE};
#[path = "win32_window/hotkey.rs"]
pub mod hotkey;
pub use hotkey::{Hotkey, HotkeyError, Hotkeys, MOD_ALT, MOD_CONTROL, MOD_SHIFT, MOD_WIN};
#[path = "win32_window/thread_input.rs"]
pub mod thread_input;
pub use thread_input::{AttachError, ThreadInputs};
#[path = "win32_window/mouse_track.rs"]
pub mod mouse_track;
pub use mouse_track::{track_action, MouseTracking, MouseTracks, TrackAction, DEFAULT_HOVER_TIME, HOVER_DEFAULT, TME_CANCEL, TME_HOVER, TME_LEAVE, TME_NONCLIENT, TME_QUERY};
#[path = "win32_window/rawinput.rs"]
pub mod rawinput;
#[path = "win32_window/msg_time.rs"]
pub mod msg_time;
pub use msg_time::{tick_ms, tick_ms_from_ns};
#[path = "win32_window/window_fnid.rs"]
pub mod window_fnid;
pub use window_fnid::{fnid_proc_index, make_fnid, CLIENT_PROC_COUNT, FNID_VALID};
#[path = "win32_window/msg_pos.rs"]
pub mod msg_pos;
pub use msg_pos::{pack_pos, pos_x, pos_y};
#[path = "win32_window/pointer.rs"]
pub mod pointer;
pub use pointer::{Pointer, PointerInfo, POINTER_INFO_BYTES, POINTER_PEN_INFO_BYTES, POINTER_TOUCH_INFO_BYTES,
    PT_POINTER, PT_TOUCH, PT_PEN, PT_MOUSE, PT_TOUCHPAD, MOUSE_POINTER_ID};
#[path = "win32_window/in_send.rs"]
pub mod in_send;
pub use in_send::{receive_flags, ReceivedSend, ISMEX_NOSEND, ISMEX_REPLIED, ISMEX_SEND};
#[path = "win32_window/queue_status.rs"]
pub mod queue_status;
pub use queue_status::{hardware_bit, queue_status_result, thread_state, ThreadState, QS_ALLINPUT, QS_ALLPOSTMESSAGE, QS_INPUT, QS_KEY, QS_MOUSEBUTTON, QS_PAINT, QS_POSTED, QS_SENDMESSAGE, QS_SMRESULT, QS_TIMER};
#[path = "win32_window/kbd_tables.rs"]
pub mod kbd_tables;
#[path = "win32_window/kbd_layout.rs"]
pub mod kbd_layout;
#[path = "win32_window/kbd_state.rs"]
pub mod kbd_state;
pub use kbd_state::{activate_layout, layout_name, locale_layout, LayoutError, DEFAULT_LOCALE, KL_NAMELENGTH};
#[path = "win32_window/set_cursor.rs"]
mod set_cursor;
pub use set_cursor::{SetCursorAction, SetCursorTarget, set_cursor_action, parent_gets_first_chance, split_lparam, WM_SETCURSOR};
#[path = "win32_window/hardware.rs"]
pub mod hardware;
pub use cursor::{IDC_ARROW, IDC_IBEAM, IDC_SIZENWSE, IDC_SIZENESW, IDC_SIZEWE, IDC_SIZENS};

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
/// Last message of the mouse range, which a mouse-only filter spans to.
pub const WM_MOUSEHWHEEL: u32 = 0x020e;
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
pub const WM_SYSTIMER: u32 = 0x0118;
const KEY_REPEAT_COUNT_MASK: u32 = 0xffff;
const KEY_PREVIOUS_STATE: u32 = 1 << 30;
const KEY_TRANSITION_STATE: u32 = 1 << 31;
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
    /// The message range this filter admits. A retrieval that names neither
    /// end asks for every message, and the whole range is what every stage of
    /// the retrieval must test against, not the zero pair the caller passed.
    /// # C: O(1)
    pub const fn range(&self) -> (u32, u32) {
        if self.first == 0 && self.last == 0 { (0, u32::MAX) } else { (self.first, self.last) }
    }
    fn matches(self, message: WinMessage) -> bool {
        let (first, last) = self.range();
        (self.hwnd.is_none() || self.hwnd == message.hwnd)
            && message.message >= first && message.message <= last
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum QueueError { Full }

const MESSAGE_QUEUE_LIMIT: usize = 10_000;

#[derive(Default)]
pub struct MessageQueue { messages: VecDeque<QueuedMessage>, quit: Option<i32>, keyboard: KeyboardState, caret: CaretState, caret_generation: u64, caret_blink: CaretBlink,
    /// Monotonic nanoseconds at which the owning thread last read this queue.
    access_ns: u64,
    /// Wake bits set since the last query that reported them.
    changed: u32,
    /// Descending windowless-timer id allocator; zero means untouched.
    next_timer_id: u64,
    /// Tick count of the message this thread last read.
    message_time: u32,
    /// Packed position of the message this thread last read.
    message_pos: u32,
    /// Extra information this thread set, which the next retrieval resets.
    message_extra: i64,
    /// Pointers this thread has seen, in the order they were first reported.
    pointers: Vec<pointer::Pointer> }

impl MessageQueue {
    /// Post one hardware message, which contributes its own input class. # C: O(1)
    pub fn post_input(&mut self, message: WinMessage, pos: u32) -> Result<(), QueueError> {
        self.post_input_at(message, msg_time::tick_ms(), pos)
    }
    /// # C: O(1)
    pub fn post_input_at(&mut self, message: WinMessage, time: u32, pos: u32) -> Result<(), QueueError> {
        if self.messages.len() >= MESSAGE_QUEUE_LIMIT { return Err(QueueError::Full); }
        self.messages.push_back(QueuedMessage { message, key: None, bits: queue_status::hardware_bit(message.message), time, pos });
        Ok(())
    }
    pub fn post(&mut self, message: WinMessage, pos: u32) -> Result<(), QueueError> {
        self.post_with_bits(message, queue_status::QS_POSTED, pos)
    }
    /// Enqueue one message carrying the wake bits its origin sets. # C: O(1)
    pub fn post_with_bits(&mut self, message: WinMessage, bits: u32, pos: u32) -> Result<(), QueueError> {
        self.post_with_bits_at(message, bits, msg_time::tick_ms(), pos)
    }
    /// Enqueue one message with the tick count and position it is stamped with. # C: O(1)
    pub fn post_with_bits_at(&mut self, message: WinMessage, bits: u32, time: u32, pos: u32) -> Result<(), QueueError> {
        if self.messages.len() >= MESSAGE_QUEUE_LIMIT { return Err(QueueError::Full); }
        self.changed |= bits;
        self.messages.push_back(QueuedMessage { message, key: None, bits, time, pos });
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
    /// Put the retrieval-prepared form of one queued message back where the
    /// queued one was, so the canonical queue stays the only place a
    /// retrieval reads a message from. # C: O(N_queued)
    fn replace_matching<F>(&mut self, matches: F, message: WinMessage) -> bool
    where F: Fn(WinMessage) -> bool {
        let Some(index) = self.messages.iter().position(|entry| matches(entry.message)) else { return false; };
        self.messages[index].message = message;
        true
    }
    pub fn len(&self) -> usize { self.messages.len() }
    fn cleanup_window(&mut self, id: WindowId) {
        self.messages.retain(|entry| entry.message.hwnd != Some(id));
        if self.caret.hwnd == Some(id) { self.caret.destroy(); self.caret_generation = self.caret_generation.saturating_add(1); }
    }
    /// Window that owns the caret and the rectangle it occupies. # C: O(1)
    pub fn caret_placement(&self) -> Option<(WindowId, WindowRect)> {
        let hwnd = self.caret.hwnd?;
        Some((hwnd, WindowRect { left: self.caret.x, top: self.caret.y,
            right: self.caret.x.saturating_add(self.caret.width),
            bottom: self.caret.y.saturating_add(self.caret.height) }))
    }
    pub fn post_quit(&mut self, code: i32) { self.quit = Some(code); }
    fn quit_pending(&self) -> bool { self.quit.is_some() }
    fn quit_message(&mut self, filter: MessageFilter, remove: bool, pos: u32) -> Option<WinMessage> {
        let code = self.quit?;
        let message = WinMessage { hwnd: None, message: WM_QUIT, wparam: code as u64, lparam: 0 };
        if !filter.matches(message) { return None; }
        if remove { self.quit = None; }
        self.note_message_time(msg_time::tick_ms());
        self.note_message_pos(pos);
        self.note_message_extra(0);
        Some(message)
    }
    fn take_quit_matching<F>(&mut self, matches: F, pos: u32) -> Option<i32>
    where F: Fn(WinMessage) -> bool {
        let code = self.quit?;
        let message = WinMessage { hwnd: None, message: WM_QUIT, wparam: code as u64, lparam: 0 };
        if !matches(message) { return None; }
        self.quit = None;
        self.note_message_time(msg_time::tick_ms());
        self.note_message_pos(pos);
        self.note_message_extra(0);
        Some(code)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WindowRecord { pub owner_tid: u64, pub parent: Option<WindowId>, pub owner: Option<WindowId>, pub wndproc: u64, pub unicode: bool, pub class_atom: Option<u16>, pub visible: bool,
    /// The window's system menu bar, whose single popup item is what the
    /// window-menu query reports.
    pub sys_menu: Option<u32>,
    /// One field holds either the window's menu handle or, for an effective
    /// child, its control identifier: the `GWLP_ID` slot, whose meaning the
    /// style decides. A child never names a menu here.
    pub id_menu: u64, pub presentation_ready: bool, pub style: u32, pub ex_style: u32, pub last_focus: Option<WindowId>, pub client_rect: Option<WindowRect>,
    /// Input context associated with this window, as the reference keeps it on
    /// the window record itself.
    pub imc: Option<crate::win32_imc::ImcId>,
    /// Builtin control identity this window's procedure belongs to; zero until
    /// one is given.
    pub fnid: u16 }


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

    /// Name of one string atom, absent when nothing holds that slot.
    /// # C: O(1)
    pub fn name(&self, atom: u16) -> Option<&[u16]> {
        let index = atom.checked_sub(USER_ATOM_BASE)?.checked_sub(1)? as usize;
        self.names.get(index)?.as_ref().map(|entry| entry.name.as_slice())
    }

    /// Whether one value can name a string atom at all. # C: O(1)
    pub const fn is_string_atom(atom: u16) -> bool { atom > USER_ATOM_BASE }
}

impl Default for UserAtomTable { fn default() -> Self { Self::new() } }


#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WindowRect { pub left: i32, pub top: i32, pub right: i32, pub bottom: i32 }

/// Canonical compositor input for one visible window paint transaction.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WindowPresentRecord { pub window: WindowId, pub bounds: WindowRect, pub damage: Option<WindowRect> }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WindowError { NoSuchWindow, NoMemory, InvalidParent, InvalidParameter, ClassInUse, WrongThread, NoFocus, QueueFull, PaintActive, PaintNotActive, NotVisible }

pub struct WindowManager { next: u32, next_atom: u16, classes: Vec<WindowClass>, windows: Vec<(WindowId, OwnedWindow)>, rects: Vec<(WindowId, WindowRect)>, texts: Vec<(WindowId, Vec<u16>)>, dirty: Vec<(WindowId, PaintDamage)>, painting: Vec<(WindowId, PaintSession)>, queues: Vec<(u64, MessageQueue)>, timers: Vec<WindowTimer>, focus: Option<WindowId>, capture: Option<WindowId>, cursor: (i32, i32), buttons: u16, destroying: Vec<WindowId>, keyboard: KeyboardState, active: Option<WindowId>,
    /// Cursor and icon objects, the displayed cursor and its show-count.
    cursors: cursor_object::CursorIcons, current_cursor: u64, cursor_count: i32,
    /// Cursor clip rectangle, its last-change tick, and the position history.
    cursor_clip: Option<WindowRect>, cursor_change: u32,
    cursor_history: [cursor_pos::CursorPos; cursor_pos::CURSOR_HISTORY], cursor_latest: usize,
    /// Menu and move/size roles the capture request also carries.
    menu_owner: Option<WindowId>, move_size: Option<WindowId>,
    hotkeys: hotkey::Hotkeys, inputs: thread_input::ThreadInputs, tracks: mouse_track::MouseTracks,
    raw_input: rawinput::RawRegistrations, layouts: Vec<(u64, u64)>, icons: window_icon::WindowIconTable,
    /// Per-window attributes only a few calls touch; absent means defaults.
    attributes: Vec<(WindowId, attributes::WindowAttributes)>,
    /// Frame identity stamped on the next pointer record; monotonic per owner.
    pointer_frame: u32 }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct WindowTimer { owner_tid: u64, hwnd: Option<WindowId>, message: u32, id: u64, period_ns: u64, due_ns: u64, proc: u64 }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum QueueResult { Message(WinMessage), Quit(i32), Empty }

impl Default for WindowManager { fn default() -> Self { Self::new() } }

#[path = "win32_window/nonclient_menu.rs"]
pub mod nonclient_menu;

#[path = "win32_window/nonclient_create.rs"]
pub mod nonclient_create;

#[path = "win32_window/class_info_abi.rs"]
pub mod class_info_abi;

#[path = "win32_window/class_find.rs"]
mod class_find;
pub use class_find::{CS_GLOBALCLASS, MAX_CLASS_EXTRA, instance_matches, registration_is_local, extra_size_admitted};

#[path = "win32_window/class_types.rs"]
mod class_types;
pub use class_types::{ClassDescription, ClassMenuName, ClassRegistration, WindowClass};
#[path = "win32_window/state.rs"]
mod state;
#[path = "win32_window/timer.rs"]
mod timer;
pub use timer::{clamp_timeout, TIMER_ID_FIRST, TIMER_ID_LAST, USER_TIMER_MAXIMUM, USER_TIMER_MINIMUM};

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

        WM_NCHITTEST => DefaultWindowResult::Return(HTCLIENT as i64),
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
    DefaultWindowResult::Return(if inside { HTCLIENT as i64 } else { HTNOWHERE as i64 })
}

#[cfg(test)]
#[path = "win32_window/tests/state.rs"]
mod tests;
#[cfg(test)]
#[path = "win32_window/tests/pump_profile.rs"]
mod pump_profile_tests;
#[cfg(test)]
#[path = "win32_window/tests/lifecycle.rs"]
mod lifecycle_tests;
#[cfg(test)]
#[path = "win32_window/tests/typed_text_paint.rs"]
mod typed_text_paint_tests;
#[cfg(test)]
#[path = "win32_window/tests/edit_damage_paint.rs"]
mod edit_damage_paint_tests;
