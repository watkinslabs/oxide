//! What one queued pointer message becomes before the application sees it:
//! nonclient renumbering, double-click synthesis, the retrieval filter, and
//! which of the four outcomes the retrieval takes.
use super::uapi::*;
use super::ladder::ProcCall;
use super::super::{MessageFilter, WinMessage, HTCLIENT, HTERROR, HTNOWHERE, WM_NCHITTEST};

/// The click a window last saw, kept so the next one can be recognised as the
/// second half of a double click.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClickRecord { pub hwnd: u32, pub message: u32, pub wparam: u64, pub time_ms: u32, pub point: (i32, i32) }

/// What the retrieval does to the remembered click after this one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClickUpdate {
    /// Not a button going down, or a peek that leaves the message queued:
    /// the remembered click is untouched.
    Keep,
    /// This click starts a pair.
    Store(ClickRecord),
    /// This click closed a pair, so the next one starts a new one.
    Clear,
}

/// The geometry, style and settings the pointer ladder reads. Every field is
/// resolved by the caller against canonical window state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MouseContext {
    pub hit_test: i32,
    /// Screen origin of the target window's client area. A client hit is
    /// reported in client coordinates, and this is what the screen point the
    /// queue carries is measured from.
    pub client_origin: (i32, i32),
    /// Menu tracking is running, which leaves every point in screen
    /// coordinates: the tracking loop resolves them against the screen
    /// rectangles of the windows its menus are shown in.
    pub menu_mode: bool,
    /// A window holds the pointer capture, which suppresses hit-testing and
    /// the whole activation ladder.
    pub captured: bool,
    /// Menu tracking or a move/size loop is running, which makes every click
    /// eligible for double-click synthesis whatever the class says.
    pub modal: bool,
    /// The class of the clicked window carries `CS_DBLCLKS`.
    pub class_dbl_clks: bool,
    pub double_click_ms: u32,
    pub double_click_width: i32,
    pub double_click_height: i32,
    pub time_ms: u32,
    /// The retrieval removes the message rather than only looking at it.
    pub remove: bool,
    /// The retrieval's own filter. The range it admits is read from it, never
    /// from its two ends: a retrieval naming neither end asks for every
    /// message, and a stage that tested the literal pair ate them all.
    pub filter: MessageFilter,
}

/// What the retrieval does with the message the stage prepared.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MouseOutcome {
    /// Outside the caller's message range: leave queued and scan onward.
    Filtered,
    /// An error or nowhere hit: tell the window's cursor and drop it.
    ErrorCursor,
    /// Nothing left to decide; hand it over.
    Deliver,
    /// Run the notify/activate/cursor ladder first.
    Ladder,
}

/// One prepared pointer message and the decision that goes with it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MousePrepared {
    pub outcome: MouseOutcome,
    /// The message as the application will see it: renumbered into the
    /// nonclient range or promoted to a double click where that applies.
    pub message: WinMessage,
    /// The message number before either renumbering, which is what the
    /// hit-test parameter of `WM_MOUSEACTIVATE` and `WM_SETCURSOR` carries.
    pub origin: u32,
    pub hit_test: i32,
    pub click: ClickUpdate,
}

/// The nonclient hit test one queued pointer message must have before
/// anything else about it can be decided. The reference resolves the code by
/// sending `WM_NCHITTEST` to the window the point landed on, carrying the
/// point in screen coordinates; a window holding the capture takes every
/// click as a client one and is never asked. Absent means the answer is
/// already known and is `HTCLIENT`. # C: O(1)
pub const fn hit_test_call(hwnd: u32, screen: i64, captured: bool) -> Option<ProcCall> {
    if captured { return None; }
    Some(ProcCall { hwnd, message: WM_NCHITTEST, wparam: 0, lparam: screen })
}

/// Whether two clicks are the halves of one double click. Both must name the
/// same window, message and button state, fall inside the double-click time,
/// and land within half the double-click rectangle of each other. # C: O(1)
pub fn is_double_click(previous: Option<ClickRecord>, current: ClickRecord, ctx: &MouseContext) -> bool {
    let Some(previous) = previous else { return false; };
    if previous.hwnd != current.hwnd || previous.message != current.message || previous.wparam != current.wparam { return false; }
    if current.time_ms.wrapping_sub(previous.time_ms) >= ctx.double_click_ms { return false; }
    let dx = (current.point.0 as i64 - previous.point.0 as i64).abs();
    let dy = (current.point.1 as i64 - previous.point.1 as i64).abs();
    dx < (ctx.double_click_width / 2) as i64 && dy < (ctx.double_click_height / 2) as i64
}

/// Whether a click over this window is eligible to become a double click at
/// all: a nonclient click and a click made during menu or move/size tracking
/// always are, a client click only for a class that asked. # C: O(1)
const fn double_click_eligible(ctx: &MouseContext) -> bool {
    ctx.modal || ctx.hit_test != HTCLIENT || ctx.class_dbl_clks
}

/// Prepare one queued pointer message. # C: O(1)
pub fn prepare(queued: WinMessage, previous: Option<ClickRecord>, ctx: &MouseContext) -> MousePrepared {
    let origin = queued.message;
    let hwnd = queued.hwnd.map_or(0, |window| window.raw());
    let mut message = origin;
    let mut wparam = queued.wparam;
    let mut lparam = queued.lparam;
    // The wheel has no nonclient form, so it is neither renumbered nor
    // translated: it is reported in screen coordinates.
    if message != WM_MOUSEWHEEL {
        if ctx.hit_test != HTCLIENT {
            message = message - (WM_MOUSEMOVE - WM_NCMOUSEMOVE);
            wparam = ctx.hit_test as i16 as u16 as u64;
        } else if !ctx.menu_mode {
            let (x, y) = split_point(queued.lparam);
            lparam = make_point(x - ctx.client_origin.0, y - ctx.client_origin.1);
        }
    }
    let mut click = ClickUpdate::Keep;
    if is_button_down(origin) {
        let current = ClickRecord { hwnd, message: origin, wparam: queued.wparam, time_ms: ctx.time_ms, point: split_point(queued.lparam) };
        if double_click_eligible(ctx) && is_double_click(previous, current, ctx) {
            message += WM_LBUTTONDBLCLK - WM_LBUTTONDOWN;
            if ctx.remove { click = ClickUpdate::Clear; }
        } else if ctx.remove { click = ClickUpdate::Store(current); }
    }
    let prepared = WinMessage { hwnd: queued.hwnd, message, wparam, lparam };
    let outcome = outcome_of(message, ctx);
    MousePrepared { outcome, message: prepared, origin, hit_test: ctx.hit_test,
        click: if matches!(outcome, MouseOutcome::Filtered) { ClickUpdate::Keep } else { click } }
}

/// The filter runs against the renumbered message, and an error or nowhere hit
/// outranks everything the ladder would otherwise do. A peek that leaves the
/// message queued, and a click while a window holds the capture, both stop
/// short of the ladder; every other removed pointer message runs it, because
/// the cursor is set for all of them and not only for a button going down.
/// # C: O(1)
const fn outcome_of(message: u32, ctx: &MouseContext) -> MouseOutcome {
    let (first, last) = ctx.filter.range();
    if message < first || message > last { return MouseOutcome::Filtered; }
    if ctx.hit_test == HTERROR || ctx.hit_test == HTNOWHERE { return MouseOutcome::ErrorCursor; }
    if !ctx.remove || ctx.captured { return MouseOutcome::Deliver; }
    MouseOutcome::Ladder
}

/// Raw pointer input can become nonclient or double-click input at retrieval.
/// # C: O(1)
pub fn possible_filter(message: u32, filter: MessageFilter) -> bool {
    let (first, last) = filter.range();
    let admits = |number| number >= first && number <= last;
    if admits(message) { return true; }
    if message == WM_MOUSEWHEEL { return false; }
    let nonclient = message.wrapping_sub(WM_MOUSEMOVE - WM_NCMOUSEMOVE);
    if admits(nonclient) { return true; }
    is_button_down(message) && (admits(message + WM_LBUTTONDBLCLK - WM_LBUTTONDOWN)
        || admits(nonclient + WM_LBUTTONDBLCLK - WM_LBUTTONDOWN))
}

/// Default activation after a parent declines: caption left-down belongs to
/// nonclient handling; other clicks activate. # C: O(1)
pub const fn default_mouse_activation(lparam:u64)->u64 {
    if (lparam >> 16) as u16 as u32 == WM_LBUTTONDOWN && lparam as u16 == HTCAPTION {
        MA_NOACTIVATE
    } else { MA_ACTIVATE }
}
