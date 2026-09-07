//! What one queued pointer message becomes before the application sees it:
//! nonclient renumbering, double-click synthesis, the retrieval filter, and
//! which of the four outcomes the retrieval takes.
use super::uapi::*;
use super::super::{WinMessage, HTCLIENT, HTERROR, HTNOWHERE};

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
    pub first: u32,
    pub last: u32,
}

/// What the retrieval does with the message the stage prepared.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MouseOutcome {
    /// Outside the caller's message range: drop it and retrieve again.
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
    // The wheel has no nonclient form, so it is never renumbered.
    if message != WM_MOUSEWHEEL && ctx.hit_test != HTCLIENT {
        message = message - (WM_MOUSEMOVE - WM_NCMOUSEMOVE);
        wparam = ctx.hit_test as i16 as u16 as u64;
    }
    let mut click = ClickUpdate::Keep;
    if is_button_down(origin) {
        let current = ClickRecord { hwnd, message: origin, wparam: queued.wparam, time_ms: ctx.time_ms, point: split_point(queued.lparam) };
        if double_click_eligible(ctx) && is_double_click(previous, current, ctx) {
            message += WM_LBUTTONDBLCLK - WM_LBUTTONDOWN;
            if ctx.remove { click = ClickUpdate::Clear; }
        } else if ctx.remove { click = ClickUpdate::Store(current); }
    }
    let prepared = WinMessage { hwnd: queued.hwnd, message, wparam, lparam: queued.lparam };
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
    if message < ctx.first || message > ctx.last { return MouseOutcome::Filtered; }
    if ctx.hit_test == HTERROR || ctx.hit_test == HTNOWHERE { return MouseOutcome::ErrorCursor; }
    if !ctx.remove || ctx.captured { return MouseOutcome::Deliver; }
    MouseOutcome::Ladder
}
