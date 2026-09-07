//! The modal menu-tracking loop, driven one step at a time.
//!
//! The loop cannot run to completion on one kernel stack: a same-thread send
//! and a message dispatch both arm a client callback and unwind the syscall.
//! So the loop's position lives in the process record, the driver performs one
//! step and suspends at every call into a window procedure, and the callback's
//! return resumes it with the `LRESULT` the step asked for.
use super::entry::{current_tid, with_entry};
use super::popup_window::{self, layout_of, window_rect};
use super::session::{MenuSession, PendingTrack};
use super::track_effects;
use crate::nt_window::send::{self, Continuation, SendOutcome};
use crate::nt_window::STATUS_PENDING;
use alloc::sync::Arc;
use ipc::win32_menu::bar_hit::{bar_hit_test, BarMetrics};
use ipc::win32_menu::popup::{hit_test, PopupHit, TPM_POPUPMENU};
use ipc::win32_menu::track::PointerEvent;
use ipc::win32_menu::track_loop::{classify, LoopAction, LoopStep, ProcCall, RetrievedMessage, TrackLoop};
use ipc::win32_menu::{MenuId, MenuRect};
use ipc::win32_window::{MessageFilter, WindowId};

/// Every message of every window of the calling thread.
const ANY_MESSAGE: MessageFilter = MessageFilter { hwnd: None, first: 0, last: 0 };
/// Capture claimed for menu tracking rather than an application drag.
const CAPTURE_MENU: u32 = ipc::win32_window::CAPTURE_MENU;
/// The cell metrics one menu bar is measured, drawn and hit-tested with.
const BAR_METRICS: BarMetrics = BarMetrics { char_width: ipc::win32_gdi::MENU_CHAR_WIDTH,
    char_height: ipc::win32_gdi::MENU_CHAR_HEIGHT, bar_height: ipc::win32_gdi::MENU_BAR_HEIGHT };

/// Take the calling thread's parked loop out of the process record; exactly
/// one driver owns it at a time. # C: O(N_process_gui_states)
fn take() -> Option<PendingTrack> {
    let tid = current_tid()?;
    let track = with_entry(|entry| entry.menu_track.take()).flatten()?;
    if track.tid == tid { return Some(track); }
    let _ = with_entry(|entry| entry.menu_track = Some(track));
    None
}

/// # C: O(N_process_gui_states)
fn put(track: PendingTrack) { let _ = with_entry(|entry| entry.menu_track = Some(track)); }

/// # C: O(N_process_gui_states)
fn record(result: Result<u64, ()>) {
    let Some(mut track) = take() else { return; };
    track.state.call_result(result);
    put(track);
}

/// Claim or release the capture the tracked menu holds. # C: O(N_windows)
fn set_capture(hwnd: Option<u64>) {
    let Some(tid) = current_tid() else { return; };
    let window = hwnd.and_then(|hwnd| u32::try_from(hwnd).ok()).and_then(WindowId::from_raw);
    with_entry(|entry| { let _ = entry.state.set_capture_window(tid, window, CAPTURE_MENU); });
}

/// Whether the session was told to stop. # C: O(N_process_gui_states)
fn cancelled() -> bool { with_entry(|entry| entry.menu_tracking.as_ref().is_some_and(|tracking| tracking.exit)).unwrap_or(true) }

/// Which menu of the tracked chain a screen point falls on, and where in it.
/// The innermost popup wins, as the reference walks the chain from the open
/// submenu outwards; only once no open popup claims the point does the top
/// menu get its turn, as a bar drawn on the owner's own window.
/// # C: O(N_open * N_items)
fn menu_from_point(session: &MenuSession, top: u32, point: (i32, i32)) -> (Option<u32>, PopupHit) {
    for (menu, hwnd) in session.innermost_first() {
        let (Some(rect), Some(layout)) = (window_rect(hwnd), layout_of(menu)) else { continue; };
        let hit = hit_test(&layout, rect, point);
        if hit != PopupHit::Nowhere { return (Some(menu), hit); }
    }
    bar_from_point(session.owner, top, point)
}

/// The top menu resolved as a menu bar: it opens no window of its own, so the
/// point is tested against its owner's window rectangle and the item
/// rectangles the bar is drawn with. A popup top menu owns no bar and claims
/// nothing here. # C: O(N_items^2)
fn bar_from_point(owner: u64, top: u32, point: (i32, i32)) -> (Option<u32>, PopupHit) {
    let Some(menu) = MenuId::from_raw(top) else { return (None, PopupHit::Nowhere); };
    let Some(window) = u32::try_from(owner).ok().and_then(WindowId::from_raw) else { return (None, PopupHit::Nowhere); };
    let hit = with_entry(|entry| {
        if entry.menus.is_popup(menu).unwrap_or(true) { return PopupHit::Nowhere; }
        let Some(rect) = entry.state.rect(window) else { return PopupHit::Nowhere; };
        let bounds = MenuRect { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom };
        bar_hit_test(&entry.menus, menu, bounds, point, BAR_METRICS)
    }).unwrap_or(PopupHit::Nowhere);
    if hit == PopupHit::Nowhere { (None, hit) } else { (Some(top), hit) }
}

/// One pointer event resolved against the open chain. # C: O(N_open * N_items)
fn pointer_event(session: &MenuSession, top: u32, point: (i32, i32), right: bool) -> PointerEvent {
    let (menu, hit) = menu_from_point(session, top, point);
    let menu_is_bar = menu.and_then(MenuId::from_raw).and_then(|id| with_entry(|entry| entry.menus.is_popup(id).unwrap_or(true))).is_some_and(|popup| !popup);
    PointerEvent { pt: point, menu, hit, menu_is_bar, right_button: right }
}

/// The chain resolution one retrieved message needs, absent for a message that
/// names no point. # C: O(N_open * N_items)
fn resolve_pointer(session: &MenuSession, top: u32, msg: RetrievedMessage) -> Option<PointerEvent> {
    match classify(msg.message, msg.wparam, msg.lparam) {
        LoopAction::ButtonDown { point, right } | LoopAction::ButtonUp { point, right } => Some(pointer_event(session, top, point, right)),
        LoopAction::Move { point } => Some(pointer_event(session, top, point, false)),
        _ => None,
    }
}

/// Where `TrackPopupMenuEx` opens a popup, and the loop that follows it. The
/// pending report says the loop suspended in a window procedure and will
/// report its command when the callback returns.
/// # C: O(N_messages * N_items); # Sleeps: yes
pub(crate) fn track_popup_menu(owner: u64, menu: u32, flags: u32, x: i32, y: i32) -> u64 {
    let Some(tid) = current_tid() else { return 0; };
    let flags = flags | TPM_POPUPMENU;
    let mut state = TrackLoop::new(flags, owner as u32, menu, (x, y));
    state.begin();
    put(PendingTrack { tid, state, session: MenuSession::new(owner), origin: (x, y) });
    drive()
}

/// Track a window's menu bar or system menu from its owner: the bar is drawn in
/// place, so no popup opens for the top menu and the owner holds the capture.
/// The pending report has the same meaning as for a popup.
/// # C: O(N_messages * N_items); # Sleeps: yes
pub(crate) fn track_bar_menu(owner: u64, menu: u32, flags: u32, point: (i32, i32)) -> u64 {
    let Some(tid) = current_tid() else { return 0; };
    let mut state = TrackLoop::new(flags & !TPM_POPUPMENU, owner as u32, menu, point);
    state.begin();
    put(PendingTrack { tid, state, session: MenuSession::new(owner), origin: point });
    drive()
}

/// Perform steps until the loop suspends in a window procedure or reports its
/// command. # C: O(N_messages * N_items); # Sleeps: yes
fn drive() -> u64 {
    loop {
        let Some(mut track) = take() else { return 0; };
        let Some(step) = with_entry(|entry| track.state.next(&mut entry.menus)) else { return 0; };
        match step {
            LoopStep::Done(executed) => return finish(executed),
            LoopStep::Send(call) | LoopStep::Dispatch(call) => { put(track); if let Some(pending) = call_window_proc(call) { return pending; } }
            LoopStep::Effect(effect) => { track_effects::apply(&mut track, effect); put(track); }
            LoopStep::ShowTop => { show_top(&mut track); put(track); }
            LoopStep::ShowSub { menu, position, submenu, select_first } => { track_effects::show_sub(&mut track, menu, position, submenu, select_first); put(track); }
            LoopStep::Close { menu } => { close_and_follow(&mut track, menu); put(track); }
            LoopStep::PressAt { point } => { initial_press(&mut track, point); put(track); }
            LoopStep::NextMessage => { if !next_message(&mut track) { track.state.cancel(); } put(track); }
        }
    }
}

/// Enter one window procedure. A same-thread target arms a client callback and
/// suspends the loop; anything the send resolves immediately is recorded and
/// the loop continues. # C: O(sends + windows); # Sleeps: yes
fn call_window_proc(call: ProcCall) -> Option<u64> {
    let Some(tid) = current_tid() else { return Some(0); };
    match send::send_resumable_current(call.hwnd, call.message, call.wparam, call.lparam as u64, Continuation { token: tid, resume }) {
        SendOutcome::Pending => Some(STATUS_PENDING),
        SendOutcome::Complete(value) => { record(Ok(value)); None }
        SendOutcome::Failed => { record(Err(())); None }
    }
}

/// Resume the loop with the result of the window procedure a step entered.
/// # C: O(N_messages * N_items); # Sleeps: yes
fn resume(token: u64, result: Result<u64, ()>) -> u64 {
    if current_tid() != Some(token) { return 0; }
    record(result);
    drive()
}

/// Release the capture and report the chosen command. # C: O(N_windows)
fn finish(executed: i32) -> u64 {
    set_capture(None);
    let _ = with_entry(|entry| { entry.menu_tracking = None; entry.menu_track = None; });
    crate::nt_rtl::set_last_win32_error(0);
    if executed < 0 { 0 } else { executed as u64 }
}

/// Measure, place and show the top menu, and claim the capture tracking holds.
/// A popup carrying no item is never tracked. # C: O(N_items + N_windows)
fn show_top(track: &mut PendingTrack) {
    let flags = track.state.flags();
    let menu = track.state.top();
    let (x, y) = track.origin;
    if flags & TPM_POPUPMENU == 0 {
        // A bar is painted in its owner's nonclient band; nothing opens until
        // an item is selected, and the owner holds the capture meanwhile.
        track.state.set_current(menu, 0);
        set_capture(Some(track.session.owner));
        return;
    }
    if popup_window::show_popup(&mut track.session, menu, flags, x, y, 0, 0).is_none() { track.state.abandon(); return; }
    let window = track.session.window_of(menu).unwrap_or(0);
    track.state.set_current(menu, window);
    set_capture(Some(if flags & TPM_POPUPMENU != 0 { window } else { track.session.owner }));
    let empty = MenuId::from_raw(menu).and_then(|id| with_entry(|entry| entry.menus.count(id).unwrap_or(0))).unwrap_or(0) == 0;
    if empty && flags & TPM_POPUPMENU != 0 { track.state.abandon(); }
}

/// Retire one popup window and keep the window the loop is following in step
/// with the menu it now tracks. # C: O(N_open)
fn close_and_follow(track: &mut PendingTrack, menu: u32) {
    popup_window::close_popup(&mut track.session, menu);
    let current = track.state.current();
    let window = track.session.window_of(current).unwrap_or(0);
    track.state.set_current(current, window);
}

/// Apply the press that entered tracking, resolved against the bar the press
/// landed on. # C: O(N_items^2)
fn initial_press(track: &mut PendingTrack, point: (i32, i32)) {
    let event = pointer_event(&track.session, track.state.top(), point, false);
    let _ = with_entry(|entry| track.state.press(&mut entry.menus, &event));
}

/// Take the next message the loop must act on. A message the loop consumes is
/// removed from the queue; one that ends tracking without being consumed stays
/// for the application, as the reference leaves it. Reports whether tracking
/// can continue. # C: O(N_queued); # Sleeps: yes
fn next_message(track: &mut PendingTrack) -> bool {
    let Some(tid) = current_tid() else { return false; };
    if cancelled() { return false; }
    let peeked = with_entry(|entry| {
        entry.state.expire_timers(timekeeper::monotonic_ns());
        entry.state.peek_for_thread(tid, ANY_MESSAGE, false)
    }).flatten();
    let Some(message) = peeked else {
        if !track.state.idle() { return true; }
        return wait_for_message(tid);
    };
    let retrieved = RetrievedMessage { hwnd: message.hwnd.map_or(0, |window| window.raw() as u64),
        message: message.message, wparam: message.wparam, lparam: message.lparam };
    let event = resolve_pointer(&track.session, track.state.top(), retrieved);
    let remove = with_entry(|entry| track.state.message(&mut entry.menus, retrieved, event)).unwrap_or(true);
    if remove {
        let filter = MessageFilter { hwnd: message.hwnd, first: message.message, last: message.message };
        with_entry(|entry| { let _ = entry.state.peek_for_thread(tid, filter, true); });
    }
    true
}

/// Park until this thread's queue can answer. # C: O(N_process_gui_states); # Sleeps: yes
fn wait_for_message(tid: u64) -> bool {
    let Some(wait) = with_entry(|entry| Arc::clone(&entry.wait)) else { return false; };
    let Some(group) = sched::live::current().map(|cur| Arc::clone(&cur.thread_group)) else { return false; };
    // SAFETY: the menu loop holds an owned wait-list reference and rechecks
    // the canonical queue after every wake, without holding the GUI lock.
    let outcome = unsafe { sched::live::wait_event_interruptible(&wait, || {
        let mut entries = crate::nt_window::GUI.lock();
        entries.retain(|entry| entry.group.upgrade().is_some());
        entries.iter_mut().find(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))
            .is_some_and(|entry| entry.state.peek_for_thread(tid, ANY_MESSAGE, false).is_some())
    }) };
    outcome == sched::task::WaitOutcome::Ready
}
