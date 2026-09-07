//! Queue wake bits, thread-state classes and mouse tracking for the calling
//! thread.
use ipc::win32_window::{MouseTracking, ThreadState, WindowId};
use super::super::owner::{current_tid, with_state, with_state_mut, with_state_waking};

/// # C: O(N_nt_processes + N_queues + N_messages)
pub(crate) fn queue_status_for_current(flags: u32) -> Option<u32> {
    let tid = current_tid()?;
    with_state_mut(|state| state.queue_status(tid, flags))?
}

/// Answer one thread-state class. Classes naming state this owner does not
/// keep answer zero, as an unsupported class does. # C: O(N_nt_processes)
pub(crate) fn thread_state_for_current(class: ThreadState) -> u64 {
    let Some(tid) = current_tid() else { return 0; };
    with_state(|state| match class {
        ThreadState::FocusWindow => state.focused().map_or(0, |id| id.raw() as u64),
        ThreadState::ActiveWindow => state.active_window().map_or(0, |id| id.raw() as u64),
        ThreadState::CaptureWindow => state.capture_window().map_or(0, |id| id.raw() as u64),
        ThreadState::InputState => state.input_state(tid) as u64,
        ThreadState::Cursor => state.current_cursor(),
        _ => 0,
    }).unwrap_or(0)
}

/// # C: O(N_nt_processes + N_threads)
pub(crate) fn mouse_tracking_for_current() -> Option<MouseTracking> {
    let tid = current_tid()?;
    with_state(|state| state.mouse_tracking(tid))
}

/// # C: O(N_nt_processes + N_threads)
pub(crate) fn set_mouse_tracking_for_current(record: MouseTracking) {
    let Some(tid) = current_tid() else { return; };
    with_state_mut(|state| state.set_mouse_tracking(tid, record));
}

/// # C: O(N_nt_processes + N_windows)
pub(crate) fn pointer_inside_for_current(id: WindowId) -> bool {
    with_state(|state| state.pointer_inside(id)).unwrap_or(false)
}

/// Whether one window belongs to the calling thread. # C: O(N_nt_processes + N_windows)
pub(crate) fn window_is_current_thread(id: WindowId) -> Option<bool> {
    let tid = current_tid()?;
    with_state(|state| state.get(id).map(|record| record.owner_tid == tid))?
}

/// Post one message to a window of the calling process. # C: O(N_windows + N_queues)
pub(crate) fn post_message_for_current(hwnd: u64, message: u32, wparam: u64, lparam: i64) -> bool {
    let Some(id) = super::super::valid_window(hwnd) else { return false; };
    with_state_waking(|state| state.post_to_window(id, ipc::win32_window::WinMessage {
        hwnd: Some(id), message, wparam, lparam }).is_ok()).unwrap_or(false)
}

/// Arm one system timer on a window of the calling process. # C: O(N_timers)
pub(crate) fn set_system_timer_for_current(hwnd: u64, id: u64, timeout_ms: u32) -> bool {
    let Some(window) = super::super::valid_window(hwnd) else { return false; };
    let Some(tid) = current_tid() else { return false; };
    with_state_mut(|state| state.set_timer(tid, Some(window), id, timeout_ms, 0, timekeeper::monotonic_ns()).is_ok()).unwrap_or(false)
}

/// # C: O(N_timers)
pub(crate) fn kill_system_timer_for_current(hwnd: u64, id: u64) -> bool {
    let Some(window) = super::super::valid_window(hwnd) else { return false; };
    with_state_mut(|state| state.kill_timer(Some(window), id)).unwrap_or(false)
}

/// Inject one pointer transition through the canonical hardware path.
/// # C: O(N_windows + N_queues)
pub(crate) fn inject_mouse_for_current(ev_type: u16, code: u16, value: i32) -> bool {
    with_state_waking(|state| state.post_hardware_mouse(ev_type, code, value).is_ok()).unwrap_or(false)
}

/// Inject one key transition on the focused window. # C: O(N_windows + N_queues)
pub(crate) fn inject_key_for_current(vkey: u16, pressed: bool) -> bool {
    with_state_waking(|state| state.post_focused_key(vkey, pressed, false).is_ok()).unwrap_or(false)
}

/// Window handle validation shared with the raw entry. # C: O(1)
pub(crate) fn window_id(hwnd: u64) -> Option<ipc::win32_window::WindowId> { super::super::valid_window(hwnd) }
