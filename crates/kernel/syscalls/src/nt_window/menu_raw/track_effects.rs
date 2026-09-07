//! What one tracking decision does to the live windows. Every effect that
//! would enter a window procedure is queued back onto the loop as a step
//! instead, so the loop suspends at the call rather than skipping it.
use super::entry::with_entry;
use super::popup_window;
use super::session::PendingTrack;
use ipc::win32_menu::track::TrackEffect;
use ipc::win32_window::WindowId;

/// Apply one effect. Effects that open or close a popup queue the owner
/// notification and the measuring step that follow it. # C: O(N_open * N_items)
pub(crate) fn apply(track: &mut PendingTrack, effect: TrackEffect) {
    match effect {
        TrackEffect::Repaint { menu } => repaint(track, menu),
        // The owner notification is a step of its own; the state machine
        // rewrites this effect into one before the driver ever sees it.
        TrackEffect::MenuSelect { .. } => {}
        TrackEffect::HideSubPopups { menu } => {
            let chain = popup_window::sub_popup_chain(&track.session, menu);
            track.state.close_popups(&chain);
        }
        TrackEffect::ShowSubPopup { menu, select_first } => {
            let Some((position, submenu)) = popup_window::submenu_target(menu) else { return; };
            track.state.open_submenu(menu, position, submenu, select_first);
            let chain = popup_window::sub_popup_chain(&track.session, menu);
            track.state.close_popups(&chain);
        }
        TrackEffect::Post { message, wparam, lparam } => post(track.session.owner, message, wparam, lparam),
        TrackEffect::Beep => popup_window::beep(),
    }
}

/// Show the submenu the owner has just been told to update, and follow it.
/// # C: O(N_items + N_windows)
pub(crate) fn show_sub(track: &mut PendingTrack, menu: u32, position: u32, submenu: u32, select_first: bool) {
    let flags = track.state.flags();
    let current = popup_window::open_sub_popup(&mut track.session, menu, position, submenu, flags);
    if select_first && current != menu { popup_window::select_first_item(&mut track.session, current); }
    let window = track.session.window_of(current).unwrap_or(0);
    track.state.set_current(current, window);
}

/// Repaint the window showing one menu, or the owner's menu bar when the menu
/// is not one the session has open. # C: O(N_windows)
fn repaint(track: &PendingTrack, menu: u32) {
    let Some(window) = track.session.window_of(menu).and_then(|hwnd| u32::try_from(hwnd).ok()).and_then(WindowId::from_raw) else {
        let _ = crate::nt_window::draw_menu_bar_for_current(track.session.owner);
        return;
    };
    with_entry(|entry| { let _ = entry.state.invalidate(window, None); });
}

/// Post one command to the menu's owner. # C: O(N_windows)
fn post(owner: u64, message: u32, wparam: u64, lparam: i64) {
    let _ = crate::nt_window::dispatch(syscall::nt::NtCall { service: syscall::nt::NtService::PostMessage,
        args: syscall::SyscallArgs { a0: owner, a1: message as u64, a2: wparam, a3: lparam as u64, a4: 0, a5: 0 } });
}
