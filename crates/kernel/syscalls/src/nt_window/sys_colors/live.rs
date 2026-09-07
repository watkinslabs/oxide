//! Live system-colour replacement and the repaint it triggers.
use super::super::*;
use super::raw::{admitted, role, ORDINAL, REPAINT_FLAGS, WM_SYSCOLORCHANGE};

/// Route `NtUserSetSysColors`. # C: O(count + windows); # Sleeps: yes
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    if ordinal != ORDINAL { return None; }
    let arg = |index: usize| args.get(index).copied().unwrap_or(0);
    Some(set(arg(0) as i32, arg(1), arg(2)))
}

/// Replace each named colour, then tell every window and repaint the desktop.
/// # C: O(count + windows); # Sleeps: yes
fn set(count: i32, indexes: u64, values: u64) -> u64 {
    if !admitted(count) || indexes == 0 || values == 0 { return 0; }
    for slot in 0..count as u64 {
        let Some(index_at) = indexes.checked_add(slot * 4) else { return 0; };
        let Some(value_at) = values.checked_add(slot * 4) else { return 0; };
        let (Ok(index), Ok(value)) = (uaccess::get_user_u32(index_at), uaccess::get_user_u32(value_at)) else { return 0; };
        let Some(role) = role(index as i32) else { continue; };
        crate::nt_gdi::set_system_color(role, value);
    }
    let desktop = crate::nt_wine_window::builtin_classes::kernel::get_desktop_window();
    broadcast(desktop);
    redraw::for_current(desktop, 0, 0, REPAINT_FLAGS);
    1
}

/// Tell every window in this process that the system colours changed.
/// # C: O(N_windows); # Sleeps: yes
fn broadcast(desktop: u64) {
    let Some(cur) = sched::live::current().filter(|cur| cur.is_nt_personality()) else { return; };
    let windows = {
        let mut entries = GUI.lock();
        entries.retain(|entry| entry.group.upgrade().is_some());
        match entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group))) {
            Some(entry) => entry.state.window_handles(),
            None => alloc::vec::Vec::new(),
        }
    };
    for window in windows {
        if window.raw() as u64 == desktop { continue; }
        let _ = send::send_for_current(window.raw() as u64, WM_SYSCOLORCHANGE, 0, 0);
    }
}
