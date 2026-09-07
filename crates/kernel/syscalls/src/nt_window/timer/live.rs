//! Live window-timer arming against the canonical per-process window owner.
use super::super::*;
use super::raw::{arm_result, decode, Request};
use alloc::sync::Arc;

/// Route the four window-timer ordinals. # C: O(N_process_gui_states + N_timers)
pub(crate) fn dispatch(ordinal: u64, args: [u64; 5]) -> Option<u64> {
    match decode(ordinal, args)? {
        Request::Arm { hwnd, message, id, timeout_ms, proc } => Some(set_for_current(hwnd, message, id, timeout_ms, proc)),
        Request::Disarm { hwnd, message, id } => Some(kill_for_current(hwnd, message, id)),
    }
}

fn window(hwnd: u64) -> Result<Option<ipc::win32_window::WindowId>, ()> {
    if hwnd == 0 { return Ok(None); }
    let raw = u32::try_from(hwnd).map_err(|_| ())?;
    ipc::win32_window::WindowId::from_raw(raw).map(Some).ok_or(())
}

/// Arm one timer; the reply is the timer id, or plain success for id zero. # C: O(N_timers)
fn set_for_current(hwnd: u64, message: u32, id: u64, timeout_ms: u32, proc: u64) -> u64 {
    let Ok(target) = window(hwnd) else { return 0; };
    let Some(cur) = sched::live::current().filter(|cur| cur.is_nt_personality()) else { return 0; };
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))
        .unwrap_or_else(|| { entries.push(new_entry(&group)); entries.len() - 1 });
    let now = timekeeper::monotonic_ns();
    match entries[index].state.set_timer(cur.tid as u64, target, message, id, timeout_ms, proc, now) {
        Ok(assigned) => arm_result(assigned),
        Err(_) => 0,
    }
}

/// Disarm one timer by its window, message space and id. # C: O(N_timers)
fn kill_for_current(hwnd: u64, message: u32, id: u64) -> u64 {
    let Ok(target) = window(hwnd) else { return 0; };
    let Some(cur) = sched::live::current().filter(|cur| cur.is_nt_personality()) else { return 0; };
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let Some(index) = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group))) else { return 0; };
    entries[index].state.kill_timer(target, message, id) as u64
}
